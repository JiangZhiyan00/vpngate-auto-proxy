//! 已认证接口材料的地址配置；同步系统调用期间始终借用并保留控制句柄。
use super::{
    management::InterfaceMaterial,
    topology::{InterfaceAssignment, InterfaceTopology},
};
use nix::{
    ifaddrs::getifaddrs,
    net::if_::{InterfaceFlags, if_nametoindex},
};
use std::{io, net::Ipv4Addr};

mod sys;

#[derive(Clone, Debug)]
struct Address {
    local: Ipv4Addr,
    destination: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
}
#[derive(Clone, Debug)]
struct State {
    name: String,
    index: u32,
    flags: InterfaceFlags,
    addresses: Vec<Address>,
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn expected(assignment: &InterfaceAssignment) -> (Ipv4Addr, Ipv4Addr) {
    match assignment.topology() {
        InterfaceTopology::PointToPoint { peer } => (peer, Ipv4Addr::BROADCAST),
        InterfaceTopology::Subnet { netmask } => (assignment.local_address(), netmask),
    }
}
fn valid_flags(flags: InterfaceFlags) -> bool {
    flags.contains(InterfaceFlags::IFF_POINTOPOINT) && !flags.contains(InterfaceFlags::IFF_LOOPBACK)
}
fn matches(state: &State, assignment: &InterfaceAssignment) -> bool {
    let (destination, mask) = expected(assignment);
    state.name == assignment.interface_name()
        && valid_flags(state.flags)
        && state.addresses.len() == 1
        && state.addresses.iter().all(|address| {
            address.local == assignment.local_address()
                && address.destination == Some(destination)
                && address.mask == Some(mask)
        })
}
fn inventory() -> io::Result<Vec<State>> {
    let mut states = std::collections::BTreeMap::<String, State>::new();
    for entry in getifaddrs()? {
        let state = states.entry(entry.interface_name.clone()).or_insert(State {
            index: if_nametoindex(entry.interface_name.as_str())?,
            name: entry.interface_name,
            flags: entry.flags,
            addresses: Vec::new(),
        });
        if state.flags != entry.flags {
            return Err(invalid("接口清单在读取期间发生变化"));
        }
        if let Some(address) = entry
            .address
            .and_then(|a| a.as_sockaddr_in().map(|a| a.ip()))
        {
            state.addresses.push(Address {
                local: address,
                destination: entry
                    .destination
                    .and_then(|a| a.as_sockaddr_in().map(|a| a.ip())),
                mask: entry
                    .netmask
                    .and_then(|a| a.as_sockaddr_in().map(|a| a.ip())),
            });
        }
    }
    Ok(states.into_values().collect())
}
fn range(local: Ipv4Addr, mask: Ipv4Addr) -> (u32, u32) {
    let low = u32::from(local) & u32::from(mask);
    (low, low | !u32::from(mask))
}
fn overlaps(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}
fn preflight(
    states: &[State],
    assignment: &InterfaceAssignment,
    index: u32,
    peers: &[(&InterfaceAssignment, u32)],
) -> io::Result<InterfaceFlags> {
    let target = states
        .iter()
        .find(|s| s.name == assignment.interface_name())
        .ok_or_else(|| invalid("本次接口已消失"))?;
    if target.index != index
        || index == 0
        || !valid_flags(target.flags)
        || !target.addresses.is_empty()
    {
        return Err(invalid("本次接口身份或未配置状态不符"));
    }
    if peers.len() > 32 {
        return Err(invalid("并存接口材料超过上限"));
    }
    let mut identities = std::collections::BTreeSet::from([index]);
    for (peer, index) in peers {
        if !identities.insert(*index)
            || !states.iter().any(|s| {
                s.index == *index && s.flags.contains(InterfaceFlags::IFF_UP) && matches(s, peer)
            })
        {
            return Err(invalid("并存接口材料重复或与内核状态不符"));
        }
    }
    let (destination, mask) = expected(assignment);
    let requested = [
        range(assignment.local_address(), mask),
        range(destination, Ipv4Addr::BROADCAST),
    ];
    for state in states
        .iter()
        .filter(|s| s.index != index && !peers.iter().any(|(_, i)| *i == s.index))
    {
        for address in &state.addresses {
            // 缺失或无效掩码不能被当作无冲突；保守拒绝任何可能覆盖的地址。
            let mask = address
                .mask
                .ok_or_else(|| invalid("外部接口地址掩码缺失"))?;
            let bits = u32::from(mask);
            let prefix = bits.leading_ones();
            if prefix == 0 || bits != u32::MAX << (32 - prefix) {
                return Err(invalid("外部接口地址掩码无效"));
            }
            let existing = range(address.local, mask);
            if requested.iter().any(|r| overlaps(*r, existing))
                || address.destination.is_some_and(|d| {
                    requested
                        .iter()
                        .any(|r| overlaps(*r, range(d, Ipv4Addr::BROADCAST)))
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "接口地址与外部网络配置冲突",
                ));
            }
        }
    }
    Ok(target.flags)
}

trait Backend {
    fn check(&mut self) -> io::Result<()>;
    fn states(&mut self) -> io::Result<Vec<State>>;
    fn mtu(&mut self, name: &str) -> io::Result<u16>;
    fn set_mtu(&mut self, name: &str, mtu: u16) -> io::Result<()>;
    fn add_address(&mut self, assignment: &InterfaceAssignment) -> io::Result<()>;
    fn set_flags(&mut self, name: &str, flags: InterfaceFlags) -> io::Result<()>;
}
fn apply(
    backend: &mut impl Backend,
    assignment: &InterfaceAssignment,
    index: u32,
    peers: &[(&InterfaceAssignment, u32)],
) -> io::Result<()> {
    backend.check()?;
    let flags = preflight(&backend.states()?, assignment, index, peers)?;
    backend.check()?;
    backend.set_mtu(assignment.interface_name(), assignment.mtu())?;
    backend.check()?;
    backend.add_address(assignment)?;
    backend.check()?;
    backend.set_flags(assignment.interface_name(), flags | InterfaceFlags::IFF_UP)?;
    backend.check()?;
    let states = backend.states()?;
    let state = states
        .iter()
        .find(|s| s.name == assignment.interface_name())
        .ok_or_else(|| invalid("配置后本次接口已消失"))?;
    if state.index != index
        || !matches(state, assignment)
        || !state.flags.contains(InterfaceFlags::IFF_UP)
        || backend.mtu(assignment.interface_name())? != assignment.mtu()
    {
        return Err(invalid("配置后内核接口状态与授权材料不符"));
    }
    backend.check()?;
    Ok(())
}

/// 路由接入前重新核对已配置地址、状态与最大传输单元，不执行写入。
pub(crate) fn verify_configured(material: &InterfaceMaterial) -> io::Result<()> {
    if material.is_revoked() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "接口材料已撤销"));
    }
    material.custody().revalidate()?;
    let state = inventory()?
        .into_iter()
        .find(|s| s.index == material.custody().interface_index())
        .ok_or_else(|| invalid("路由配置前接口已消失"))?;
    if !matches(&state, material.assignment())
        || !state.flags.contains(InterfaceFlags::IFF_UP)
        || sys::Control::new()?.mtu(material.assignment().interface_name())?
            != material.assignment().mtu()
    {
        return Err(invalid("路由配置前接口内核状态不符"));
    }
    Ok(())
}

struct Native<'a> {
    material: &'a InterfaceMaterial,
    peers: &'a [&'a InterfaceMaterial],
    socket: sys::Control,
}
impl Backend for Native<'_> {
    fn check(&mut self) -> io::Result<()> {
        for material in std::iter::once(self.material).chain(self.peers.iter().copied()) {
            if material.is_revoked() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "接口配置所属会话已撤销",
                ));
            }
            material.custody().revalidate()?;
        }
        Ok(())
    }
    fn states(&mut self) -> io::Result<Vec<State>> {
        inventory()
    }
    fn mtu(&mut self, name: &str) -> io::Result<u16> {
        self.socket.mtu(name)
    }
    fn set_mtu(&mut self, name: &str, mtu: u16) -> io::Result<()> {
        self.socket.set_mtu(name, mtu)
    }
    fn add_address(&mut self, assignment: &InterfaceAssignment) -> io::Result<()> {
        self.socket.add_address(assignment)
    }
    fn set_flags(&mut self, name: &str, flags: InterfaceFlags) -> io::Result<()> {
        self.socket.set_flags(name, flags)
    }
}

/// 仅配置本次仍由真实句柄持有的接口，不接纳裸名称、索引或任意命令。
/// 必须串行调用；并存材料只可来自仍存活的本项目会话，并逐一核对内核配置。
/// 成功只表示地址状态一致；公网作用域路由、出口及宿主影响仍须另行验证。
/// 失败撤销会话且保留调用方材料；调用方须先回收消费者再释放句柄。
pub fn configure(material: &InterfaceMaterial, peers: &[&InterfaceMaterial]) -> io::Result<()> {
    let result = (|| {
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "配置隧道接口需要管理员身份",
            ));
        }
        if peers.len() > 32 {
            return Err(invalid("并存接口材料超过上限"));
        }
        static CONFIGURATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serial = CONFIGURATION
            .lock()
            .map_err(|_| io::Error::other("接口配置串行锁已失效"))?;
        let mut backend = Native {
            material,
            peers,
            socket: sys::Control::new()?,
        };
        let peers = peers
            .iter()
            .map(|m| (m.assignment(), m.custody().interface_index()))
            .collect::<Vec<_>>();
        apply(
            &mut backend,
            material.assignment(),
            material.custody().interface_index(),
            &peers,
        )
    })();
    if result.is_err() {
        material.revoke();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::topology::AssignmentParser;
    use super::*;
    fn assignment(subnet: bool) -> InterfaceAssignment {
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP").unwrap();
        for field in [
            "dev=utun42",
            "dev_type=tun",
            "tun_mtu=1400",
            "ifconfig_local=10.231.66.2",
            if subnet {
                "ifconfig_netmask=255.255.255.0"
            } else {
                "ifconfig_remote=10.231.66.1"
            },
        ] {
            parser.consume(&format!(">UPDOWN:ENV,{field}")).unwrap();
        }
        parser.consume(">UPDOWN:ENV,END").unwrap().unwrap()
    }
    fn target() -> State {
        State {
            name: "utun42".to_owned(),
            index: 42,
            flags: InterfaceFlags::IFF_POINTOPOINT,
            addresses: Vec::new(),
        }
    }
    struct Fake {
        states: Vec<State>,
        mtu: u16,
        calls: Vec<&'static str>,
        check_count: usize,
        fail_check: usize,
        fail_step: Option<&'static str>,
        corrupt: bool,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                states: vec![target()],
                mtu: 1500,
                calls: Vec::new(),
                check_count: 0,
                fail_check: usize::MAX,
                fail_step: None,
                corrupt: false,
            }
        }
    }
    impl Fake {
        fn step(&mut self, name: &'static str) -> io::Result<()> {
            self.calls.push(name);
            if self.fail_step == Some(name) {
                return Err(io::Error::other("受控配置失败"));
            }
            Ok(())
        }
    }
    impl Backend for Fake {
        fn check(&mut self) -> io::Result<()> {
            self.check_count += 1;
            if self.check_count == self.fail_check {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "受控撤销"));
            }
            Ok(())
        }
        fn states(&mut self) -> io::Result<Vec<State>> {
            Ok(self.states.clone())
        }
        fn mtu(&mut self, _: &str) -> io::Result<u16> {
            Ok(if self.corrupt { 999 } else { self.mtu })
        }
        fn set_mtu(&mut self, _: &str, mtu: u16) -> io::Result<()> {
            self.step("最大传输单元")?;
            self.mtu = mtu;
            Ok(())
        }
        fn add_address(&mut self, assignment: &InterfaceAssignment) -> io::Result<()> {
            self.step("地址")?;
            let (destination, mask) = expected(assignment);
            self.states[0].addresses.push(Address {
                local: assignment.local_address(),
                destination: Some(destination),
                mask: Some(mask),
            });
            Ok(())
        }
        fn set_flags(&mut self, _: &str, flags: InterfaceFlags) -> io::Result<()> {
            self.step("标志")?;
            self.states[0].flags = flags;
            Ok(())
        }
    }
    #[test]
    fn both_topologies_configure_and_verify_exact_kernel_material() {
        for subnet in [false, true] {
            let assignment = assignment(subnet);
            let mut backend = Fake::default();
            apply(&mut backend, &assignment, 42, &[]).unwrap();
            assert_eq!(backend.calls, ["最大传输单元", "地址", "标志"]);
            assert!(matches(&backend.states[0], &assignment));
            assert!(backend.states[0].flags.contains(InterfaceFlags::IFF_UP));
            assert_eq!(backend.mtu, 1400);
        }
    }
    #[test]
    fn preexisting_address_or_wrong_identity_never_mutates_interface() {
        for case in 0..5 {
            let assignment = assignment(false);
            let mut backend = Fake::default();
            match case {
                0 => backend.states[0].index = 43,
                1 => backend.states[0].name = "utun43".to_owned(),
                2 => backend.states[0].flags |= InterfaceFlags::IFF_LOOPBACK,
                3 => backend.states[0].flags = InterfaceFlags::IFF_BROADCAST,
                _ => backend.add_address(&assignment).unwrap(),
            }
            backend.calls.clear();
            assert!(apply(&mut backend, &assignment, 42, &[]).is_err());
            assert!(backend.calls.is_empty());
        }
    }
    #[test]
    fn foreign_network_overlap_and_destination_conflicts_are_refused() {
        for (local, mask, destination) in [
            ("10.231.66.99", Some("255.255.255.0"), None),
            ("192.0.2.2", Some("255.255.255.255"), Some("10.231.66.1")),
            ("192.0.2.2", None, None),
            ("192.0.2.2", Some("255.0.255.0"), None),
        ] {
            let mut backend = Fake::default();
            let mut foreign = target();
            foreign.name = "en0".to_owned();
            foreign.index = 5;
            foreign.addresses.push(Address {
                local: local.parse().unwrap(),
                mask: mask.map(|m| m.parse().unwrap()),
                destination: destination.map(|d| d.parse().unwrap()),
            });
            backend.states.push(foreign);
            assert!(apply(&mut backend, &assignment(false), 42, &[]).is_err());
            assert!(backend.calls.is_empty());
        }
    }
    #[test]
    fn only_exact_live_peer_material_can_authorize_duplicate_addresses() {
        let mut backend = Fake::default();
        let mut peer = backend.states[0].clone();
        peer.name = "utun43".to_owned();
        peer.index = 43;
        peer.flags |= InterfaceFlags::IFF_UP;
        let mut peer_assignment = assignment(false);
        peer_assignment_test_name(&mut peer_assignment, "utun43");
        let (destination, mask) = expected(&peer_assignment);
        peer.addresses.push(Address {
            local: peer_assignment.local_address(),
            destination: Some(destination),
            mask: Some(mask),
        });
        backend.states.push(peer);
        assert!(preflight(&backend.states, &assignment(false), 42, &[]).is_err());
        assert!(
            preflight(
                &backend.states,
                &assignment(false),
                42,
                &[(&peer_assignment, 43)]
            )
            .is_ok()
        );
        assert!(
            preflight(
                &backend.states,
                &assignment(false),
                42,
                &[(&peer_assignment, 44)]
            )
            .is_err()
        );
        assert!(
            preflight(
                &backend.states,
                &assignment(false),
                42,
                &[(&peer_assignment, 43), (&peer_assignment, 43)]
            )
            .is_err()
        );
        backend.states[1].flags.remove(InterfaceFlags::IFF_UP);
        assert!(
            preflight(
                &backend.states,
                &assignment(false),
                42,
                &[(&peer_assignment, 43)]
            )
            .is_err()
        );
        backend.states[1].flags.insert(InterfaceFlags::IFF_UP);
        assert!(
            preflight(
                &backend.states,
                &assignment(false),
                42,
                &vec![(&peer_assignment, 43); 33]
            )
            .is_err()
        );
        backend.states[1].addresses[0].mask = None;
        assert!(
            preflight(
                &backend.states,
                &assignment(false),
                42,
                &[(&peer_assignment, 43)]
            )
            .is_err()
        );
    }
    fn peer_assignment_test_name(assignment: &mut InterfaceAssignment, name: &str) {
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP").unwrap();
        for field in [
            format!("dev={name}"),
            "dev_type=tun".to_owned(),
            "tun_mtu=1400".to_owned(),
            "ifconfig_local=10.231.66.2".to_owned(),
            "ifconfig_remote=10.231.66.1".to_owned(),
        ] {
            parser.consume(&format!(">UPDOWN:ENV,{field}")).unwrap();
        }
        *assignment = parser.consume(">UPDOWN:ENV,END").unwrap().unwrap();
    }
    #[test]
    fn cancellation_at_each_boundary_prevents_later_mutations() {
        for boundary in 1..=6 {
            let mut backend = Fake {
                fail_check: boundary,
                ..Fake::default()
            };
            assert_eq!(
                apply(&mut backend, &assignment(false), 42, &[])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Interrupted
            );
            assert_eq!(backend.calls.len(), boundary.saturating_sub(2).min(3));
        }
    }
    #[test]
    fn each_system_failure_stops_without_attempting_unowned_rollback() {
        for (count, step) in ["最大传输单元", "地址", "标志"].into_iter().enumerate() {
            let mut backend = Fake {
                fail_step: Some(step),
                ..Fake::default()
            };
            assert!(apply(&mut backend, &assignment(false), 42, &[]).is_err());
            assert_eq!(backend.calls.len(), count + 1);
        }
    }
    #[test]
    fn postconfiguration_mismatch_is_never_reported_as_success() {
        let mut backend = Fake {
            corrupt: true,
            ..Fake::default()
        };
        assert!(apply(&mut backend, &assignment(false), 42, &[]).is_err());
        let assignment = assignment(false);
        backend.corrupt = false;
        assert!(matches(&backend.states[0], &assignment));
        for case in 0..4 {
            let mut state = backend.states[0].clone();
            match case {
                0 => state.addresses[0].destination = None,
                1 => state.addresses[0].mask = None,
                2 => state.addresses[0].local = "10.231.66.3".parse().unwrap(),
                _ => state.addresses.push(state.addresses[0].clone()),
            }
            assert!(!matches(&state, &assignment));
        }
    }
    #[test]
    fn native_read_only_inventory_and_mtu_agree_for_loopback() {
        let states = inventory().unwrap();
        let loopback = states.iter().find(|s| s.name == "lo0").unwrap();
        assert!(loopback.flags.contains(InterfaceFlags::IFF_LOOPBACK));
        assert!(
            loopback
                .addresses
                .iter()
                .any(|a| a.local == Ipv4Addr::LOCALHOST)
        );
        assert!(sys::Control::new().unwrap().mtu("lo0").unwrap() >= 576);
    }
}
