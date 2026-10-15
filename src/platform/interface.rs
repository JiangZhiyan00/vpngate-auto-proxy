//! 特权父进程创建本次独占的控制连接；不配置地址、路由或发布出口。
use super::custody::{UtunCustody, protect_descriptor};
use nix::{
    errno::Errno,
    ifaddrs::getifaddrs,
    net::if_::{InterfaceFlags, if_nameindex, if_nametoindex},
    sys::socket::{SysControlAddr, connect, getsockopt, sockopt},
};
use std::{
    collections::BTreeMap,
    io,
    os::fd::{AsRawFd, OwnedFd},
};

const CONTROL_NAME: &str = "com.apple.net.utun_control";
const MAX_UNIT: u32 = 255;

enum AttemptError {
    Occupied,
    Failed(io::Error),
}
impl From<io::Error> for AttemptError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}
impl From<Errno> for AttemptError {
    fn from(error: Errno) -> Self {
        Self::Failed(error.into())
    }
}

fn allocate<T>(mut attempt: impl FnMut(u32) -> Result<T, AttemptError>) -> io::Result<T> {
    for unit in 1..=MAX_UNIT {
        match attempt(unit) {
            Ok(owned) => return Ok(owned),
            Err(AttemptError::Occupied) => {}
            Err(AttemptError::Failed(error)) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "限定范围内没有可用的隧道控制单元",
    ))
}

fn inventory() -> io::Result<BTreeMap<String, u32>> {
    if_nameindex()?
        .iter()
        .map(|interface| {
            let name = interface
                .name()
                .to_str()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "接口名称编码无效"))?;
            Ok((name.to_owned(), interface.index()))
        })
        .collect()
}

fn require_fresh(
    name: &str,
    index: u32,
    before: &BTreeMap<String, u32>,
    flags: Option<InterfaceFlags>,
    has_ipv4: bool,
) -> io::Result<()> {
    if index == 0
        || before.contains_key(name)
        || before.values().any(|old| *old == index)
        || !flags.is_some_and(|flags| {
            flags.contains(InterfaceFlags::IFF_POINTOPOINT)
                && !flags.contains(InterfaceFlags::IFF_LOOPBACK)
        })
        || has_ipv4
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "新建接口与既有资源冲突或初始状态不符",
        ));
    }
    Ok(())
}

fn open_control_socket() -> io::Result<OwnedFd> {
    // socket2 在返回前设置执行时关闭标志；名称查询及连接前再次确认保护。
    let descriptor: OwnedFd = socket2::Socket::new(
        socket2::Domain::from(nix::libc::PF_SYSTEM),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::from(nix::libc::SYSPROTO_CONTROL)),
    )?
    .into();
    protect_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn connect_unit(unit: u32, before: &BTreeMap<String, u32>) -> Result<UtunCustody, AttemptError> {
    let descriptor = open_control_socket()?;
    let address = SysControlAddr::from_name(descriptor.as_raw_fd(), CONTROL_NAME, unit)?;
    match connect(descriptor.as_raw_fd(), &address) {
        Ok(()) => {}
        // 只在连接阶段的明确占用时尝试下一个单元；查询及权限错误直接失败。
        Err(Errno::EBUSY) => return Err(AttemptError::Occupied),
        Err(error) => return Err(error.into()),
    }
    // 不调用苹果控制套接字不支持的本地地址查询，也不推导单元与接口编号关系。
    let name = getsockopt(&descriptor, sockopt::UtunIfname)?;
    let name = name
        .to_str()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "控制接口名称编码无效"))?;
    let index = if_nametoindex(name)?;
    let custody = UtunCustody::verify(descriptor, index)?;
    let mut flags = None;
    let mut has_ipv4 = false;
    for entry in getifaddrs()?.filter(|entry| entry.interface_name == custody.interface_name()) {
        flags = Some(entry.flags);
        has_ipv4 |= entry
            .address
            .is_some_and(|address| address.as_sockaddr_in().is_some());
    }
    require_fresh(custody.interface_name(), index, before, flags, has_ipv4)?;
    custody.revalidate()?;
    Ok(custody)
}

/// 仅供可信父进程创建新接口，不接管预先存在的接口或接受远端指定单元。
/// 返回的句柄须持续持有至完成隧道及业务交接；失败只关闭本次连接，不主动销毁接口。
/// 苹果创建套接字与设置继承保护为两个系统调用，调用期间不得并发派生子进程。
pub fn create() -> io::Result<UtunCustody> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "创建隧道接口需要管理员身份",
        ));
    }
    super::spawn::guarded(|| {
        let before = inventory()?;
        allocate(|unit| connect_unit(unit, &before))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::unix::net::UnixStream};

    #[test]
    fn ordinary_user_cannot_attempt_interface_creation() {
        assert!(!nix::unistd::getuid().is_root(), "本项回归须以普通用户运行");
        let error = create().err().expect("普通用户不得创建接口");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn occupied_attempts_release_descriptors_and_preserve_successful_owner() {
        let mut peers = Vec::new();
        let mut attempted = Vec::new();
        let owner = allocate(|unit| {
            attempted.push(unit);
            let (owner, peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            peers.push(peer);
            let descriptor = OwnedFd::from(owner);
            if unit < 3 {
                drop(descriptor);
                Err(AttemptError::Occupied)
            } else {
                Ok(descriptor)
            }
        })
        .unwrap();
        assert_eq!(attempted, [1, 2, 3]);
        for peer in &mut peers[..2] {
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
        assert!(peers[2].read(&mut [0]).is_err(), "成功句柄仍须持有");
        drop(owner);
        assert_eq!(peers[2].read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn lookup_busy_and_unrelated_errors_do_not_trigger_retry() {
        for failure in [Errno::EBUSY, Errno::EPERM, Errno::EINVAL] {
            let mut attempts = 0;
            let error = allocate::<()>(|_| {
                attempts += 1;
                Err(AttemptError::Failed(failure.into()))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(failure as i32));
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn exhausted_units_are_bounded_and_release_all_attempts() {
        let mut attempted = Vec::new();
        let error = allocate::<()>(|unit| {
            attempted.push(unit);
            let (owner, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            drop(owner);
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            Err(AttemptError::Occupied)
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(attempted, (1..=MAX_UNIT).collect::<Vec<_>>());
    }

    #[test]
    fn newly_created_identity_must_not_adopt_existing_or_configured_resource() {
        let before = BTreeMap::from([("utun2".to_owned(), 8)]);
        let flags = Some(InterfaceFlags::IFF_POINTOPOINT);
        assert!(require_fresh("utun3", 9, &before, flags, false).is_ok());
        for (name, index, flags, address) in [
            ("utun2", 9, flags, false),
            ("utun3", 8, flags, false),
            ("utun3", 0, flags, false),
            ("utun3", 9, flags, true),
            ("utun3", 9, None, false),
            (
                "utun3",
                9,
                Some(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT),
                false,
            ),
            ("utun3", 9, Some(InterfaceFlags::IFF_BROADCAST), false),
        ] {
            assert_eq!(
                require_fresh(name, index, &before, flags, address)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn real_interface_inventory_matches_kernel_loopback_identity() {
        let before = inventory().unwrap();
        assert_eq!(
            before.get("lo0").copied(),
            Some(if_nametoindex("lo0").unwrap())
        );
        assert!(before.values().all(|index| *index != 0));
    }

    #[test]
    fn real_control_socket_setup_and_lookup_do_not_create_interface() {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        let before = inventory().unwrap();
        let descriptor = open_control_socket().unwrap();
        assert!(
            FdFlag::from_bits_truncate(fcntl(&descriptor, FcntlArg::F_GETFD).unwrap())
                .contains(FdFlag::FD_CLOEXEC)
        );
        let address = SysControlAddr::from_name(descriptor.as_raw_fd(), CONTROL_NAME, 17).unwrap();
        assert_ne!(address.id(), 0);
        assert_eq!(address.unit(), 17);
        drop(descriptor);
        assert_eq!(inventory().unwrap(), before);
    }
}
