//! 固定路由消息的安全字节编解码；布局取自当前系统绑定，不转换裸指针。
use nix::libc;
use std::{
    io::{self, Read},
    mem::{offset_of, size_of},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

const HEADER: usize = size_of::<libc::rt_msghdr>();
const INDEX: usize = offset_of!(libc::rt_msghdr, rtm_index);
const FLAGS: usize = offset_of!(libc::rt_msghdr, rtm_flags);
const ADDRS: usize = offset_of!(libc::rt_msghdr, rtm_addrs);
const PID: usize = offset_of!(libc::rt_msghdr, rtm_pid);
const SEQ: usize = offset_of!(libc::rt_msghdr, rtm_seq);
const ERROR: usize = offset_of!(libc::rt_msghdr, rtm_errno);
const LIMIT: Duration = Duration::from_secs(1);
const REQUIRED: i32 = libc::RTF_UP | libc::RTF_STATIC | libc::RTF_IFSCOPE;
const VOLATILE: i32 = libc::RTF_DONE | libc::RTF_IFREF;
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn integer(bytes: &[u8], at: usize) -> i32 {
    i32::from_ne_bytes(bytes[at..at + 4].try_into().expect("字段范围已经核对"))
}
fn put(bytes: &mut [u8], at: usize, value: i32) {
    bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}
fn rounded(length: usize) -> usize {
    length.max(1).div_ceil(4) * 4
}
fn ipv4(address: Ipv4Addr) -> Vec<u8> {
    let mut bytes = vec![0; size_of::<libc::sockaddr_in>()];
    bytes[0] = bytes.len() as u8;
    bytes[1] = libc::AF_INET as u8;
    bytes[4..8].copy_from_slice(&address.octets());
    bytes
}
fn link(index: u16, name: &str) -> Vec<u8> {
    let mut bytes = vec![0; rounded((8 + name.len()).max(size_of::<libc::sockaddr_dl>()))];
    bytes[0] = (8 + name.len()).max(size_of::<libc::sockaddr_dl>()) as u8;
    bytes[1] = libc::AF_LINK as u8;
    bytes[2..4].copy_from_slice(&index.to_ne_bytes());
    bytes[5] = name.len() as u8;
    bytes[8..8 + name.len()].copy_from_slice(name.as_bytes());
    bytes
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Gateway {
    Link(u16, String),
    Ip(Ipv4Addr),
    Other(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Record {
    index: u16,
    flags: i32,
    destination: Ipv4Addr,
    mask: Option<Ipv4Addr>,
    gateway: Gateway,
    interface: Option<(u16, String)>,
}
impl Record {
    pub(super) fn is_key(&self, index: u16) -> bool {
        self.index == index
            && self.flags & libc::RTF_IFSCOPE != 0
            && self.destination.is_unspecified()
            && self.mask.is_some_and(|m| m.is_unspecified())
    }
    pub(super) fn is_direct(&self, index: u16, name: &str) -> bool {
        self.is_key(index)
            && self.flags & REQUIRED == REQUIRED
            && self.flags & !(REQUIRED | libc::RTF_CLONING | libc::RTF_PRCLONING) == 0
            && matches!(&self.gateway, Gateway::Link(i, n) if *i == index && (n.is_empty() || n == name))
            && self
                .interface
                .as_ref()
                .is_none_or(|(i, n)| *i == index && n == name)
    }
    #[cfg(test)]
    pub(super) fn test_direct(index: u16, name: &str) -> Self {
        Self {
            index,
            flags: REQUIRED,
            destination: Ipv4Addr::UNSPECIFIED,
            mask: Some(Ipv4Addr::UNSPECIFIED),
            gateway: Gateway::Link(index, name.into()),
            interface: None,
        }
    }
}
fn read_ip(bytes: &[u8], mask: bool) -> io::Result<Ipv4Addr> {
    if mask && bytes.is_empty() {
        return Ok(Ipv4Addr::UNSPECIFIED);
    }
    if bytes.len() > size_of::<libc::sockaddr_in>()
        || bytes.len() < 2
        || (!mask && (bytes[1] != libc::AF_INET as u8 || bytes.len() < 8))
        || (mask && bytes[1] != 0 && bytes[1] != libc::AF_INET as u8)
    {
        return Err(invalid("路由地址族或长度无效"));
    }
    let mut octets = [0; 4];
    if bytes.len() > 4 {
        let count = (bytes.len() - 4).min(4);
        octets[..count].copy_from_slice(&bytes[4..4 + count]);
    }
    Ok(octets.into())
}
fn read_link(bytes: &[u8]) -> io::Result<(u16, String)> {
    if bytes.len() < 8 || bytes[1] != libc::AF_LINK as u8 {
        return Err(invalid("链路地址长度或类型无效"));
    }
    let name_end = 8 + bytes[5] as usize;
    let end = name_end + bytes[6] as usize + bytes[7] as usize;
    if end > bytes.len() || bytes[5] as usize >= libc::IFNAMSIZ {
        return Err(invalid("链路地址字段超限"));
    }
    let name = std::str::from_utf8(&bytes[8..name_end]).map_err(|_| invalid("链路接口名称无效"))?;
    if !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid("链路接口名称无效"));
    }
    Ok((
        u16::from_ne_bytes(bytes[2..4].try_into().unwrap()),
        name.into(),
    ))
}
fn decode(bytes: &[u8]) -> io::Result<Record> {
    if bytes.len() < HEADER
        || u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize != bytes.len()
        || bytes[2] != libc::RTM_VERSION as u8
    {
        return Err(invalid("路由回复版本或长度无效"));
    }
    let bits = integer(bytes, ADDRS);
    if bits < 0 || bits & !255 != 0 {
        return Err(invalid("路由地址位图无效"));
    }
    let mut addresses: [Option<&[u8]>; 8] = [None; 8];
    let mut offset = HEADER;
    for (bit, slot) in addresses.iter_mut().enumerate() {
        if bits & (1 << bit) == 0 {
            continue;
        }
        let length = *bytes.get(offset).ok_or_else(|| invalid("路由地址缺失"))? as usize;
        let end = offset
            .checked_add(rounded(length))
            .ok_or_else(|| invalid("路由地址长度溢出"))?;
        if end > bytes.len() {
            return Err(invalid("路由地址截断"));
        }
        *slot = Some(&bytes[offset..offset + length]);
        offset = end;
    }
    if offset != bytes.len() {
        return Err(invalid("路由回复尾随未知内容"));
    }
    let gateway = addresses[1].ok_or_else(|| invalid("路由缺少下一跳"))?;
    let gateway = match gateway.get(1).copied() {
        Some(family) if family == libc::AF_LINK as u8 => {
            let (i, n) = read_link(gateway)?;
            Gateway::Link(i, n)
        }
        Some(family) if family == libc::AF_INET as u8 => Gateway::Ip(read_ip(gateway, false)?),
        _ => Gateway::Other(gateway.to_vec()),
    };
    Ok(Record {
        index: u16::from_ne_bytes(bytes[INDEX..INDEX + 2].try_into().unwrap()),
        flags: integer(bytes, FLAGS) & !VOLATILE,
        destination: read_ip(
            addresses[0].ok_or_else(|| invalid("路由缺少目的地址"))?,
            false,
        )?,
        mask: addresses[2].map(|b| read_ip(b, true)).transpose()?,
        gateway,
        interface: addresses[4].map(read_link).transpose()?,
    })
}
fn message(kind: i32, index: u16, name: &str, address: Ipv4Addr, seq: i32) -> io::Result<Vec<u8>> {
    if ![libc::RTM_GET, libc::RTM_ADD, libc::RTM_DELETE].contains(&kind)
        || seq <= 0
        || name.len() >= libc::IFNAMSIZ
        || !name.bytes().all(|b| b.is_ascii_alphanumeric())
        || (kind != libc::RTM_GET
            && (index == 0
                || !name.starts_with("utun")
                || name.len() <= 4
                || !name[4..].bytes().all(|b| b.is_ascii_digit())
                || !address.is_unspecified()))
    {
        return Err(invalid("固定路由请求参数无效"));
    }
    let mut bytes = vec![0; HEADER];
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = kind as u8;
    bytes[INDEX..INDEX + 2].copy_from_slice(&index.to_ne_bytes());
    put(
        &mut bytes,
        FLAGS,
        if kind == libc::RTM_GET {
            if index == 0 { 0 } else { libc::RTF_IFSCOPE }
        } else {
            REQUIRED
        },
    );
    put(&mut bytes, PID, std::process::id() as i32);
    put(&mut bytes, SEQ, seq);
    let mut bits = libc::RTA_DST;
    bytes.extend(ipv4(address));
    if kind != libc::RTM_GET {
        bits |= libc::RTA_GATEWAY | libc::RTA_NETMASK;
        bytes.extend(link(index, name));
        bytes.extend(ipv4(Ipv4Addr::UNSPECIFIED));
    } else {
        bits |= libc::RTA_IFP;
        bytes.extend(link(0, ""));
    }
    put(&mut bytes, ADDRS, bits);
    let length = u16::try_from(bytes.len()).map_err(|_| invalid("路由请求超限"))?;
    bytes[..2].copy_from_slice(&length.to_ne_bytes());
    Ok(bytes)
}

pub(super) struct Control {
    socket: socket2::Socket,
    seq: i32,
}
impl Control {
    pub(super) fn new() -> io::Result<Self> {
        crate::platform::spawn::guarded(|| {
            let socket = socket2::Socket::new(
                socket2::Domain::from(libc::PF_ROUTE),
                socket2::Type::RAW,
                None,
            )?;
            socket.set_cloexec(true)?;
            socket.set_write_timeout(Some(LIMIT))?;
            Ok(Self { socket, seq: 0 })
        })
    }
    fn request(
        &mut self,
        kind: i32,
        index: u16,
        name: &str,
        address: Ipv4Addr,
    ) -> io::Result<Option<Record>> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| invalid("路由请求序列耗尽"))?;
        let bytes = message(kind, index, name, address, self.seq)?;
        let deadline = Instant::now() + LIMIT;
        let written = self.socket.send(&bytes)?;
        if written != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "路由消息未完整提交",
            ));
        }
        for _ in 0..4096 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "路由回复超时"))?;
            self.socket.set_read_timeout(Some(remaining))?;
            let mut buffer = [0; 65536];
            let length = match (&self.socket).read(&mut buffer) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "路由通道提前关闭",
                ));
            }
            let reply = &buffer[..length];
            // 其他通知有不同头布局，不按本请求的路由头解析。
            if length < HEADER
                || reply[2] != libc::RTM_VERSION as u8
                || reply[3] != kind as u8
                || integer(reply, SEQ) != self.seq
                || integer(reply, PID) != std::process::id() as i32
            {
                continue;
            }
            let error = integer(reply, ERROR);
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            return if kind == libc::RTM_GET {
                decode(reply).map(Some)
            } else {
                Ok(None)
            };
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "路由通知数量超过回复预算",
        ))
    }
    pub(super) fn lookup(&mut self, index: u16) -> io::Result<Option<Record>> {
        match self.request(libc::RTM_GET, index, "", Ipv4Addr::UNSPECIFIED) {
            Ok(record) => Ok(record.filter(|r| r.is_key(index))),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub(super) fn add(&mut self, index: u16, name: &str) -> io::Result<()> {
        self.request(libc::RTM_ADD, index, name, Ipv4Addr::UNSPECIFIED)
            .map(|_| ())
    }
    pub(super) fn delete(&mut self, index: u16, name: &str) -> io::Result<()> {
        self.request(libc::RTM_DELETE, index, name, Ipv4Addr::UNSPECIFIED)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoding_matches_current_system_layout_and_is_always_scoped_for_writes() {
        assert_eq!(HEADER, 92);
        assert_eq!(
            (INDEX, FLAGS, ADDRS, PID, SEQ, ERROR),
            (4, 8, 12, 16, 20, 24)
        );
        assert_eq!(size_of::<libc::sockaddr_in>(), 16);
        assert_eq!(size_of::<libc::sockaddr_dl>(), 20);
        for kind in [libc::RTM_ADD, libc::RTM_DELETE] {
            let bytes = message(kind, 42, "utun41", Ipv4Addr::UNSPECIFIED, 1).unwrap();
            let route = decode(&bytes).unwrap();
            assert!(route.is_direct(42, "utun41"));
            assert!(!route.is_direct(41, "utun41"));
            assert!(!route.is_direct(42, "utun40"));
            assert!(message(kind, 0, "utun41", Ipv4Addr::UNSPECIFIED, 1).is_err());
            assert!(message(kind, 42, "en0", Ipv4Addr::UNSPECIFIED, 1).is_err());
            assert!(message(kind, 42, "utun41", "8.8.8.8".parse().unwrap(), 1).is_err());
        }
    }
    #[test]
    fn malformed_lengths_bitmaps_and_link_names_are_rejected() {
        let original = message(libc::RTM_ADD, 42, "utun41", Ipv4Addr::UNSPECIFIED, 1).unwrap();
        for length in 0..original.len() {
            assert!(decode(&original[..length]).is_err());
        }
        for (offset, value) in [
            (2, 99),
            (HEADER, 255),
            (HEADER + 16, 255),
            (HEADER + 16 + 5, 255),
            (HEADER + 16 + 8, b';'),
        ] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            assert!(decode(&bytes).is_err());
        }
        let mut bytes = original.clone();
        put(&mut bytes, ADDRS, 256);
        assert!(decode(&bytes).is_err());
    }
    #[test]
    fn global_gateway_reject_host_and_missing_masks_never_match_owned_default() {
        for flags in [
            libc::RTF_UP | libc::RTF_STATIC,
            REQUIRED | libc::RTF_GATEWAY,
            REQUIRED | libc::RTF_HOST,
            REQUIRED | libc::RTF_REJECT,
            REQUIRED | libc::RTF_BLACKHOLE,
        ] {
            let mut record = Record::test_direct(42, "utun41");
            record.flags = flags;
            assert!(!record.is_direct(42, "utun41"));
        }
        let mut record = Record::test_direct(42, "utun41");
        record.mask = None;
        assert!(!record.is_key(42));
        record.mask = Some(Ipv4Addr::UNSPECIFIED);
        record.gateway = Gateway::Ip("8.8.8.8".parse().unwrap());
        assert!(!record.is_direct(42, "utun41"));
        assert_eq!(read_ip(&[], true).unwrap(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            read_ip(&[7, 0, 0, 0, 255, 255, 255], true).unwrap(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
    }
    #[test]
    fn live_read_only_loopback_query_uses_the_real_route_channel() {
        let mut control = Control::new().unwrap();
        let record = control
            .request(libc::RTM_GET, 0, "", "127.0.0.1".parse().unwrap())
            .unwrap()
            .unwrap();
        assert_ne!(record.index, 0);
        assert_eq!(record.destination, Ipv4Addr::LOCALHOST);
        assert!(!record.is_key(record.index));
    }
}
