//! 苹果网络控制请求的窄封装；不对外接受请求编号或原始指针。
// nix 尚无上述网卡控制操作的安全封装；仅在本私有模块内允许固定请求的外部函数调用。
// 仓库其余代码继续拒绝不安全代码；布局、字段偏移及请求编号由当前系统头文件回归核对。
#![allow(unsafe_code)]
use super::{InterfaceAssignment, InterfaceFlags, expected};
use nix::libc;
use std::{io, mem::size_of, net::Ipv4Addr, os::fd::AsRawFd};

#[repr(C)]
struct Alias {
    name: [libc::c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in,
    destination: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}
nix::ioctl_readwrite!(get_mtu, b'i', 51, libc::ifreq);
nix::ioctl_write_ptr!(set_mtu, b'i', 52, libc::ifreq);
nix::ioctl_write_ptr!(set_flags, b'i', 16, libc::ifreq);
nix::ioctl_write_ptr!(add_address, b'i', 26, Alias);
fn name(value: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    if value.is_empty()
        || value.len() >= libc::IFNAMSIZ
        || !value.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "网络控制接口名称无效",
        ));
    }
    let mut name = [0; libc::IFNAMSIZ];
    for (target, source) in name.iter_mut().zip(value.bytes()) {
        *target = source as libc::c_char;
    }
    Ok(name)
}
fn sockaddr(address: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    }
}
fn request(interface: &str) -> io::Result<libc::ifreq> {
    Ok(libc::ifreq {
        ifr_name: name(interface)?,
        ifr_ifru: libc::__c_anonymous_ifr_ifru {
            ifru_addr: libc::sockaddr {
                sa_len: 0,
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    })
}
pub(super) struct Control(socket2::Socket);
impl Control {
    pub(super) fn new() -> io::Result<Self> {
        crate::platform::spawn::guarded(|| {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
            socket.set_cloexec(true)?;
            Ok(Self(socket))
        })
    }
    pub(super) fn mtu(&self, interface: &str) -> io::Result<u16> {
        let mut request = request(interface)?;
        // 安全性：固定读写请求匹配完整已初始化的 ifreq；内核只在调用期间借用可写存储。
        unsafe {
            get_mtu(self.0.as_raw_fd(), &mut request)?;
        }
        // 安全性：上面的固定请求成功后，该联合体字段是内核交付的最大传输单元。
        u16::try_from(unsafe { request.ifr_ifru.ifru_mtu })
            .map_err(|_| io::Error::other("内核最大传输单元无效"))
    }
    pub(super) fn set_mtu(&self, interface: &str, mtu: u16) -> io::Result<()> {
        let mut request = request(interface)?;
        request.ifr_ifru.ifru_mtu = mtu.into();
        // 安全性：固定只读入请求匹配有效 ifreq，套接字和请求在调用返回前始终存活。
        unsafe {
            set_mtu(self.0.as_raw_fd(), &request)?;
        }
        Ok(())
    }
    pub(super) fn set_flags(&self, interface: &str, flags: InterfaceFlags) -> io::Result<()> {
        let mut request = request(interface)?;
        request.ifr_ifru.ifru_flags = flags.bits() as i16;
        // 安全性：固定标志请求只读取完整 ifreq，名称有界且以零终止。
        unsafe {
            set_flags(self.0.as_raw_fd(), &request)?;
        }
        Ok(())
    }
    pub(super) fn add_address(&self, assignment: &InterfaceAssignment) -> io::Result<()> {
        let (destination, mask) = expected(assignment);
        let request = Alias {
            name: name(assignment.interface_name())?,
            address: sockaddr(assignment.local_address()),
            destination: sockaddr(destination),
            mask: sockaddr(mask),
        };
        // 安全性：repr(C) 的固定四字段布局匹配苹果 ifaliasreq；三地址均完整初始化。
        // 不向外暴露可替换请求编号、原始指针或对象生存期。
        unsafe {
            add_address(self.0.as_raw_fd(), &request)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_request_layout_and_numbers_match_installed_system_headers() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("layout.c");
        let binary = dir.path().join("layout");
        std::fs::write(
            &source,
            r#"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <stddef.h>
#include <stdio.h>
int main(void) {
 printf("%zu %zu %zu %zu %zu %lu %lu %lu %lu\n", sizeof(struct ifreq), sizeof(struct ifaliasreq),
 offsetof(struct ifaliasreq, ifra_addr), offsetof(struct ifaliasreq, ifra_broadaddr),
 offsetof(struct ifaliasreq, ifra_mask), (unsigned long)SIOCGIFMTU, (unsigned long)SIOCSIFMTU,
 (unsigned long)SIOCSIFFLAGS, (unsigned long)SIOCAIFADDR);
 return 0;
}
"#,
        )
        .unwrap();
        let compilation = std::process::Command::new("/usr/bin/xcrun")
            .args(["clang", "-Wall", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        let output = std::process::Command::new(&binary).output().unwrap();
        assert!(output.status.success());
        let values = std::str::from_utf8(&output.stdout)
            .unwrap()
            .split_ascii_whitespace()
            .map(|s| s.parse::<u64>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec![
                size_of::<libc::ifreq>() as u64,
                size_of::<Alias>() as u64,
                std::mem::offset_of!(Alias, address) as u64,
                std::mem::offset_of!(Alias, destination) as u64,
                std::mem::offset_of!(Alias, mask) as u64,
                nix::request_code_readwrite!(b'i', 51, size_of::<libc::ifreq>()),
                nix::request_code_write!(b'i', 52, size_of::<libc::ifreq>()),
                nix::request_code_write!(b'i', 16, size_of::<libc::ifreq>()),
                nix::request_code_write!(b'i', 26, size_of::<Alias>())
            ]
        );
        assert_eq!(
            size_of::<libc::__c_anonymous_ifr_ifru>(),
            size_of::<libc::sockaddr>()
        );
    }
    #[test]
    fn control_requests_reject_unbounded_names_and_encode_network_byte_order() {
        for invalid in ["", "utun42\0bad", "utun42;up", "utun1234567890123", "接口"] {
            assert!(name(invalid).is_err());
        }
        let name = name("utun42").unwrap();
        assert_eq!(name[6], 0);
        let address = sockaddr("10.231.66.2".parse().unwrap());
        assert_eq!(address.sin_addr.s_addr.to_ne_bytes(), [10, 231, 66, 2]);
        assert_eq!(address.sin_len as usize, size_of::<libc::sockaddr_in>());
        assert_eq!(address.sin_family as i32, libc::AF_INET);
        assert_eq!(address.sin_port, 0);
    }
}
