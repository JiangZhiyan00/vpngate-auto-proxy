//! 私有启动通道上的描述符交接；调用方负责认证对端及核对隧道身份。
use std::{
    io::{self, IoSlice, IoSliceMut, Write},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use unix_ancillary::{AncillaryData, SocketAncillary, cmsg_recvmsg, cmsg_sendmsg};
use uuid::Uuid;

/// 由可信父进程交接并核对身份的控制句柄；不向业务暴露读写或断开操作。
pub struct UtunCustody {
    descriptor: OwnedFd,
    index: u32,
    name: String,
}

impl UtunCustody {
    #[cfg(test)]
    pub(crate) fn test_unverified_resource(descriptor: OwnedFd) -> Self {
        // 仅验证材料对象的资源归属；不得用作真实控制句柄身份通过证据。
        Self {
            descriptor,
            index: 1,
            name: "utun42".to_owned(),
        }
    }

    pub fn verify(descriptor: OwnedFd, expected_index: u32) -> io::Result<Self> {
        use nix::{
            net::if_::if_nametoindex,
            sys::socket::{SockType, getsockopt, sockopt},
        };
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "控制句柄与预期隧道接口不符");
        if expected_index == 0 || getsockopt(&descriptor, sockopt::SockType)? != SockType::Datagram
        {
            return Err(invalid());
        }
        // 直接查询收到的控制连接，不能信任启动材料给出的接口名称或数字索引。
        let name = getsockopt(&descriptor, sockopt::UtunIfname)?;
        let name = name.to_str().map_err(|_| invalid())?;
        let digits = name.strip_prefix("utun").ok_or_else(invalid)?;
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || if_nametoindex(name)? != expected_index
        {
            return Err(invalid());
        }
        protect_descriptor(&descriptor)?;
        Ok(Self {
            descriptor,
            index: expected_index,
            name: name.to_owned(),
        })
    }

    pub fn interface_name(&self) -> &str {
        &self.name
    }

    /// 再次从持有的真实连接核对身份，不能只凭缓存索引或接口名称接管资源。
    pub fn revalidate(&self) -> io::Result<()> {
        let checked = Self::verify(self.duplicate_descriptor()?, self.index)?;
        if checked.name != self.name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "控制句柄接口名称发生变化",
            ));
        }
        Ok(())
    }

    pub(crate) fn duplicate_descriptor(&self) -> io::Result<OwnedFd> {
        // 父方保留原件时，只给复制件设置标志不够：原件也不得隐式进入新子进程。
        protect_descriptor(&self.descriptor)?;
        self.descriptor.try_clone()
    }

    pub(crate) fn interface_index(&self) -> u32 {
        self.index
    }

    pub(crate) fn into_descriptor(self) -> (OwnedFd, u32) {
        (self.descriptor, self.index)
    }

    pub fn into_generation(
        self,
    ) -> (
        super::macos::InterfaceScope,
        super::generation::WorkerGeneration,
    ) {
        (
            super::macos::InterfaceScope::new(self.index).expect("已校验非零索引"),
            super::generation::WorkerGeneration::with_custody(self.descriptor),
        )
    }
}

pub(crate) fn protect_descriptor(descriptor: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let flags = FdFlag::from_bits_truncate(fcntl(descriptor, FcntlArg::F_GETFD)?);
    fcntl(descriptor, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(())
}

/// 仅由可信监督方通过刚为直属子进程创建的专属通道交接。
/// 第一次发送附带句柄，部分写入后只继续写数据，绝不重复发送句柄。
pub(crate) fn send(
    channel: &UnixStream,
    descriptor: BorrowedFd<'_>,
    authorization: Uuid,
    interface_index: u32,
    budget: Duration,
) -> io::Result<()> {
    if authorization.is_nil() || interface_index == 0 || budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "描述符交接身份无效",
        ));
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "描述符交接截止无效"))?;
    let previous_timeout = channel.write_timeout()?;
    let result = (|| {
        let frame = [
            b"VAP1".as_slice(),
            authorization.as_bytes(),
            &interface_index.to_be_bytes(),
        ]
        .concat();
        let mut storage = [0; 32];
        let mut ancillary = SocketAncillary::new(&mut storage);
        ancillary
            .add_fds(&[descriptor])
            .map_err(|_| io::Error::other("描述符交接附属数据构造失败"))?;
        channel.set_write_timeout(Some(budget))?;
        let mut offset = cmsg_sendmsg(channel.as_fd(), &[IoSlice::new(&frame)], &ancillary)?;
        if offset == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "描述符交接提前结束",
            ));
        }
        while offset < frame.len() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "描述符交接超时"))?;
            channel.set_write_timeout(Some(remaining))?;
            let written = (&*channel).write(&frame[offset..])?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "描述符交接提前结束",
                ));
            }
            offset += written;
        }
        Ok(())
    })();
    let restored = channel.set_write_timeout(previous_timeout);
    result.and(restored)
}

/// 仅供独立工作进程的串行启动阶段调用；期间不得并发派生或执行其他程序。
/// 任一错误必须退出工作进程，不能恢复接纳。苹果截断交接可能存在内核已安装但
/// 未交付编号的描述符，仅进程退出能确保全部回收；不适用于长驻辅助进程。
pub fn receive(
    channel: &UnixStream,
    authorization: Uuid,
    interface_index: u32,
    budget: Duration,
) -> io::Result<OwnedFd> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "描述符交接材料无效");
    if authorization.is_nil() || interface_index == 0 || budget.is_zero() {
        return Err(invalid());
    }
    let deadline = Instant::now().checked_add(budget).ok_or_else(invalid)?;
    let previous_timeout = channel.read_timeout()?;
    let result = (|| {
        let mut frame = [0; 24];
        let mut offset = 0;
        let mut descriptor = None;
        while offset < frame.len() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "描述符交接超时"))?;
            channel.set_read_timeout(Some(remaining))?;
            // 小缓冲只接受有限交接；超量及截断一律让启动失败并退出工作进程。
            let mut storage = [0; 24];
            let mut ancillary = SocketAncillary::new(&mut storage);
            let message = cmsg_recvmsg(
                channel.as_fd(),
                &mut [IoSliceMut::new(&mut frame[offset..])],
                &mut ancillary,
            )?;
            let mut malformed = message.truncated || message.data_truncated;
            for item in ancillary.messages() {
                match item {
                    AncillaryData::ScmRights(rights) => {
                        for fd in rights {
                            if descriptor.is_some() {
                                malformed = true;
                            } else {
                                descriptor = Some(fd);
                            }
                        }
                    }
                    _ => malformed = true,
                }
            }
            if malformed {
                return Err(invalid());
            }
            if message.bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "描述符交接提前结束",
                ));
            }
            offset += message.bytes_read;
        }
        if &frame[..4] != b"VAP1"
            || &frame[4..20] != authorization.as_bytes()
            || frame[20..] != interface_index.to_be_bytes()
        {
            return Err(invalid());
        }
        descriptor.ok_or_else(invalid)
    })();
    let restored = channel.set_read_timeout(previous_timeout);
    match (result, restored) {
        (Ok(descriptor), Ok(())) => Ok(descriptor),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    #[tokio::test]
    async fn interface_material_entry_refuses_unverified_custody_and_closes_channels() {
        use std::io::Read;
        let (descriptor, mut descriptor_peer) = UnixStream::pair().unwrap();
        descriptor_peer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let custody = UtunCustody {
            descriptor: OwnedFd::from(descriptor),
            index: 1,
            name: "utun42".to_owned(),
        };
        let (management, mut management_peer) = tokio::net::UnixStream::pair().unwrap();
        let credentials = management.peer_cred().unwrap();
        let peer = super::super::management::TunnelPeer {
            pid: credentials.pid().unwrap().try_into().unwrap(),
            uid: credentials.uid(),
        };
        let revoked = tokio_util::sync::CancellationToken::new();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        assert!(
            super::super::management::supervise_with_interface(
                management,
                peer,
                Duration::from_secs(1),
                custody,
                "198.51.100.7".parse().unwrap(),
                sender,
                revoked.clone()
            )
            .await
            .is_err()
        );
        assert!(receiver.await.is_err());
        assert!(revoked.is_cancelled());
        assert_eq!(descriptor_peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(
            tokio::io::AsyncReadExt::read(&mut management_peer, &mut [0])
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn revalidation_rejects_unrelated_socket_without_closing_original() {
        let (owner, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let custody = UtunCustody {
            descriptor: OwnedFd::from(owner),
            index: nix::net::if_::if_nametoindex("lo0").unwrap(),
            name: "lo0".to_owned(),
        };
        assert!(custody.revalidate().is_err());
        // 核验拒绝仅关闭本次复制件，不撤销调用方仍持有的原始连接。
        let copy = std::os::unix::net::UnixDatagram::from(custody.duplicate_descriptor().unwrap());
        copy.send(b"held").unwrap();
        let mut bytes = [0; 4];
        assert_eq!(peer.recv(&mut bytes).unwrap(), 4);
        assert_eq!(&bytes, b"held");
        assert!(
            FdFlag::from_bits_truncate(fcntl(&custody.descriptor, FcntlArg::F_GETFD).unwrap())
                .contains(FdFlag::FD_CLOEXEC)
        );
    }

    #[test]
    fn retained_custody_and_launch_copy_are_both_non_inheritable() {
        const MARKER: &str = "VAP_CUSTODY_CLOEXEC_TEST_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "platform::custody::tests::retained_custody_and_launch_copy_are_both_non_inheritable", "--nocapture"])
                .env(MARKER, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // 仅在独立测试进程中制造可继承原件，不与其它回归的派生操作竞争。
        let (owner, _peer) = UnixStream::pair().unwrap();
        let descriptor = OwnedFd::from(owner);
        fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let custody = UtunCustody {
            descriptor,
            index: 1,
            name: "仅用于描述符标志测试".to_owned(),
        };
        let copy = custody.duplicate_descriptor().unwrap();
        for fd in [&custody.descriptor, &copy] {
            assert!(
                FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).unwrap())
                    .contains(FdFlag::FD_CLOEXEC)
            );
        }
        let child = std::process::Command::new("/usr/bin/python3")
            .args(["-c", "import os,stat\nfor fd in range(3,1024):\n try: item=os.fstat(fd)\n except OSError: continue\n assert not stat.S_ISSOCK(item.st_mode), fd"])
            .output().unwrap();
        assert!(
            child.status.success(),
            "原件或复制件隐式进入子进程：{}",
            String::from_utf8_lossy(&child.stderr)
        );
    }
}
