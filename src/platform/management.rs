//! 已认证的直属隧道管理会话；连接成功仍须另行验证接口、路由及出口。
use std::{io, net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, unix::OwnedReadHalf},
    sync::oneshot,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::{
    custody::UtunCustody,
    topology::{AssignmentParser, InterfaceAssignment},
};

#[derive(Clone, Copy)]
pub struct TunnelPeer {
    pub pid: u32,
    pub uid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectedTunnel {
    pub local_address: Ipv4Addr,
    pub remote_address: Ipv4Addr,
}

/// 已认证会话交付的配置材料，同时继续持有实际控制连接；尚未配置或验证出口。
pub struct InterfaceMaterial {
    custody: UtunCustody,
    assignment: InterfaceAssignment,
    connection: ConnectedTunnel,
    revoked: CancellationToken,
}
impl InterfaceMaterial {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.revoked.clone()
    }
    pub(crate) fn custody(&self) -> &UtunCustody {
        &self.custody
    }
    pub(crate) fn revoke(&self) {
        self.revoked.cancel();
    }
    pub(crate) fn duplicate_checked(&self) -> io::Result<Self> {
        if self.is_revoked() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "并存接口材料已经撤销",
            ));
        }
        self.custody.revalidate()?;
        let custody = UtunCustody::verify(
            self.custody.duplicate_descriptor()?,
            self.custody.interface_index(),
        )?;
        if self.is_revoked() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "并存接口材料已经撤销",
            ));
        }
        Ok(Self {
            custody,
            assignment: self.assignment.clone(),
            connection: self.connection,
            revoked: self.revoked.clone(),
        })
    }
    pub fn assignment(&self) -> &InterfaceAssignment {
        &self.assignment
    }
    pub fn connection(&self) -> ConnectedTunnel {
        self.connection
    }
    pub fn is_revoked(&self) -> bool {
        self.revoked.is_cancelled()
    }
    /// 已撤销材料不能用于配置；调用方须继续用同一令牌监督配置与后续生命周期。
    pub fn into_parts(
        self,
    ) -> io::Result<(
        UtunCustody,
        InterfaceAssignment,
        ConnectedTunnel,
        CancellationToken,
    )> {
        if self.is_revoked() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "接口材料所属管理会话已撤销",
            ));
        }
        Ok((self.custody, self.assignment, self.connection, self.revoked))
    }
}

#[cfg(test)]
pub(crate) fn test_material(custody: UtunCustody, revoked: CancellationToken) -> InterfaceMaterial {
    let mut parser = AssignmentParser::default();
    let mut assignment = None;
    for line in [
        ">UPDOWN:UP",
        ">UPDOWN:ENV,dev=utun42",
        ">UPDOWN:ENV,dev_type=tun",
        ">UPDOWN:ENV,tun_mtu=1400",
        ">UPDOWN:ENV,ifconfig_local=10.231.66.2",
        ">UPDOWN:ENV,ifconfig_remote=10.231.66.1",
        ">UPDOWN:ENV,END",
    ] {
        assignment = parser.consume(line).unwrap().or(assignment);
    }
    InterfaceMaterial {
        custody,
        assignment: assignment.unwrap(),
        connection: ConnectedTunnel {
            local_address: "10.231.66.2".parse().unwrap(),
            remote_address: "8.8.8.8".parse().unwrap(),
        },
        revoked,
    }
}

struct InterfaceExpectation {
    name: String,
    remote: Ipv4Addr,
}

pub(crate) fn authenticate(stream: &UnixStream, peer: TunnelPeer) -> io::Result<()> {
    let credentials = stream.peer_cred()?;
    if peer.pid == 0
        || credentials.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(peer.pid)
        || peer.uid != credentials.uid()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "隧道管理对端身份不符",
        ));
    }
    Ok(())
}

/// 对端必须是仍由调用方持有直属子进程对象的进程，不得使用持久化的裸进程号。
/// 撤销令牌必须连接业务代际；调用方负责监听、子进程回收和路径归属。
pub async fn supervise(
    stream: UnixStream,
    peer: TunnelPeer,
    startup_budget: Duration,
    ready: oneshot::Sender<ConnectedTunnel>,
    revoked: CancellationToken,
) -> io::Result<()> {
    supervise_inner(
        stream,
        peer,
        startup_budget,
        None,
        move |detail, _| {
            ready
                .send(detail)
                .map_err(|_| invalid("隧道启动接收方已退出"))
        },
        revoked,
    )
    .await
}

/// 同时要求完整接口通知与连接成功；材料携带句柄，不将承载远端当作虚拟对端。
/// 调用方须让固定隧道程序启用接口启停通知，并把本次直属子进程与句柄交入。
pub async fn supervise_with_interface(
    stream: UnixStream,
    peer: TunnelPeer,
    startup_budget: Duration,
    custody: UtunCustody,
    authorized_remote: Ipv4Addr,
    ready: oneshot::Sender<InterfaceMaterial>,
    revoked: CancellationToken,
) -> io::Result<()> {
    let _guard = revoked.clone().drop_guard();
    custody.revalidate()?;
    let name = custody.interface_name().to_owned();
    let material_revoked = revoked.clone();
    supervise_inner(
        stream,
        peer,
        startup_budget,
        Some(InterfaceExpectation {
            name,
            remote: authorized_remote,
        }),
        move |detail, assignment| {
            custody.revalidate()?;
            ready
                .send(InterfaceMaterial {
                    custody,
                    assignment: assignment.ok_or_else(|| invalid("接口配置材料缺失"))?,
                    connection: detail,
                    revoked: material_revoked,
                })
                .map_err(|_| invalid("接口材料接收方已退出"))
        },
        revoked,
    )
    .await
}

async fn supervise_inner(
    stream: UnixStream,
    peer: TunnelPeer,
    startup_budget: Duration,
    expected: Option<InterfaceExpectation>,
    publish: impl FnOnce(ConnectedTunnel, Option<InterfaceAssignment>) -> io::Result<()>,
    revoked: CancellationToken,
) -> io::Result<()> {
    // 包括调用方取消此未来在内，所有离开路径均撤销；不派生脱离监督的读取任务。
    let _guard = revoked.clone().drop_guard();
    authenticate(&stream, peer)?;
    if startup_budget.is_zero() || startup_budget > Duration::from_secs(120) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "隧道启动截止无效",
        ));
    }
    let session = async {
        let deadline = Instant::now() + startup_budget;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut ready = Some(publish);
        let mut connected = None;
        let mut parser = AssignmentParser::default();
        let mut assignment: Option<InterfaceAssignment> = None;
        let mut released = false;
        let mut startup_bytes = 0;
        loop {
            let raw_line = Zeroizing::new(if ready.is_some() {
                timeout_at(deadline, record(&mut reader))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "隧道管理启动超时"))??
            } else {
                record(&mut reader).await?
            });
            let line = raw_line.as_str();
            if ready.is_some() {
                startup_bytes += line.len() + 1;
                if startup_bytes > 65536 {
                    return Err(invalid("隧道启动管理输出总量超限"));
                }
            }
            if parser.in_frame() && !line.starts_with(">UPDOWN:ENV,") {
                return Err(invalid("接口环境帧被其他记录中断"));
            }
            if line.starts_with(">UPDOWN:") {
                if !released || expected.is_none() {
                    return Err(invalid("接口通知尚未获准或未启用"));
                }
                if let Some(material) = parser.consume(line)? {
                    if expected
                        .as_ref()
                        .is_none_or(|expected| material.interface_name() != expected.name)
                    {
                        return Err(invalid("接口通知与授权句柄名称不符"));
                    }
                    assignment = Some(material);
                }
            } else if line == ">HOLD:Waiting for hold release"
                || line
                    .strip_prefix(">HOLD:Waiting for hold release:")
                    .is_some_and(|delay| {
                        !delay.is_empty() && delay.bytes().all(|byte| byte.is_ascii_digit())
                    })
            {
                if released {
                    return Err(invalid("隧道重复进入等待状态"));
                }
                // 先订阅，再释放等待；保留等待标志，使后续内部重启无法自动沿用。
                timeout_at(deadline, writer.write_all(b"state on\nhold release\n"))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "隧道管理命令超时"))??;
                released = true;
            } else if let Some(state) = line.strip_prefix(">STATE:") {
                let mut fields = state.split(',');
                fields
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| invalid("隧道状态时间无效"))?;
                let name = fields.next().ok_or_else(|| invalid("隧道状态缺失"))?;
                let description = fields.next().ok_or_else(|| invalid("隧道状态描述缺失"))?;
                if name == "CONNECTED" {
                    if !released || description != "SUCCESS" {
                        return Err(invalid("隧道尚未获准启动或连接未成功"));
                    }
                    let detail = ConnectedTunnel {
                        local_address: address(fields.next())?,
                        remote_address: address(fields.next())?,
                    };
                    if expected
                        .as_ref()
                        .is_some_and(|expected| detail.remote_address != expected.remote)
                    {
                        return Err(invalid("隧道远端与授权端点不符"));
                    }
                    if connected.is_some_and(|previous| previous != detail) {
                        return Err(invalid("隧道连接身份发生变化"));
                    }
                    connected = Some(detail);
                } else if connected.is_some()
                    || !matches!(
                        name,
                        "CONNECTING"
                            | "TCP_CONNECT"
                            | "WAIT"
                            | "AUTH"
                            | "AUTH_PENDING"
                            | "GET_CONFIG"
                            | "ASSIGN_IP"
                            | "ADD_ROUTES"
                    )
                {
                    return Err(invalid("隧道退出连接状态"));
                }
            } else if !(line.starts_with(">INFO:") || line.starts_with("SUCCESS:")) {
                // 不执行密码请求、任意管理命令或重连；错误与未知通知一律撤销。
                return Err(invalid("隧道管理记录无效或报告故障"));
            }
            if let Some(detail) = connected
                && ready.is_some()
                && (expected.is_none() || assignment.is_some())
            {
                if assignment
                    .as_ref()
                    .is_some_and(|material| material.local_address() != detail.local_address)
                {
                    return Err(invalid("接口地址与连接状态不符"));
                }
                ready.take().expect("已检查发布回调")(detail, assignment.take())?;
            }
        }
    };
    tokio::select! {
        biased;
        _ = revoked.cancelled() => Ok(()),
        result = session => result,
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn address(field: Option<&str>) -> io::Result<Ipv4Addr> {
    let address = field
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .ok_or_else(|| invalid("隧道状态地址不是有效四版地址"))?;
    if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
        return Err(invalid("隧道状态地址不可用"));
    }
    Ok(address)
}

async fn record(reader: &mut BufReader<OwnedReadHalf>) -> io::Result<String> {
    let mut line = Vec::with_capacity(256);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "隧道管理通道关闭",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |position| position + 1);
        if line.len() + count > 4096 {
            return Err(invalid("隧道管理记录超限"));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return String::from_utf8(line).map_err(|_| invalid("隧道管理记录编码无效"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const HOLD: &[u8] = b">HOLD:Waiting for hold release:0\r\n";
    const CONNECTED: &[u8] =
        b">STATE:1728700000,CONNECTED,SUCCESS,10.231.66.2,198.51.100.7,443,192.0.2.8,40000\r\n";
    const INTERFACE: &[u8] = b">UPDOWN:UP\n>UPDOWN:ENV,dev=utun42\n>UPDOWN:ENV,dev_type=tun\n>UPDOWN:ENV,tun_mtu=1500\n>UPDOWN:ENV,ifconfig_local=10.231.66.2\n>UPDOWN:ENV,ifconfig_netmask=255.255.255.0\n>UPDOWN:ENV,END\n";

    struct MaterialHarness {
        tunnel: UnixStream,
        ready: oneshot::Receiver<(ConnectedTunnel, InterfaceAssignment)>,
        revoked: CancellationToken,
        task: tokio::task::JoinHandle<io::Result<()>>,
    }

    fn material_harness(budget: Duration) -> MaterialHarness {
        let (owner, tunnel) = UnixStream::pair().unwrap();
        let identity = peer(&owner);
        let revoked = CancellationToken::new();
        let (sender, ready) = oneshot::channel();
        let task = tokio::spawn(supervise_inner(
            owner,
            identity,
            budget,
            Some(InterfaceExpectation {
                name: "utun42".to_owned(),
                remote: "198.51.100.7".parse().unwrap(),
            }),
            move |connection, assignment| {
                sender
                    .send((connection, assignment.expect("完整材料才能发布")))
                    .map_err(|_| invalid("测试接收方已退出"))
            },
            revoked.clone(),
        ));
        MaterialHarness {
            tunnel,
            ready,
            revoked,
            task,
        }
    }

    async fn release(harness: &mut MaterialHarness) {
        harness.tunnel.write_all(HOLD).await.unwrap();
        commands(&mut harness.tunnel).await;
    }

    #[tokio::test]
    async fn fragmented_interface_and_state_publish_only_after_both_in_either_order() {
        for state_first in [false, true] {
            let mut harness = material_harness(Duration::from_secs(2));
            release(&mut harness).await;
            if state_first {
                harness.tunnel.write_all(CONNECTED).await.unwrap();
            }
            harness.tunnel.write_all(&INTERFACE[..30]).await.unwrap();
            tokio::task::yield_now().await;
            assert!(matches!(
                harness.ready.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            harness.tunnel.write_all(&INTERFACE[30..]).await.unwrap();
            if !state_first {
                tokio::task::yield_now().await;
                assert!(matches!(
                    harness.ready.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
                harness.tunnel.write_all(CONNECTED).await.unwrap();
            }
            let (connection, assignment) = (&mut harness.ready).await.unwrap();
            assert_eq!(connection.local_address, assignment.local_address());
            assert_eq!(assignment.interface_name(), "utun42");
            assert_eq!(assignment.mtu(), 1500);
            drop(harness.tunnel);
            assert!(harness.task.await.unwrap().is_err());
            assert!(harness.revoked.is_cancelled());
        }
    }

    #[tokio::test]
    async fn wrong_interface_or_local_address_never_publishes_material() {
        for material in [
            String::from_utf8(INTERFACE.to_vec())
                .unwrap()
                .replace("utun42", "utun43"),
            String::from_utf8(INTERFACE.to_vec())
                .unwrap()
                .replace("10.231.66.2", "10.231.66.3"),
        ] {
            let mut harness = material_harness(Duration::from_secs(2));
            release(&mut harness).await;
            let payload = [CONNECTED, material.as_bytes()].concat();
            let _ = harness.tunnel.write_all(&payload).await;
            assert_eq!(
                harness.task.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(harness.ready.await.is_err());
            assert!(harness.revoked.is_cancelled());
        }
        let mut harness = material_harness(Duration::from_secs(2));
        release(&mut harness).await;
        let wrong_remote = String::from_utf8(CONNECTED.to_vec())
            .unwrap()
            .replace("198.51.100.7", "198.51.100.8");
        harness
            .tunnel
            .write_all(wrong_remote.as_bytes())
            .await
            .unwrap();
        assert_eq!(
            harness.task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(harness.ready.await.is_err());
        assert!(harness.revoked.is_cancelled());
    }

    #[tokio::test]
    async fn connected_state_cannot_remove_deadline_or_startup_output_limit() {
        for partial in [false, true] {
            let mut harness = material_harness(Duration::from_millis(150));
            release(&mut harness).await;
            harness.tunnel.write_all(CONNECTED).await.unwrap();
            if partial {
                harness
                    .tunnel
                    .write_all(&INTERFACE[..INTERFACE.len() - 16])
                    .await
                    .unwrap();
            }
            assert_eq!(
                harness.task.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert!(harness.ready.await.is_err());
            assert!(harness.revoked.is_cancelled());
        }
        let mut harness = material_harness(Duration::from_secs(2));
        release(&mut harness).await;
        let mut output = CONNECTED.to_vec();
        for _ in 0..17 {
            output.extend(format!(">INFO:{}\n", "a".repeat(4000)).bytes());
        }
        let _ = harness.tunnel.write_all(&output).await;
        assert_eq!(
            harness.task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(harness.ready.await.is_err());
        assert!(harness.revoked.is_cancelled());
    }

    #[tokio::test]
    async fn interrupted_or_unreleased_interface_frame_is_rejected() {
        let mut harness = material_harness(Duration::from_secs(2));
        harness.tunnel.write_all(INTERFACE).await.unwrap();
        assert!(harness.task.await.unwrap().is_err());
        assert!(harness.ready.await.is_err());
        assert!(harness.revoked.is_cancelled());
        let mut harness = material_harness(Duration::from_secs(2));
        release(&mut harness).await;
        let output = [
            b">UPDOWN:UP\n>UPDOWN:ENV,dev=utun42\n".as_slice(),
            CONNECTED,
        ]
        .concat();
        harness.tunnel.write_all(&output).await.unwrap();
        assert!(harness.task.await.unwrap().is_err());
        assert!(harness.ready.await.is_err());
        assert!(harness.revoked.is_cancelled());
    }

    #[tokio::test]
    async fn down_repeated_up_and_extra_environment_revoke_published_material() {
        for fault in [
            b">UPDOWN:DOWN\n".as_slice(),
            b">UPDOWN:UP\n",
            b">UPDOWN:ENV,dev=utun42\n",
        ] {
            let mut harness = material_harness(Duration::from_secs(2));
            release(&mut harness).await;
            harness
                .tunnel
                .write_all(&[INTERFACE, CONNECTED].concat())
                .await
                .unwrap();
            (&mut harness.ready).await.unwrap();
            harness.tunnel.write_all(fault).await.unwrap();
            assert!(harness.task.await.unwrap().is_err());
            assert!(harness.revoked.is_cancelled());
        }
    }

    #[tokio::test]
    async fn abandoned_material_session_releases_pending_publication_resource() {
        use std::{io::Read, os::unix::net::UnixStream as StdStream};
        let (resource, mut peer_resource) = StdStream::pair().unwrap();
        peer_resource
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (owner, mut tunnel) = UnixStream::pair().unwrap();
        let identity = peer(&owner);
        let revoked = CancellationToken::new();
        let task = tokio::spawn(supervise_inner(
            owner,
            identity,
            Duration::from_secs(2),
            Some(InterfaceExpectation {
                name: "utun42".to_owned(),
                remote: "198.51.100.7".parse().unwrap(),
            }),
            move |_, _| {
                drop(resource);
                Ok(())
            },
            revoked.clone(),
        ));
        tunnel.write_all(HOLD).await.unwrap();
        commands(&mut tunnel).await;
        tunnel.write_all(CONNECTED).await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(peer_resource.read(&mut [0]).unwrap(), 0);
        assert!(revoked.is_cancelled());
        assert_eq!(tunnel.read(&mut [0]).await.unwrap(), 0);
    }

    #[test]
    fn revoked_material_refuses_consumption_and_releases_held_resource() {
        use std::{
            io::Read,
            os::{fd::OwnedFd, unix::net::UnixStream as StdStream},
        };
        for cancelled in [false, true] {
            let (owner, mut peer) = StdStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let custody = UtunCustody::test_unverified_resource(OwnedFd::from(owner));
            let mut parser = AssignmentParser::default();
            let mut assignment = None;
            for line in std::str::from_utf8(INTERFACE).unwrap().lines() {
                assignment = parser.consume(line).unwrap().or(assignment);
            }
            let revoked = CancellationToken::new();
            let material = InterfaceMaterial {
                custody,
                assignment: assignment.unwrap(),
                connection: ConnectedTunnel {
                    local_address: "10.231.66.2".parse().unwrap(),
                    remote_address: "198.51.100.7".parse().unwrap(),
                },
                revoked: revoked.clone(),
            };
            if cancelled {
                revoked.cancel();
                assert!(material.is_revoked());
                assert_eq!(
                    material
                        .into_parts()
                        .err()
                        .expect("已撤销材料不得交接")
                        .kind(),
                    io::ErrorKind::Interrupted
                );
            } else {
                let (custody, assignment, connection, handed_token) =
                    material.into_parts().unwrap();
                assert_eq!(assignment.local_address(), connection.local_address);
                assert!(peer.read(&mut [0]).is_err(), "交接前后资源须继续持有");
                revoked.cancel();
                assert!(handed_token.is_cancelled(), "交接不得换成无关撤销令牌");
                drop(custody);
            }
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn address_configuration_denied_without_privilege_revokes_but_retains_material() {
        use std::{
            io::Read,
            os::{fd::OwnedFd, unix::net::UnixStream as StdStream},
        };
        assert!(!nix::unistd::getuid().is_root(), "本项须以普通用户运行");
        let (owner, mut peer) = StdStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut parser = AssignmentParser::default();
        let mut assignment = None;
        for line in std::str::from_utf8(INTERFACE).unwrap().lines() {
            assignment = parser.consume(line).unwrap().or(assignment);
        }
        let material = InterfaceMaterial {
            custody: UtunCustody::test_unverified_resource(OwnedFd::from(owner)),
            assignment: assignment.unwrap(),
            connection: ConnectedTunnel {
                local_address: "10.231.66.2".parse().unwrap(),
                remote_address: "198.51.100.7".parse().unwrap(),
            },
            revoked: CancellationToken::new(),
        };
        assert_eq!(
            super::super::address::configure(&material, &[])
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(material.is_revoked());
        assert!(
            peer.read(&mut [0]).is_err(),
            "失败不能提前释放调用方持有的控制资源"
        );
        drop(material);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    fn peer(stream: &UnixStream) -> TunnelPeer {
        let credentials = stream.peer_cred().unwrap();
        TunnelPeer {
            pid: credentials.pid().unwrap().try_into().unwrap(),
            uid: credentials.uid(),
        }
    }

    async fn commands(stream: &mut UnixStream) {
        let expected = b"state on\nhold release\n";
        let mut received = vec![0; expected.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn fragmented_records_publish_once_then_eof_revokes() {
        let (owner, mut tunnel) = UnixStream::pair().unwrap();
        let identity = peer(&owner);
        let revoked = CancellationToken::new();
        let (ready, mut receiver) = oneshot::channel();
        let task = tokio::spawn(supervise(
            owner,
            identity,
            Duration::from_secs(2),
            ready,
            revoked.clone(),
        ));
        tunnel
            .write_all(b">INFO:OpenVPN Management Interface Version 5\r\n>HOLD:Waiting for ")
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert!(matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        tunnel.write_all(b"hold release:0\r\n").await.unwrap();
        commands(&mut tunnel).await;
        assert!(matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        // 固定版本的流式承载会先报告此状态；不能误判为隧道故障。
        tunnel
            .write_all(b">STATE:1728700000,TCP_CONNECT,,,,\r\n")
            .await
            .unwrap();
        tunnel.write_all(b"SUCCESS: real-time state notification set to ON\r\nSUCCESS: hold release succeeded\r\n>STATE:1728700000,AUTH,,,\r\n").await.unwrap();
        for part in CONNECTED.chunks(7) {
            tunnel.write_all(part).await.unwrap();
        }
        assert_eq!(
            receiver.await.unwrap().local_address,
            "10.231.66.2".parse::<Ipv4Addr>().unwrap()
        );
        assert!(!revoked.is_cancelled());
        drop(tunnel);
        assert!(task.await.unwrap().is_err());
        assert!(revoked.is_cancelled());
    }

    #[tokio::test]
    async fn wrong_process_or_user_is_rejected_before_commands() {
        for wrong_pid in [true, false] {
            let (owner, mut tunnel) = UnixStream::pair().unwrap();
            let mut identity = peer(&owner);
            if wrong_pid {
                identity.pid += 1;
            } else {
                identity.uid += 1;
            }
            let (ready, receiver) = oneshot::channel();
            let revoked = CancellationToken::new();
            assert_eq!(
                supervise(
                    owner,
                    identity,
                    Duration::from_secs(1),
                    ready,
                    revoked.clone()
                )
                .await
                .unwrap_err()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(receiver.await.is_err());
            assert!(revoked.is_cancelled());
            assert_eq!(
                tunnel.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn reconnect_exit_and_rehold_revoke_ready_generation() {
        for event in [
            b">STATE:1728700001,RECONNECTING,ping-restart,,,\n".as_slice(),
            b">STATE:1728700001,EXITING,SIGTERM,,,\n",
            b">STATE:1728700001,WAIT,,,,\n",
            HOLD,
        ] {
            let (owner, mut tunnel) = UnixStream::pair().unwrap();
            let identity = peer(&owner);
            let revoked = CancellationToken::new();
            let (ready, receiver) = oneshot::channel();
            let task = tokio::spawn(supervise(
                owner,
                identity,
                Duration::from_secs(2),
                ready,
                revoked.clone(),
            ));
            tunnel.write_all(HOLD).await.unwrap();
            commands(&mut tunnel).await;
            tunnel.write_all(CONNECTED).await.unwrap();
            receiver.await.unwrap();
            tunnel.write_all(event).await.unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(revoked.is_cancelled());
        }
    }

    #[tokio::test]
    async fn malformed_and_fatal_records_never_publish_ready() {
        for record in [
            CONNECTED.to_vec(),
            vec![b'x'; 4097],
            b">FATAL:failure\n".to_vec(),
            b">PASSWORD:Need 'Auth' username/password\n".to_vec(),
            b"ERROR:unknown command\n".to_vec(),
            b">STATE:bad,CONNECTED,SUCCESS,10.0.0.2,198.51.100.7\n".to_vec(),
            b">STATE:1,CONNECTED,SUCCESS,::1,198.51.100.7\n".to_vec(),
            b">STATE:1,UNKNOWN,,,\n".to_vec(),
            vec![b'>', b'I', b'N', b'F', b'O', b':', 255, 10],
        ] {
            let (owner, mut tunnel) = UnixStream::pair().unwrap();
            let identity = peer(&owner);
            let revoked = CancellationToken::new();
            let (ready, receiver) = oneshot::channel();
            let task = tokio::spawn(supervise(
                owner,
                identity,
                Duration::from_secs(2),
                ready,
                revoked.clone(),
            ));
            tunnel.write_all(&record).await.unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(receiver.await.is_err());
            assert!(revoked.is_cancelled());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn partial_records_cannot_extend_total_startup_deadline() {
        let (owner, mut tunnel) = UnixStream::pair().unwrap();
        let identity = peer(&owner);
        let revoked = CancellationToken::new();
        let (ready, receiver) = oneshot::channel();
        let task = tokio::spawn(supervise(
            owner,
            identity,
            Duration::from_secs(3),
            ready,
            revoked.clone(),
        ));
        tokio::task::yield_now().await;
        for _ in 0..3 {
            tunnel.write_all(b">").await.unwrap();
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(receiver.await.is_err());
        assert!(revoked.is_cancelled());
    }

    #[tokio::test]
    async fn cancelling_or_aborting_closes_channel_and_revokes() {
        for abort in [true, false] {
            let (owner, mut tunnel) = UnixStream::pair().unwrap();
            let identity = peer(&owner);
            let revoked = CancellationToken::new();
            let (ready, receiver) = oneshot::channel();
            let task = tokio::spawn(supervise(
                owner,
                identity,
                Duration::from_secs(2),
                ready,
                revoked.clone(),
            ));
            tunnel.write_all(HOLD).await.unwrap();
            commands(&mut tunnel).await;
            tunnel.write_all(CONNECTED).await.unwrap();
            receiver.await.unwrap();
            if abort {
                task.abort();
            } else {
                revoked.cancel();
            }
            let result = task.await;
            if abort {
                assert!(result.unwrap_err().is_cancelled());
            } else {
                assert!(result.unwrap().is_ok());
            }
            assert!(revoked.is_cancelled());
            assert_eq!(
                tunnel.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn invalid_connected_details_and_changed_identity_revoke() {
        for state in [
            b">STATE:1,CONNECTED,SUCCESS,::1,198.51.100.7\n".as_slice(),
            b">STATE:1,CONNECTED,FAILED,10.0.0.2,198.51.100.7\n",
            b">STATE:1,CONNECTED,SUCCESS,0.0.0.0,198.51.100.7\n",
            b">STATE:1,CONNECTED,SUCCESS,10.0.0.2\n",
        ] {
            let (owner, mut tunnel) = UnixStream::pair().unwrap();
            let identity = peer(&owner);
            let revoked = CancellationToken::new();
            let (ready, receiver) = oneshot::channel();
            let task = tokio::spawn(supervise(
                owner,
                identity,
                Duration::from_secs(2),
                ready,
                revoked.clone(),
            ));
            tunnel.write_all(HOLD).await.unwrap();
            commands(&mut tunnel).await;
            tunnel.write_all(state).await.unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(receiver.await.is_err());
            assert!(revoked.is_cancelled());
        }
        let (owner, mut tunnel) = UnixStream::pair().unwrap();
        let identity = peer(&owner);
        let revoked = CancellationToken::new();
        let (ready, receiver) = oneshot::channel();
        let task = tokio::spawn(supervise(
            owner,
            identity,
            Duration::from_secs(2),
            ready,
            revoked.clone(),
        ));
        tunnel.write_all(HOLD).await.unwrap();
        commands(&mut tunnel).await;
        tunnel.write_all(CONNECTED).await.unwrap();
        receiver.await.unwrap();
        tunnel
            .write_all(b">STATE:2,CONNECTED,SUCCESS,10.231.66.3,198.51.100.7\n")
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(revoked.is_cancelled());
    }

    #[tokio::test]
    #[ignore = "需明确指定本地受控隧道程序；只使用空设备与回环地址"]
    async fn actual_openvpn_hold_commands_and_deadline_disconnect() {
        use std::{fs::File, process::Stdio};
        use tokio::{net::UnixListener, process::Command};
        let binary = std::env::var_os("VAP_TEST_OPENVPN").expect("须指定受控隧道程序");
        let directory = tempfile::Builder::new()
            .prefix("vap-mgmt-")
            .tempdir_in("/tmp")
            .unwrap();
        let key = directory.path().join("key");
        let path = directory.path().join("m.sock");
        assert!(
            Command::new(&binary)
                .args(["--genkey", "secret"])
                .arg(&key)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .unwrap()
                .success()
        );
        let listener = UnixListener::bind(&path).unwrap();
        let log_path = directory.path().join("log");
        let log = File::create(&log_path).unwrap();
        let mut child = Command::new(binary)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            // 静态密钥仅用于无远端、无系统设备的管理协议回归，不属于生产配置。
            .args([
                "--dev",
                "null",
                "--proto",
                "udp",
                "--nobind",
                "--remote",
                "127.0.0.1",
                "9",
                "--secret",
            ])
            .arg(&key)
            .args([
                "--cipher",
                "AES-256-CBC",
                "--auth",
                "SHA256",
                "--ifconfig",
                "10.231.66.2",
                "10.231.66.1",
                "--ifconfig-noexec",
                "--route-noexec",
                "--management",
            ])
            .arg(&path)
            .args([
                "unix",
                "--management-client",
                "--management-hold",
                "--verb",
                "3",
            ])
            .stdin(Stdio::null())
            .stderr(log.try_clone().unwrap())
            .stdout(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let identity = TunnelPeer {
            pid: child.id().unwrap(),
            uid: stream.peer_cred().unwrap().uid(),
        };
        let revoked = CancellationToken::new();
        let (ready, receiver) = oneshot::channel();
        let error = supervise(
            stream,
            identity,
            Duration::from_millis(300),
            ready,
            revoked.clone(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(receiver.await.is_err());
        assert!(revoked.is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        let log = std::fs::read_to_string(log_path).unwrap();
        assert!(log.contains("CMD 'state on'") && log.contains("CMD 'hold release'"));
        assert!(log.contains("management-exit"));
        assert!(!log.contains("Opening utun") && !log.contains("TUN/TAP device"));
    }
}
