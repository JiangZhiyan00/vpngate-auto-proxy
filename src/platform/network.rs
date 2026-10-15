//! 与真实隧道身份和工作代际绑定的苹果网络操作。
use std::{io, net::SocketAddrV4, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use super::{
    custody::UtunCustody,
    generation::{RetiredGeneration, WorkerGeneration, WorkerLease},
    macos::InterfaceScope,
};
use crate::domain::is_public_ipv4;

/// 只能由已核对真实控制连接身份的句柄构造。控制句柄在全部登记操作退出后释放。
pub struct VerifiedNetworkGeneration {
    scope: InterfaceScope,
    generation: WorkerGeneration,
    policy: EgressPolicy,
}

#[derive(Clone, Copy)]
enum EgressPolicy {
    Public,
    #[cfg(test)]
    LoopbackTest,
}

impl EgressPolicy {
    fn check(self, destination: SocketAddrV4) -> io::Result<()> {
        let allowed = match self {
            Self::Public => is_public_ipv4(*destination.ip()),
            #[cfg(test)]
            Self::LoopbackTest => destination.ip().is_loopback(),
        };
        if !allowed || destination.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "出口目标不在允许范围",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct VerifiedNetworkLease {
    scope: InterfaceScope,
    lease: WorkerLease,
    policy: EgressPolicy,
}

impl VerifiedNetworkGeneration {
    pub fn from_custody(custody: UtunCustody) -> Self {
        let (scope, generation) = custody.into_generation();
        Self {
            scope,
            generation,
            policy: EgressPolicy::Public,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_parts(scope: InterfaceScope, generation: WorkerGeneration) -> Self {
        Self {
            scope,
            generation,
            policy: EgressPolicy::LoopbackTest,
        }
    }

    #[cfg(test)]
    fn from_parts_public(scope: InterfaceScope, generation: WorkerGeneration) -> Self {
        Self {
            scope,
            generation,
            policy: EgressPolicy::Public,
        }
    }

    pub fn lease(&self) -> VerifiedNetworkLease {
        VerifiedNetworkLease {
            scope: self.scope,
            lease: self.generation.lease(),
            policy: self.policy,
        }
    }

    pub fn revoke(&self) {
        self.generation.revoke();
    }

    pub async fn retire(&self) -> RetiredGeneration {
        self.generation.retire().await
    }
}

impl VerifiedNetworkLease {
    pub fn id(&self) -> Uuid {
        self.lease.id()
    }

    pub(crate) fn allows_destination(&self, destination: SocketAddrV4) -> bool {
        self.policy.check(destination).is_ok()
    }

    /// 已完成代理握手的客户端连接只在登记操作内转发，撤销即丢弃两端套接字。
    pub async fn relay_tcp<S>(&self, client: S, destination: SocketAddrV4) -> io::Result<(u64, u64)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.relay_tcp_with_prelude(client, destination, &[]).await
    }

    /// 目标固定接口建连成功后再向私有工作通道发布有限的就绪帧。
    pub async fn relay_tcp_with_prelude<S>(
        &self,
        client: S,
        destination: SocketAddrV4,
        prelude: &[u8],
    ) -> io::Result<(u64, u64)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.relay_tcp_with_replies(client, destination, prelude, &[])
            .await
    }

    /// 失败帧仅在目标固定接口建连失败时发送，撤销不发布成功帧。
    pub async fn relay_tcp_with_replies<S>(
        &self,
        mut client: S,
        destination: SocketAddrV4,
        success: &[u8],
        failure: &[u8],
    ) -> io::Result<(u64, u64)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if success.len() > 32 || failure.len() > 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "就绪帧超限"));
        }
        self.policy.check(destination)?;
        let scope = self.scope;
        self.lease
            .execute(|| async move {
                let connected =
                    tokio::time::timeout(Duration::from_secs(10), scope.connect_tcp(destination))
                        .await
                        .unwrap_or_else(|_| {
                            Err(io::Error::new(io::ErrorKind::TimedOut, "流式连接超时"))
                        });
                let mut remote = match connected {
                    Ok(remote) => remote,
                    Err(error) => {
                        client.write_all(failure).await?;
                        return Err(error);
                    }
                };
                client.write_all(success).await?;
                tokio::io::copy_bidirectional(&mut client, &mut remote).await
            })
            .await
    }

    /// 有界原始 DNS 查询；解析后的地址还须由上层按目标策略校验。
    /// 仅接收 UDP 的正常答复或同接口 TCP 重试答复，不调用系统解析。
    pub async fn query_dns(&self, server: SocketAddrV4, query: &[u8]) -> io::Result<Vec<u8>> {
        self.policy.check(server)?;
        if query.len() < 12 || query.len() > 512 || query[2] & 0x80 != 0 || query[4..6] != [0, 1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS 查询材料无效",
            ));
        }
        let query = query.to_vec();
        let scope = self.scope;
        tokio::time::timeout(
            Duration::from_secs(5),
            self.lease.execute(|| async move {
                let udp = scope.bind_udp()?;
                udp.connect(server).await?;
                udp.send(&query).await?;
                let mut response = vec![0; 4096];
                let length = udp.recv(&mut response).await?;
                response.truncate(length);
                validate_dns_response(&query, &response)?;
                if response[2] & 0x02 == 0 {
                    return Ok(response);
                }
                let mut tcp = scope.connect_tcp(server).await?;
                tcp.write_u16(query.len() as u16).await?;
                tcp.write_all(&query).await?;
                let length = usize::from(tcp.read_u16().await?);
                if !(12..=4096).contains(&length) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS 流式响应长度无效",
                    ));
                }
                let mut response = vec![0; length];
                tcp.read_exact(&mut response).await?;
                validate_dns_response(&query, &response)?;
                if response[2] & 0x02 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS 流式响应仍被截断",
                    ));
                }
                Ok(response)
            }),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS 查询超时"))?
    }
}

fn validate_dns_response(query: &[u8], response: &[u8]) -> io::Result<()> {
    if response.len() < 12
        || response[..2] != query[..2]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != query[2] & 0x78
        || response[4..6] != query[4..6]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS 答复事务或标志无效",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket, UnixStream},
    };

    fn loopback_scope() -> InterfaceScope {
        let output = std::process::Command::new("/sbin/ifconfig")
            .args(["-v", "lo0"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let words = String::from_utf8(output.stdout).unwrap();
        let words: Vec<_> = words.split_whitespace().collect();
        let index = words.windows(2).find(|parts| parts[0] == "index").unwrap()[1]
            .parse()
            .unwrap();
        InterfaceScope::new(index).unwrap()
    }

    #[tokio::test]
    async fn dns_truncation_retries_on_same_scope_and_revoke_rejects_new_query() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, udp.local_addr().unwrap().port()))
            .await
            .unwrap();
        let server = match udp.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        let lease = generation.lease();
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let server_task = tokio::spawn(async move {
            let mut request = [0; 512];
            let (count, peer) = udp.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..count], &query);
            let truncated = [0x12, 0x34, 0x82, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            udp.send_to(&truncated, peer).await.unwrap();
            let (mut stream, _) = tcp.accept().await.unwrap();
            assert_eq!(stream.read_u16().await.unwrap(), query.len() as u16);
            stream
                .read_exact(&mut request[..query.len()])
                .await
                .unwrap();
            assert_eq!(&request[..query.len()], &query);
            let answer = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            stream.write_u16(answer.len() as u16).await.unwrap();
            stream.write_all(&answer).await.unwrap();
        });
        let answer = tokio::time::timeout(Duration::from_secs(2), lease.query_dns(server, &query))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&answer[..4], &[0x12, 0x34, 0x81, 0x80]);
        server_task.await.unwrap();
        let retired = generation.retire().await;
        assert_eq!(retired.id(), lease.id());
        assert_eq!(
            lease.query_dns(server, &query).await.unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
    }

    #[tokio::test]
    async fn retiring_generation_closes_both_relay_sockets_without_peer_shutdown() {
        let inbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let outbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = match outbound.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        let lease = generation.lease();
        let mut client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = inbound.accept().await.unwrap();
        let relay = tokio::spawn(async move { lease.relay_tcp(accepted, target).await });
        let (mut remote, _) = tokio::time::timeout(Duration::from_secs(2), outbound.accept())
            .await
            .unwrap()
            .unwrap();
        let retired = tokio::time::timeout(Duration::from_secs(2), generation.retire())
            .await
            .unwrap();
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), remote.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(!retired.id().is_nil());
    }

    #[tokio::test]
    async fn invalid_dns_message_never_opens_a_network_socket() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = match udp.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        assert_eq!(
            generation
                .lease()
                .query_dns(address, b"bad")
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        let mut buffer = [0; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), udp.recv_from(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn pending_dns_socket_closes_before_retirement_ack() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server = match udp.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        let lease = generation.lease();
        let query_task = tokio::spawn(async move {
            lease
                .query_dns(server, &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
        });
        let mut bytes = [0; 32];
        let (_, peer) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), generation.retire())
            .await
            .unwrap();
        assert_eq!(
            query_task.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        // 旧查询的本地端口可重新占用，退休确认没有越过套接字析构。
        let replacement = UdpSocket::bind(peer).await.unwrap();
        assert_eq!(replacement.local_addr().unwrap(), peer);
    }

    #[tokio::test]
    async fn public_policy_rejects_private_destinations_before_any_egress() {
        let outbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = match outbound.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let inbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let _client = TcpStream::connect(inbound.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = inbound.accept().await.unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = match udp.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts_public(loopback_scope(), WorkerGeneration::new());
        let lease = generation.lease();
        assert_eq!(
            lease.relay_tcp(accepted, target).await.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            lease
                .query_dns(resolver, &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), outbound.accept())
                .await
                .is_err()
        );
        let mut buffer = [0; 8];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), udp.recv_from(&mut buffer))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn relay_accepts_private_worker_channel_without_exposing_exit_socket() {
        let outbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = match outbound.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        let lease = generation.lease();
        let (mut gateway, worker) = UnixStream::pair().unwrap();
        let relay = tokio::spawn(async move { lease.relay_tcp(worker, target).await });
        let (mut remote, _) = outbound.accept().await.unwrap();
        gateway.write_all(b"abc").await.unwrap();
        let mut bytes = [0; 3];
        remote.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abc");
        remote.write_all(b"xyz").await.unwrap();
        gateway.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"xyz");
        generation.revoke();
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        generation.retire().await;
    }

    #[tokio::test]
    async fn worker_ready_frame_is_sent_only_after_scoped_target_connects() {
        let outbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = match outbound.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        let lease = generation.lease();
        let (mut gateway, worker) = UnixStream::pair().unwrap();
        let relay =
            tokio::spawn(
                async move { lease.relay_tcp_with_prelude(worker, target, b"ready").await },
            );
        let (_remote, _) = tokio::time::timeout(Duration::from_secs(1), outbound.accept())
            .await
            .unwrap()
            .unwrap();
        let mut frame = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), gateway.read_exact(&mut frame))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&frame, b"ready");
        generation.revoke();
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        generation.retire().await;
    }

    #[tokio::test]
    async fn failed_scoped_connect_returns_failure_frame_without_success() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        drop(listener);
        let generation =
            VerifiedNetworkGeneration::from_parts(loopback_scope(), WorkerGeneration::new());
        let (mut gateway, worker) = UnixStream::pair().unwrap();
        let error = generation
            .lease()
            .relay_tcp_with_replies(worker, target, b"success", b"failure")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        let mut frame = [0; 7];
        gateway.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"failure");
        generation.retire().await;
    }
}
