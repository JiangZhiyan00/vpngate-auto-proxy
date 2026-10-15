//! 从直属管理连接到地址配置的持续监督；不发布已经验证的代理出口。
use super::*;
use crate::platform::{
    address,
    management::{ConnectedTunnel, InterfaceMaterial},
    topology::InterfaceAssignment,
};
use std::future::Future;
use tokio::sync::oneshot;

/// 地址配置已核对的材料；丢弃未交接材料会撤销对应监督会话。
/// 不表示路由或出口已经通过验证。
pub struct ConfiguredMacInterface {
    material: Option<InterfaceMaterial>,
}
impl ConfiguredMacInterface {
    #[cfg(test)]
    pub(crate) fn test_material(material: InterfaceMaterial) -> Self {
        Self {
            material: Some(material),
        }
    }
    pub fn material(&self) -> &InterfaceMaterial {
        self.material.as_ref().expect("交接前材料存在")
    }
    pub fn assignment(&self) -> &InterfaceAssignment {
        self.material().assignment()
    }
    pub fn connection(&self) -> ConnectedTunnel {
        self.material().connection()
    }
    /// 为另一次串行配置复制并存材料；复制件沿用原撤销令牌及真实接口身份。
    pub fn peer_material(&self) -> io::Result<InterfaceMaterial> {
        self.material().duplicate_checked()
    }
    /// 后续业务与路由仍须由同一撤销令牌监督；已撤销材料拒绝交接。
    pub fn into_parts(
        mut self,
    ) -> io::Result<(
        UtunCustody,
        InterfaceAssignment,
        ConnectedTunnel,
        CancellationToken,
    )> {
        self.material.take().expect("材料只交接一次").into_parts()
    }
}
impl Drop for ConfiguredMacInterface {
    fn drop(&mut self) {
        if let Some(material) = &self.material {
            material.revoke();
        }
    }
}

impl ManagedMacTunnel {
    /// 消费已启用拓扑通知的直属隧道与原始控制句柄，直到停止或发生故障。
    /// 交付配置材料后仍须持续轮询本未来；不能在收到材料后取消它。
    /// 并存材料使用同令牌的核验复制件，配置结束后释放；业务与完整路由尚须另行接入。
    pub async fn run_configured(
        mut self,
        custody: UtunCustody,
        peers: Vec<InterfaceMaterial>,
        ready: oneshot::Sender<ConfiguredMacInterface>,
        stop: CancellationToken,
    ) -> io::Result<()> {
        let revoked = CancellationToken::new();
        let (sender, receiver) = oneshot::channel();
        let stream = self.management.take();
        let pid = self.pid();
        let uid = self.uid;
        let index = self.index;
        let remote = self.endpoint.ip;
        let enabled = self.interface_notifications;
        let startup_budget = self.startup_budget;
        let descriptor = custody.duplicate_descriptor();
        let custody_index = custody.interface_index();
        let managing_revoked = revoked.clone();
        // 验证失败同样通过阶段驱动回收直属子进程，原始句柄保留至回收尝试结束。
        let managing = async move {
            if !enabled || index != custody_index {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "隧道通知模式或接口归属不符",
                ));
            }
            let custody = UtunCustody::verify(descriptor?, index)?;
            management::supervise_with_interface(
                stream.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotConnected, "隧道管理通道缺失")
                })?,
                TunnelPeer {
                    pid: pid
                        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "隧道已经退出"))?,
                    uid,
                },
                startup_budget,
                custody,
                remote,
                sender,
                managing_revoked,
            )
            .await
        };
        self.run_configuration_stage(
            custody,
            managing,
            receiver,
            move |m| {
                let borrowed = peers.iter().collect::<Vec<_>>();
                address::configure(m, &borrowed)
            },
            ready,
            stop,
            revoked,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_configuration_stage(
        mut self,
        keeper: UtunCustody,
        managing: impl Future<Output = io::Result<()>>,
        mut receiver: oneshot::Receiver<InterfaceMaterial>,
        configure: impl FnOnce(&InterfaceMaterial) -> io::Result<()>,
        ready: oneshot::Sender<ConfiguredMacInterface>,
        stop: CancellationToken,
        revoked: CancellationToken,
    ) -> io::Result<()> {
        let _guard = revoked.clone().drop_guard();
        let mut pending = None;
        let outcome = async {
            tokio::pin!(managing);
            let deadline = tokio::time::Instant::now() + self.startup_budget;
            let child = self.child.as_mut().ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "直属隧道缺失"))?;
            let material = tokio::select! {
                biased;
                _ = stop.cancelled() => return Ok(()),
                _ = revoked.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "配置会话已撤销")),
                result = child.wait() => { result?; return Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道在配置前退出")); }
                result = &mut managing => return management_end(result),
                _ = tokio::time::sleep_until(deadline) => return Err(io::Error::new(io::ErrorKind::TimedOut, "接口配置材料等待超时")),
                result = &mut receiver => result.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "完整配置材料未交付"))?,
            };
            pending = Some(material);
            let material = pending.as_ref().expect("材料已保留");
            if material.is_revoked() || material.custody().interface_index() != self.index {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "配置材料已撤销或不属于直属隧道"));
            }
            configure(material)?;
            // 同步配置返回后再轮询管理未来，先处理已经到达的断开或故障，不能直接发布。
            tokio::select! {
                biased;
                _ = stop.cancelled() => return Ok(()),
                _ = revoked.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "配置会话已撤销")),
                result = child.wait() => { result?; return Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道在配置期间退出")); }
                result = &mut managing => return management_end(result),
                _ = tokio::time::sleep_until(deadline) => return Err(io::Error::new(io::ErrorKind::TimedOut, "接口配置后已经超过启动截止")),
                _ = tokio::task::yield_now() => {},
            }
            if pending.as_ref().expect("发布前材料仍持有").is_revoked() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "配置材料发布前已经撤销"));
            }
            ready.send(ConfiguredMacInterface { material: pending.take() })
                .map_err(|material| { material.material().revoke(); io::Error::new(io::ErrorKind::BrokenPipe, "配置材料接收方已退出") })?;
            tokio::select! {
                biased;
                _ = stop.cancelled() => Ok(()),
                _ = revoked.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "配置会话已撤销")),
                result = child.wait() => { result?; Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道配置后意外退出")) }
                result = &mut managing => management_end(result),
            }
        }.await;
        revoked.cancel();
        let cleanup = self.retire().await;
        // 失败材料、未接收材料与父方原件均保留至直属子进程回收尝试结束。
        drop(pending);
        drop(receiver);
        drop(keeper);
        match (outcome, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::new(
                error.kind(),
                format!("{error}；配置监督回收：{cleanup}"),
            )),
        }
    }
}

fn management_end(result: io::Result<()>) -> io::Result<()> {
    result.and_then(|()| {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "隧道管理会话意外结束",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::{assert_no_socket, assert_reaped, fixture};
    use super::*;
    use std::{
        io::Read,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn configuration_stage_publishes_after_configuration_and_reaps_on_stop() {
        let (dir, executable, request, descriptor, mut peer, uid) = fixture();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
        let revoked = CancellationToken::new();
        let material = management::test_material(
            UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
            revoked.clone(),
        );
        let mut tunnel = ManagedMacTunnel::launch(
            &executable,
            request,
            descriptor,
            1,
            uid,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut stream = tunnel.management.take().unwrap();
        let (sender, receiver) = oneshot::channel();
        let managing = async move {
            sender.send(material).ok().unwrap();
            let _ = stream.read_u8().await;
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "受控管理结束"))
        };
        let (ready, confirmation) = oneshot::channel();
        let stop = CancellationToken::new();
        let count = Arc::new(AtomicUsize::new(0));
        let checked = count.clone();
        let running = tunnel.run_configuration_stage(
            keeper,
            managing,
            receiver,
            move |_| {
                checked.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            ready,
            stop.clone(),
            revoked,
        );
        let observing = async {
            let material = confirmation.await.unwrap();
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(
                material.assignment().local_address(),
                material.connection().local_address
            );
            assert!(peer.read(&mut [0]).is_err());
            stop.cancel();
            material
        };
        let (result, material) = tokio::join!(running, observing);
        result.unwrap();
        assert_reaped(dir.path());
        assert_no_socket(dir.path());
        assert!(material.material().is_revoked());
        drop(material);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}

#[cfg(test)]
mod failures {
    use super::super::tests::{assert_no_socket, assert_reaped, fixture};
    use super::*;
    use std::{
        io::Read,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[tokio::test]
    async fn configuration_failures_and_abandoned_receivers_revoke_and_reap() {
        for abandoned in [false, true] {
            let (dir, executable, request, descriptor, mut peer, uid) = fixture();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
            let revoked = CancellationToken::new();
            let material = management::test_material(
                UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
                revoked.clone(),
            );
            let mut tunnel = ManagedMacTunnel::launch(
                &executable,
                request,
                descriptor,
                1,
                uid,
                CancellationToken::new(),
            )
            .await
            .unwrap();
            let stream = tunnel.management.take().unwrap();
            let (sender, receiver) = oneshot::channel();
            let managing = async move {
                let _stream = stream;
                sender.send(material).ok().unwrap();
                std::future::pending::<io::Result<()>>().await
            };
            let (ready, mut confirmation) = oneshot::channel();
            if abandoned {
                confirmation.close();
            }
            let result = tunnel
                .run_configuration_stage(
                    keeper,
                    managing,
                    receiver,
                    move |_| {
                        if abandoned {
                            Ok(())
                        } else {
                            Err(io::Error::other("受控地址写入失败"))
                        }
                    },
                    ready,
                    CancellationToken::new(),
                    revoked.clone(),
                )
                .await;
            assert!(result.is_err());
            assert!(confirmation.await.is_err());
            assert!(revoked.is_cancelled());
            assert_reaped(dir.path());
            assert_no_socket(dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn startup_timeout_and_already_stopped_never_configure_or_publish() {
        for stopped in [false, true] {
            let (dir, executable, request, descriptor, mut peer, uid) = fixture();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
            let mut tunnel = ManagedMacTunnel::launch(
                &executable,
                request,
                descriptor,
                1,
                uid,
                CancellationToken::new(),
            )
            .await
            .unwrap();
            tunnel.startup_budget = Duration::from_millis(30);
            let stream = tunnel.management.take().unwrap();
            let (sender, receiver) = oneshot::channel::<InterfaceMaterial>();
            let managing = async move {
                let _stream = stream;
                let _sender = sender;
                std::future::pending::<io::Result<()>>().await
            };
            let (ready, confirmation) = oneshot::channel();
            let stop = CancellationToken::new();
            if stopped {
                stop.cancel();
            }
            let revoked = CancellationToken::new();
            let result = tunnel
                .run_configuration_stage(
                    keeper,
                    managing,
                    receiver,
                    |_| panic!("未获得完整材料不能配置"),
                    ready,
                    stop,
                    revoked.clone(),
                )
                .await;
            if stopped {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            }
            assert!(confirmation.await.is_err());
            assert!(revoked.is_cancelled());
            assert_reaped(dir.path());
            assert_no_socket(dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn management_fault_before_or_during_configuration_prevents_publication() {
        for during in [false, true] {
            let (dir, executable, request, descriptor, mut peer, uid) = fixture();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
            let revoked = CancellationToken::new();
            let material = management::test_material(
                UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
                revoked.clone(),
            );
            let mut tunnel = ManagedMacTunnel::launch(
                &executable,
                request,
                descriptor,
                1,
                uid,
                CancellationToken::new(),
            )
            .await
            .unwrap();
            let stream = tunnel.management.take().unwrap();
            let (sender, receiver) = oneshot::channel();
            let fault = Arc::new(tokio::sync::Notify::new());
            let waiting = fault.clone();
            let managing = async move {
                let _stream = stream;
                sender.send(material).ok().unwrap();
                if during {
                    waiting.notified().await;
                }
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "受控管理故障"))
            };
            let count = Arc::new(AtomicUsize::new(0));
            let called = count.clone();
            let (ready, confirmation) = oneshot::channel();
            let result = tunnel
                .run_configuration_stage(
                    keeper,
                    managing,
                    receiver,
                    move |_| {
                        called.fetch_add(1, Ordering::SeqCst);
                        fault.notify_one();
                        Ok(())
                    },
                    ready,
                    CancellationToken::new(),
                    revoked.clone(),
                )
                .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(count.load(Ordering::SeqCst), usize::from(during));
            assert!(confirmation.await.is_err());
            assert!(revoked.is_cancelled());
            assert_reaped(dir.path());
            assert_no_socket(dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn dropping_configured_material_stops_supervision_without_external_signal() {
        let (dir, executable, request, descriptor, mut peer, uid) = fixture();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
        let revoked = CancellationToken::new();
        let material = management::test_material(
            UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
            revoked.clone(),
        );
        let mut tunnel = ManagedMacTunnel::launch(
            &executable,
            request,
            descriptor,
            1,
            uid,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let stream = tunnel.management.take().unwrap();
        let (sender, receiver) = oneshot::channel();
        let managing = async move {
            let _stream = stream;
            sender.send(material).ok().unwrap();
            std::future::pending::<io::Result<()>>().await
        };
        let (ready, confirmation) = oneshot::channel();
        let running = tunnel.run_configuration_stage(
            keeper,
            managing,
            receiver,
            |_| Ok(()),
            ready,
            CancellationToken::new(),
            revoked.clone(),
        );
        let observing = async {
            drop(confirmation.await.unwrap());
        };
        let (result, ()) = tokio::join!(running, observing);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(revoked.is_cancelled());
        assert_reaped(dir.path());
        assert_no_socket(dir.path());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn public_configuration_entry_rejects_legacy_mode_and_invalid_custody_then_reaps() {
        for enabled in [false, true] {
            let (dir, executable, request, descriptor, mut peer, uid) = fixture();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
            let tunnel = ManagedMacTunnel::launch_mode(
                &executable,
                request,
                descriptor,
                1,
                uid,
                CancellationToken::new(),
                enabled,
            )
            .await
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.path().join("notifications")).unwrap(),
                if enabled { "True" } else { "False" }
            );
            let (ready, confirmation) = oneshot::channel();
            assert!(
                tunnel
                    .run_configured(keeper, Vec::new(), ready, CancellationToken::new())
                    .await
                    .is_err()
            );
            assert!(confirmation.await.is_err());
            assert_reaped(dir.path());
            assert_no_socket(dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn configured_material_transfer_preserves_token_and_rejects_stale_or_unverified_copies() {
        use std::os::{fd::OwnedFd, unix::net::UnixStream};
        for stale in [false, true] {
            let (owner, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let revoked = CancellationToken::new();
            let material = management::test_material(
                UtunCustody::test_unverified_resource(OwnedFd::from(owner)),
                revoked.clone(),
            );
            let configured = ConfiguredMacInterface {
                material: Some(material),
            };
            assert!(
                configured.peer_material().is_err(),
                "普通套接字不能成为核验复制件"
            );
            if stale {
                revoked.cancel();
                assert_eq!(
                    configured.peer_material().err().unwrap().kind(),
                    io::ErrorKind::Interrupted
                );
                assert!(configured.into_parts().is_err());
            } else {
                let (custody, _, _, token) = configured.into_parts().unwrap();
                assert!(!token.is_cancelled(), "有效交接不能因包装析构撤销");
                revoked.cancel();
                assert!(token.is_cancelled());
                assert!(peer.read(&mut [0]).is_err());
                drop(custody);
            }
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }
}

#[cfg(test)]
mod cancellation {
    use super::super::tests::{assert_no_socket, assert_reaped, fixture};
    use super::*;
    use std::io::Read;

    #[tokio::test]
    async fn aborted_configuration_supervision_revokes_and_closes_management() {
        let (dir, executable, request, descriptor, mut peer, uid) = fixture();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
        let revoked = CancellationToken::new();
        let material = management::test_material(
            UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
            revoked.clone(),
        );
        let mut tunnel = ManagedMacTunnel::launch(
            &executable,
            request,
            descriptor,
            1,
            uid,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let stream = tunnel.management.take().unwrap();
        let (sender, receiver) = oneshot::channel();
        let managing = async move {
            let _stream = stream;
            sender.send(material).ok().unwrap();
            std::future::pending::<io::Result<()>>().await
        };
        let (ready, confirmation) = oneshot::channel();
        let task = tokio::spawn(tunnel.run_configuration_stage(
            keeper,
            managing,
            receiver,
            |_| Ok(()),
            ready,
            CancellationToken::new(),
            revoked.clone(),
        ));
        let material = confirmation.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(revoked.is_cancelled());
        assert!(material.material().is_revoked());
        tokio::time::timeout(Duration::from_secs(3), async {
            let pid = std::fs::read_to_string(dir.path().join("child.pid")).unwrap();
            loop {
                if !std::process::Command::new("/bin/ps")
                    .args(["-p", pid.trim(), "-o", "stat="])
                    .output()
                    .unwrap()
                    .status
                    .success()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_reaped(dir.path());
        assert_no_socket(dir.path());
        assert!(peer.read(&mut [0]).is_err(), "接收方仍持有材料句柄");
        drop(material);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn revoked_or_wrong_interface_material_never_reaches_configuration() {
        for stale in [false, true] {
            let (dir, executable, request, descriptor, mut peer, uid) = fixture();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let keeper = UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap());
            let revoked = CancellationToken::new();
            let material_token = CancellationToken::new();
            if stale {
                material_token.cancel();
            }
            let material = management::test_material(
                UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
                material_token,
            );
            let mut tunnel = ManagedMacTunnel::launch(
                &executable,
                request,
                descriptor,
                1,
                uid,
                CancellationToken::new(),
            )
            .await
            .unwrap();
            if !stale {
                tunnel.index = 2;
            }
            let stream = tunnel.management.take().unwrap();
            let (sender, receiver) = oneshot::channel();
            let managing = async move {
                let _stream = stream;
                sender.send(material).ok().unwrap();
                std::future::pending::<io::Result<()>>().await
            };
            let (ready, confirmation) = oneshot::channel();
            assert!(
                tunnel
                    .run_configuration_stage(
                        keeper,
                        managing,
                        receiver,
                        |_| panic!("过期或错误归属材料不得配置"),
                        ready,
                        CancellationToken::new(),
                        revoked.clone()
                    )
                    .await
                    .is_err()
            );
            assert!(confirmation.await.is_err());
            assert!(revoked.is_cancelled());
            assert_reaped(dir.path());
            assert_no_socket(dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }
}
