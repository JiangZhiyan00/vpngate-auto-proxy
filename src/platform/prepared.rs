//! 已配置隧道与低权限业务进程的持续联合监督；就绪材料不能替代出口验证。
use super::{
    custody::UtunCustody,
    management::{ConnectedTunnel, InterfaceMaterial},
    supervisor::{ManagedMacWorker, WorkerCredentials},
    topology::InterfaceAssignment,
    tunnel::{ConfiguredMacInterface, ManagedMacTunnel},
};
use std::{
    future::Future,
    io,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

trait Routing {
    fn install(&mut self, material: &InterfaceMaterial) -> io::Result<()>;
    fn retire(&mut self) -> io::Result<()>;
    fn consumers_reaped(&self) -> Option<bool> {
        None
    }
}
struct NativeRouting {
    route: Option<super::route::ScopedRoute>,
    cleanup: super::bootstrap::CleanupStatus,
    tunnel: super::process::Receipt,
    worker: super::process::Receipt,
}
impl Routing for NativeRouting {
    fn install(&mut self, material: &InterfaceMaterial) -> io::Result<()> {
        self.cleanup.unknown();
        self.route = Some(super::route::ScopedRoute::install(material)?);
        Ok(())
    }
    fn retire(&mut self) -> io::Result<()> {
        match &mut self.route {
            Some(route) => {
                route.retire()?;
                self.cleanup.confirm();
                Ok(())
            }
            None => Ok(()),
        }
    }
    fn consumers_reaped(&self) -> Option<bool> {
        Some(self.tunnel.reaped() && self.worker.reaped())
    }
}

pub struct MacWorkerRequest {
    pub runtime: PathBuf,
    pub credentials: WorkerCredentials,
    pub max_connections: usize,
}

/// 上层候选验证所需的私有业务入口；丢弃会撤销整个代际。
pub struct PreparedMacGeneration {
    configured: ConfiguredMacInterface,
    socket: PathBuf,
    generation: Uuid,
}
impl PreparedMacGeneration {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.configured.material().cancellation()
    }
    #[cfg(test)]
    pub(crate) fn test_material(configured: ConfiguredMacInterface, socket: PathBuf) -> Self {
        Self {
            configured,
            socket,
            generation: Uuid::new_v4(),
        }
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
    pub fn generation(&self) -> Uuid {
        self.generation
    }
    pub fn assignment(&self) -> &InterfaceAssignment {
        self.configured.assignment()
    }
    pub fn connection(&self) -> ConnectedTunnel {
        self.configured.connection()
    }
    pub fn is_revoked(&self) -> bool {
        self.configured.material().is_revoked()
    }
    pub fn peer_material(&self) -> io::Result<InterfaceMaterial> {
        self.configured.peer_material()
    }
}

/// 持续轮询至两侧均回收；收到就绪材料后仍须保持本未来运行。
/// 业务启动前配置作用域默认路由；出口验证及公共代理提升由外层编排负责。
pub async fn run(
    tunnel: ManagedMacTunnel,
    custody: UtunCustody,
    peers: Vec<InterfaceMaterial>,
    request: MacWorkerRequest,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
) -> io::Result<()> {
    run_tracked(
        tunnel,
        custody,
        peers,
        request,
        ready,
        stop,
        super::process::Receipt::default(),
        super::bootstrap::CleanupStatus::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_tracked(
    tunnel: ManagedMacTunnel,
    custody: UtunCustody,
    peers: Vec<InterfaceMaterial>,
    request: MacWorkerRequest,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
    worker_receipt: super::process::Receipt,
    cleanup: super::bootstrap::CleanupStatus,
) -> io::Result<()> {
    let receipts = NativeRouting {
        route: None,
        cleanup,
        tunnel: tunnel.receipt(),
        worker: worker_receipt.clone(),
    };
    let tunnel_stop = CancellationToken::new();
    let (sender, receiver) = oneshot::channel();
    let pipeline = tunnel.run_configured(custody, peers, sender, tunnel_stop.clone());
    drive_routed(
        pipeline,
        receiver,
        move |descriptor, index, cancelled| async move {
            let custody = UtunCustody::verify(descriptor, index)?;
            ManagedMacWorker::start_tracked(
                &request.runtime,
                custody,
                request.credentials,
                request.max_connections,
                cancelled,
                worker_receipt,
            )
            .await
        },
        ready,
        stop,
        tunnel_stop,
        receipts,
    )
    .await
}

async fn drive_routed<F, L, S>(
    pipeline: F,
    mut receiver: oneshot::Receiver<ConfiguredMacInterface>,
    launch: L,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
    tunnel_stop: CancellationToken,
    mut routing: impl Routing,
) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
    L: FnOnce(OwnedFd, u32, CancellationToken) -> S,
    S: Future<Output = io::Result<ManagedMacWorker>>,
{
    let _stop_guard = tunnel_stop.clone().drop_guard();
    tokio::pin!(pipeline);
    let mut pipeline_result = None;
    let mut worker = None;
    let mut pending = None;
    let mut keeper = None;
    let mut revoke_guard = None;
    let outcome = async {
        let configured = tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            result = &mut pipeline => { pipeline_result = Some(result); return Err(io::Error::new(io::ErrorKind::BrokenPipe, "配置监督在业务启动前结束")); }
            result = &mut receiver => result.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "已配置接口材料未交付"))?,
        };
        let revoked = configured.material().cancellation();
        revoke_guard = Some(revoked.clone().drop_guard());
        pending = Some(configured);
        let material = pending.as_ref().expect("业务启动前材料已保留").material();
        if material.is_revoked() { return Err(io::Error::new(io::ErrorKind::Interrupted, "业务启动材料已经撤销")); }
        let index = material.custody().interface_index();
        // 业务交接使用复制件，监督方保留一份至业务与隧道的回收均已尝试。
        keeper = Some(material.custody().duplicate_descriptor()?);
        routing.install(material)?;
        let descriptor = material.custody().duplicate_descriptor()?;
        let worker_stop = CancellationToken::new();
        let starting = launch(descriptor, index, worker_stop.clone());
        tokio::pin!(starting);
        let mut cancelled = false;
        let mut startup_failure = None;
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled(), if !cancelled => { cancelled = true; worker_stop.cancel(); }
                _ = revoked.cancelled(), if !cancelled => {
                    cancelled = true; worker_stop.cancel();
                    startup_failure = Some(io::Error::new(io::ErrorKind::Interrupted, "隧道在业务启动期间撤销"));
                }
                result = &mut pipeline, if pipeline_result.is_none() => {
                    pipeline_result = Some(result); cancelled = true; worker_stop.cancel();
                    startup_failure = Some(io::Error::new(io::ErrorKind::BrokenPipe, "配置监督在业务启动期间结束"));
                }
                result = &mut starting => {
                    // 取消后仍等待启动未来完成显式回收，不直接丢弃派生中的子进程。
                    worker = Some(result?);
                    if let Some(error) = startup_failure { return Err(error); }
                    if cancelled { return Ok(()); }
                    break;
                }
            }
        }
        let business = worker.as_mut().expect("业务已经就绪");
        if business.interface_index() != index || !business.is_running()? {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "业务就绪身份或直属进程状态不符"));
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            _ = revoked.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "业务材料发布前已经撤销")),
            result = &mut pipeline => { pipeline_result = Some(result); return Err(io::Error::new(io::ErrorKind::BrokenPipe, "配置监督在业务发布前结束")); }
            result = business.wait_for_exit() => { result?; return Err(io::Error::new(io::ErrorKind::BrokenPipe, "业务在发布前退出")); }
            _ = tokio::task::yield_now() => {},
        }
        if revoked.is_cancelled() { return Err(io::Error::new(io::ErrorKind::Interrupted, "业务材料发布前已经撤销")); }
        let detail = PreparedMacGeneration {
            configured: pending.take().expect("发布前持有配置材料"),
            socket: business.socket_path().to_path_buf(), generation: business.generation(),
        };
        ready.send(detail).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "业务就绪材料接收方退出"))?;
        tokio::select! {
            biased;
            _ = stop.cancelled() => Ok(()),
            _ = revoked.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "业务代际已经撤销")),
            result = &mut pipeline => { pipeline_result = Some(result); Err(io::Error::new(io::ErrorKind::BrokenPipe, "配置监督意外结束")) }
            result = business.wait_for_exit() => { result?; Err(io::Error::new(io::ErrorKind::BrokenPipe, "业务子进程意外退出")) }
        }
    }.await;
    drop(revoke_guard);
    tunnel_stop.cancel();
    // 两侧同时等待；一侧失败不得跳过另一侧。先轮询业务退休以尽早停止接纳。
    let business_cleanup = async {
        match worker.as_mut() {
            Some(worker) => worker.retire().await,
            None => Ok(()),
        }
    };
    let tunnel_cleanup = async {
        match pipeline_result.take() {
            Some(result) => result,
            None => pipeline.await,
        }
    };
    let (business_cleanup, tunnel_cleanup) = tokio::join!(biased; business_cleanup, tunnel_cleanup);
    // 路由撤销晚于两侧回收尝试；路由自身继续持有句柄，防止数字索引复用。
    let confirmed = routing
        .consumers_reaped()
        .unwrap_or(business_cleanup.is_ok() && tunnel_cleanup.is_ok());
    let route_cleanup = if confirmed {
        routing.retire()
    } else {
        Err(io::Error::other(
            "消费者回收结果未全部确认，保留作用域路由至所属接口释放",
        ))
    };
    drop(pending);
    drop(receiver);
    drop(keeper);
    let mut failures = Vec::new();
    for (stage, result) in [
        ("联合监督", outcome),
        ("业务回收", business_cleanup),
        ("隧道回收", tunnel_cleanup),
        ("路由回收", route_cleanup),
    ] {
        if let Err(error) = result {
            failures.push((error.kind(), format!("{stage}：{error}")));
        }
    }
    if let Some((kind, _)) = failures.first() {
        Err(io::Error::new(
            *kind,
            failures
                .iter()
                .map(|(_, message)| message.as_str())
                .collect::<Vec<_>>()
                .join("；"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
async fn drive<F, L, S>(
    pipeline: F,
    receiver: oneshot::Receiver<ConfiguredMacInterface>,
    launch: L,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
    tunnel_stop: CancellationToken,
) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
    L: FnOnce(OwnedFd, u32, CancellationToken) -> S,
    S: Future<Output = io::Result<ManagedMacWorker>>,
{
    struct NoRoutes;
    impl Routing for NoRoutes {
        fn install(&mut self, _: &InterfaceMaterial) -> io::Result<()> {
            Ok(())
        }
        fn retire(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    drive_routed(
        pipeline,
        receiver,
        launch,
        ready,
        stop,
        tunnel_stop,
        NoRoutes,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::super::{
        management,
        supervisor::{
            test_launch_cancellable,
            tests::{assert_reaped, fixture},
        },
    };
    use super::*;
    use std::{io::Read, os::unix::net::UnixStream, time::Duration};
    #[test]
    fn ambiguous_route_install_never_confirms_cleanup_without_owned_route() {
        let receipt = super::super::bootstrap::CleanupStatus::default();
        let mut routing = NativeRouting {
            route: None,
            cleanup: receipt.clone(),
            tunnel: super::super::process::Receipt::default(),
            worker: super::super::process::Receipt::default(),
        };
        assert!(receipt.confirmed());
        let (descriptor, peer) = UnixStream::pair().unwrap();
        let material = management::test_material(
            UtunCustody::test_unverified_resource(descriptor.into()),
            CancellationToken::new(),
        );
        assert!(routing.install(&material).is_err());
        assert!(routing.retire().is_ok());
        assert!(!receipt.confirmed());
        assert_eq!(routing.consumers_reaped(), Some(true));
        drop(material);
        drop(peer);
    }

    #[tokio::test]
    async fn confirmed_forced_reaping_allows_route_cleanup_without_hiding_retirement_failure() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Checked {
            receipt: super::super::process::Receipt,
            removed: Arc<AtomicBool>,
        }
        impl Routing for Checked {
            fn install(&mut self, _: &InterfaceMaterial) -> io::Result<()> {
                Ok(())
            }
            fn retire(&mut self) -> io::Result<()> {
                self.removed.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn consumers_reaped(&self) -> Option<bool> {
                Some(self.receipt.reaped())
            }
        }
        let (directory, executable, credentials) = fixture("hang");
        let runtime = directory.path().to_path_buf();
        let worker_runtime = runtime.clone();
        let receipt = super::super::process::Receipt::default();
        let worker_receipt = receipt.clone();
        let removed = Arc::new(AtomicBool::new(false));
        let (owner, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let configured = ConfiguredMacInterface::test_material(management::test_material(
            UtunCustody::test_unverified_resource(owner.into()),
            CancellationToken::new(),
        ));
        let tunnel_stop = CancellationToken::new();
        let waiting = tunnel_stop.clone();
        let (sender, receiver) = oneshot::channel();
        let pipeline = async move {
            let _ = sender.send(configured);
            waiting.cancelled().await;
            Ok(())
        };
        let (ready, confirmation) = oneshot::channel();
        let stop = CancellationToken::new();
        let running = drive_routed(
            pipeline,
            receiver,
            move |descriptor, index, cancelled| async move {
                super::super::supervisor::test_launch_tracked(
                    &executable,
                    &worker_runtime,
                    descriptor,
                    index,
                    credentials,
                    cancelled,
                    worker_receipt,
                )
                .await
            },
            ready,
            stop.clone(),
            tunnel_stop,
            Checked {
                receipt: receipt.clone(),
                removed: removed.clone(),
            },
        );
        let stopping = async {
            let detail = confirmation.await.unwrap();
            stop.cancel();
            detail
        };
        let (result, detail) = tokio::join!(running, stopping);
        assert!(result.unwrap_err().to_string().contains("业务回收"));
        assert!(receipt.reaped());
        assert!(removed.load(Ordering::SeqCst));
        assert_reaped(&runtime);
        drop(detail);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn missing_or_stale_configuration_never_launches_business() {
        for stale in [false, true] {
            let (sender, receiver) = oneshot::channel();
            let tunnel_stop = CancellationToken::new();
            let waiting = tunnel_stop.clone();
            let revoked = CancellationToken::new();
            let signal = revoked.clone();
            let pipeline = async move {
                if stale {
                    let (owner, _peer) = UnixStream::pair().unwrap();
                    signal.cancel();
                    let material = management::test_material(
                        UtunCustody::test_unverified_resource(owner.into()),
                        signal,
                    );
                    let _ = sender.send(ConfiguredMacInterface::test_material(material));
                    waiting.cancelled().await;
                    Ok(())
                } else {
                    drop(sender);
                    Err(io::Error::new(io::ErrorKind::InvalidData, "受控配置失败"))
                }
            };
            let (ready, confirmation) = oneshot::channel();
            let result = drive(
                pipeline,
                receiver,
                |_, _, _| async { panic!("配置失败不得启动业务") },
                ready,
                CancellationToken::new(),
                tunnel_stop,
            )
            .await;
            assert!(result.is_err());
            assert!(confirmation.await.is_err());
            if stale {
                assert!(revoked.is_cancelled());
            }
        }
    }

    #[tokio::test]
    async fn already_stopped_driver_cancels_pipeline_without_launch() {
        let stop = CancellationToken::new();
        stop.cancel();
        let tunnel_stop = CancellationToken::new();
        let waiting = tunnel_stop.clone();
        let (sender, receiver) = oneshot::channel();
        let pipeline = async move {
            waiting.cancelled().await;
            drop(sender);
            Ok(())
        };
        let (ready, confirmation) = oneshot::channel();
        drive(
            pipeline,
            receiver,
            |_, _, _| async { panic!("已停止监督不得启动业务") },
            ready,
            stop,
            tunnel_stop.clone(),
        )
        .await
        .unwrap();
        assert!(tunnel_stop.is_cancelled());
        assert!(confirmation.await.is_err());
    }

    #[tokio::test]
    async fn configured_generation_starts_worker_then_retires_both_on_stop() {
        let (directory, executable, credentials) = fixture("normal");
        let runtime = directory.path().to_path_buf();
        let worker_runtime = runtime.clone();
        let (owner, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let revoked = CancellationToken::new();
        let configured = ConfiguredMacInterface::test_material(management::test_material(
            UtunCustody::test_unverified_resource(owner.into()),
            revoked.clone(),
        ));
        let tunnel_stop = CancellationToken::new();
        let waiting = tunnel_stop.clone();
        let (sender, receiver) = oneshot::channel();
        let pipeline = async move {
            sender.send(configured).ok().unwrap();
            waiting.cancelled().await;
            Ok(())
        };
        let (ready, confirmation) = oneshot::channel();
        let stop = CancellationToken::new();
        let running = drive(
            pipeline,
            receiver,
            move |descriptor, index, cancelled| async move {
                test_launch_cancellable(
                    &executable,
                    &worker_runtime,
                    descriptor,
                    index,
                    credentials,
                    cancelled,
                )
                .await
            },
            ready,
            stop.clone(),
            tunnel_stop,
        );
        let observing = async {
            let details = confirmation.await.unwrap();
            assert!(!details.generation().is_nil());
            assert!(!details.is_revoked());
            assert!(details.socket_path().starts_with(&runtime));
            assert!(peer.read(&mut [0]).is_err());
            stop.cancel();
            details
        };
        let (result, details) = tokio::join!(running, observing);
        result.unwrap();
        assert!(details.is_revoked());
        assert!(revoked.is_cancelled());
        assert_reaped(&runtime);
        drop(details);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}

#[cfg(test)]
mod coupled_tests {
    use super::*;
    use crate::platform::{
        management,
        supervisor::{
            test_launch_cancellable,
            tests::{assert_reaped, fixture},
        },
        tunnel,
    };
    use std::{io::Read, os::unix::net::UnixStream, time::Duration};

    async fn paired(
        stop: CancellationToken,
        fault: CancellationToken,
        hang: bool,
    ) -> (
        tempfile::TempDir,
        impl Future<Output = io::Result<()>>,
        oneshot::Receiver<ConfiguredMacInterface>,
        UnixStream,
        CancellationToken,
    ) {
        let (directory, executable, request, descriptor, peer, uid) = tunnel::tests::fixture();
        if hang {
            tunnel::tests::set_mode(&executable, "hang");
        }
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let revoked = CancellationToken::new();
        let configured = ConfiguredMacInterface::test_material(management::test_material(
            UtunCustody::test_unverified_resource(descriptor.try_clone().unwrap()),
            revoked.clone(),
        ));
        let mut tunnel = ManagedMacTunnel::test_launch(&executable, request, descriptor, 1, uid)
            .await
            .unwrap();
        let (sender, receiver) = oneshot::channel();
        let cancel = revoked.clone();
        let pipeline = async move {
            let _ = sender.send(configured);
            let outcome = tokio::select! {
                biased;
                _ = stop.cancelled() => Ok(()),
                _ = fault.cancelled() => { cancel.cancel(); Err(io::Error::new(io::ErrorKind::BrokenPipe, "受控隧道故障")) },
            };
            let cleanup = tunnel.retire().await;
            outcome.and(cleanup)
        };
        (directory, pipeline, receiver, peer, revoked)
    }
    async fn wait_started(runtime: &Path) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !runtime.join("child.pid").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    async fn wait_reaped(runtime: &Path) {
        let pid = std::fs::read_to_string(runtime.join("child.pid")).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
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
    }

    #[tokio::test]
    async fn routing_precedes_launch_and_retires_after_both_real_consumers() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct CheckedRoutes {
            step: Arc<AtomicUsize>,
            worker: PathBuf,
            tunnel: PathBuf,
        }
        impl Routing for CheckedRoutes {
            fn install(&mut self, _: &InterfaceMaterial) -> io::Result<()> {
                assert_eq!(self.step.fetch_add(1, Ordering::SeqCst), 0);
                assert!(!self.worker.join("child.pid").exists());
                Ok(())
            }
            fn retire(&mut self) -> io::Result<()> {
                assert_reaped(&self.worker);
                tunnel::tests::assert_reaped(&self.tunnel);
                assert_eq!(self.step.fetch_add(1, Ordering::SeqCst), 2);
                Ok(())
            }
        }
        let (directory, executable, credentials) = fixture("normal");
        let runtime = directory.path().to_path_buf();
        let worker_runtime = runtime.clone();
        let tunnel_stop = CancellationToken::new();
        let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
            paired(tunnel_stop.clone(), CancellationToken::new(), false).await;
        let step = Arc::new(AtomicUsize::new(0));
        let launching = step.clone();
        let routes = CheckedRoutes {
            step: step.clone(),
            worker: runtime,
            tunnel: tunnel_dir.path().into(),
        };
        let (ready, confirmation) = oneshot::channel();
        let stop = CancellationToken::new();
        let running = drive_routed(
            pipeline,
            receiver,
            move |descriptor, index, cancelled| async move {
                assert_eq!(launching.fetch_add(1, Ordering::SeqCst), 1);
                test_launch_cancellable(
                    &executable,
                    &worker_runtime,
                    descriptor,
                    index,
                    credentials,
                    cancelled,
                )
                .await
            },
            ready,
            stop.clone(),
            tunnel_stop,
            routes,
        );
        let stopping = async {
            let detail = confirmation.await.unwrap();
            stop.cancel();
            detail
        };
        let (result, detail) = tokio::join!(running, stopping);
        result.unwrap();
        assert_eq!(step.load(Ordering::SeqCst), 3);
        assert!(revoked.is_cancelled());
        drop(detail);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn rejected_routing_never_launches_business_but_reaps_tunnel() {
        struct Reject;
        impl Routing for Reject {
            fn install(&mut self, _: &InterfaceMaterial) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::AddrInUse, "受控路由冲突"))
            }
            fn retire(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let tunnel_stop = CancellationToken::new();
        let (directory, pipeline, receiver, mut peer, revoked) =
            paired(tunnel_stop.clone(), CancellationToken::new(), false).await;
        let (ready, confirmation) = oneshot::channel();
        let error = drive_routed(
            pipeline,
            receiver,
            |_, _, _| async { panic!("路由失败不得启动业务") },
            ready,
            CancellationToken::new(),
            tunnel_stop,
            Reject,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(confirmation.await.is_err());
        assert!(revoked.is_cancelled());
        tunnel::tests::assert_reaped(directory.path());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn two_real_consumers_retire_on_stop_and_material_drop() {
        for drop_material in [false, true] {
            let (directory, executable, credentials) = fixture("normal");
            let runtime = directory.path().to_path_buf();
            let worker_runtime = runtime.clone();
            let tunnel_stop = CancellationToken::new();
            let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
                paired(tunnel_stop.clone(), CancellationToken::new(), false).await;
            let (ready, confirmation) = oneshot::channel();
            let stop = CancellationToken::new();
            let running = drive(
                pipeline,
                receiver,
                move |descriptor, index, cancelled| async move {
                    test_launch_cancellable(
                        &executable,
                        &worker_runtime,
                        descriptor,
                        index,
                        credentials,
                        cancelled,
                    )
                    .await
                },
                ready,
                stop.clone(),
                tunnel_stop,
            );
            let observing = async {
                let detail = confirmation.await.unwrap();
                assert!(!detail.is_revoked());
                if drop_material {
                    drop(detail);
                    None
                } else {
                    stop.cancel();
                    Some(detail)
                }
            };
            let (result, detail) = tokio::join!(running, observing);
            if drop_material {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            } else {
                result.unwrap();
            }
            assert!(revoked.is_cancelled());
            assert_reaped(&runtime);
            tunnel::tests::assert_reaped(tunnel_dir.path());
            drop(detail);
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn stop_or_tunnel_failure_during_silent_worker_start_waits_for_reaping() {
        for faulted in [false, true] {
            let (directory, executable, credentials) = fixture("silent");
            let runtime = directory.path().to_path_buf();
            let worker_runtime = runtime.clone();
            let tunnel_stop = CancellationToken::new();
            let fault = CancellationToken::new();
            let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
                paired(tunnel_stop.clone(), fault.clone(), false).await;
            let (ready, confirmation) = oneshot::channel();
            let stop = CancellationToken::new();
            let running = drive(
                pipeline,
                receiver,
                move |descriptor, index, cancelled| async move {
                    test_launch_cancellable(
                        &executable,
                        &worker_runtime,
                        descriptor,
                        index,
                        credentials,
                        cancelled,
                    )
                    .await
                },
                ready,
                stop.clone(),
                tunnel_stop,
            );
            let interrupting = async {
                wait_started(&runtime).await;
                if faulted {
                    fault.cancel();
                } else {
                    stop.cancel();
                }
            };
            let (result, ()) = tokio::join!(running, interrupting);
            assert!(result.is_err());
            assert!(confirmation.await.is_err());
            assert!(revoked.is_cancelled());
            assert_reaped(&runtime);
            tunnel::tests::assert_reaped(tunnel_dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn worker_start_rejection_and_abandoned_ready_receiver_reap_both() {
        for abandoned in [false, true] {
            let (directory, executable, credentials) =
                fixture(if abandoned { "normal" } else { "wrong" });
            let runtime = directory.path().to_path_buf();
            let worker_runtime = runtime.clone();
            let tunnel_stop = CancellationToken::new();
            let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
                paired(tunnel_stop.clone(), CancellationToken::new(), false).await;
            let (ready, mut confirmation) = oneshot::channel();
            if abandoned {
                confirmation.close();
            }
            let result = drive(
                pipeline,
                receiver,
                move |descriptor, index, cancelled| async move {
                    test_launch_cancellable(
                        &executable,
                        &worker_runtime,
                        descriptor,
                        index,
                        credentials,
                        cancelled,
                    )
                    .await
                },
                ready,
                CancellationToken::new(),
                tunnel_stop,
            )
            .await;
            assert!(result.is_err());
            assert!(confirmation.await.is_err());
            assert!(revoked.is_cancelled());
            assert_reaped(&runtime);
            tunnel::tests::assert_reaped(tunnel_dir.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn unexpected_worker_exit_retires_its_tunnel() {
        let (directory, executable, credentials) = fixture("normal");
        let runtime = directory.path().to_path_buf();
        let worker_runtime = runtime.clone();
        let tunnel_stop = CancellationToken::new();
        let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
            paired(tunnel_stop.clone(), CancellationToken::new(), false).await;
        let (ready, confirmation) = oneshot::channel();
        let running = drive(
            pipeline,
            receiver,
            move |descriptor, index, cancelled| async move {
                test_launch_cancellable(
                    &executable,
                    &worker_runtime,
                    descriptor,
                    index,
                    credentials,
                    cancelled,
                )
                .await
            },
            ready,
            CancellationToken::new(),
            tunnel_stop,
        );
        let terminating = async {
            let detail = confirmation.await.unwrap();
            let pid = std::fs::read_to_string(runtime.join("child.pid")).unwrap();
            assert!(
                std::process::Command::new("/bin/kill")
                    .args(["-KILL", pid.trim()])
                    .status()
                    .unwrap()
                    .success()
            );
            detail
        };
        let (result, detail) = tokio::join!(running, terminating);
        assert!(result.is_err());
        assert!(revoked.is_cancelled());
        assert!(detail.is_revoked());
        assert_reaped(&runtime);
        tunnel::tests::assert_reaped(tunnel_dir.path());
        drop(detail);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn cleanup_attempts_both_unresponsive_consumers_and_preserves_errors() {
        let (directory, executable, credentials) = fixture("hang");
        let runtime = directory.path().to_path_buf();
        let worker_runtime = runtime.clone();
        let tunnel_stop = CancellationToken::new();
        let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
            paired(tunnel_stop.clone(), CancellationToken::new(), true).await;
        let (ready, confirmation) = oneshot::channel();
        let stop = CancellationToken::new();
        let running = drive(
            pipeline,
            receiver,
            move |descriptor, index, cancelled| async move {
                test_launch_cancellable(
                    &executable,
                    &worker_runtime,
                    descriptor,
                    index,
                    credentials,
                    cancelled,
                )
                .await
            },
            ready,
            stop.clone(),
            tunnel_stop,
        );
        let stopping = async {
            let detail = confirmation.await.unwrap();
            stop.cancel();
            detail
        };
        let (result, detail) = tokio::join!(running, stopping);
        let error = result.unwrap_err().to_string();
        assert!(error.contains("业务回收"));
        assert!(error.contains("隧道回收"));
        assert!(revoked.is_cancelled());
        assert_reaped(&runtime);
        tunnel::tests::assert_reaped(tunnel_dir.path());
        drop(detail);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[tokio::test]
    async fn aborting_combined_future_revokes_and_terminates_both_real_consumers() {
        let (directory, executable, credentials) = fixture("normal");
        let runtime = directory.path().to_path_buf();
        let worker_runtime = runtime.clone();
        let tunnel_stop = CancellationToken::new();
        let (tunnel_dir, pipeline, receiver, mut peer, revoked) =
            paired(tunnel_stop.clone(), CancellationToken::new(), false).await;
        let (ready, confirmation) = oneshot::channel();
        let task = tokio::spawn(drive(
            pipeline,
            receiver,
            move |descriptor, index, cancelled| async move {
                test_launch_cancellable(
                    &executable,
                    &worker_runtime,
                    descriptor,
                    index,
                    credentials,
                    cancelled,
                )
                .await
            },
            ready,
            CancellationToken::new(),
            tunnel_stop,
        ));
        let detail = confirmation.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(revoked.is_cancelled());
        assert!(detail.is_revoked());
        tokio::join!(wait_reaped(&runtime), wait_reaped(tunnel_dir.path()));
        drop(detail);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
