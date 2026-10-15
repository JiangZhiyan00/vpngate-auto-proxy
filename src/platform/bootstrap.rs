//! 可信特权父进程的代际完整调用；仍须外层候选验证及公共出口提升。
use super::{
    interface, launcher,
    management::InterfaceMaterial,
    prepared::{self, MacWorkerRequest, PreparedMacGeneration},
    program,
    runtime::GenerationRuntime,
    supervisor::WorkerCredentials,
    tunnel::{ManagedMacTunnel, TunnelStartup},
};
use crate::{
    domain::Endpoint,
    openvpn::{SanitizedOpenVpn, validate_regenerated},
};
use std::{io, path::PathBuf, time::Duration};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// 记录所属回收步骤的确认状态；不证明宿主基线或外部持有复制件已释放。
#[derive(Clone)]
pub(crate) struct CleanupStatus(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Default for CleanupStatus {
    fn default() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            true,
        )))
    }
}
impl CleanupStatus {
    pub(super) fn unknown(&self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
    pub(super) fn confirm(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
    pub(crate) fn confirmed(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

pub struct MacGenerationRequest {
    pub parent: PathBuf,
    pub instance_id: uuid::Uuid,
    pub dependency_manifest: PathBuf,
    pub profile: SanitizedOpenVpn,
    pub credentials: WorkerCredentials,
    pub startup_budget: Duration,
    pub max_connections: usize,
}
fn validate(request: &MacGenerationRequest) -> io::Result<Endpoint> {
    if request.instance_id.is_nil() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "候选所属实例身份为空",
        ));
    }
    request.credentials.validate_account()?;
    if request.startup_budget.is_zero()
        || request.startup_budget > Duration::from_secs(120)
        || request.max_connections == 0
        || request.max_connections > tokio::sync::Semaphore::MAX_PERMITS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "代际启动截止或容量无效",
        ));
    }
    let remote = request.profile.remote();
    let endpoint = Endpoint {
        ip: *remote.ip(),
        port: remote.port(),
        transport: request.profile.transport(),
    };
    validate_regenerated(request.profile.as_str(), &endpoint)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "代际隧道配置与白名单不符"))?;
    Ok(endpoint)
}
/// 先验证部署及账户、准备材料，再创建接口并持续运行隧道/业务/路由监督。
/// 所有错误均不发布已验证出口；回收未确认或取消本未来保留归属材料，不能凭进程号自动回收。
pub async fn run(
    request: MacGenerationRequest,
    peers: Vec<InterfaceMaterial>,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
) -> io::Result<()> {
    run_tracked(request, peers, ready, stop, CleanupStatus::default()).await
}
pub(crate) async fn run_tracked(
    request: MacGenerationRequest,
    peers: Vec<InterfaceMaterial>,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
    cleanup: CleanupStatus,
) -> io::Result<()> {
    run_tracked_with_lease(request, peers, ready, stop, cleanup, None, None).await
}
pub(crate) async fn run_tracked_with_lease(
    request: MacGenerationRequest,
    peers: Vec<InterfaceMaterial>,
    ready: oneshot::Sender<PreparedMacGeneration>,
    stop: CancellationToken,
    cleanup: CleanupStatus,
    lease: Option<std::sync::Arc<super::lease::ConsumerLease>>,
    probes: Option<super::exit_probe::ProbeRegistry>,
) -> io::Result<()> {
    if stop.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "代际启动已经取消",
        ));
    }
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "代际启动需要管理员身份",
        ));
    }
    if peers.len() > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "并存代际材料超过上限",
        ));
    }
    let endpoint = validate(&request)?;
    program::verify_current()?;
    launcher::preflight_dependency(&request.dependency_manifest)?;
    cleanup.unknown();
    let mut runtime = GenerationRuntime::prepare(
        &request.parent,
        request.profile.as_str().as_bytes(),
        request.credentials,
    )?;
    let lease = match lease {
        Some(lease) => lease,
        None => match runtime.consumer_lease() {
            Ok(lease) => lease,
            Err(error) => return finish_tracked(runtime, Err(error), true, &cleanup),
        },
    };
    if let Some(probes) = probes
        && let Err(error) = probes.attach_lease(lease.clone())
    {
        return finish_tracked(runtime, Err(error), true, &cleanup);
    }
    if stop.is_cancelled() {
        return finish_tracked(
            runtime,
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "代际材料准备期间已经取消",
            )),
            true,
            &cleanup,
        );
    }
    if let Err(error) = runtime
        .bind_instance(request.instance_id)
        .and_then(|()| runtime.begin_interface_creation())
    {
        return finish_tracked(runtime, Err(error), true, &cleanup);
    }
    let custody = match interface::create() {
        Ok(custody) => custody,
        Err(error) => return finish_tracked(runtime, Err(error), true, &cleanup),
    };
    if let Err(error) = runtime.record_interface(&custody) {
        drop(custody);
        return finish_tracked(runtime, Err(error), true, &cleanup);
    }
    let tunnel_receipt = super::process::Receipt::default().with_lease(Some(lease.clone()));
    let worker_receipt = super::process::Receipt::default().with_lease(Some(lease));
    let tunnel = ManagedMacTunnel::start_tracked(
        TunnelStartup {
            runtime: runtime.tunnel(),
            dependency_manifest: request.dependency_manifest,
            profile: runtime.profile(),
            endpoint,
            startup_budget: request.startup_budget,
        },
        &custody,
        stop.clone(),
        tunnel_receipt.clone(),
    )
    .await;
    let mut tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(error) => {
            drop(custody);
            return finish_tracked(runtime, Err(error), tunnel_receipt.reaped(), &cleanup);
        }
    };
    if let Err(error) = tunnel
        .management_path()
        .and_then(|path| runtime.register_socket(path))
    {
        let retirement = tunnel.retire().await;
        drop(tunnel);
        drop(custody);
        let error = match retirement {
            Ok(()) => error,
            Err(retirement) => io::Error::new(
                error.kind(),
                format!("{error}；隧道端点登记失败后回收：{retirement}"),
            ),
        };
        return finish_tracked(runtime, Err(error), tunnel_receipt.reaped(), &cleanup);
    }
    let routing_cleanup = CleanupStatus::default();
    let (prepared_ready, mut prepared_receiver) = oneshot::channel();
    let running = prepared::run_tracked(
        tunnel,
        custody,
        peers,
        MacWorkerRequest {
            runtime: runtime.worker(),
            credentials: request.credentials,
            max_connections: request.max_connections,
        },
        prepared_ready,
        stop.clone(),
        worker_receipt.clone(),
        routing_cleanup.clone(),
    );
    tokio::pin!(running);
    let first = tokio::select! {
        biased;
        material = &mut prepared_receiver => Ok(material),
        result = &mut running => Err(result),
    };
    let result = match first {
        Err(result) => result,
        Ok(Err(_)) => running.await,
        Ok(Ok(material)) => {
            let registered = runtime.register_socket(material.socket_path());
            match registered {
                Ok(()) => {
                    if ready.send(material).is_err() {
                        stop.cancel();
                    }
                    running.await
                }
                Err(error) => {
                    drop(material);
                    stop.cancel();
                    let retirement = running.await;
                    match retirement {
                        Ok(()) => Err(error),
                        Err(retirement) => Err(io::Error::new(
                            error.kind(),
                            format!("{error}；业务端点登记失败后回收：{retirement}"),
                        )),
                    }
                }
            }
        }
    };
    // 逻辑失败仍可清理已确认回收的消费者；路由未确认时同样保留归属材料。
    let confirmed =
        tunnel_receipt.reaped() && worker_receipt.reaped() && routing_cleanup.confirmed();
    finish_tracked(runtime, result, confirmed, &cleanup)
}
#[cfg(test)]
fn finish(
    runtime: GenerationRuntime,
    result: io::Result<()>,
    consumers_absent: bool,
) -> io::Result<()> {
    finish_tracked(runtime, result, consumers_absent, &CleanupStatus::default())
}
fn finish_tracked(
    mut runtime: GenerationRuntime,
    result: io::Result<()>,
    consumers_absent: bool,
    cleanup: &CleanupStatus,
) -> io::Result<()> {
    cleanup.unknown();
    if !consumers_absent {
        let error = result
            .err()
            .unwrap_or_else(|| io::Error::other("消费者或路由回收未确认"));
        return Err(io::Error::new(
            error.kind(),
            format!("{error}；代际材料保留于：{}", runtime.root().display()),
        ));
    }
    let directory = runtime.cleanup();
    if directory.is_ok() {
        cleanup.confirm();
    }
    match (result, directory) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) => Err(e),
        (Ok(()), Err(e)) => Err(io::Error::new(
            e.kind(),
            format!(
                "代际目录回收：{e}；材料保留于：{}",
                runtime.root().display()
            ),
        )),
        (Err(e), Err(cleanup)) => Err(io::Error::new(
            e.kind(),
            format!(
                "{e}；代际目录回收：{cleanup}；材料保留于：{}",
                runtime.root().display()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_receipt_is_independent_of_logical_failure() {
        for success in [false, true] {
            let (_parent, runtime) = GenerationRuntime::test_prepare();
            let root = runtime.root().to_path_buf();
            let receipt = CleanupStatus::default();
            receipt.unknown();
            let result = finish_tracked(
                runtime,
                if success {
                    Ok(())
                } else {
                    Err(io::Error::other("受控逻辑失败"))
                },
                true,
                &receipt,
            );
            assert_eq!(result.is_ok(), success);
            assert!(receipt.confirmed());
            assert!(!root.exists());
        }
    }
    #[test]
    fn absent_consumers_do_not_confirm_failed_directory_cleanup() {
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let receipt = CleanupStatus::default();
        std::fs::write(runtime.worker().join("unowned"), b"keep").unwrap();
        assert!(finish_tracked(runtime, Ok(()), true, &receipt).is_err());
        assert!(!receipt.confirmed());
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_path_buf();
        assert!(finish_tracked(runtime, Ok(()), false, &receipt).is_err());
        assert!(!receipt.confirmed());
        assert!(root.join("ownership.json").exists());
    }
    fn fixture() -> MacGenerationRequest {
        let profile=crate::openvpn::sanitize_openvpn(b"client\ndev tun\nproto tcp\nremote 1.2.3.4 443\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n","1.2.3.4".parse().unwrap()).unwrap();
        MacGenerationRequest {
            parent: "/missing/runtime".into(),
            instance_id: uuid::Uuid::new_v4(),
            dependency_manifest: "/missing/dependency".into(),
            profile,
            credentials: WorkerCredentials {
                uid: nix::unistd::getuid().as_raw(),
                gid: nix::unistd::getgid().as_raw(),
            },
            startup_budget: Duration::from_secs(3),
            max_connections: 5,
        }
    }
    #[tokio::test]
    async fn root_and_stop_gates_precede_installation_or_filesystem_access() {
        assert!(!nix::unistd::geteuid().is_root());
        for cancelled in [false, true] {
            let (ready, confirmation) = oneshot::channel();
            let stop = CancellationToken::new();
            if cancelled {
                stop.cancel();
            }
            let error = run(fixture(), Vec::new(), ready, stop).await.unwrap_err();
            assert_eq!(
                error.kind(),
                if cancelled {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::PermissionDenied
                }
            );
            assert!(confirmation.await.is_err());
        }
    }
    #[test]
    fn account_primary_group_capacity_and_deadline_are_checked() {
        let mut request = fixture();
        validate(&request).unwrap();
        request.credentials.uid = 0;
        assert!(validate(&request).is_err());
        request = fixture();
        request.credentials.gid = 1;
        assert!(validate(&request).is_err());
        for budget in [Duration::ZERO, Duration::from_secs(121)] {
            request = fixture();
            request.startup_budget = budget;
            assert!(validate(&request).is_err());
        }
        for capacity in [0, tokio::sync::Semaphore::MAX_PERMITS + 1] {
            request = fixture();
            request.max_connections = capacity;
            assert!(validate(&request).is_err());
        }
    }
    #[test]
    fn confirmed_retirement_and_prelaunch_failure_clean_owned_layout() {
        for success in [false, true] {
            let (_parent, runtime) = GenerationRuntime::test_prepare();
            let root = runtime.root().to_path_buf();
            let result = finish(
                runtime,
                if success {
                    Ok(())
                } else {
                    Err(io::Error::other("受控启动前失败"))
                },
                true,
            );
            assert_eq!(result.is_ok(), success);
            assert!(!root.exists());
        }
    }
    #[test]
    fn unconfirmed_consumers_and_abandoned_scope_preserve_materials() {
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_path_buf();
        let error = finish(
            runtime,
            Err(io::Error::new(io::ErrorKind::TimedOut, "受控消费者未回收")),
            false,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains(root.to_str().unwrap()));
        assert!(root.join("ownership.json").exists());
        let (_other, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_path_buf();
        drop(runtime);
        assert!(root.join("t/profile.ovpn").exists());
    }
    #[test]
    fn cleanup_error_is_preserved_with_initial_failure_and_manifest() {
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_path_buf();
        std::fs::write(runtime.worker().join("unowned"), b"keep").unwrap();
        let error = finish(
            runtime,
            Err(io::Error::new(io::ErrorKind::InvalidInput, "受控原始失败")),
            true,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("受控原始失败") && error.to_string().contains("目录回收")
        );
        assert!(root.join("ownership.json").exists());
    }
}
