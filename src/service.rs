//! 前台实例、降权控制进程与唯一活动出口。
use crate::{
    config::{AppConfig, Credentials},
    domain::*,
    logging::{self, EventKind, LogLevel, LogPolicy, SummaryClock},
    netd::{self, InstanceLock, protocol::*, system::*, workers::WorkerManager},
    probe,
    scheduler::{Backoff, Catalog, Scheduler},
    socks::{self, ActiveWorker},
    storage::Storage,
    vpngate,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{Semaphore, watch},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
struct Bootstrap {
    config: AppConfig,
    credentials: Option<Credentials>,
    instance_id: uuid::Uuid,
    listen_scope: logging::ListenScope,
}
pub async fn wait_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}};
    Ok(())
}
pub fn emit(
    config: &AppConfig,
    event_type: EventKind,
    state: ServiceState,
    node: Option<NodeId>,
    worker: Option<WorkerId>,
    reason: Option<&str>,
    elapsed: Duration,
) {
    if let Some(event) = logging::event(config, event_type, state, node, worker, reason, elapsed) {
        logging::write(config, event_type, &event);
    }
}

struct EmptyRuntimeGuard {
    path: std::path::PathBuf,
    created: bool,
    lock: Arc<InstanceLock>,
}
#[derive(Debug, thiserror::Error)]
#[error("实例资源清理失败：{0}")]
pub struct ShutdownFailure(pub String);
impl Drop for EmptyRuntimeGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let Ok(entries) = std::fs::read_dir(&self.path) else {
            return;
        };
        let entries: Vec<_> = entries.flatten().collect();
        let path = self.path.join("instance.lock");
        if entries.len() == 1 && entries[0].path() == path {
            let (Ok(actual), Ok(expected)) =
                (std::fs::symlink_metadata(&path), self.lock.file.metadata())
            else {
                return;
            };
            if actual.is_file() && actual.ino() == expected.ino() && actual.dev() == expected.dev()
            {
                let _ = std::fs::remove_file(path);
                if self.created {
                    let _ = std::fs::remove_dir(&self.path);
                }
            }
        }
    }
}
pub async fn run(config: AppConfig, credentials: Option<Credentials>) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "服务端仅支持 Linux");
    let created_runtime = !config.runtime_dir.exists();
    let lock = Arc::new(InstanceLock::acquire(&config.runtime_dir)?);
    let _empty_runtime = EmptyRuntimeGuard {
        path: config.runtime_dir.clone(),
        created: created_runtime,
        lock: lock.clone(),
    };
    if let Some(manifest) = lock.read_manifest()? {
        for worker in &manifest.workers {
            ensure!(
                worker.socket_path
                    == config
                        .runtime_dir
                        .join("workers")
                        .join(format!("{}.sock", worker.worker_id)),
                "遗留套接字归属不一致"
            );
            if let Ok(metadata) = std::fs::symlink_metadata(&worker.socket_path) {
                use std::os::unix::fs::FileTypeExt;
                ensure!(
                    metadata.file_type().is_socket(),
                    "遗留工作路径不是套接字，拒绝回收"
                );
            }
        }
        let private: std::path::PathBuf =
            format!("/run/vap-private-{}", manifest.instance_id.simple()).into();
        if private.exists() {
            ensure!(
                std::fs::read_to_string(private.join("owner"))? == manifest.instance_id.to_string(),
                "遗留私有目录归属不一致"
            );
        }
        reclaim_stale_processes(
            &manifest,
            Instant::now() + Duration::from_secs_f64(config.shutdown_timeout_seconds as f64 * 0.8),
        )
        .await?;
        for worker in &manifest.workers {
            cleanup(&NetworkAllocation::new(
                manifest.instance_id,
                worker.worker_id,
                0,
            ))
            .await?;
            if let Ok(metadata) = std::fs::symlink_metadata(&worker.socket_path) {
                use std::os::unix::fs::FileTypeExt;
                ensure!(
                    metadata.file_type().is_socket(),
                    "遗留工作路径不是套接字，拒绝删除"
                );
                std::fs::remove_file(&worker.socket_path)?;
            }
        }
        if private.exists() {
            std::fs::remove_dir_all(private)?;
        }
        if config.runtime_dir.join("workers").exists() {
            std::fs::remove_dir(config.runtime_dir.join("workers"))?;
        }
        for name in ["netd.sock", "control.sock"] {
            let path = config.runtime_dir.join(name);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
    }
    let uid = run_command("id", &["-u"]).await?;
    ensure!(uid == b"0\n", "启动实例需要管理员权限");
    preflight().await?;
    let port = tokio::net::TcpListener::bind(config.listen)
        .await
        .context("代理监听地址或端口不可用")?;
    drop(port);
    std::fs::create_dir_all(&config.data_dir)?;
    ensure!(
        std::fs::symlink_metadata(&config.data_dir)?.is_dir(),
        "数据路径不是普通目录"
    );
    std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::chown(&config.data_dir, Some(CONTROL_UID), Some(CONTROL_UID))?;
    std::os::unix::fs::chown(&config.runtime_dir, Some(0), Some(CONTROL_UID))?;
    let instance_id = uuid::Uuid::new_v4();
    let manager = Arc::new(WorkerManager::new(
        instance_id,
        &config.runtime_dir,
        config.candidate_concurrency + 1,
        Duration::from_secs(config.tunnel_timeout_seconds),
        Duration::from_secs(config.port_probe_timeout_seconds),
        config.allow_legacy_vpngate_crypto,
        lock.clone(),
    )?);
    let cancel = CancellationToken::new();
    let mut server = None;
    let mut controller = None;
    let result:Result<()>=async {
    manager.persist_state().await?;
    let listener = bind_private_socket(&config.runtime_dir.join("netd.sock"))?;
    std::os::unix::fs::chown(
        config.runtime_dir.join("netd.sock"),
        Some(0),
        Some(CONTROL_UID),
    )?;
    let control = std::os::unix::net::UnixListener::bind(config.runtime_dir.join("control.sock"))?;
    std::fs::set_permissions(
        config.runtime_dir.join("control.sock"),
        std::fs::Permissions::from_mode(0o660),
    )?;
    std::os::unix::fs::chown(
        config.runtime_dir.join("control.sock"),
        Some(0),
        Some(CONTROL_UID),
    )?;
    let executable = std::env::current_exe()?;
    server = Some(tokio::spawn(netd::server::serve(
        listener,
        manager.clone(),
        executable.clone(),
        config.max_connections,
        config.candidate_concurrency + 8,
        Duration::from_secs(config.tunnel_timeout_seconds),
        cancel.clone(),
    )));
    let (parent, child_bootstrap) = std::os::unix::net::UnixStream::pair()?;
    let mut command = restricted_command(None, false, &executable);
    command
        .arg("controller")
        .stdin(Stdio::from(OwnedFd::from(control)))
        .stdout(Stdio::from(OwnedFd::from(child_bootstrap)))
        .stderr(Stdio::inherit());
    controller = Some(SupervisedProcess::spawn(&mut command)?);
    manager.register_controller(controller.as_ref().context("控制进程缺失")?)?;
    drop(command);
    parent.set_nonblocking(true)?;
    let mut parent = UnixStream::from_std(parent)?;
    let payload = zeroize::Zeroizing::new(serde_json::to_vec(&Bootstrap {
        config: config.clone(),
        credentials,
        instance_id,
        listen_scope: config.listen_scope,
    })?);
    parent.write_all(&payload).await?;
    parent.shutdown().await?;
    drop(parent);
    let controller=controller.as_mut().context("控制进程缺失")?;
    tokio::select! {
        result=controller.wait()=>result.and_then(|status| {ensure!(status.success(),"控制进程异常退出，状态 {status}");Ok(())}),
        result=wait_signal()=>result,
    }
    }.await;
    let deadline =
        Instant::now() + Duration::from_secs_f64(config.shutdown_timeout_seconds as f64 * 0.8);
    cancel.cancel();
    let server_stopped: Result<()> = async {
        if let Some(server) = server {
            tokio::time::timeout_at(deadline, server)
                .await
                .context("辅助服务停止超时")???;
        }
        Ok(())
    }
    .await;
    let (stopped, cleanup) = tokio::join!(
        async {
            if let Some(controller) = &mut controller {
                controller.terminate(deadline).await
            } else {
                Ok(())
            }
        },
        async {
            tokio::time::timeout_at(deadline, manager.stop_all(deadline))
                .await
                .context("实例资源清理总时限耗尽")?
        }
    );
    let cleaned: Result<()> = async {
        stopped?;
        server_stopped?;
        cleanup?;
        for name in [
            "netd.sock",
            "control.sock",
            "resources.json",
            "instance.lock",
        ] {
            let path = config.runtime_dir.join(name);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        std::fs::remove_dir(&config.runtime_dir)?;
        Ok(())
    }
    .await;
    cleaned.map_err(|error| ShutdownFailure(error.to_string()))?;
    if result.is_ok() {
        emit(
            &config,
            EventKind::Stopped,
            ServiceState::Stopped,
            None,
            None,
            None,
            Duration::ZERO,
        );
    }
    logging::flush(deadline.saturating_duration_since(Instant::now())).await;
    result
}
pub(crate) fn revoke_active(active: &watch::Sender<Option<ActiveWorker>>) {
    if let Some(worker) = active.send_replace(None) {
        worker.cancel.cancel();
    }
}
pub async fn controller() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    ensure!(
        status.lines().any(|line| line.starts_with("Uid:\t10001\t"))
            && status.contains("CapEff:\t0000000000000000"),
        "控制进程身份或能力不符合要求"
    );
    let socket =
        std::os::unix::net::UnixStream::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    socket.set_nonblocking(true)?;
    let mut socket = UnixStream::from_std(socket)?;
    ensure!(socket.peer_cred()?.uid() == 0, "启动通道来源不符合要求");
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    tokio::time::timeout(
        Duration::from_secs(5),
        (&mut socket)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes),
    )
    .await
    .context("启动资料读取超时")??;
    ensure!(bytes.len() <= 4 * 1024 * 1024, "启动资料过大");
    let mut payload: Bootstrap = serde_json::from_slice(&bytes).context("启动资料无效")?;
    payload.config.listen_scope = payload.listen_scope;
    payload.config.validate()?;
    let control =
        std::os::unix::net::UnixListener::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    control.set_nonblocking(true)?;
    let control = tokio::net::UnixListener::from_std(control)?;
    let cancel = CancellationToken::new();
    let quota = Arc::new(Semaphore::new(payload.config.max_connections));
    let (active_tx, active_rx) = watch::channel(None::<ActiveWorker>);
    let stop = cancel.clone();
    let stopping_active = active_tx.clone();
    tokio::spawn(async move {
        let _ = wait_signal().await;
        revoke_active(&stopping_active);
        stop.cancel();
    });
    let listener =
        socks::bind_gateway(payload.config.listen.into(), payload.credentials.as_ref()).await?;
    if let Some(summary) =
        logging::StartupSummary::new(&payload.config, payload.instance_id, listener.local_addr()?)
    {
        logging::write(&payload.config, EventKind::StartupSummary, &summary);
    }
    let gateway = tokio::spawn(socks::serve_gateway(
        listener,
        active_rx,
        payload.credentials,
        quota.clone(),
        cancel.clone(),
    ));
    let client = NetdClient {
        socket_path: payload.config.runtime_dir.join("netd.sock"),
        instance_id: payload.instance_id,
    };
    let now = chrono::Utc::now();
    let (status_tx, status_rx) = watch::channel(crate::cli::StatusSnapshot {
        schema_version: 1,
        instance_id: payload.instance_id,
        state: ServiceState::Starting,
        ready: false,
        listen_address: payload.config.listen,
        timezone: payload.config.timezone,
        active_node: None,
        last_exit_check: None,
        source: source_summary(
            None,
            now,
            Duration::from_secs(payload.config.source_cache_ttl_seconds),
            None,
        ),
        candidates: candidate_summary(
            &Catalog::default(),
            &Scheduler::new(
                payload.config.candidate_batch_size,
                payload.config.candidate_concurrency,
            ),
            now,
            now,
        ),
        connections: crate::cli::Connections {
            current: 0,
            limit: payload.config.max_connections,
        },
        last_switch_reason: None,
        last_error: None,
    });
    let control_task = tokio::spawn(crate::cli::serve_control(
        control,
        status_rx,
        quota,
        payload.config.shutdown_timeout_seconds,
        active_tx.clone(),
        cancel.clone(),
    ));
    let result = control_loop(&payload.config, &client, &active_tx, &cancel, &status_tx).await;
    if let Some(active) = active_tx.send_replace(None) {
        active.cancel.cancel();
    }
    cancel.cancel();
    gateway.await.context("代理入口任务退出失败")??;
    control_task.await.context("管理入口任务退出失败")??;
    result
}
struct AttemptResult {
    node: VpnNode,
    worker: WorkerId,
    socket: Option<std::path::PathBuf>,
    checks: Vec<CheckResult>,
}

fn result_for(
    node: &VpnNode,
    layer: Layer,
    outcome: Outcome,
    start: Instant,
    started_at: chrono::DateTime<chrono::Utc>,
    reason: Option<String>,
) -> CheckResult {
    CheckResult {
        node_id: node.id.clone(),
        profile_digest: node.profile_digest.clone(),
        layer,
        outcome,
        started_at,
        finished_at: chrono::Utc::now(),
        elapsed_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        attempts: 1,
        status: None,
        expires_at: None,
        failure_reason: reason,
    }
}
async fn stop_worker(client: &NetdClient, id: WorkerId) -> Result<()> {
    let response = client
        .request(
            NetdRequest::StopWorker {
                instance_id: client.instance_id,
                worker_id: id,
            },
            Duration::from_secs(12),
        )
        .await?;
    ensure!(
        matches!(response, NetdResponse::Stopped),
        "工作资源清理未完成"
    );
    Ok(())
}
async fn attempt_node(
    config: AppConfig,
    client: NetdClient,
    node: VpnNode,
    id: WorkerId,
    role: WorkerRole,
    cancel: CancellationToken,
) -> Result<AttemptResult> {
    let mut final_checks = Vec::new();
    for retry in 0..=config.candidate_retries {
        if cancel.is_cancelled() {
            break;
        }
        node.validate()?;
        let started = Instant::now();
        let started_at = chrono::Utc::now();
        emit(
            &config,
            if role == WorkerRole::Pending {
                EventKind::PendingStarted
            } else {
                EventKind::CandidateStarted
            },
            ServiceState::Validating,
            Some(node.id.clone()),
            Some(id),
            None,
            Duration::ZERO,
        );
        let response = tokio::select! {
            _=cancel.cancelled()=>{stop_worker(&client,id).await?;break;},
            value=client.request(NetdRequest::StartWorker {instance_id:client.instance_id,worker_id:id,node_id:node.id.clone(),endpoint:node.endpoint.clone(),profile:node.profile.clone(),connect_timeout_ms:config.tunnel_timeout_seconds*1000,role},Duration::from_secs(config.tunnel_timeout_seconds+15))=>value?,
        };
        let mut checks = Vec::new();
        match response {
            NetdResponse::WorkerStarted {
                socks_socket,
                port_result,
                tunnel_result,
                ..
            } => {
                checks.extend([*port_result, *tunnel_result]);
                emit(
                    &config,
                    EventKind::TunnelConnected,
                    ServiceState::Validating,
                    Some(node.id.clone()),
                    Some(id),
                    None,
                    started.elapsed(),
                );
                let started = Instant::now();
                let started_at = chrono::Utc::now();
                let report = tokio::select! {
                    _=cancel.cancelled()=>{stop_worker(&client,id).await?;break;},
                    value=probe::check_exit(&socks_socket,&config.exit_check_urls,config.exit_check_max_attempts,Duration::from_secs(config.exit_check_timeout_seconds))=>value,
                };
                let mut check = result_for(
                    &node,
                    Layer::Exit,
                    if report.success {
                        Outcome::Succeeded
                    } else {
                        Outcome::Failed
                    },
                    started,
                    started_at,
                    report.failure.map(|f| {
                        match f {
                            probe::ProbeFailure::Timeout => "检测总时限耗尽",
                            probe::ProbeFailure::Tls => "检测证书校验失败",
                            probe::ProbeFailure::Response => "检测响应失败",
                            _ => "检测连接失败",
                        }
                        .into()
                    }),
                );
                check.attempts = report.attempts;
                check.status = report.status;
                if report.success {
                    check.expires_at =
                        check
                            .finished_at
                            .checked_add_signed(chrono::Duration::seconds(
                                i64::try_from(config.candidate_result_ttl_seconds)
                                    .context("候选有效期溢出")?,
                            ));
                }
                checks.push(check);
                if report.success && role == WorkerRole::Pending {
                    return Ok(AttemptResult {
                        node,
                        worker: id,
                        socket: Some(socks_socket),
                        checks,
                    });
                }
                stop_worker(&client, id).await?;
                final_checks = checks;
                if report.success {
                    break;
                }
            }
            NetdResponse::WorkerFailed { checks } => {
                final_checks = checks;
            }
            NetdResponse::Error { code, message } => {
                ensure!(
                    code != "system_failed" && code != "cleanup_failed",
                    "{message}"
                );
                // 辅助进程仅在真实端口探测失败时返回此分类；不从隧道失败推断端口成功。
                let layer = if code == "port_failed" {
                    Layer::Port
                } else {
                    Layer::Tunnel
                };
                checks.push(result_for(
                    &node,
                    layer,
                    Outcome::Failed,
                    started,
                    started_at,
                    Some(message),
                ));
                final_checks = checks;
            }
            _ => anyhow::bail!("辅助进程返回非预期的节点启动结果"),
        }
        if retry == config.candidate_retries {
            break;
        }
    }
    Ok(AttemptResult {
        node,
        worker: id,
        socket: None,
        checks: final_checks,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSummary {
    pub total: usize,
    pub available: usize,
    pub expired: usize,
    pub not_tested: usize,
    pub round_selected: usize,
    pub round_completed: usize,
    pub running: usize,
    pub next_scheduled_at: chrono::DateTime<chrono::Utc>,
}
pub fn candidate_summary(
    catalog: &Catalog,
    scheduler: &Scheduler,
    now: chrono::DateTime<chrono::Utc>,
    next: chrono::DateTime<chrono::Utc>,
) -> CandidateSummary {
    let mut summary = CandidateSummary {
        total: 0,
        available: 0,
        expired: 0,
        not_tested: 0,
        round_selected: scheduler.selected,
        round_completed: scheduler.completed,
        running: scheduler.running(),
        next_scheduled_at: next,
    };
    for node in catalog.nodes.values().filter(|n| n.present) {
        summary.total += 1;
        match catalog.checks.get(&(node.id.clone(), Layer::Exit)) {
            Some(check) if check.is_usable_for(node, now) => summary.available += 1,
            Some(check) if check.current_outcome(now) == Outcome::Expired => summary.expired += 1,
            None => summary.not_tested += 1,
            _ => {}
        }
    }
    summary
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveCheckSummary {
    pub node_id: NodeId,
    pub worker_id: WorkerId,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub success: bool,
    pub attempts: u32,
    pub elapsed_ms: u64,
    pub status: Option<u16>,
    pub failure: Option<String>,
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct ActivitySummary {
    pub ready: bool,
    pub last_check: Option<ActiveCheckSummary>,
    pub last_switch_reason: Option<String>,
}
fn probe_failure_reason(failure: Option<probe::ProbeFailure>) -> Option<String> {
    failure.map(|failure| {
        match failure {
            probe::ProbeFailure::Timeout => "出口检测总时限耗尽",
            probe::ProbeFailure::Tls => "出口检测证书校验失败",
            probe::ProbeFailure::Response => "出口检测响应失败",
            _ => "出口检测连接失败",
        }
        .into()
    })
}
async fn control_loop(
    config: &AppConfig,
    client: &NetdClient,
    active: &watch::Sender<Option<ActiveWorker>>,
    cancel: &CancellationToken,
    status: &watch::Sender<crate::cli::StatusSnapshot>,
) -> Result<()> {
    let storage = Storage::new(&config.data_dir)?;
    let mut catalog = Catalog::default();
    let mut fetched_at = None;
    let mut source_empty_error: Option<String> = None;
    match storage.load_source_with_policy(
        config.source_url.as_str(),
        Duration::from_secs(config.source_cache_ttl_seconds),
        chrono::Utc::now(),
        config.allow_legacy_vpngate_crypto,
    ) {
        Ok(snapshot) => {
            source_empty_error = config.source_empty_reason(&snapshot);
            fetched_at = Some(snapshot.fetched_at);
            catalog.merge(&config.selected_source(&snapshot), None);
            emit(
                config,
                EventKind::CacheLoaded,
                ServiceState::Fetching,
                None,
                None,
                None,
                Duration::ZERO,
            );
        }
        Err(_) => emit(
            config,
            EventKind::CacheIgnored,
            ServiceState::Fetching,
            None,
            None,
            Some("来源缓存不存在、无效或已过期"),
            Duration::ZERO,
        ),
    }
    // 历史摘要仅检查及报告，不注入 Catalog.checks 或可用排序。
    if storage.load_checks().is_err() {
        emit(
            config,
            EventKind::DiagnosticsIgnored,
            ServiceState::Fetching,
            None,
            None,
            Some("诊断缓存不存在或无效，不影响来源恢复"),
            Duration::ZERO,
        );
    }
    let mut scheduler = Scheduler::new(config.candidate_batch_size, config.candidate_concurrency);
    let mut attempts = tokio::task::JoinSet::new();
    let mut in_flight = std::collections::BTreeMap::<NodeId, (String, CancellationToken)>::new();
    let mut source_tasks =
        tokio::task::JoinSet::<Result<SourceSnapshot, vpngate::VpnGateError>>::new();
    let mut next_source = Instant::now();
    let mut next_round = Instant::now();
    let mut source_delay = Backoff::new(config.retry_initial_seconds, config.retry_max_seconds);
    let mut node_delay = Backoff::new(config.retry_initial_seconds, config.retry_max_seconds);
    let mut active_node: Option<VpnNode> = None;
    let mut activity = ActivitySummary::default();
    let mut structures = tokio::task::JoinSet::<(WorkerId, bool)>::new();
    let mut health =
        tokio::task::JoinSet::<(WorkerId, chrono::DateTime<chrono::Utc>, probe::ProbeReport)>::new(
        );
    let mut next_structure = Instant::now();
    let mut next_health = Instant::now();
    let mut recovering = false;
    let mut round_was_running = false;
    let mut summary_clock = SummaryClock::new(LogPolicy::from(config).summary_interval);
    let mut source_error: Option<String> = None;
    let mut last_error: Option<String> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let mut blocked: Option<(WorkerId, String)> = None;
        tokio::select! {
            biased;
            _=cancel.cancelled()=>{attempts.abort_all();source_tasks.abort_all();return Ok(());},
            Some(value)=structures.join_next(),if !structures.is_empty()=>{
                match value {
                    Ok((id,false)) if active.borrow().as_ref().is_some_and(|a|a.worker_id==id)=>{
                        blocked=Some((id,"结构性隧道故障".into()));
                        if let Some(node)=&active_node {
                            catalog.checks.remove(&(node.id.clone(),Layer::Exit));
                            catalog.record(result_for(node,Layer::Tunnel,Outcome::Failed,Instant::now(),chrono::Utc::now(),Some("活动隧道结构检查失败".into())));
                        }
                    },
                    Err(error) if !error.is_cancelled()=>return Err(error.into()),
                    _=>{},
                }
            },
            Some(value)=health.join_next(),if !health.is_empty()=>{
                match value {
                    Ok((id,started_at,report)) if active.borrow().as_ref().is_some_and(|a|a.worker_id==id)=>{
                        let node=active_node.as_ref().context("活动节点资料缺失")?;
                        let finished_at=chrono::Utc::now();
                        let reason=probe_failure_reason(report.failure);
                        activity.last_check=Some(ActiveCheckSummary {node_id:node.id.clone(),worker_id:id,finished_at,success:report.success,attempts:report.attempts,elapsed_ms:report.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,status:report.status,failure:reason.clone()});
                        catalog.record(CheckResult {node_id:node.id.clone(),profile_digest:node.profile_digest.clone(),layer:Layer::Exit,outcome:if report.success {Outcome::Succeeded}else{Outcome::Failed},started_at,finished_at,elapsed_ms:report.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,attempts:report.attempts,status:report.status,expires_at:if report.success {finished_at.checked_add_signed(chrono::Duration::seconds(i64::try_from(config.candidate_result_ttl_seconds)?))}else{None},failure_reason:reason.clone()});
                        let detail=serde_json::to_string(&activity.last_check)?;
                        emit(config,if report.success {EventKind::ActiveCheckSucceeded}else{EventKind::ActiveCheckFailed},ServiceState::Ready,Some(node.id.clone()),Some(id),Some(&detail),report.elapsed);
                        if !report.success {blocked=Some((id,reason.unwrap_or_else(||"出口检测全部失败".into())));}
                    },
                    Err(error) if !error.is_cancelled()=>return Err(error.into()),
                    _=>{},
                }
            },
            Some(value)=source_tasks.join_next(),if !source_tasks.is_empty()=>{
                match value.context("来源刷新任务退出失败")? {
                    Ok(snapshot)=>{
                        let selected = config.selected_source(&snapshot);
                        let previous_nodes: std::collections::BTreeMap<_, _> = catalog.nodes.iter().filter(|(_, node)| node.present).map(|(id, node)| (id.clone(), node.profile_digest.clone())).collect();
                        let incoming_nodes: std::collections::BTreeMap<_, _> = selected.nodes.iter().map(|node| (node.id.clone(), node.profile_digest.clone())).collect();
                        let source_changed = fetched_at.is_none() || source_error.is_some() || previous_nodes != incoming_nodes;
                        source_empty_error = config.source_empty_reason(&snapshot);
                        let source_reopens = source_adds_usable_nodes(&catalog, &config.selected_source(&snapshot),
                            !source_summary(fetched_at,chrono::Utc::now(),Duration::from_secs(config.source_cache_ttl_seconds),None).expired);
                        source_error=None;source_delay.reset();fetched_at=Some(snapshot.fetched_at);
                        let active_id=active.borrow().as_ref().map(|a|a.node_id.clone());
                        catalog.merge(&config.selected_source(&snapshot),active_id.as_ref());
                        for (id,(digest,token)) in &in_flight {
                            if !catalog.nodes.get(id).is_some_and(|n|n.present && &n.profile_digest==digest) {token.cancel();}
                        }
                        if storage.save_source_with_policy(&snapshot, config.allow_legacy_vpngate_crypto).is_err() {emit(config,EventKind::CacheWriteFailed,ServiceState::Fetching,None,None,Some("来源缓存写入失败"),Duration::ZERO);}
                        next_source=Instant::now()+Duration::from_secs(config.source_refresh_seconds);
                        if source_reopens && !scheduler.is_running() && active.borrow().is_none() && catalog.nodes.values().any(|node|node.present) {next_round=Instant::now();}
                        persist_checks(config, &storage,&catalog,active_id.as_ref());
                        if source_changed { emit(config,EventKind::SourceChanged,if active_id.is_some() {ServiceState::Ready} else {ServiceState::Fetching},None,None,source_empty_error.as_deref(),Duration::ZERO); }
                        emit(config,EventKind::SourceUpdated,if active_id.is_some() {ServiceState::Ready} else {ServiceState::Fetching},None,None,source_empty_error.as_deref(),Duration::ZERO);
                    }
                    Err(_)=>{
                        source_error=Some("来源获取或解析失败，保留原快照与时间".into());
                        next_source=Instant::now()+Duration::from_secs(source_delay.next_delay());
                        emit(config,EventKind::SourceFailed,if active.borrow().is_some(){ServiceState::Ready}else{ServiceState::Waiting},None,None,source_error.as_deref(),Duration::ZERO);
                    }
                }
            },
            Some(value)=attempts.join_next(),if !attempts.is_empty()=>{
                let result:AttemptResult=value.context("节点验证任务退出失败")??;
                let cancelled=in_flight.remove(&result.node.id).is_none_or(|(_,token)|token.is_cancelled());scheduler.finish(&result.node.id);
                let current=!cancelled && !source_summary(fetched_at,chrono::Utc::now(),Duration::from_secs(config.source_cache_ttl_seconds),None).expired && catalog.nodes.get(&result.node.id).is_some_and(|n|n.present && n.profile_digest==result.node.profile_digest);
                let last_exit=result.checks.iter().find(|check|check.layer==Layer::Exit).cloned();
                if current {for check in result.checks {if check.outcome==Outcome::Failed {last_error=check.failure_reason.clone();}catalog.record(check);}}
                if let Some(socket)=result.socket {
                    if current && active.borrow().is_none() {
                        ensure!(matches!(client.request(NetdRequest::PromoteWorker {instance_id:client.instance_id,worker_id:result.worker},Duration::from_secs(5)).await?,NetdResponse::Pong),"活动出口提升失败");
                        active.send_replace(Some(ActiveWorker {socket_path:socket,node_id:result.node.id.clone(),worker_id:result.worker,cancel:cancel.child_token()}));
                        active_node=Some(result.node.clone());activity.ready=true;
                        last_error=None;
                        if let Some(check)=last_exit {activity.last_check=Some(ActiveCheckSummary {node_id:check.node_id,worker_id:result.worker,finished_at:check.finished_at,success:check.outcome==Outcome::Succeeded,attempts:check.attempts,elapsed_ms:check.elapsed_ms,status:check.status,failure:check.failure_reason});}
                        recovering=false;node_delay.reset();
                        next_structure=Instant::now()+Duration::from_secs(1);
                        next_health=Instant::now()+Duration::from_secs(config.health_interval_seconds);
                        emit(config,EventKind::ActivePromoted,ServiceState::Ready,Some(result.node.id.clone()),Some(result.worker),None,Duration::ZERO);
                    } else {stop_worker(client,result.worker).await?;}
                }
                let active_id=active.borrow().as_ref().map(|a|a.node_id.clone());
                persist_checks(config, &storage,&catalog,active_id.as_ref());
                emit(config,EventKind::CandidateResult,if active_id.is_some(){ServiceState::Ready}else{ServiceState::Validating},Some(result.node.id),Some(result.worker),None,Duration::ZERO);
            },
            _=interval.tick()=>{},
        }
        if let Some((id, reason)) = blocked {
            let old = active.send_replace(None).context("活动引用缺失")?;
            ensure!(old.worker_id == id, "活动故障结果归属不一致");
            old.cancel.cancel();
            activity.ready = false;
            activity.last_switch_reason = Some(reason.clone());
            last_error = Some(reason.clone());
            emit(
                config,
                EventKind::ActiveBlocked,
                ServiceState::Switching,
                Some(old.node_id),
                Some(id),
                Some(&reason),
                Duration::ZERO,
            );
            for (_, token) in in_flight.values() {
                token.cancel();
            }
            scheduler.cancel_queued();
            round_was_running = false;
            recovering = true;
            structures.shutdown().await;
            health.shutdown().await;
            stop_worker(client, id).await?;
            active_node = None;
            next_round = Instant::now();
            persist_checks(config, &storage, &catalog, None);
        }
        let now = Instant::now();
        let wall = chrono::Utc::now();
        let fresh = fetched_at
            .and_then(|at| wall.signed_duration_since(at).to_std().ok())
            .is_some_and(|age| age < Duration::from_secs(config.source_cache_ttl_seconds));
        if now >= next_source && source_tasks.is_empty() {
            emit(
                config,
                EventKind::SourceFetch,
                if active.borrow().is_some() {
                    ServiceState::Ready
                } else {
                    ServiceState::Fetching
                },
                None,
                None,
                None,
                Duration::ZERO,
            );
            let url = config.source_url.clone();
            let timeout = Duration::from_secs(config.source_timeout_seconds);
            let allow_legacy_vpngate_crypto = config.allow_legacy_vpngate_crypto;
            source_tasks.spawn(async move {
                vpngate::fetch_snapshot_with_policy(
                    &url,
                    timeout,
                    vpngate::CsvLimits::default(),
                    allow_legacy_vpngate_crypto,
                )
                .await
            });
        }
        if round_was_running && !scheduler.is_running() {
            round_was_running = false;
            let ready = active.borrow().is_some();
            next_round = now
                + Duration::from_secs(if ready {
                    config.candidate_interval_seconds
                } else {
                    node_delay.next_delay()
                });
            emit(
                config,
                EventKind::RoundFinished,
                if ready {
                    ServiceState::Ready
                } else {
                    ServiceState::Waiting
                },
                None,
                None,
                source_error.as_deref(),
                Duration::ZERO,
            );
        }
        if now >= next_round && !scheduler.is_running() && fresh {
            let active_id = active.borrow().as_ref().map(|a| a.node_id.clone());
            if recovering {
                scheduler.begin_recovery(&catalog, wall);
            } else {
                scheduler.begin(&catalog, active_id.as_ref());
            }
            round_was_running = scheduler.is_running();
            emit(
                config,
                EventKind::RoundStarted,
                if active_id.is_some() {
                    ServiceState::Ready
                } else {
                    ServiceState::Validating
                },
                None,
                None,
                None,
                Duration::ZERO,
            );
            if !round_was_running {
                next_round = now
                    + Duration::from_secs(if active_id.is_some() {
                        config.candidate_interval_seconds
                    } else {
                        node_delay.next_delay()
                    });
            }
        }
        // 成功的空来源按无可用节点退避恢复；来源失败仍使用独立的失败退避。
        if fresh
            && source_error.is_none()
            && active.borrow().is_none()
            && !scheduler.is_running()
            && !catalog.nodes.values().any(|node| node.present)
        {
            next_source = next_source.min(next_round);
        }
        if config.log_level == LogLevel::Debug && summary_clock.due(now) {
            emit_summary(
                config,
                &catalog,
                &scheduler,
                fetched_at,
                source_error.as_deref(),
                next_round,
                &activity,
            );
        }
        let current_active = active.borrow().clone();
        if let Some(current) = current_active {
            if now >= next_structure && structures.is_empty() {
                next_structure = now + Duration::from_secs(1);
                let client = client.clone();
                let id = current.worker_id;
                structures.spawn(async move {
                    let ready = matches!(
                        client
                            .request(
                                NetdRequest::WorkerStatus {
                                    instance_id: client.instance_id,
                                    worker_id: id
                                },
                                Duration::from_millis(950)
                            )
                            .await,
                        Ok(NetdResponse::WorkerStatus { ready: true })
                    );
                    (id, ready)
                });
            }
            if now >= next_health && health.is_empty() {
                next_health = now + Duration::from_secs(config.health_interval_seconds);
                let urls = config.exit_check_urls.clone();
                let attempts = config.exit_check_max_attempts;
                let budget = Duration::from_secs(config.health_timeout_seconds);
                health.spawn(async move {
                    let started_at = chrono::Utc::now();
                    let report =
                        probe::check_exit(&current.socket_path, &urls, attempts, budget).await;
                    (current.worker_id, started_at, report)
                });
            }
        }
        let now_wall = chrono::Utc::now();
        let next_at =
            chrono::Duration::from_std(next_round.saturating_duration_since(Instant::now()))
                .ok()
                .and_then(|wait| now_wall.checked_add_signed(wait))
                .unwrap_or(now_wall);
        status.send_replace(crate::cli::StatusSnapshot {
            schema_version: 1,
            instance_id: client.instance_id,
            state: if activity.ready {
                ServiceState::Ready
            } else if scheduler.is_running() {
                if recovering {
                    ServiceState::Switching
                } else {
                    ServiceState::Validating
                }
            } else {
                ServiceState::Waiting
            },
            ready: activity.ready,
            listen_address: config.listen,
            timezone: config.timezone,
            active_node: active_node.as_ref().map(|node| crate::cli::ActiveNode {
                id: node.id.clone(),
                endpoint: node.endpoint.clone(),
            }),
            last_exit_check: activity.last_check.clone(),
            source: source_summary(
                fetched_at,
                now_wall,
                Duration::from_secs(config.source_cache_ttl_seconds),
                source_error.as_deref(),
            ),
            candidates: candidate_summary(&catalog, &scheduler, now_wall, next_at),
            connections: crate::cli::Connections {
                current: 0,
                limit: config.max_connections,
            },
            last_switch_reason: activity.last_switch_reason.clone(),
            last_error: last_error
                .clone()
                .or_else(|| source_error.clone())
                .or_else(|| source_empty_error.clone())
                .or_else(|| (!activity.ready).then(|| "当前无已验证出口，等待节点".into())),
        });
        if fresh {
            while let Some(node) = scheduler.next(&mut catalog, wall) {
                catalog.start_attempt(&node, wall);
                let id = WorkerId::default();
                let token = cancel.child_token();
                in_flight.insert(
                    node.id.clone(),
                    (node.profile_digest.clone(), token.clone()),
                );
                let role = if active.borrow().is_some() {
                    WorkerRole::Candidate
                } else {
                    WorkerRole::Pending
                };
                attempts.spawn(attempt_node(
                    config.clone(),
                    client.clone(),
                    node,
                    id,
                    role,
                    token,
                ));
            }
        } else {
            // 缓存到期不关闭健康活动，但不得继续启动过期来源的节点。
            for (_, token) in in_flight.values() {
                token.cancel();
            }
        }
    }
}
fn persist_checks(
    config: &AppConfig,
    storage: &Storage,
    catalog: &Catalog,
    active: Option<&NodeId>,
) {
    let checks: Vec<_> = catalog.checks.values().cloned().collect();
    let present: Vec<_> = catalog
        .nodes
        .values()
        .filter(|n| n.present)
        .map(|n| n.id.clone())
        .collect();
    if storage.save_checks(&checks, &present, active).is_err() {
        emit(
            config,
            EventKind::DiagnosticsWriteFailed,
            ServiceState::Validating,
            None,
            None,
            Some("诊断写入失败，不改变当前可用性"),
            Duration::ZERO,
        );
    }
}

/// 相同有效来源的成功刷新不得绕过无可用节点退避；新增、变更或恢复有效来源可唤醒。
pub fn source_adds_usable_nodes(
    catalog: &Catalog,
    source: &SourceSnapshot,
    previous_fresh: bool,
) -> bool {
    source.nodes.iter().any(|node| {
        node.present
            && (!previous_fresh
                || !catalog
                    .nodes
                    .get(&node.id)
                    .is_some_and(|old| old.present && old.profile_digest == node.profile_digest))
    })
}

pub fn empty_source_reason(source: &SourceSnapshot) -> Option<String> {
    if !source.nodes.is_empty() {
        return None;
    }
    if source.stats.rows_seen == 0 {
        return Some("来源已获取，但节点列表为空".into());
    }
    Some(format!(
        "来源已获取，但 {} 条节点记录均未通过配置校验（其中 {} 条配置不受支持）",
        source.stats.rows_seen, source.stats.unsupported
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSummary {
    pub fetched_at: Option<chrono::DateTime<chrono::Utc>>,
    pub age_seconds: Option<u64>,
    pub expired: bool,
    pub last_error: Option<String>,
}
pub fn source_summary(
    fetched_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    ttl: Duration,
    error: Option<&str>,
) -> SourceSummary {
    let age = fetched_at.and_then(|at| now.signed_duration_since(at).to_std().ok());
    SourceSummary {
        fetched_at,
        age_seconds: age.map(|v| v.as_secs()),
        expired: age.is_none_or(|v| v >= ttl),
        last_error: error.map(str::to_owned),
    }
}
fn emit_summary(
    config: &AppConfig,
    catalog: &Catalog,
    scheduler: &Scheduler,
    fetched: Option<chrono::DateTime<chrono::Utc>>,
    error: Option<&str>,
    next: Instant,
    activity: &ActivitySummary,
) {
    #[derive(Serialize)]
    struct Summary<'a> {
        #[serde(flatten)]
        event: Event,
        source: SourceSummary,
        candidates: CandidateSummary,
        ready: bool,
        activity: &'a ActivitySummary,
    }
    let now = chrono::Utc::now();
    let until = chrono::Duration::from_std(next.saturating_duration_since(Instant::now())).ok();
    let next = until.and_then(|v| now.checked_add_signed(v)).unwrap_or(now);
    if !LogPolicy::from(config).allows(LogLevel::Debug) {
        return;
    }
    let event = Event {
        level: LogLevel::Debug,
        timestamp: now.with_timezone(&config.timezone).fixed_offset(),
        event_type: "runtime_summary".into(),
        node_id: None,
        worker_id: None,
        state: if activity.ready {
            ServiceState::Ready
        } else if scheduler.is_running() {
            ServiceState::Validating
        } else {
            ServiceState::Waiting
        },
        reason: None,
        elapsed_ms: 0,
    };
    let summary = Summary {
        event,
        source: source_summary(
            fetched,
            now,
            Duration::from_secs(config.source_cache_ttl_seconds),
            error,
        ),
        candidates: candidate_summary(catalog, scheduler, now, next),
        ready: activity.ready,
        activity,
    };
    logging::write(config, EventKind::RuntimeSummary, &summary);
}
