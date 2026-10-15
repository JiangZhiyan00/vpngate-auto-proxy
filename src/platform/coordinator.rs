//! 低权限来源与候选协调；实际子进程启动、身份交付及公共入口由外层生命周期负责。
use super::{
    control::{MacControlClient, MacControlCommand as Command, MacControlResponse as Response},
    exit_probe::ExitProbeSettings,
    health::MacHealthSettings,
    supervisor::WorkerCredentials,
};
use crate::{
    cli::{ActiveNode, Connections, StatusSnapshot},
    config::AppConfig,
    domain::*,
    scheduler::{Backoff, Catalog, Scheduler},
    service::{self, ActiveCheckSummary},
    socks::ActiveWorker,
    storage::Storage,
    vpngate,
};
use std::{collections::BTreeMap, future::Future, io, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
const CONTROL_BUDGET: Duration = Duration::from_secs(5);
const RETIRE_BUDGET: Duration = Duration::from_secs(15);

pub struct CoordinatorRequest {
    pub config: AppConfig,
    pub identity: WorkerCredentials,
    pub instance_id: Uuid,
    pub active: watch::Sender<Option<ActiveWorker>>,
    pub status: watch::Sender<StatusSnapshot>,
    pub quota: Arc<Semaphore>,
}
trait Rpc: Clone + Send + Sync + 'static {
    fn request(
        &self,
        command: Command,
        budget: Duration,
    ) -> impl Future<Output = io::Result<Response>> + Send;
    fn close(&self);
    fn cancellation(&self) -> CancellationToken;
}
impl Rpc for MacControlClient {
    async fn request(&self, command: Command, budget: Duration) -> io::Result<Response> {
        self.request(command, budget).await
    }
    fn close(&self) {
        self.close()
    }
    fn cancellation(&self) -> CancellationToken {
        self.cancellation()
    }
}
trait Source: Clone + Send + Sync + 'static {
    fn fetch(
        &self,
        url: url::Url,
        budget: Duration,
    ) -> impl Future<Output = Result<SourceSnapshot, String>> + Send;
}
#[derive(Clone)]
struct DirectSource;
impl Source for DirectSource {
    async fn fetch(&self, url: url::Url, budget: Duration) -> Result<SourceSnapshot, String> {
        vpngate::fetch_snapshot(&url, budget, vpngate::CsvLimits::default())
            .await
            .map_err(|_| "来源请求或解析失败，保留旧快照与时间".into())
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(super) fn validate(request: &CoordinatorRequest) -> io::Result<()> {
    use nix::unistd::{getegid, geteuid, getgid, getuid};
    request.identity.validate_account()?;
    if getuid().as_raw() != request.identity.uid
        || geteuid().as_raw() != request.identity.uid
        || getgid().as_raw() != request.identity.gid
        || getegid().as_raw() != request.identity.gid
        || rustix::process::getgroups()?
            .iter()
            .any(|group| group.as_raw() != request.identity.gid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "来源协调必须在指定且无额外组权限的低权限身份运行",
        ));
    }
    validate_config(&request.config)?;
    if request.instance_id.is_nil() || request.active.borrow().is_some() {
        return Err(invalid("协调实例身份无效或已有活动引用"));
    }
    Ok(())
}
pub(super) fn validate_config(config: &AppConfig) -> io::Result<()> {
    config
        .validate()
        .map_err(|error| invalid(&error.to_string()))?;
    if !config.data_dir.is_absolute()
        || !config.runtime_dir.is_absolute()
        || config.candidate_concurrency > 32
        || config.candidate_retries > 32
        || config.tunnel_timeout_seconds > 120
    {
        return Err(invalid("苹果协调配置超过平台上限"));
    }
    let exit = ExitProbeSettings {
        urls: config.exit_check_urls.clone(),
        max_attempts: config.exit_check_max_attempts,
        budget: Duration::from_secs(config.exit_check_timeout_seconds),
    };
    exit.validate()?;
    MacHealthSettings {
        interval: Duration::from_secs(config.health_interval_seconds),
        exit: ExitProbeSettings {
            budget: Duration::from_secs(config.health_timeout_seconds),
            ..exit
        },
    }
    .validate()
}
fn revoke(active: &watch::Sender<Option<ActiveWorker>>) {
    if let Some(old) = active.send_replace(None) {
        old.cancel.cancel();
    }
}
struct Guard<C: Rpc> {
    client: C,
    active: watch::Sender<Option<ActiveWorker>>,
    status: watch::Sender<StatusSnapshot>,
    stop: CancellationToken,
}
impl<C: Rpc> Drop for Guard<C> {
    fn drop(&mut self) {
        revoke(&self.active);
        self.status.send_modify(|status| {
            status.ready = false;
            status.active_node = None;
            status.state = ServiceState::Stopping;
        });
        self.stop.cancel();
        self.client.close();
    }
}
/// 调用前须由启动方交付私有控制通道。本入口不派生进程或绑定公开监听。
/// 外层等待取消会立即撤销本地引用并关闭控制通道，原任务仍等待本地操作结束。
pub async fn coordinate(
    request: CoordinatorRequest,
    client: MacControlClient,
    parent_stop: CancellationToken,
) -> io::Result<()> {
    validate(&request)?;
    let stop = parent_stop.child_token();
    let _guard = Guard {
        client: client.clone(),
        active: request.active.clone(),
        status: request.status.clone(),
        stop: stop.clone(),
    };
    tokio::spawn(run(request, client, DirectSource, stop))
        .await
        .map_err(|_| io::Error::other("来源协调任务异常，活动引用已撤销"))?
}
fn check(
    node: &VpnNode,
    layer: Layer,
    outcome: Outcome,
    started_at: chrono::DateTime<chrono::Utc>,
    elapsed: Duration,
    reason: Option<String>,
) -> CheckResult {
    CheckResult {
        node_id: node.id.clone(),
        profile_digest: node.profile_digest.clone(),
        layer,
        outcome,
        started_at,
        finished_at: chrono::Utc::now(),
        elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        attempts: 1,
        status: None,
        expires_at: None,
        failure_reason: reason,
    }
}
struct Attempt {
    node: VpnNode,
    worker: Option<WorkerId>,
    checks: Vec<CheckResult>,
}
async fn retire<C: Rpc>(client: &C, gate: &Mutex<()>, worker: WorkerId) -> io::Result<()> {
    let _gate = gate.lock().await;
    match client
        .request(Command::Retire { worker }, RETIRE_BUDGET)
        .await?
    {
        Response::Retired { worker: actual, .. } if actual == worker => Ok(()),
        _ => Err(io::Error::other("所属代际退休未确认")),
    }
}
async fn attempt<C: Rpc>(
    config: AppConfig,
    client: C,
    node: VpnNode,
    pending: bool,
    gate: Arc<Mutex<()>>,
    stop: CancellationToken,
) -> io::Result<Attempt> {
    let mut final_checks = Vec::new();
    for _ in 0..=config.candidate_retries {
        if stop.is_cancelled() {
            break;
        }
        node.validate().map_err(|_| invalid("所选节点材料无效"))?;
        let start = Instant::now();
        let at = chrono::Utc::now();
        let port = match node.endpoint.transport {
            Transport::Udp => Outcome::NotApplicable,
            Transport::Tcp => {
                let connected = tokio::select! {
                    biased;
                    _=stop.cancelled()=>break,
                    result=tokio::time::timeout(Duration::from_secs(config.port_probe_timeout_seconds),TcpStream::connect(node.endpoint.socket()))=>matches!(result,Ok(Ok(_))),
                };
                if connected {
                    Outcome::Succeeded
                } else {
                    Outcome::Failed
                }
            }
        };
        final_checks = vec![check(
            &node,
            Layer::Port,
            port,
            at,
            start.elapsed(),
            (port == Outcome::Failed).then(|| "端口探测失败".into()),
        )];
        if port == Outcome::Failed {
            continue;
        }
        let locked = tokio::select! {biased;_=stop.cancelled()=>break,value=gate.lock()=>value};
        if stop.is_cancelled() {
            break;
        }
        let start = Instant::now();
        let at = chrono::Utc::now();
        let worker = match client
            .request(
                Command::Start {
                    node: Box::new(node.clone()),
                },
                CONTROL_BUDGET,
            )
            .await?
        {
            Response::Started { worker } => worker,
            Response::Error { .. } => {
                final_checks.push(check(
                    &node,
                    Layer::Tunnel,
                    Outcome::Failed,
                    at,
                    start.elapsed(),
                    Some("隧道启动请求被拒绝".into()),
                ));
                continue;
            }
            _ => return Err(io::Error::other("隧道启动响应类型不符")),
        };
        let ready = client
            .request(
                Command::Ready { worker },
                Duration::from_secs(config.tunnel_timeout_seconds + 15),
            )
            .await?;
        if !matches!(ready,Response::Ready {worker:actual,..} if actual==worker) {
            // 仍持配置锁；释放失败槽位后才能允许下一次配置。
            match client
                .request(Command::Retire { worker }, RETIRE_BUDGET)
                .await?
            {
                Response::Retired { .. } => {}
                _ => return Err(io::Error::other("启动失败后所属回收未确认")),
            }
            final_checks.push(check(
                &node,
                Layer::Tunnel,
                Outcome::Failed,
                at,
                start.elapsed(),
                Some("隧道就绪失败".into()),
            ));
            continue;
        }
        drop(locked);
        final_checks.push(check(
            &node,
            Layer::Tunnel,
            Outcome::Succeeded,
            at,
            start.elapsed(),
            None,
        ));
        if stop.is_cancelled() {
            retire(&client, &gate, worker).await?;
            break;
        }
        let start = Instant::now();
        let at = chrono::Utc::now();
        if !matches!(client.request(Command::BeginVerify {worker},CONTROL_BUDGET).await?,Response::CheckStarted {worker:actual} if actual==worker)
        {
            retire(&client, &gate, worker).await?;
            final_checks.push(check(
                &node,
                Layer::Exit,
                Outcome::Failed,
                at,
                start.elapsed(),
                Some("出口检测请求被拒绝".into()),
            ));
            continue;
        }
        let report = loop {
            if stop.is_cancelled() {
                retire(&client, &gate, worker).await?;
                return Ok(Attempt {
                    node,
                    worker: None,
                    checks: final_checks,
                });
            }
            match client
                .request(Command::VerifyResult { worker }, CONTROL_BUDGET)
                .await?
            {
                Response::Checking { worker: actual } if actual == worker => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Response::Verified {
                    worker: actual,
                    report,
                    finished_at,
                } if actual == worker => break Some((report, finished_at)),
                Response::Error { .. } => break None,
                _ => return Err(io::Error::other("出口检测结果归属或类型不符")),
            }
        };
        let success = report.as_ref().is_some_and(|(report, _)| report.success);
        let mut result = check(
            &node,
            Layer::Exit,
            if success {
                Outcome::Succeeded
            } else {
                Outcome::Failed
            },
            at,
            start.elapsed(),
            (!success).then(|| "出口检测或检测监督失败".into()),
        );
        if let Some((report, finished_at)) = report {
            if finished_at < at || finished_at > chrono::Utc::now() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "出口检测完成时间无效",
                ));
            }
            result.finished_at = finished_at;
            result.attempts = report.attempts;
            result.status = report.status;
            result.elapsed_ms = report.elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        }
        if success {
            result.expires_at = result
                .finished_at
                .checked_add_signed(chrono::Duration::seconds(
                    config.candidate_result_ttl_seconds as i64,
                ));
        }
        final_checks.push(result);
        if success && pending && !stop.is_cancelled() {
            return Ok(Attempt {
                node,
                worker: Some(worker),
                checks: final_checks,
            });
        }
        retire(&client, &gate, worker).await?;
        if success {
            break;
        }
    }
    Ok(Attempt {
        node,
        worker: None,
        checks: final_checks,
    })
}
struct Active {
    node: VpnNode,
    worker: WorkerId,
    generation: Uuid,
    health_sequence: u64,
}
fn persist(config: &AppConfig, storage: &Storage, catalog: &Catalog, active: Option<&NodeId>) {
    let checks = catalog.checks.values().cloned().collect::<Vec<_>>();
    let present = catalog
        .nodes
        .values()
        .filter(|node| node.present)
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    if storage.save_checks(&checks, &present, active).is_err() {
        service::emit(
            config,
            "diagnostics_write_failed",
            ServiceState::Validating,
            None,
            None,
            Some("诊断写入失败，不改变可用性"),
            Duration::ZERO,
        );
    }
}
async fn run<C: Rpc, S: Source>(
    request: CoordinatorRequest,
    client: C,
    source: S,
    stop: CancellationToken,
) -> io::Result<()> {
    let mut attempts = JoinSet::new();
    let mut sources = JoinSet::new();
    let mut statuses = JoinSet::new();
    let result = drive(
        &request,
        &client,
        source,
        &stop,
        &mut attempts,
        &mut sources,
        &mut statuses,
    )
    .await;
    revoke(&request.active);
    request.status.send_modify(|status| {
        status.ready = false;
        status.active_node = None;
        status.state = ServiceState::Stopping;
        if let Err(error) = &result {
            status.last_error = Some(error.to_string());
        }
    });
    stop.cancel();
    client.close();
    sources.shutdown().await;
    // 关闭控制连接取消在途请求；不直接中止仍执行清理逻辑的候选任务。
    while attempts.join_next().await.is_some() {}
    while statuses.join_next().await.is_some() {}
    result
}
#[allow(clippy::too_many_arguments)]
async fn drive<C: Rpc, S: Source>(
    request: &CoordinatorRequest,
    client: &C,
    source: S,
    stop: &CancellationToken,
    attempts: &mut JoinSet<io::Result<Attempt>>,
    sources: &mut JoinSet<Result<SourceSnapshot, String>>,
    statuses: &mut JoinSet<(Option<WorkerId>, io::Result<Response>)>,
) -> io::Result<()> {
    let config = &request.config;
    let storage =
        Storage::new(&config.data_dir).map_err(|_| io::Error::other("来源缓存目录不可用"))?;
    let mut catalog = Catalog::default();
    let mut fetched = None;
    let mut source_empty_error = None;
    if let Ok(snapshot) = storage.load_source(
        config.source_url.as_str(),
        Duration::from_secs(config.source_cache_ttl_seconds),
        chrono::Utc::now(),
    ) {
        source_empty_error = config.source_empty_reason(&snapshot);
        fetched = Some(snapshot.fetched_at);
        catalog.merge(&config.selected_source(&snapshot), None);
    }
    // 历史诊断仅供观察，不恢复可用性；唯一写入者仍是此协调任务。
    let _ = storage.load_checks();
    let mut scheduler = Scheduler::new(config.candidate_batch_size, config.candidate_concurrency);
    let mut in_flight = BTreeMap::<NodeId, (String, CancellationToken)>::new();
    let gate = Arc::new(Mutex::new(()));
    let mut active: Option<Active> = None;
    let mut last_check = None;
    let mut last_switch = None;
    let mut last_error = None;
    let mut source_error = None;
    let mut source_delay = Backoff::new(config.retry_initial_seconds, config.retry_max_seconds);
    let mut node_delay = Backoff::new(config.retry_initial_seconds, config.retry_max_seconds);
    let mut next_source = Instant::now();
    let mut next_round = Instant::now();
    let mut next_status = Instant::now();
    let mut round_running = false;
    let mut urgent = false;
    let closed = client.cancellation();
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>return Ok(()),
            _=closed.cancelled()=>return Err(io::Error::new(io::ErrorKind::BrokenPipe,"特权控制连接已撤销")),
            Some(result)=sources.join_next(),if !sources.is_empty()=>match result.map_err(|_|io::Error::other("来源任务异常"))? {
                Ok(snapshot)=>{
                    source_empty_error = config.source_empty_reason(&snapshot);
                    let reopen=service::source_adds_usable_nodes(&catalog,&config.selected_source(&snapshot),!service::source_summary(fetched,chrono::Utc::now(),Duration::from_secs(config.source_cache_ttl_seconds),None).expired);
                    fetched=Some(snapshot.fetched_at);source_error=None;source_delay.reset();
                    catalog.merge(&config.selected_source(&snapshot),active.as_ref().map(|value|&value.node.id));
                    for (id,(digest,token)) in &in_flight {if !catalog.nodes.get(id).is_some_and(|node|node.present && node.profile_digest==*digest){token.cancel();}}
                    let _=storage.save_source(&snapshot);
                    next_source=Instant::now()+Duration::from_secs(config.source_refresh_seconds);
                    if reopen && active.is_none() && !scheduler.is_running(){next_round=Instant::now();}
                    persist(config, &storage,&catalog,active.as_ref().map(|value|&value.node.id));
                },
                Err(error)=>{source_error=Some(error);next_source=Instant::now()+Duration::from_secs(source_delay.next_delay());},
            },
            Some(result)=attempts.join_next(),if !attempts.is_empty()=>{
                let result=result.map_err(|_|io::Error::other("候选协调任务异常"))??;
                let current=in_flight.remove(&result.node.id).is_some_and(|(_,token)|!token.is_cancelled())
                    && !service::source_summary(fetched,chrono::Utc::now(),Duration::from_secs(config.source_cache_ttl_seconds),None).expired
                    && catalog.nodes.get(&result.node.id).is_some_and(|node|node.present && node.profile_digest==result.node.profile_digest);
                scheduler.finish(&result.node.id);
                let latest=result.checks.iter().find(|check|check.layer==Layer::Exit).cloned();
                if current {for check in result.checks {if check.outcome==Outcome::Failed {last_error=check.failure_reason.clone();}catalog.record(check);}}
                if let Some(worker)=result.worker {
                    if current && active.is_none() {
                        let node=catalog.nodes.get(&result.node.id).ok_or_else(||invalid("待提升来源节点缺失"))?.clone();
                        match client.request(Command::Promote {worker,node:Box::new(node.clone())},CONTROL_BUDGET).await? {
                            Response::Promoted {worker:actual,node_id,generation,socket} if actual==worker && node_id==node.id=>{
                                request.active.send_replace(Some(ActiveWorker {socket_path:socket,node_id:node.id.clone(),worker_id:worker,cancel:client.cancellation().child_token()}));
                                active=Some(Active {node,worker,generation,health_sequence:0});scheduler.continue_with_active();node_delay.reset();urgent=false;last_error=None;next_status=Instant::now();
                                if let Some(check)=latest {last_check=Some(ActiveCheckSummary {node_id:check.node_id,worker_id:worker,finished_at:check.finished_at,success:true,attempts:check.attempts,elapsed_ms:check.elapsed_ms,status:check.status,failure:None});}
                            },
                            Response::Error {..}=>{retire(client,&gate,worker).await?;last_error=Some("活动提升失败，所属代际已退休".into());},
                            _=>return Err(io::Error::other("活动提升响应归属或类型不符")),
                        }
                    } else {retire(client,&gate,worker).await?;}
                }
                persist(config, &storage,&catalog,active.as_ref().map(|value|&value.node.id));
            },
            Some(result)=statuses.join_next(),if !statuses.is_empty()=>{
                let (worker,response)=result.map_err(|_|io::Error::other("活动状态任务异常"))?;
                let Some(worker)=worker else {
                    if !matches!(response?,Response::Pong) {return Err(io::Error::other("空闲控制存活响应无效"));}
                    continue;
                };
                if let Some(current)=active.as_mut().filter(|value|value.worker==worker) {
                    let Response::Status {worker:actual,live,active:is_active,health}=response? else{return Err(io::Error::other("活动状态响应类型不符"));};
                    if actual!=worker {return Err(io::Error::other("活动状态工作归属不符"));}
                    let structural=!live || !is_active;
                    let mut failed=structural;
                    if structural {
                        catalog.checks.remove(&(current.node.id.clone(),Layer::Exit));
                        catalog.record(check(&current.node,Layer::Tunnel,Outcome::Failed,chrono::Utc::now(),Duration::ZERO,Some("活动代际结构检查失效".into())));
                    }
                    if let Some(health)=health {
                        if health.worker_id!=worker || health.generation!=current.generation {return Err(io::Error::other("活动健康结果代际归属不符"));}
                        if health.sequence>current.health_sequence && (!structural || !health.report.as_ref().is_some_and(|report|report.success)) {
                            current.health_sequence=health.sequence;
                            let success=health.report.as_ref().is_some_and(|report|report.success);failed|=!success;
                            let mut result=check(&current.node,Layer::Exit,if success {Outcome::Succeeded}else{Outcome::Failed},health.started_at,Duration::ZERO,(!success).then(||"活动出口检测失败".into()));
                            if let Some(report)=health.report {result.attempts=report.attempts;result.status=report.status;result.elapsed_ms=report.elapsed.as_millis().min(u128::from(u64::MAX)) as u64;}
                            result.finished_at=health.finished_at;
                            if success {result.expires_at=health.finished_at.checked_add_signed(chrono::Duration::seconds(config.candidate_result_ttl_seconds as i64));}
                            last_check=Some(ActiveCheckSummary {node_id:current.node.id.clone(),worker_id:worker,finished_at:health.finished_at,success,attempts:result.attempts,elapsed_ms:result.elapsed_ms,status:result.status,failure:result.failure_reason.clone()});catalog.record(result);
                        }
                    }
                    if failed {
                        revoke(&request.active);last_switch=Some("活动代际或出口检测失效".into());last_error=last_switch.clone();
                        scheduler.cancel_queued();for (_,token) in in_flight.values(){token.cancel();}
                        retire(client,&gate,worker).await?;active=None;urgent=true;next_round=Instant::now();
                    }
                    persist(config, &storage,&catalog,active.as_ref().map(|value|&value.node.id));
                }
            },
            _=tick.tick()=>{},
        }
        let now = Instant::now();
        let wall = chrono::Utc::now();
        let fresh = !service::source_summary(
            fetched,
            wall,
            Duration::from_secs(config.source_cache_ttl_seconds),
            None,
        )
        .expired;
        if now >= next_source && sources.is_empty() {
            let source = source.clone();
            let url = config.source_url.clone();
            let budget = Duration::from_secs(config.source_timeout_seconds);
            sources.spawn(async move { source.fetch(url, budget).await });
        }
        if round_running && !scheduler.is_running() {
            round_running = false;
            next_round = now
                + Duration::from_secs(if active.is_some() {
                    config.candidate_interval_seconds
                } else if urgent {
                    0
                } else {
                    node_delay.next_delay()
                });
        }
        if now >= next_round && !scheduler.is_running() && fresh {
            if active.is_none() {
                scheduler.begin_recovery(&catalog, wall);
            } else {
                scheduler.begin(&catalog, active.as_ref().map(|value| &value.node.id));
            }
            round_running = scheduler.is_running();
            urgent = false;
            if !round_running {
                next_round = now
                    + Duration::from_secs(if active.is_some() {
                        config.candidate_interval_seconds
                    } else {
                        node_delay.next_delay()
                    });
            }
        }
        if fresh
            && source_error.is_none()
            && active.is_none()
            && !scheduler.is_running()
            && !catalog.nodes.values().any(|node| node.present)
        {
            next_source = next_source.min(next_round);
        }
        if now >= next_status && statuses.is_empty() {
            let client = client.clone();
            let worker = active.as_ref().map(|current| current.worker);
            statuses.spawn(async move {
                (
                    worker,
                    client
                        .request(
                            worker.map_or(Command::Ping, |worker| Command::Status { worker }),
                            CONTROL_BUDGET,
                        )
                        .await,
                )
            });
            next_status = now + Duration::from_secs(1);
        }
        if fresh {
            while let Some(node) = scheduler.next(&mut catalog, wall) {
                catalog.start_attempt(&node, wall);
                let token = stop.child_token();
                in_flight.insert(
                    node.id.clone(),
                    (node.profile_digest.clone(), token.clone()),
                );
                attempts.spawn(attempt(
                    config.clone(),
                    client.clone(),
                    node,
                    active.is_none(),
                    gate.clone(),
                    token,
                ));
            }
        } else {
            for (_, token) in in_flight.values() {
                token.cancel();
            }
        }
        let next = chrono::Duration::from_std(next_round.saturating_duration_since(now))
            .ok()
            .and_then(|delta| wall.checked_add_signed(delta))
            .unwrap_or(wall);
        request.status.send_replace(StatusSnapshot {
            schema_version: 1,
            instance_id: request.instance_id,
            state: if active.is_some() {
                ServiceState::Ready
            } else if scheduler.is_running() {
                ServiceState::Validating
            } else {
                ServiceState::Waiting
            },
            ready: active.is_some(),
            listen_address: config.listen,
            timezone: config.timezone,
            active_node: active.as_ref().map(|value| ActiveNode {
                id: value.node.id.clone(),
                endpoint: value.node.endpoint.clone(),
            }),
            last_exit_check: last_check.clone(),
            source: service::source_summary(
                fetched,
                wall,
                Duration::from_secs(config.source_cache_ttl_seconds),
                source_error.as_deref(),
            ),
            candidates: service::candidate_summary(&catalog, &scheduler, wall, next),
            connections: Connections {
                current: config
                    .max_connections
                    .saturating_sub(request.quota.available_permits()),
                limit: config.max_connections,
            },
            last_switch_reason: last_switch.clone(),
            last_error: last_error
                .clone()
                .or_else(|| source_error.clone())
                .or_else(|| source_empty_error.clone()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    #[derive(Default)]
    struct FakeState {
        workers: HashMap<WorkerId, (VpnNode, Uuid)>,
        active: Option<WorkerId>,
        checks: HashSet<WorkerId>,
        finished: HashMap<WorkerId, chrono::DateTime<chrono::Utc>>,
        failed: HashSet<WorkerId>,
        hold_checks: bool,
        hold_ready: bool,
        fail_checks: bool,
        bad_health: bool,
        retire_error: bool,
        starts: Vec<Instant>,
        retires: Vec<Instant>,
        maximum: usize,
    }
    #[derive(Clone, Default)]
    struct FakeRpc {
        state: Arc<Mutex<FakeState>>,
        closed: CancellationToken,
    }
    impl Rpc for FakeRpc {
        async fn request(&self, command: Command, _: Duration) -> io::Result<Response> {
            if self.closed.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "受控通道已关闭",
                ));
            }
            let mut state = self.state.lock().await;
            Ok(match command {
                Command::Start { node } => {
                    let worker = WorkerId::default();
                    state.workers.insert(worker, (*node, Uuid::new_v4()));
                    state.starts.push(Instant::now());
                    state.maximum = state.maximum.max(state.workers.len());
                    Response::Started { worker }
                }
                Command::Ready { worker } => {
                    if state.hold_ready {
                        drop(state);
                        self.closed.cancelled().await;
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "就绪等待因通道关闭结束",
                        ));
                    }
                    Response::Ready {
                        worker,
                        generation: state.workers[&worker].1,
                        socket: format!("/private/tmp/fake-{worker}.sock").into(),
                    }
                }
                Command::BeginVerify { worker } => {
                    state.checks.insert(worker);
                    state.finished.insert(worker, chrono::Utc::now());
                    Response::CheckStarted { worker }
                }
                Command::VerifyResult { worker } => {
                    if state.hold_checks && state.active.is_some() {
                        Response::Checking { worker }
                    } else {
                        state.checks.remove(&worker);
                        let success = !state.fail_checks;
                        Response::Verified {
                            worker,
                            finished_at: state.finished[&worker],
                            report: crate::probe::ProbeReport {
                                success,
                                attempts: 1,
                                status: success.then_some(204),
                                failure: (!success).then_some(crate::probe::ProbeFailure::Response),
                                elapsed: Duration::from_millis(1),
                            },
                        }
                    }
                }
                Command::Promote { worker, node } => {
                    state.active = Some(worker);
                    Response::Promoted {
                        worker,
                        node_id: node.id.clone(),
                        generation: state.workers[&worker].1,
                        socket: format!("/private/tmp/fake-{worker}.sock").into(),
                    }
                }
                Command::Retire { worker } => {
                    if state.retire_error {
                        Response::Error {
                            code: "operation_failed".into(),
                        }
                    } else {
                        state.workers.remove(&worker);
                        state.checks.remove(&worker);
                        state.retires.push(Instant::now());
                        if state.active == Some(worker) {
                            state.active = None;
                        }
                        Response::Retired {
                            worker,
                            failure: None,
                        }
                    }
                }
                Command::Status { worker } => {
                    let live =
                        state.workers.contains_key(&worker) && !state.failed.contains(&worker);
                    let health = state.bad_health.then(|| {
                        Box::new(super::super::health::MacHealthResult {
                            worker_id: worker,
                            generation: Uuid::new_v4(),
                            sequence: 1,
                            started_at: chrono::Utc::now(),
                            finished_at: chrono::Utc::now(),
                            report: None,
                            error: Some("受控错误代际".into()),
                        })
                    });
                    Response::Status {
                        worker,
                        live,
                        active: state.active == Some(worker) && live,
                        health,
                    }
                }
                _ => Response::Pong,
            })
        }
        fn close(&self) {
            self.closed.cancel();
        }
        fn cancellation(&self) -> CancellationToken {
            self.closed.clone()
        }
    }
    #[derive(Clone)]
    struct FakeSource(Arc<Mutex<Result<SourceSnapshot, String>>>);
    impl Source for FakeSource {
        async fn fetch(&self, _: url::Url, _: Duration) -> Result<SourceSnapshot, String> {
            self.0.lock().await.clone()
        }
    }
    fn snapshot(count: usize) -> SourceSnapshot {
        let fetched_at = chrono::Utc::now();
        let mut nodes = Vec::new();
        for index in 0..count {
            let port = 1194 + index as u16;
            let profile=crate::openvpn::sanitize_openvpn(format!("client\ndev tun\nproto udp\nremote 1.2.3.4 {port}\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n").as_bytes(),"1.2.3.4".parse().unwrap()).unwrap();
            let endpoint = Endpoint {
                ip: *profile.remote().ip(),
                port,
                transport: profile.transport(),
            };
            nodes.push(VpnNode {
                id: NodeId::from_endpoint(&endpoint),
                endpoint,
                source_hostname: String::new(),
                country: String::new(),
                profile_digest: blake3::hash(profile.as_str().as_bytes())
                    .to_hex()
                    .to_string(),
                profile: profile.as_str().into(),
                source_fetched_at: fetched_at,
                present: true,
                last_attempt_at: None,
            });
        }
        SourceSnapshot {
            schema_version: 1,
            source_url: "http://127.0.0.1/".into(),
            fetched_at,
            stats: Default::default(),
            nodes,
        }
    }
    fn request(directory: &std::path::Path) -> CoordinatorRequest {
        let config = AppConfig {
            data_dir: directory.join("data"),
            runtime_dir: directory.join("run"),
            source_url: "http://127.0.0.1/".parse().unwrap(),
            source_refresh_seconds: 1,
            candidate_interval_seconds: 1,
            retry_initial_seconds: 2,
            retry_max_seconds: 2,
            candidate_batch_size: 2,
            candidate_concurrency: 2,
            ..Default::default()
        };
        let (active, _) = watch::channel(None);
        let now = chrono::Utc::now();
        let (status, _) = watch::channel(StatusSnapshot {
            schema_version: 1,
            instance_id: Uuid::new_v4(),
            state: ServiceState::Starting,
            ready: false,
            listen_address: config.listen,
            timezone: config.timezone,
            active_node: None,
            last_exit_check: None,
            source: service::source_summary(
                None,
                now,
                Duration::from_secs(config.source_cache_ttl_seconds),
                None,
            ),
            candidates: service::candidate_summary(
                &Catalog::default(),
                &Scheduler::new(2, 2),
                now,
                now,
            ),
            connections: Connections {
                current: 0,
                limit: 50,
            },
            last_switch_reason: None,
            last_error: None,
        });
        CoordinatorRequest {
            config,
            identity: WorkerCredentials {
                uid: nix::unistd::getuid().as_raw(),
                gid: nix::unistd::getgid().as_raw(),
            },
            instance_id: Uuid::new_v4(),
            active,
            status,
            quota: Arc::new(Semaphore::new(50)),
        }
    }
    async fn step() {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
    }
    async fn ready(active: &watch::Sender<Option<ActiveWorker>>) -> ActiveWorker {
        for _ in 0..100 {
            if let Some(value) = active.borrow().clone() {
                return value;
            }
            step().await;
        }
        panic!("受控协调未提升活动出口")
    }
    #[tokio::test(start_paused = true)]
    async fn background_candidates_are_parallel_retired_and_do_not_rotate_healthy_activity() {
        let directory = tempfile::tempdir().unwrap();
        let mut request = request(directory.path());
        request.config.candidate_batch_size = 3;
        let active = request.active.clone();
        let status = request.status.clone();
        let rpc = FakeRpc::default();
        rpc.state.lock().await.hold_checks = true;
        let source = FakeSource(Arc::new(Mutex::new(Ok(snapshot(3)))));
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(request, rpc.clone(), source, stop.clone()));
        let old = ready(&active).await;
        for _ in 0..100 {
            if rpc.state.lock().await.checks.len() == 2 {
                break;
            }
            step().await;
        }
        assert_eq!(rpc.state.lock().await.checks.len(), 2);
        assert!(rpc.state.lock().await.maximum <= 3);
        assert_eq!(active.borrow().as_ref().unwrap().worker_id, old.worker_id);
        assert!(!old.cancel.is_cancelled());
        rpc.state.lock().await.hold_checks = false;
        for _ in 0..50 {
            if rpc.state.lock().await.workers.len() == 1 {
                break;
            }
            step().await;
        }
        assert_eq!(rpc.state.lock().await.workers.len(), 1);
        assert!(status.borrow().ready);
        assert_eq!(active.borrow().as_ref().unwrap().worker_id, old.worker_id);
        stop.cancel();
        task.await.unwrap().unwrap();
        assert!(old.cancel.is_cancelled());
        assert!(rpc.closed.is_cancelled());
    }
    #[tokio::test(start_paused = true)]
    async fn removing_active_from_source_keeps_existing_healthy_reference() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let active = request.active.clone();
        let rpc = FakeRpc::default();
        let source = FakeSource(Arc::new(Mutex::new(Ok(snapshot(1)))));
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(request, rpc.clone(), source.clone(), stop.clone()));
        let old = ready(&active).await;
        *source.0.lock().await = Ok(snapshot(0));
        for _ in 0..50 {
            step().await;
        }
        assert_eq!(active.borrow().as_ref().unwrap().worker_id, old.worker_id);
        assert!(!old.cancel.is_cancelled());
        assert_eq!(rpc.state.lock().await.starts.len(), 1);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn source_failure_uses_fresh_cache_without_refreshing_its_age_or_trusting_diagnostics() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let active = request.active.clone();
        let status = request.status.clone();
        let cached = snapshot(1);
        Storage::new(&request.config.data_dir)
            .unwrap()
            .save_source(&cached)
            .unwrap();
        let rpc = FakeRpc::default();
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Err("受控来源失败".into())))),
            stop.clone(),
        ));
        ready(&active).await;
        for _ in 0..5 {
            step().await;
        }
        assert_eq!(status.borrow().source.fetched_at, Some(cached.fetched_at));
        assert!(status.borrow().source.last_error.is_some());
        assert_eq!(rpc.state.lock().await.starts.len(), 1);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn repeated_identical_source_does_not_bypass_failed_node_backoff() {
        let directory = tempfile::tempdir().unwrap();
        let mut request = request(directory.path());
        request.config.candidate_batch_size = 1;
        let rpc = FakeRpc::default();
        rpc.state.lock().await.fail_checks = true;
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Ok(snapshot(1))))),
            stop.clone(),
        ));
        for _ in 0..100 {
            if rpc.state.lock().await.starts.len() >= 2 {
                break;
            }
            step().await;
        }
        let state = rpc.state.lock().await;
        assert!(state.starts.len() >= 2);
        assert!(state.starts[1].duration_since(state.retires[0]) >= Duration::from_secs(2));
        drop(state);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn stop_closes_waiting_ready_request_instead_of_waiting_for_startup_budget() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let rpc = FakeRpc::default();
        rpc.state.lock().await.hold_ready = true;
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Ok(snapshot(1))))),
            stop.clone(),
        ));
        for _ in 0..30 {
            if rpc.state.lock().await.starts.len() == 1 {
                break;
            }
            step().await;
        }
        assert_eq!(rpc.state.lock().await.starts.len(), 1);
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(rpc.closed.is_cancelled());
    }
    #[tokio::test(start_paused = true)]
    async fn structural_failure_revokes_old_reference_and_revalidates_before_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let active = request.active.clone();
        let rpc = FakeRpc::default();
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Ok(snapshot(1))))),
            stop.clone(),
        ));
        let old = ready(&active).await;
        rpc.state.lock().await.failed.insert(old.worker_id);
        for _ in 0..100 {
            if old.cancel.is_cancelled() {
                break;
            }
            step().await;
        }
        assert!(old.cancel.is_cancelled());
        let new = ready(&active).await;
        assert_ne!(new.worker_id, old.worker_id);
        assert!(rpc.state.lock().await.starts.len() >= 2);
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn wrong_health_generation_is_fatal_and_clears_local_activity() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let active = request.active.clone();
        let rpc = FakeRpc::default();
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Ok(snapshot(1))))),
            stop,
        ));
        let old = ready(&active).await;
        rpc.state.lock().await.bad_health = true;
        for _ in 0..100 {
            if task.is_finished() {
                break;
            }
            step().await;
        }
        assert!(task.await.unwrap().is_err());
        assert!(old.cancel.is_cancelled());
        assert!(active.borrow().is_none());
        assert!(rpc.closed.is_cancelled());
    }
    #[test]
    fn invalid_platform_settings_and_identity_fail_before_filesystem_activity() {
        let directory = tempfile::tempdir().unwrap();
        let mut request = request(directory.path());
        request.config.candidate_concurrency = 33;
        assert!(validate_config(&request.config).is_err());
        request.config.candidate_concurrency = 2;
        request.config.exit_check_timeout_seconds = 121;
        assert!(validate_config(&request.config).is_err());
        request.config.exit_check_timeout_seconds = 10;
        request.identity.uid = 0;
        assert!(validate(&request).is_err());
        assert!(!request.config.data_dir.exists());
    }
    #[tokio::test(start_paused = true)]
    async fn expired_source_and_successful_history_never_restore_availability() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let active = request.active.clone();
        let status = request.status.clone();
        let mut cached = snapshot(1);
        cached.fetched_at -= chrono::Duration::days(2);
        for node in &mut cached.nodes {
            node.source_fetched_at = cached.fetched_at;
        }
        let storage = Storage::new(&request.config.data_dir).unwrap();
        storage.save_source(&cached).unwrap();
        let mut old = check(
            &cached.nodes[0],
            Layer::Exit,
            Outcome::Succeeded,
            chrono::Utc::now(),
            Duration::ZERO,
            None,
        );
        old.status = Some(204);
        old.expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(60));
        storage
            .save_checks(&[old], &[cached.nodes[0].id.clone()], None)
            .unwrap();
        let rpc = FakeRpc::default();
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Err(String::new())))),
            stop.clone(),
        ));
        for _ in 0..50 {
            step().await;
        }
        assert!(active.borrow().is_none());
        assert!(!status.borrow().ready);
        assert!(status.borrow().source.expired);
        assert!(rpc.state.lock().await.starts.is_empty());
        assert!(!task.is_finished());
        stop.cancel();
        task.await.unwrap().unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn unconfirmed_retirement_stops_coordinator_and_clears_readiness() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let active = request.active.clone();
        let status = request.status.clone();
        let rpc = FakeRpc::default();
        let task = tokio::spawn(run(
            request,
            rpc.clone(),
            FakeSource(Arc::new(Mutex::new(Ok(snapshot(1))))),
            CancellationToken::new(),
        ));
        let old = ready(&active).await;
        {
            let mut state = rpc.state.lock().await;
            state.retire_error = true;
            state.failed.insert(old.worker_id);
        }
        for _ in 0..100 {
            if task.is_finished() {
                break;
            }
            step().await;
        }
        assert!(task.await.unwrap().is_err());
        assert!(old.cancel.is_cancelled());
        assert!(active.borrow().is_none());
        assert!(!status.borrow().ready);
        assert_eq!(status.borrow().state, ServiceState::Stopping);
        assert!(rpc.closed.is_cancelled());
    }
    #[tokio::test]
    async fn abandoning_coordinator_wait_synchronously_revokes_reference_and_readiness() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let rpc = FakeRpc::default();
        let stop = CancellationToken::new();
        let token = CancellationToken::new();
        request.active.send_replace(Some(ActiveWorker {
            socket_path: "/private/tmp/fake.sock".into(),
            node_id: snapshot(1).nodes[0].id.clone(),
            worker_id: WorkerId::default(),
            cancel: token.clone(),
        }));
        request.status.send_modify(|status| status.ready = true);
        let guard = Guard {
            client: rpc.clone(),
            active: request.active.clone(),
            status: request.status.clone(),
            stop: stop.clone(),
        };
        drop(guard);
        assert!(token.is_cancelled());
        assert!(stop.is_cancelled());
        assert!(rpc.closed.is_cancelled());
        assert!(request.active.borrow().is_none());
        assert!(!request.status.borrow().ready);
    }
    #[tokio::test]
    async fn exit_cache_expiry_uses_privileged_completion_time() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let rpc = FakeRpc::default();
        let node = snapshot(1).nodes.remove(0);
        let result = attempt(
            request.config.clone(),
            rpc.clone(),
            node,
            true,
            Arc::new(Mutex::new(())),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let worker = result.worker.unwrap();
        let finished = rpc.state.lock().await.finished[&worker];
        let exit = result
            .checks
            .iter()
            .find(|check| check.layer == Layer::Exit)
            .unwrap();
        assert_eq!(exit.finished_at, finished);
        assert_eq!(
            exit.expires_at,
            Some(
                finished
                    + chrono::Duration::seconds(request.config.candidate_result_ttl_seconds as i64)
            )
        );
        retire(&rpc, &Mutex::new(()), worker).await.unwrap();
    }
    #[tokio::test]
    async fn idle_parent_channel_eof_is_detected_without_any_available_nodes() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let status = request.status.clone();
        let (mut peer, stream) = tokio::net::UnixStream::pair().unwrap();
        let client = MacControlClient::new(stream, Uuid::new_v4());
        let closed = client.cancellation();
        let task = tokio::spawn(run(
            request,
            client,
            FakeSource(Arc::new(Mutex::new(Err(String::new())))),
            CancellationToken::new(),
        ));
        let frame: serde_json::Value = crate::netd::protocol::read_frame(&mut peer).await.unwrap();
        assert_eq!(frame["operation"]["command"], "ping");
        drop(peer);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(closed.is_cancelled());
        assert!(!status.borrow().ready);
    }
}
