//! 继承私有通道上的有限控制协议；创建与核验低权限控制进程仍由部署启动方负责。
use super::{
    health::{MacHealthResult, MacHealthSettings},
    pool::{MacCandidatePool, OwnedVerification, VerifiedCandidate},
};
use crate::{
    domain::{NodeId, VpnNode, WorkerId},
    probe::ProbeReport,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, io, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    sync::{Mutex, watch},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;
const MAX_FRAME: usize = 1024 * 1024;
const FRAME_BUDGET: Duration = Duration::from_secs(3);

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacControlCommand {
    Ping,
    Start {
        node: Box<VpnNode>,
    },
    Ready {
        worker: WorkerId,
    },
    Verify {
        worker: WorkerId,
    },
    BeginVerify {
        worker: WorkerId,
    },
    VerifyResult {
        worker: WorkerId,
    },
    Promote {
        worker: WorkerId,
        node: Box<VpnNode>,
    },
    Retire {
        worker: WorkerId,
    },
    Status {
        worker: WorkerId,
    },
    Shutdown,
}
impl std::fmt::Debug for MacControlCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("苹果控制请求（私有材料省略）")
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    authorization: Uuid,
    sequence: u64,
    operation: MacControlCommand,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("苹果控制帧（授权与私有材料省略）")
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacControlResponse {
    Pong,
    Started {
        worker: WorkerId,
    },
    Ready {
        worker: WorkerId,
        generation: Uuid,
        socket: PathBuf,
    },
    Verified {
        worker: WorkerId,
        report: ProbeReport,
        finished_at: chrono::DateTime<chrono::Utc>,
    },
    CheckStarted {
        worker: WorkerId,
    },
    Checking {
        worker: WorkerId,
    },
    Promoted {
        worker: WorkerId,
        node_id: NodeId,
        generation: Uuid,
        socket: PathBuf,
    },
    Retired {
        worker: WorkerId,
        failure: Option<String>,
    },
    Status {
        worker: WorkerId,
        live: bool,
        active: bool,
        health: Option<Box<MacHealthResult>>,
    },
    Stopped,
    Error {
        code: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    authorization: Uuid,
    sequence: u64,
    outcome: MacControlResponse,
}
fn matches_operation(operation: &MacControlCommand, outcome: &MacControlResponse) -> bool {
    match (operation, outcome) {
        (
            MacControlCommand::BeginVerify { worker },
            MacControlResponse::CheckStarted { worker: actual },
        )
        | (
            MacControlCommand::VerifyResult { worker },
            MacControlResponse::Checking { worker: actual },
        )
        | (
            MacControlCommand::VerifyResult { worker },
            MacControlResponse::Verified { worker: actual, .. },
        ) => worker == actual,
        (_, MacControlResponse::Error { .. }) => true,
        (MacControlCommand::Ping, MacControlResponse::Pong)
        | (MacControlCommand::Shutdown, MacControlResponse::Stopped) => true,
        (MacControlCommand::Start { .. }, MacControlResponse::Started { worker }) => {
            !worker.0.is_nil()
        }
        (
            MacControlCommand::Ready { worker },
            MacControlResponse::Ready {
                worker: actual,
                generation,
                socket,
            },
        ) => worker == actual && !generation.is_nil() && socket.is_absolute(),
        (
            MacControlCommand::Verify { worker },
            MacControlResponse::Verified { worker: actual, .. },
        )
        | (
            MacControlCommand::Retire { worker },
            MacControlResponse::Retired { worker: actual, .. },
        )
        | (
            MacControlCommand::Status { worker },
            MacControlResponse::Status { worker: actual, .. },
        ) => worker == actual,
        (
            MacControlCommand::Promote { worker, node },
            MacControlResponse::Promoted {
                worker: actual,
                node_id,
                generation,
                socket,
            },
        ) => {
            worker == actual && node.id == *node_id && !generation.is_nil() && socket.is_absolute()
        }
        _ => false,
    }
}
async fn send<W: AsyncWrite + Unpin, T: Serialize>(stream: &mut W, value: &T) -> io::Result<()> {
    let bytes =
        Zeroizing::new(serde_json::to_vec(value).map_err(|_| io::Error::other("控制帧编码失败"))?);
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "控制帧超限"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}
async fn receive<R: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut R) -> io::Result<T> {
    // 空闲连接不设帧截止；收到首字节后，长度、载荷共同受固定截止约束。
    let first = stream.read_u8().await?;
    tokio::time::timeout(FRAME_BUDGET, async {
        let mut header = [first, 0, 0, 0];
        stream.read_exact(&mut header[1..]).await?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "控制帧长度无效"));
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        stream.read_exact(&mut bytes).await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "控制帧字段或格式无效"))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "控制帧接收超时"))?
}
struct Channel {
    stream: Option<UnixStream>,
    sequence: u64,
}
#[derive(Clone)]
pub struct MacControlClient {
    channel: Arc<Mutex<Channel>>,
    authorization: Uuid,
    closed: CancellationToken,
}
impl MacControlClient {
    /// 仅接受部署方交付的继承通道，不按调用方提供的路径连接管理员监听器。
    pub fn new(stream: UnixStream, authorization: Uuid) -> Self {
        Self {
            channel: Arc::new(Mutex::new(Channel {
                stream: Some(stream),
                sequence: 0,
            })),
            authorization,
            closed: CancellationToken::new(),
        }
    }
    /// 立即撤销全部克隆；空闲时关闭通道，在途请求在下一轮轮询关闭其独占连接。
    pub fn close(&self) {
        self.closed.cancel();
        if let Ok(mut channel) = self.channel.try_lock() {
            channel.stream.take();
        }
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.closed.clone()
    }
    pub async fn request(
        &self,
        operation: MacControlCommand,
        budget: Duration,
    ) -> io::Result<MacControlResponse> {
        if budget.is_zero() || tokio::time::Instant::now().checked_add(budget).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "控制请求截止无效",
            ));
        }
        let operation = tokio::time::timeout(budget, async {
            let mut channel = self.channel.lock().await;
            // 取消或超时会丢弃已取出的通道，禁止复用有半帧或迟到响应的连接。
            let mut stream = channel
                .stream
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "控制通道已关闭"))?;
            let failure = self.closed.clone().drop_guard();
            channel.sequence = channel
                .sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("控制请求序号耗尽"))?;
            let sequence = channel.sequence;
            let request = Request {
                version: 1,
                authorization: self.authorization,
                sequence,
                operation,
            };
            send(&mut stream, &request).await?;
            let response: Response = receive(&mut stream).await?;
            if response.version != 1
                || response.authorization != self.authorization
                || response.sequence != sequence
                || !matches_operation(&request.operation, &response.outcome)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "控制响应归属不符",
                ));
            }
            if !matches!(response.outcome, MacControlResponse::Stopped) {
                channel.stream = Some(stream);
            } else {
                self.closed.cancel();
            }
            failure.disarm();
            Ok(response.outcome)
        });
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => Err(io::Error::new(io::ErrorKind::NotConnected,"控制连接已主动关闭")),
            result = operation => result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "控制请求超时；已开始执行的连接不再复用",
            )
            })?,
        }
    }
}
struct State {
    pool: MacCandidatePool,
    proofs: BTreeMap<Uuid, VerifiedCandidate>,
    checks: BTreeMap<Uuid, OwnedVerification>,
    health: BTreeMap<Uuid, watch::Receiver<Option<MacHealthResult>>>,
    settings: MacHealthSettings,
}
impl State {
    async fn execute(
        &mut self,
        command: MacControlCommand,
        stop: &CancellationToken,
    ) -> io::Result<MacControlResponse> {
        self.pool.refresh_active();
        Ok(match command {
            MacControlCommand::Ping => MacControlResponse::Pong,
            MacControlCommand::Start { node } => MacControlResponse::Started {
                worker: self.pool.start_candidate(*node)?,
            },
            MacControlCommand::Ready { worker } => {
                self.pool.wait_ready(worker).await?;
                let generation = self.pool.generation(worker)?;
                let socket = self.socket(worker)?;
                MacControlResponse::Ready {
                    worker,
                    generation,
                    socket,
                }
            }
            MacControlCommand::Verify { worker } => {
                if self.checks.contains_key(&worker.0) {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "所属检测结果尚未取走",
                    ));
                }
                self.proofs.remove(&worker.0);
                let checked = self.pool.check(worker, stop.clone()).await?;
                if let Some(proof) = checked.verified {
                    self.proofs.insert(worker.0, proof);
                }
                MacControlResponse::Verified {
                    worker,
                    report: checked.report,
                    finished_at: checked.finished_at,
                }
            }
            MacControlCommand::BeginVerify { worker } => {
                if self.checks.contains_key(&worker.0) {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "所属检测结果尚未取走",
                    ));
                }
                let check = self.pool.begin_check(worker, stop)?;
                self.proofs.remove(&worker.0);
                self.checks.insert(worker.0, check);
                MacControlResponse::CheckStarted { worker }
            }
            MacControlCommand::VerifyResult { worker } => {
                let check = self.checks.get(&worker.0).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "所属检测不存在或结果已取走")
                })?;
                if !check.is_finished() {
                    return Ok(MacControlResponse::Checking { worker });
                }
                let mut check = self
                    .checks
                    .remove(&worker.0)
                    .ok_or_else(|| io::Error::other("所属检测消失"))?;
                let checked = check.wait().await?;
                if let Some(proof) = checked.verified {
                    self.proofs.insert(worker.0, proof);
                }
                MacControlResponse::Verified {
                    worker,
                    report: checked.report,
                    finished_at: checked.finished_at,
                }
            }
            MacControlCommand::Promote { worker, node } => {
                let proof = self.proofs.remove(&worker.0).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "缺少当前成功检测凭据")
                })?;
                self.pool.promote(proof, &node)?;
                match self.pool.start_health(worker, self.settings.clone()) {
                    Ok(receiver) => {
                        self.health.insert(worker.0, receiver);
                    }
                    Err(error) => {
                        let _ = self.pool.retire(worker).await;
                        return Err(error);
                    }
                }
                MacControlResponse::Promoted {
                    worker,
                    node_id: node.id,
                    generation: self.pool.generation(worker)?,
                    socket: self.socket(worker)?,
                }
            }
            MacControlCommand::Retire { worker } => {
                self.proofs.remove(&worker.0);
                self.checks.remove(&worker.0);
                self.health.remove(&worker.0);
                let retired = self.pool.retire(worker).await?;
                MacControlResponse::Retired {
                    worker,
                    failure: retired.failure,
                }
            }
            MacControlCommand::Status { worker } => {
                let live = self.pool.generation(worker).is_ok();
                let active = self
                    .pool
                    .subscribe()
                    .borrow()
                    .as_ref()
                    .is_some_and(|active| {
                        active.worker_id == worker && !active.cancel.is_cancelled()
                    });
                let health = self
                    .health
                    .get(&worker.0)
                    .and_then(|receiver| receiver.borrow().clone())
                    .map(Box::new);
                MacControlResponse::Status {
                    worker,
                    live,
                    active,
                    health,
                }
            }
            MacControlCommand::Shutdown => {
                self.proofs.clear();
                self.checks.clear();
                self.health.clear();
                self.pool.shutdown().await?;
                MacControlResponse::Stopped
            }
        })
    }
    fn socket(&self, worker: WorkerId) -> io::Result<PathBuf> {
        self.pool.worker_socket(worker).map(PathBuf::from)
    }
    async fn run(
        &mut self,
        stream: UnixStream,
        authorization: Uuid,
        stop: &CancellationToken,
    ) -> io::Result<()> {
        self.settings.validate()?;
        let (mut reader, mut writer) = stream.into_split();
        let mut expected = 0_u64;
        loop {
            let request: Request = tokio::select! {
                biased;
                _ = stop.cancelled() => return Ok(()),
                request = receive(&mut reader) => request?,
            };
            expected = expected
                .checked_add(1)
                .ok_or_else(|| io::Error::other("控制请求序号耗尽"))?;
            if request.version != 1
                || request.authorization != authorization
                || request.sequence != expected
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "控制请求归属或次序不符",
                ));
            }
            let shutting_down = matches!(request.operation, MacControlCommand::Shutdown);
            let outcome = tokio::select! {
                biased;
                _ = stop.cancelled() => return Ok(()),
                // 同一通道仅一项在途操作；提前请求或断开都撤销整条会话。
                _ = receive::<_,Request>(&mut reader) => return Err(io::Error::new(io::ErrorKind::BrokenPipe,"控制方在操作完成前断开或发送重叠请求")),
                result = self.execute(request.operation,stop) => match result {
                    Ok(outcome) => outcome,
                    Err(_) => MacControlResponse::Error {code:"operation_failed".into()},
                },
            };
            let stopped = matches!(outcome, MacControlResponse::Stopped);
            tokio::time::timeout(
                FRAME_BUDGET,
                send(
                    &mut writer,
                    &Response {
                        version: 1,
                        authorization,
                        sequence: expected,
                        outcome,
                    },
                ),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "控制结果交付超时"))??;
            if shutting_down || stopped {
                return Ok(());
            }
        }
    }
}
/// 通道必须由部署方在身份核验后私有交付。此函数不建立公开监听、不启动公共服务。
/// 外层等待取消后，同一任务仍持有所属池并执行回收；运行时须持续存活。
pub async fn serve(
    pool: MacCandidatePool,
    stream: UnixStream,
    authorization: Uuid,
    settings: MacHealthSettings,
    parent_stop: CancellationToken,
) -> io::Result<()> {
    serve_tracked(
        pool,
        stream,
        authorization,
        settings,
        parent_stop,
        super::bootstrap::CleanupStatus::default(),
    )
    .await
}
/// 回收确认和控制会话结果独立；只有全部代际槽位已确认回收才确认实例资源。
pub(super) async fn serve_tracked(
    pool: MacCandidatePool,
    stream: UnixStream,
    authorization: Uuid,
    settings: MacHealthSettings,
    parent_stop: CancellationToken,
    receipt: super::bootstrap::CleanupStatus,
) -> io::Result<()> {
    receipt.unknown();
    let stop = parent_stop.child_token();
    let _guard = stop.clone().drop_guard();
    tokio::spawn(async move {
        let mut state = State {
            pool,
            proofs: BTreeMap::new(),
            checks: BTreeMap::new(),
            health: BTreeMap::new(),
            settings,
        };
        let result = state.run(stream, authorization, &stop).await;
        stop.cancel();
        state.proofs.clear();
        state.checks.clear();
        state.health.clear();
        let cleanup = state.pool.shutdown().await;
        if state.pool.is_empty() {
            receipt.confirm();
        }
        match (result, cleanup) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
                "{error}；控制会话回收：{cleanup}"
            ))),
        }
    })
    .await
    .map_err(|_| io::Error::other("控制会话监督异常，回收未确认"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        exit_probe::ExitProbeSettings, pool::MacPoolSettings, supervisor::WorkerCredentials,
    };
    fn pool() -> MacCandidatePool {
        MacCandidatePool::new(
            MacPoolSettings {
                parent: "/missing/runtime".into(),
                instance_id: uuid::Uuid::new_v4(),
                dependency_manifest: "/missing/dependency".into(),
                credentials: WorkerCredentials {
                    uid: nix::unistd::getuid().as_raw(),
                    gid: nix::unistd::getgid().as_raw(),
                },
                startup_budget: Duration::from_secs(3),
                max_connections: 50,
                candidate_slots: 2,
                verification_ttl: Duration::from_secs(30),
                source_ttl: Duration::from_secs(300),
                exit: settings().exit,
            },
            &CancellationToken::new(),
        )
        .unwrap()
    }
    fn settings() -> MacHealthSettings {
        MacHealthSettings {
            interval: Duration::from_secs(10),
            exit: ExitProbeSettings {
                urls: vec![url::Url::parse("https://example.com/").unwrap()],
                max_attempts: 1,
                budget: Duration::from_secs(1),
            },
        }
    }
    fn node() -> VpnNode {
        let profile=crate::openvpn::sanitize_openvpn(b"client\ndev tun\nproto tcp\nremote 1.2.3.4 443\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nPRIVATE_MATERIAL\n</key>\n","1.2.3.4".parse().unwrap()).unwrap();
        let endpoint = crate::domain::Endpoint {
            ip: *profile.remote().ip(),
            port: 443,
            transport: profile.transport(),
        };
        VpnNode {
            id: NodeId::from_endpoint(&endpoint),
            endpoint,
            source_hostname: String::new(),
            country: String::new(),
            profile_digest: blake3::hash(profile.as_str().as_bytes())
                .to_hex()
                .to_string(),
            profile: profile.as_str().into(),
            source_fetched_at: chrono::Utc::now(),
            present: true,
            last_attempt_at: None,
        }
    }
    #[tokio::test]
    async fn control_shutdown_does_not_confirm_unknown_generation_cleanup() {
        let mut pool = pool();
        pool.test_register_unknown_cleanup(node());
        let receipt = super::super::bootstrap::CleanupStatus::default();
        let (server, client) = UnixStream::pair().unwrap();
        let authorization = Uuid::new_v4();
        let service = tokio::spawn(serve_tracked(
            pool,
            server,
            authorization,
            settings(),
            CancellationToken::new(),
            receipt.clone(),
        ));
        let client = MacControlClient::new(client, authorization);
        assert!(matches!(
            client
                .request(MacControlCommand::Shutdown, Duration::from_secs(2))
                .await
                .unwrap(),
            MacControlResponse::Error { .. }
        ));
        assert!(service.await.unwrap().is_err());
        assert!(!receipt.confirmed());
    }
    #[tokio::test]
    async fn control_failure_and_confirmed_empty_pool_cleanup_are_independent() {
        let receipt = super::super::bootstrap::CleanupStatus::default();
        let (server, client) = UnixStream::pair().unwrap();
        let service = tokio::spawn(serve_tracked(
            pool(),
            server,
            Uuid::new_v4(),
            settings(),
            CancellationToken::new(),
            receipt.clone(),
        ));
        drop(client);
        assert!(service.await.unwrap().is_err());
        assert!(receipt.confirmed());
    }
    #[tokio::test]
    async fn real_protocol_rejects_unverified_promotion_and_retires_failed_start() {
        let authorization = Uuid::new_v4();
        let (server, client) = UnixStream::pair().unwrap();
        let service = tokio::spawn(serve(
            pool(),
            server,
            authorization,
            settings(),
            CancellationToken::new(),
        ));
        let client = MacControlClient::new(client, authorization);
        assert_eq!(
            client
                .request(MacControlCommand::Ping, Duration::ZERO)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            client
                .request(MacControlCommand::Ping, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Pong
        ));
        let absent = WorkerId::default();
        assert!(matches!(
            client
                .request(MacControlCommand::Status { worker: absent }, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Status {
                live: false,
                active: false,
                ..
            }
        ));
        for operation in [
            MacControlCommand::Verify { worker: absent },
            MacControlCommand::Promote {
                worker: absent,
                node: Box::new(node()),
            },
        ] {
            assert!(matches!(
                client.request(operation, FRAME_BUDGET).await.unwrap(),
                MacControlResponse::Error { .. }
            ));
        }
        let started = client
            .request(
                MacControlCommand::Start {
                    node: Box::new(node()),
                },
                FRAME_BUDGET,
            )
            .await
            .unwrap();
        let worker = match started {
            MacControlResponse::Started { worker } => worker,
            _ => panic!("未登记启动所有者"),
        };
        assert!(matches!(
            client
                .request(MacControlCommand::Ready { worker }, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Error { .. }
        ));
        let retired = client
            .request(MacControlCommand::Retire { worker }, FRAME_BUDGET)
            .await
            .unwrap();
        assert!(matches!(
            retired,
            MacControlResponse::Retired {
                failure: Some(_),
                ..
            }
        ));
        assert!(matches!(
            client
                .request(MacControlCommand::Shutdown, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Stopped
        ));
        service.await.unwrap().unwrap();
        assert_eq!(
            client
                .request(MacControlCommand::Ping, FRAME_BUDGET)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    #[tokio::test]
    async fn server_rejects_wrong_authorization_version_and_sequence() {
        for case in 0..3 {
            let authorization = Uuid::new_v4();
            let (server, mut client) = UnixStream::pair().unwrap();
            let task = tokio::spawn(serve(
                pool(),
                server,
                authorization,
                settings(),
                CancellationToken::new(),
            ));
            let mut request = Request {
                version: 1,
                authorization,
                sequence: 1,
                operation: MacControlCommand::Ping,
            };
            match case {
                0 => request.authorization = Uuid::new_v4(),
                1 => request.version = 2,
                _ => request.sequence = 2,
            }
            send(&mut client, &request).await.unwrap();
            assert_eq!(
                task.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
    #[tokio::test]
    async fn client_rejects_wrong_response_identity_and_permanently_closes_channel() {
        for case in 0..4 {
            let authorization = Uuid::new_v4();
            let (mut server, client) = UnixStream::pair().unwrap();
            let fake = tokio::spawn(async move {
                let request: Request = receive(&mut server).await.unwrap();
                let mut response = Response {
                    version: 1,
                    authorization,
                    sequence: request.sequence,
                    outcome: MacControlResponse::Pong,
                };
                match case {
                    0 => response.authorization = Uuid::new_v4(),
                    1 => response.version = 2,
                    2 => response.sequence += 1,
                    _ => {
                        response.outcome = MacControlResponse::Started {
                            worker: WorkerId::default(),
                        }
                    }
                }
                send(&mut server, &response).await.unwrap();
                assert_eq!(
                    server.read_u8().await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            });
            let client = MacControlClient::new(client, authorization);
            assert_eq!(
                client
                    .request(MacControlCommand::Ping, FRAME_BUDGET)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                client
                    .request(MacControlCommand::Ping, FRAME_BUDGET)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotConnected
            );
            fake.await.unwrap();
        }
    }
    #[tokio::test(start_paused = true)]
    async fn timeout_closes_inflight_channel_and_rejects_late_reuse() {
        let (mut server, client) = UnixStream::pair().unwrap();
        let client = MacControlClient::new(client, Uuid::new_v4());
        let fake = tokio::spawn(async move {
            let _: Request = receive(&mut server).await.unwrap();
            assert_eq!(
                server.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        });
        assert_eq!(
            client
                .request(MacControlCommand::Ping, Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        fake.await.unwrap();
        assert_eq!(
            client
                .request(MacControlCommand::Ping, FRAME_BUDGET)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    #[tokio::test]
    async fn correctly_enveloped_response_for_another_worker_is_rejected() {
        let authorization = Uuid::new_v4();
        let (mut server, stream) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            let request: Request = receive(&mut server).await.unwrap();
            send(
                &mut server,
                &Response {
                    version: 1,
                    authorization,
                    sequence: request.sequence,
                    outcome: MacControlResponse::Ready {
                        worker: WorkerId::default(),
                        generation: Uuid::new_v4(),
                        socket: "/private/tmp/other.sock".into(),
                    },
                },
            )
            .await
            .unwrap();
        });
        let client = MacControlClient::new(stream, authorization);
        assert_eq!(
            client
                .request(
                    MacControlCommand::Ready {
                        worker: WorkerId::default()
                    },
                    FRAME_BUDGET
                )
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        task.await.unwrap();
    }
    #[tokio::test]
    async fn queued_timeout_does_not_close_another_inflight_request_or_skip_sequence() {
        let authorization = Uuid::new_v4();
        let (mut server, stream) = UnixStream::pair().unwrap();
        let client = MacControlClient::new(stream, authorization);
        let cloned = client.clone();
        let first = tokio::spawn(async move {
            cloned
                .request(MacControlCommand::Ping, Duration::from_secs(60))
                .await
        });
        let request: Request = receive(&mut server).await.unwrap();
        assert_eq!(request.sequence, 1);
        assert_eq!(
            client
                .request(MacControlCommand::Ping, Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        send(
            &mut server,
            &Response {
                version: 1,
                authorization,
                sequence: 1,
                outcome: MacControlResponse::Pong,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            first.await.unwrap().unwrap(),
            MacControlResponse::Pong
        ));
        let next =
            tokio::spawn(
                async move { client.request(MacControlCommand::Ping, FRAME_BUDGET).await },
            );
        let request: Request = receive(&mut server).await.unwrap();
        assert_eq!(request.sequence, 2);
        send(
            &mut server,
            &Response {
                version: 1,
                authorization,
                sequence: 2,
                outcome: MacControlResponse::Pong,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            next.await.unwrap().unwrap(),
            MacControlResponse::Pong
        ));
    }
    #[tokio::test]
    async fn aborting_request_closes_taken_channel_even_with_other_client_clones() {
        let (mut server, stream) = UnixStream::pair().unwrap();
        let client = MacControlClient::new(stream, Uuid::new_v4());
        let cloned = client.clone();
        let request = tokio::spawn(async move {
            cloned
                .request(MacControlCommand::Ping, Duration::from_secs(60))
                .await
        });
        let _: Request = receive(&mut server).await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            client
                .request(MacControlCommand::Ping, FRAME_BUDGET)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    #[tokio::test(start_paused = true)]
    async fn idle_control_is_allowed_but_partial_frame_expires() {
        let (server, stream) = UnixStream::pair().unwrap();
        let authorization = Uuid::new_v4();
        let task = tokio::spawn(serve(
            pool(),
            server,
            authorization,
            settings(),
            CancellationToken::new(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(100)).await;
        assert!(!task.is_finished());
        let client = MacControlClient::new(stream, authorization);
        assert!(matches!(
            client
                .request(MacControlCommand::Shutdown, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Stopped
        ));
        task.await.unwrap().unwrap();
        for partial_body in [false, true] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            if partial_body {
                client.write_u32(100).await.unwrap();
                client.write_u8(b'{').await.unwrap();
            } else {
                client.write_u8(0).await.unwrap();
            }
            assert_eq!(
                receive::<_, Request>(&mut server).await.unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }
    #[tokio::test]
    async fn oversized_unknown_and_duplicate_frames_are_rejected_without_private_errors() {
        for bytes in [
            Vec::new(),
            vec![b'a'; MAX_FRAME + 1],
            br#"{"version":1,"version":1}"#.to_vec(),
            br#"{"unknown":"PRIVATE_MATERIAL"}"#.to_vec(),
        ] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            client.write_u32(bytes.len() as u32).await.unwrap();
            if bytes.len() <= MAX_FRAME {
                client.write_all(&bytes).await.unwrap();
            }
            let error = receive::<_, Request>(&mut server).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!error.to_string().contains("PRIVATE_MATERIAL"));
        }
        assert!(
            !format!(
                "{:?}",
                MacControlCommand::Start {
                    node: Box::new(node())
                }
            )
            .contains("PRIVATE_MATERIAL")
        );
    }
    #[tokio::test]
    async fn two_pending_checks_do_not_block_channel_and_results_are_single_use() {
        let mut state = State {
            pool: pool(),
            proofs: BTreeMap::new(),
            checks: BTreeMap::new(),
            health: BTreeMap::new(),
            settings: settings(),
        };
        let mut workers = Vec::new();
        let mut gates = Vec::new();
        for _ in 0..2 {
            let worker = WorkerId::default();
            let (allow, gate) = tokio::sync::oneshot::channel();
            state.checks.insert(
                worker.0,
                OwnedVerification::test_launch(
                    &CancellationToken::new(),
                    CancellationToken::new(),
                    move |_| async move {
                        gate.await.unwrap();
                        Ok(super::super::pool::CandidateVerification {
                            finished_at: chrono::Utc::now(),
                            report: ProbeReport {
                                success: false,
                                attempts: 1,
                                status: None,
                                failure: Some(crate::probe::ProbeFailure::Transport),
                                elapsed: Duration::from_millis(1),
                            },
                            verified: None,
                        })
                    },
                ),
            );
            workers.push(worker);
            gates.push(allow);
        }
        let (server, stream) = UnixStream::pair().unwrap();
        let authorization = Uuid::new_v4();
        let task = tokio::spawn(async move {
            state
                .run(server, authorization, &CancellationToken::new())
                .await
        });
        let client = MacControlClient::new(stream, authorization);
        assert!(matches!(
            client
                .request(MacControlCommand::Ping, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Pong
        ));
        for worker in &workers {
            assert!(matches!(
                client
                    .request(
                        MacControlCommand::VerifyResult { worker: *worker },
                        FRAME_BUDGET
                    )
                    .await
                    .unwrap(),
                MacControlResponse::Checking { .. }
            ));
            assert!(matches!(
                client
                    .request(
                        MacControlCommand::BeginVerify { worker: *worker },
                        FRAME_BUDGET
                    )
                    .await
                    .unwrap(),
                MacControlResponse::Error { .. }
            ));
            assert!(matches!(
                client
                    .request(MacControlCommand::Verify { worker: *worker }, FRAME_BUDGET)
                    .await
                    .unwrap(),
                MacControlResponse::Error { .. }
            ));
        }
        for gate in gates {
            gate.send(()).unwrap();
        }
        for worker in workers {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match client
                        .request(MacControlCommand::VerifyResult { worker }, FRAME_BUDGET)
                        .await
                        .unwrap()
                    {
                        MacControlResponse::Checking { .. } => tokio::task::yield_now().await,
                        MacControlResponse::Verified { report, .. } => {
                            assert!(!report.success);
                            break;
                        }
                        _ => panic!("检测结果类型无效"),
                    }
                }
            })
            .await
            .unwrap();
            assert!(matches!(
                client
                    .request(MacControlCommand::VerifyResult { worker }, FRAME_BUDGET)
                    .await
                    .unwrap(),
                MacControlResponse::Error { .. }
            ));
        }
        assert!(matches!(
            client
                .request(MacControlCommand::Shutdown, FRAME_BUDGET)
                .await
                .unwrap(),
            MacControlResponse::Stopped
        ));
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn explicit_close_cancels_inflight_and_queued_clones_and_closes_peer() {
        let (mut server, stream) = UnixStream::pair().unwrap();
        let client = MacControlClient::new(stream, Uuid::new_v4());
        let first = client.clone();
        let inflight = tokio::spawn(async move {
            first
                .request(MacControlCommand::Ping, Duration::from_secs(60))
                .await
        });
        let _: Request = receive(&mut server).await.unwrap();
        let second = client.clone();
        let queued = tokio::spawn(async move {
            second
                .request(MacControlCommand::Ping, Duration::from_secs(60))
                .await
        });
        client.close();
        assert!(client.cancellation().is_cancelled());
        assert_eq!(
            inflight.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            queued.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[tokio::test]
    async fn idle_close_immediately_closes_descriptor_and_is_idempotent() {
        let (mut server, stream) = UnixStream::pair().unwrap();
        let client = MacControlClient::new(stream, Uuid::new_v4());
        let cloned = client.clone();
        client.close();
        client.close();
        assert!(cloned.cancellation().is_cancelled());
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            cloned
                .request(MacControlCommand::Ping, FRAME_BUDGET)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
}
