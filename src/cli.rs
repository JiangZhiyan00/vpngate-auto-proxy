//! 本地管理协议；仅允许状态与正常停止，不按外部传入的进程号发送信号。
use crate::{
    domain::*,
    service::{ActiveCheckSummary, CandidateSummary, SourceSummary},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

fn default_timezone() -> chrono_tz::Tz {
    chrono_tz::Asia::Shanghai
}

pub const MAX_CONTROL_BYTES: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveNode {
    pub id: NodeId,
    pub endpoint: Endpoint,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connections {
    pub current: usize,
    pub limit: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshot {
    pub schema_version: u32,
    pub instance_id: uuid::Uuid,
    pub state: ServiceState,
    pub ready: bool,
    pub listen_address: std::net::SocketAddrV4,
    #[serde(default = "default_timezone")]
    pub timezone: chrono_tz::Tz,
    pub active_node: Option<ActiveNode>,
    pub last_exit_check: Option<ActiveCheckSummary>,
    pub source: SourceSummary,
    pub candidates: CandidateSummary,
    pub connections: Connections,
    pub last_switch_reason: Option<String>,
    pub last_error: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Status,
    Stop,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub schema_version: u32,
    pub command: Operation,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResponse {
    Status {
        status: Box<StatusSnapshot>,
    },
    Accepted {
        instance_id: uuid::Uuid,
        shutdown_timeout_seconds: u64,
    },
    Error {
        message: String,
    },
}
pub async fn read_control<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let length = stream.read_u32().await? as usize;
        ensure!(length > 0 && length <= MAX_CONTROL_BYTES, "控制帧长度无效");
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("控制帧格式或版本无效"))
    })
    .await
    .map_err(|_| anyhow::anyhow!("控制帧读取超时"))?
}
pub async fn write_control<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CONTROL_BYTES,
        "控制响应超过限额"
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("控制帧写入超时"))?
}
pub async fn serve_control(
    listener: UnixListener,
    status: watch::Receiver<StatusSnapshot>,
    quota: Arc<Semaphore>,
    shutdown_seconds: u64,
    active: watch::Sender<Option<crate::socks::ActiveWorker>>,
    cancel: CancellationToken,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(16));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let (mut stream,_)=accepted?;let Ok(permit)=permits.clone().try_acquire_owned()else{continue;};
            let status=status.clone();let quota=quota.clone();let stop=cancel.clone();let active=active.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let request=read_control::<ControlRequest>(&mut stream).await;
                    let request=match request {Ok(request) if request.schema_version==1=>request,_=>{let _=write_control(&mut stream,&ControlResponse::Error {message:"控制帧格式、版本或长度无效".into()}).await;return;}};
                    match request.command {
                        Operation::Status=>{
                            let mut snapshot=status.borrow().clone();snapshot.connections.current=snapshot.connections.limit.saturating_sub(quota.available_permits());
                            let _=write_control(&mut stream,&ControlResponse::Status {status:Box::new(snapshot)}).await;
                        },
                        Operation::Stop=>{
                            let id=status.borrow().instance_id;
                        if write_control(&mut stream,&ControlResponse::Accepted {instance_id:id,shutdown_timeout_seconds:shutdown_seconds}).await.is_ok() {crate::service::revoke_active(&active);stop.cancel();}
                        },
                    }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CliFailure {
    pub code: u8,
    pub message: String,
}
fn communication(error: anyhow::Error) -> CliFailure {
    CliFailure {
        code: 1,
        message: format!("本地控制通信失败：{error}"),
    }
}
fn cleanup(message: &str) -> CliFailure {
    CliFailure {
        code: 4,
        message: message.into(),
    }
}
fn validate_runtime(runtime: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(runtime)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o007 == 0,
        "运行目录须为私有普通目录"
    );
    let socket = std::fs::symlink_metadata(runtime.join("control.sock"))?;
    ensure!(
        socket.file_type().is_socket() && socket.permissions().mode() & 0o007 == 0,
        "控制路径须为私有套接字"
    );
    Ok(())
}
async fn request(runtime: &Path, command: Operation) -> Result<ControlResponse> {
    validate_runtime(runtime)?;
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut stream = UnixStream::connect(runtime.join("control.sock")).await?;
        write_control(
            &mut stream,
            &ControlRequest {
                schema_version: 1,
                command,
            },
        )
        .await?;
        read_control(&mut stream).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("本地控制请求超时"))?
}
pub async fn status(
    runtime: &Path,
    json: bool,
    check_ready: bool,
) -> std::result::Result<u8, CliFailure> {
    let response = request(runtime, Operation::Status)
        .await
        .map_err(communication)?;
    let ControlResponse::Status { status } = response else {
        return Err(communication(anyhow::anyhow!("状态响应类型无效")));
    };
    if status.schema_version != 1 {
        return Err(communication(anyhow::anyhow!("状态模式版本不支持")));
    }
    if json {
        println!(
            "{}",
            serde_json::to_string(&status).map_err(|e| communication(e.into()))?
        );
    } else {
        let state = match status.state {
            ServiceState::Starting => "正在启动",
            ServiceState::Fetching => "正在获取来源",
            ServiceState::Validating => "正在验证节点",
            ServiceState::Ready => "已就绪",
            ServiceState::Waiting => "等待可用节点",
            ServiceState::Switching => "正在恢复出口",
            ServiceState::Stopping => "正在停止",
            ServiceState::Stopped => "已停止",
        };
        println!(
            "状态：{state}\n监听地址：{}\n代理就绪：{}\n连接：{}/{}\n候选：总计 {}，可用 {}，过期 {}，未检测 {}",
            status.listen_address,
            if status.ready { "是" } else { "否" },
            status.connections.current,
            status.connections.limit,
            status.candidates.total,
            status.candidates.available,
            status.candidates.expired,
            status.candidates.not_tested
        );
        if let Some(check) = &status.last_exit_check {
            let at = check.finished_at.with_timezone(&status.timezone);
            println!(
                "最近出口检测：{}，{} 次，{} 毫秒，{}",
                at.to_rfc3339(),
                check.attempts,
                check.elapsed_ms,
                if check.success { "成功" } else { "失败" }
            );
        }
        if let Some(reason) = status
            .last_switch_reason
            .as_ref()
            .or(status.last_error.as_ref())
        {
            println!("最近原因：{reason}");
        }
    }
    Ok(if check_ready && !status.ready { 3 } else { 0 })
}
pub async fn stop(runtime: &Path) -> std::result::Result<u8, CliFailure> {
    let started = Instant::now();
    if std::fs::symlink_metadata(runtime).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(0);
    }
    let response = request(runtime, Operation::Stop)
        .await
        .map_err(communication)?;
    let ControlResponse::Accepted {
        instance_id,
        shutdown_timeout_seconds,
    } = response
    else {
        return Err(communication(anyhow::anyhow!("停止响应类型无效")));
    };
    let deadline = started
        .checked_add(Duration::from_secs(shutdown_timeout_seconds))
        .ok_or_else(|| cleanup("停止预算无效"))?;
    loop {
        match std::fs::symlink_metadata(runtime) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("实例已停止，资源已回收");
                return Ok(0);
            }
            Ok(metadata) if metadata.is_dir() => {}
            _ => return Err(cleanup("停止期间运行目录归属发生变化")),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(cleanup("停止超时或资源清理失败，请检查本实例运行目录"));
        }
        if let Ok(Ok(ControlResponse::Status { status })) = tokio::time::timeout(
            remaining.min(IO_TIMEOUT),
            request(runtime, Operation::Status),
        )
        .await
            && status.instance_id != instance_id
        {
            return Err(cleanup("运行目录已属于其他实例，停止轮询已结束"));
        }
        tokio::time::sleep(
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
}
