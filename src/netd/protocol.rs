//! 长度前缀帧读写裁剪自固定上游提交；请求仅允许受控操作。
use crate::domain::{CheckResult, Endpoint, NodeId, WorkerId, WorkerRecord, WorkerRole};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{io, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use uuid::Uuid;
pub const MAX_FRAME_BYTES: usize = 512 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetdRequest {
    Ping {
        instance_id: Uuid,
    },
    StartWorker {
        instance_id: Uuid,
        worker_id: WorkerId,
        node_id: NodeId,
        endpoint: Endpoint,
        profile: String,
        connect_timeout_ms: u64,
        role: WorkerRole,
    },
    StopWorker {
        instance_id: Uuid,
        worker_id: WorkerId,
    },
    WorkerStatus {
        instance_id: Uuid,
        worker_id: WorkerId,
    },
    PromoteWorker {
        instance_id: Uuid,
        worker_id: WorkerId,
    },
}
impl std::fmt::Debug for NetdRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ping { .. } => "Ping（身份省略）",
            Self::StartWorker { .. } => "StartWorker（私有连接资料省略）",
            Self::StopWorker { .. } => "StopWorker（身份省略）",
            Self::WorkerStatus { .. } => "WorkerStatus（身份省略）",
            Self::PromoteWorker { .. } => "PromoteWorker（身份省略）",
        })
    }
}

pub fn bind_private_socket(path: &std::path::Path) -> anyhow::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("套接字目录缺失"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o750,
        "套接字目录须为权限 0750 的普通目录"
    );
    anyhow::ensure!(!path.exists(), "套接字路径已存在，拒绝替换");
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetdResponse {
    Pong,
    WorkerStarted {
        socks_socket: PathBuf,
        worker: Box<WorkerRecord>,
        port_result: Box<CheckResult>,
        tunnel_result: Box<CheckResult>,
    },
    Stopped,
    WorkerFailed {
        checks: Vec<CheckResult>,
    },
    WorkerStatus {
        ready: bool,
    },
    Error {
        code: String,
        message: String,
    },
}
#[derive(Clone)]
pub struct NetdClient {
    pub socket_path: PathBuf,
    pub instance_id: Uuid,
}
impl NetdClient {
    pub async fn request(
        &self,
        request: NetdRequest,
        timeout: Duration,
    ) -> anyhow::Result<NetdResponse> {
        tokio::time::timeout(timeout, async {
            let mut stream = UnixStream::connect(&self.socket_path).await?;
            write_frame(&mut stream, &request).await?;
            Ok::<_, anyhow::Error>(read_frame(&mut stream).await?)
        })
        .await
        .map_err(|_| anyhow::anyhow!("辅助进程请求超时"))?
    }
}
pub async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "帧长度超限"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
pub async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "帧长度超限"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}
