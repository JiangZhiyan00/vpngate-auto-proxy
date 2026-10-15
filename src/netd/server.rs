//! 私有特权协议服务；请求没有任意命令、文件路径或远端替换操作。
use super::{protocol::*, system::CONTROL_UID, workers::WorkerManager};
use crate::domain::*;
use anyhow::{Context, Result, ensure};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub async fn serve(
    listener: UnixListener,
    manager: Arc<WorkerManager>,
    executable: PathBuf,
    max_connections: usize,
    max_requests: usize,
    tunnel_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let quota = Arc::new(Semaphore::new(max_requests));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let (mut stream,_)=accepted?;
                let peer=stream.peer_cred()?;
                if ![0,CONTROL_UID].contains(&peer.uid()) {continue;}
                let Ok(permit)=quota.clone().try_acquire_owned() else {continue;};
                let manager=manager.clone();let executable=executable.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let Ok(Ok(request))=tokio::time::timeout(Duration::from_secs(5),read_frame::<NetdRequest>(&mut stream)).await else {return;};
                    let response=dispatch(request,&mut stream,&manager,&executable,max_connections,tunnel_timeout).await.unwrap_or_else(|error| {
                        let message=error.to_string();
                        let code=if message.contains("清理") {"cleanup_failed"} else if message.contains("系统命令") || message.contains("资源清单") || message.contains("归属") {"system_failed"} else if message.contains("端口不可达") {"port_failed"} else {"tunnel_failed"};
                        if matches!(code,"port_failed"|"tunnel_failed") && let Some(failure)=error.downcast_ref::<super::workers::StageFailure>() {
                            return NetdResponse::WorkerFailed {checks:failure.checks.clone()};
                        }
                        NetdResponse::Error {code:code.into(),message:match code {"cleanup_failed"=>"工作资源回收失败", "system_failed"=>"系统隔离或资源归属检查失败", "port_failed"=>"节点端口不可达", _=>"节点配置或隧道建立失败"}.into()}
                    });
                    let _=tokio::time::timeout(Duration::from_secs(5),write_frame(&mut stream,&response)).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn dispatch(
    request: NetdRequest,
    stream: &mut UnixStream,
    manager: &WorkerManager,
    executable: &std::path::Path,
    max_connections: usize,
    tunnel_timeout: Duration,
) -> Result<NetdResponse> {
    let instance = match &request {
        NetdRequest::Ping { instance_id }
        | NetdRequest::StartWorker { instance_id, .. }
        | NetdRequest::StopWorker { instance_id, .. }
        | NetdRequest::WorkerStatus { instance_id, .. }
        | NetdRequest::PromoteWorker { instance_id, .. } => *instance_id,
    };
    ensure!(instance == manager.instance_id, "实例归属不一致");
    match request {
        NetdRequest::Ping { .. } => Ok(NetdResponse::Pong),
        NetdRequest::StartWorker {
            worker_id,
            node_id,
            endpoint,
            profile,
            connect_timeout_ms,
            role,
            ..
        } => {
            ensure!(
                connect_timeout_ms > 0
                    && u128::from(connect_timeout_ms) == tunnel_timeout.as_millis(),
                "连接时限与实例配置不一致"
            );
            let node = VpnNode {
                id: node_id,
                endpoint,
                profile_digest: blake3::hash(profile.as_bytes()).to_hex().to_string(),
                profile,
                source_hostname: String::new(),
                country: String::new(),
                source_fetched_at: chrono::Utc::now(),
                present: true,
                last_attempt_at: None,
            };
            let operation = async {
                let slot = manager.start_tunnel(worker_id, &node, role).await?;
                let socket = {
                    let mut worker = slot.worker.lock().await;
                    worker.attach_socks(executable, max_connections + 8)?;
                    worker.record.socket_path.clone()
                };
                loop {
                    let mut worker = slot.worker.lock().await;
                    ensure!(worker.structurally_ready().await?, "业务工作进程提前退出");
                    if socket.exists() {
                        return Ok::<_, anyhow::Error>(NetdResponse::WorkerStarted {
                            socks_socket: socket,
                            worker: Box::new(worker.record.clone()),
                            port_result: Box::new(worker.port_result.clone()),
                            tunnel_result: Box::new(
                                worker.tunnel_result.clone().context("缺少隧道验证摘要")?,
                            ),
                        });
                    }
                    drop(worker);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            };
            let deadline = Instant::now() + tunnel_timeout;
            let result = tokio::select! {
                result=tokio::time::timeout_at(deadline,operation)=>result.unwrap_or_else(|_|Err(anyhow::anyhow!("隧道建立总时限耗尽"))),
                _=stream.read_u8()=>Err(anyhow::anyhow!("辅助调用方已断开或发送多余数据")),
            };
            let checks = if result.is_err() {
                if let Some(slot) = manager.get(worker_id).await {
                    Some(
                        slot.worker
                            .lock()
                            .await
                            .failed_checks(deadline, tunnel_timeout),
                    )
                } else {
                    None
                }
            } else {
                None
            };
            if result.is_err() {
                manager
                    .stop(worker_id, Instant::now() + Duration::from_secs(10))
                    .await
                    .context("失败工作资源清理失败")?;
            }
            match (result, checks) {
                (Err(cause), Some(checks)) => {
                    Err(super::workers::StageFailure { checks, cause }.into())
                }
                (result, _) => result,
            }
        }
        NetdRequest::StopWorker { worker_id, .. } => {
            manager
                .stop(worker_id, Instant::now() + Duration::from_secs(10))
                .await?;
            Ok(NetdResponse::Stopped)
        }
        NetdRequest::WorkerStatus { worker_id, .. } => {
            let ready = if let Some(slot) = manager.get(worker_id).await {
                tokio::time::timeout(Duration::from_millis(800), async {
                    slot.worker.lock().await.structurally_ready().await
                })
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false)
            } else {
                false
            };
            Ok(NetdResponse::WorkerStatus { ready })
        }
        NetdRequest::PromoteWorker { worker_id, .. } => {
            let slot = manager.get(worker_id).await.context("工作进程不存在")?;
            slot.worker.lock().await.promote()?;
            Ok(NetdResponse::Pong)
        }
    }
}
