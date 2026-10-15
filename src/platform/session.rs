//! 隧道、管理会话与业务子进程的联合监督；不代表出口已经通过业务验证。
use std::{io, net::Ipv4Addr, time::Duration};
use tokio::{net::UnixStream, process::Child, sync::oneshot};
use tokio_util::sync::CancellationToken;

use super::{
    management::{self, ConnectedTunnel, TunnelPeer},
    supervisor::{ManagedMacWorker, force_reap},
    tunnel::{ManagedMacTunnel, ManagementPath},
};

pub struct CoupledMacGeneration {
    worker: ManagedMacWorker,
    management: Option<UnixStream>,
    tunnel: Child,
    tunnel_uid: u32,
    remote: Ipv4Addr,
    startup_budget: Duration,
    exit_budget: Duration,
    management_path: Option<ManagementPath>,
}

impl CoupledMacGeneration {
    #[cfg(test)]
    pub(crate) fn test_exit_budget(&mut self, budget: Duration) {
        self.exit_budget = budget;
    }
    /// 仅接收调用方直接启动并持续持有的隧道子进程及其管理连接。
    /// 私有工作进程已经就绪，但必须继续核验路由、业务及解析后才能发布活动出口。
    pub fn new(
        worker: ManagedMacWorker,
        tunnel: Child,
        management: UnixStream,
        tunnel_uid: u32,
        remote: Ipv4Addr,
        startup_budget: Duration,
    ) -> Self {
        Self {
            worker,
            tunnel,
            management: Some(management),
            tunnel_uid,
            remote,
            startup_budget,
            exit_budget: Duration::from_secs(2),
            management_path: None,
        }
    }

    /// 接入已通过串行桥接启动并核验直属管理端的隧道，移交全部资源归属。
    /// 管理状态与出口仍须验证；业务与隧道应来自同一次可信接口创建流程。
    pub async fn from_tunnel(
        mut worker: ManagedMacWorker,
        mut tunnel: ManagedMacTunnel,
        startup_budget: Duration,
    ) -> io::Result<Self> {
        let validation = (|| {
            if tunnel.requires_configuration() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拓扑通知隧道不能接入旧连接状态会话",
                ));
            }
            if worker.interface_index() != tunnel.interface_index() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "业务与隧道不属于同一接口",
                ));
            }
            if startup_budget.is_zero() || startup_budget > Duration::from_secs(120) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "联合监督启动截止无效",
                ));
            }
            tunnel.ensure_running()
        })();
        if let Err(error) = validation {
            // 接入被拒绝时，仍须等两侧回收；任何一步失败不能跳过另一侧。
            let worker_result = worker.retire().await;
            let tunnel_result = tunnel.retire().await;
            let mut details = vec![error.to_string()];
            for (stage, result) in [("业务退休", worker_result), ("隧道回收", tunnel_result)]
            {
                if let Err(cleanup) = result {
                    details.push(format!("{stage}：{cleanup}"));
                }
            }
            return Err(io::Error::new(error.kind(), details.join("；")));
        }
        let remote = tunnel.remote_address();
        let (child, management, path, uid) = tunnel.into_parts()?;
        let mut session = Self::new(worker, child, management, uid, remote, startup_budget);
        session.management_path = Some(path);
        Ok(session)
    }

    /// 独占整个生命周期。取消已经运行的未来会关闭控制端并终止直属子进程；
    /// 完整回收成功须等待正常返回，取消本身不等同于已回收。
    pub async fn run(
        mut self,
        connected: oneshot::Sender<ConnectedTunnel>,
        stop: CancellationToken,
    ) -> io::Result<()> {
        let outcome = async {
            let pid = self.tunnel.id().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "隧道子进程已经退出")
            })?;
            let stream = self.management.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "隧道管理通道缺失")
            })?;
            let revoked = CancellationToken::new();
            let (ready, mut receiver) = oneshot::channel();
            let managing = management::supervise(
                stream,
                TunnelPeer { pid, uid: self.tunnel_uid },
                self.startup_budget,
                ready,
                revoked,
            );
            tokio::pin!(managing);
            let mut connected = Some(connected);
            loop {
                tokio::select! {
                    biased;
                    result = self.worker.wait_for_exit() => {
                        result?;
                        break Err(io::Error::new(io::ErrorKind::BrokenPipe, "业务子进程意外退出"));
                    }
                    result = self.tunnel.wait() => {
                        result?;
                        break Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道子进程意外退出"));
                    }
                    _ = stop.cancelled() => break Ok(()),
                    result = &mut managing => {
                        break result.and_then(|()| Err(io::Error::new(
                            io::ErrorKind::BrokenPipe, "隧道管理会话意外结束")));
                    }
                    detail = &mut receiver, if connected.is_some() => {
                        let detail = detail.map_err(|_| io::Error::new(
                            io::ErrorKind::BrokenPipe, "隧道连接材料未确认"))?;
                        if detail.remote_address != self.remote {
                            break Err(io::Error::new(io::ErrorKind::InvalidData, "隧道远端与授权端点不符"));
                        }
                        connected.take().expect("已检查连接确认通道").send(detail)
                            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "连接材料接收方已经退出"))?;
                    }
                }
            }
            // 管理未来在此作用域结束时关闭连接，先于两种子进程的回收等待。
        }.await;
        // 两步都必须尝试；业务退休失败不能跳过隧道回收。
        let worker = self.worker.retire().await;
        let tunnel = match tokio::time::timeout(self.exit_budget, self.tunnel.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(_)) => Err(io::Error::other("隧道退出状态异常")),
            result => {
                let error = match result {
                    Ok(Err(error)) => error,
                    Err(_) => io::Error::new(io::ErrorKind::TimedOut, "隧道管理断开后退出超时"),
                    _ => unreachable!(),
                };
                match force_reap(&mut self.tunnel, self.exit_budget).await {
                    Ok(_) => Err(error),
                    Err(reap) => Err(io::Error::new(
                        reap.kind(),
                        format!("{error}；强制回收：{reap}"),
                    )),
                }
            }
        };
        let mut errors = Vec::new();
        let path = self
            .management_path
            .as_mut()
            .map_or(Ok(()), ManagementPath::remove);
        for (stage, result) in [
            ("联合监督", outcome),
            ("业务退休", worker),
            ("隧道回收", tunnel),
            ("管理端点清理", path),
        ] {
            if let Err(error) = result {
                errors.push((error.kind(), format!("{stage}：{error}")));
            }
        }
        if let Some((kind, _)) = errors.first() {
            Err(io::Error::new(
                *kind,
                errors
                    .iter()
                    .map(|(_, message)| message.as_str())
                    .collect::<Vec<_>>()
                    .join("；"),
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for CoupledMacGeneration {
    fn drop(&mut self) {
        self.worker.close_control();
        self.management.take();
        // 异常丢弃不能异步等待；正常路径在返回前显式等待两种直属子进程。
        let _ = self.tunnel.start_kill();
    }
}
