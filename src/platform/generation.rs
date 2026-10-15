//! 工作代际的撤销原型；尚未接入服务，不代表接口复用或进程隔离防护完成。
use std::{future::Future, io, os::fd::OwnedFd, sync::Arc};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct State {
    id: Uuid,
    cancelled: CancellationToken,
    // 登记操作共享读锁；只有等待它们全部释放的退休方可关闭持有句柄。
    operations: RwLock<Option<OwnedFd>>,
}

/// 由监督方独占；业务方只得到可复制、不可重新启用的引用。
pub struct WorkerGeneration(Arc<State>);
#[derive(Clone)]
pub struct WorkerLease(Arc<State>);
/// 仅说明已登记操作均已释放，不证明操作系统子进程已经退出。
#[derive(Debug)]
pub struct RetiredGeneration(Uuid);

impl WorkerGeneration {
    /// 持有由平台后端校验并授权的描述符；来源与接口身份由调用方验证。
    pub fn with_custody(descriptor: OwnedFd) -> Self {
        Self::create(Some(descriptor))
    }
    pub fn new() -> Self {
        Self::create(None)
    }
    fn create(custody: Option<OwnedFd>) -> Self {
        Self(Arc::new(State {
            id: Uuid::new_v4(),
            cancelled: CancellationToken::new(),
            operations: RwLock::new(custody),
        }))
    }
    pub fn lease(&self) -> WorkerLease {
        WorkerLease(self.0.clone())
    }
    pub fn revoke(&self) {
        self.0.cancelled.cancel();
    }
    /// 先永久撤销，再等待所有登记操作的异步体被释放。
    /// 调用方可施加总时限；等待被取消不会重新开放本代际。
    pub async fn retire(&self) -> RetiredGeneration {
        self.revoke();
        let mut exclusive = self.0.operations.write().await;
        drop(exclusive.take());
        RetiredGeneration(self.0.id)
    }
}
impl Drop for WorkerGeneration {
    fn drop(&mut self) {
        // 析构不能异步等待操作退出。句柄随共享状态保留，不能在此提前关闭。
        self.revoke();
    }
}
impl Default for WorkerGeneration {
    fn default() -> Self {
        Self::new()
    }
}
impl RetiredGeneration {
    pub fn id(&self) -> Uuid {
        self.0
    }
}
impl WorkerLease {
    pub fn id(&self) -> Uuid {
        self.0.id
    }
    /// 操作必须拥有其套接字与资源，取消时同步释放；不得派生未登记任务、
    /// 将资源存入外部容器或返回可继续执行网络操作的句柄。
    /// 本约束需要工作进程封装保证，此原型自身不是权限或沙箱边界。
    pub async fn execute<F, Fut, T>(&self, operation: F) -> io::Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let interrupted = || io::Error::new(io::ErrorKind::Interrupted, "工作代际已撤销");
        let _admission = tokio::select! {
            biased;
            _ = self.0.cancelled.cancelled() => return Err(interrupted()),
            guard = self.0.operations.read() => guard,
        };
        // 将构造也放在异步体内，保证已撤销时不调用操作工厂。
        // select 的异步体先释放，之后才释放 admission，退休确认不会越过资源析构。
        tokio::select! {
            biased;
            _ = self.0.cancelled.cancelled() => Err(interrupted()),
            result = async { operation().await } => result,
        }
    }
}
