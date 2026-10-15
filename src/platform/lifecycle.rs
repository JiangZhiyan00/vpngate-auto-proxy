//! 服务编排拥有的代际任务；就绪只提供验证入口，不发布活动出口。
use super::{
    bootstrap::{self, MacGenerationRequest},
    management::InterfaceMaterial,
    prepared::PreparedMacGeneration,
};
use std::{future::Future, io, path::Path};
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// 不复制控制句柄的检测会话。存活期间占用回收登记，防止停止与后续检测派生竞争。
pub(crate) struct MacExitSession {
    socket: std::path::PathBuf,
    generation: Uuid,
    credentials: super::supervisor::WorkerCredentials,
    revoked: CancellationToken,
    owner_stop: CancellationToken,
    probes: super::exit_probe::ProbeRegistry,
    _reservation: super::exit_probe::ProbeActivity,
}
impl MacExitSession {
    pub(crate) fn generation(&self) -> Uuid {
        self.generation
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.revoked.clone()
    }
    pub(crate) async fn check(
        &self,
        settings: super::exit_probe::ExitProbeSettings,
        stop: CancellationToken,
    ) -> io::Result<crate::probe::ProbeReport> {
        if self.owner_stop.is_cancelled() || self.revoked.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "检测会话所属代际已撤销",
            ));
        }
        let failure = self.revoked.clone().drop_guard();
        let result = super::exit_probe::check(
            self.socket.clone(),
            self.generation,
            self.credentials,
            settings,
            self.revoked.clone(),
            stop,
            self.probes.start(),
        )
        .await;
        if result.as_ref().is_ok_and(|report| report.success)
            && !self.owner_stop.is_cancelled()
            && !self.revoked.is_cancelled()
        {
            failure.disarm();
            result
        } else if result.as_ref().is_ok_and(|report| report.success) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "检测结束时所属代际已撤销",
            ))
        } else {
            result
        }
    }
}

#[derive(Clone)]
struct Completion(Option<(io::ErrorKind, String)>);
impl Completion {
    fn from_join(result: Result<io::Result<()>, tokio::task::JoinError>) -> Self {
        Self(match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some((error.kind(), error.to_string())),
            Err(error) => Some((io::ErrorKind::Other, format!("代际监督任务失败：{error}"))),
        })
    }
    fn result(&self) -> io::Result<()> {
        match &self.0 {
            None => Ok(()),
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
        }
    }
}

/// 不可复制的服务侧所有者。丢弃取消监督并释放材料，但不终止仍在执行回收的任务。
/// 显式 shutdown 才能取得回收结果；外层运行时须保持存活直到回收完成。
pub struct MacGenerationHandle {
    cleanup: bootstrap::CleanupStatus,
    probes: super::exit_probe::ProbeRegistry,
    credentials: Option<super::supervisor::WorkerCredentials>,
    stop: CancellationToken,
    receiver: Option<oneshot::Receiver<PreparedMacGeneration>>,
    material: Option<PreparedMacGeneration>,
    task: Option<JoinHandle<io::Result<()>>>,
    completion: Option<Completion>,
}
impl MacGenerationHandle {
    #[cfg(test)]
    pub(super) fn test_launch<F, R>(parent_stop: &CancellationToken, run: R) -> Self
    where
        R: FnOnce(oneshot::Sender<PreparedMacGeneration>, CancellationToken) -> F,
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        Self::launch(parent_stop, run)
    }
    #[cfg(test)]
    pub(super) fn test_unconfirmed_cleanup(&self) {
        self.cleanup.unknown();
    }
    #[cfg(test)]
    pub(super) fn test_probe_credentials(&mut self) {
        self.credentials = Some(super::supervisor::WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        });
    }
    /// 派生本进程内监督任务；实际特权及部署检查仍由正式启动链执行。
    pub fn spawn(
        request: MacGenerationRequest,
        peers: Vec<InterfaceMaterial>,
        parent_stop: &CancellationToken,
    ) -> Self {
        Self::spawn_with_lease(request, peers, parent_stop, None)
    }
    pub(super) fn spawn_with_lease(
        request: MacGenerationRequest,
        peers: Vec<InterfaceMaterial>,
        parent_stop: &CancellationToken,
        lease: Option<std::sync::Arc<super::lease::ConsumerLease>>,
    ) -> Self {
        let credentials = request.credentials;
        let cleanup = bootstrap::CleanupStatus::default();
        let tracking = cleanup.clone();
        let probes = super::exit_probe::ProbeRegistry::with_lease(lease.clone());
        let registry = probes.clone();
        let mut handle = Self::launch(parent_stop, move |ready, stop| {
            bootstrap::run_tracked_with_lease(
                request,
                peers,
                ready,
                stop,
                tracking,
                lease,
                Some(registry),
            )
        });
        handle.cleanup = cleanup;
        handle.credentials = Some(credentials);
        handle.probes = probes;
        handle
    }
    fn launch<F, R>(parent_stop: &CancellationToken, run: R) -> Self
    where
        R: FnOnce(oneshot::Sender<PreparedMacGeneration>, CancellationToken) -> F,
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        let stop = parent_stop.child_token();
        let (sender, receiver) = oneshot::channel();
        let (prepared, preparation) = oneshot::channel();
        let future = run(prepared, stop.clone());
        let finished = stop.clone();
        let task = tokio::spawn(async move {
            // 正常结束、错误或任务展开均停止任何仍持有的上层引用。
            let _finished = finished.clone().drop_guard();
            tokio::pin!(future);
            let invalidated = tokio::select! {
                biased;
                result = &mut future => return result,
                material = preparation => match material {
                    Ok(material) => {
                        let invalidated = material.cancellation().drop_guard();
                        if sender.send(material).is_err() { finished.cancel(); }
                        Some(invalidated)
                    }
                    Err(_) => None,
                },
            };
            // 所有者仍存活时监督错误也必须撤销已交付的令牌，不能只依靠材料 Drop。
            let _invalidated = invalidated;
            future.await
        });
        Self {
            cleanup: bootstrap::CleanupStatus::default(),
            probes: super::exit_probe::ProbeRegistry::default(),
            credentials: None,
            stop,
            receiver: Some(receiver),
            material: None,
            task: Some(task),
            completion: None,
        }
    }
    /// 可取消后重试的就绪等待；未来被丢弃不丢弃所有者或监督任务。
    pub async fn wait_ready(&mut self) -> io::Result<()> {
        if self.is_live() {
            return Ok(());
        }
        if self.material.is_some() || self.completion.is_some() || self.stop.is_cancelled() {
            return self
                .fail_and_shutdown(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "代际已撤销或结束",
                ))
                .await;
        }
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| io::Error::other("代际就绪接收已结束"))?;
        let task = self
            .task
            .as_mut()
            .ok_or_else(|| io::Error::other("代际监督任务缺失"))?;
        let material = tokio::select! {
            biased;
            _ = self.stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "代际就绪等待已取消")),
            result = task => {
                self.completion = Some(Completion::from_join(result));
                self.task.take();
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "代际监督在交付前结束"))
            }
            result = receiver => result.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "代际未交付就绪材料")),
        };
        match material {
            Ok(material) => {
                self.receiver.take();
                self.material = Some(material);
                if self.is_live() {
                    Ok(())
                } else {
                    self.fail_and_shutdown(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "代际材料交付时已经撤销",
                    ))
                    .await
                }
            }
            Err(error) => self.fail_and_shutdown(error).await,
        }
    }
    async fn fail_and_shutdown(&mut self, error: io::Error) -> io::Result<()> {
        match self.shutdown().await {
            Ok(()) => Err(error),
            Err(cleanup) => Err(io::Error::new(
                cleanup.kind(),
                format!("{error}；代际回收：{cleanup}"),
            )),
        }
    }
    pub fn is_live(&self) -> bool {
        !self.stop.is_cancelled()
            && self.task.as_ref().is_some_and(|task| !task.is_finished())
            && self
                .material
                .as_ref()
                .is_some_and(|material| !material.is_revoked())
    }
    /// 只能在显式停止后使用；确认直属消费者、检测、路由步骤及所属目录回收。
    /// 不证明宿主基线或外部复制件释放，逻辑失败不能替代资源回收凭据。
    pub(crate) fn cleanup_confirmed(&self) -> bool {
        self.task.is_none()
            && self.completion.is_some()
            && self.cleanup.confirmed()
            && self.probes.confirmed()
    }
    fn live_material(&self) -> io::Result<&PreparedMacGeneration> {
        if !self.is_live() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "代际未就绪或已撤销",
            ));
        }
        self.material
            .as_ref()
            .ok_or_else(|| io::Error::other("代际材料缺失"))
    }
    pub fn socket_path(&self) -> io::Result<&Path> {
        Ok(self.live_material()?.socket_path())
    }
    pub fn generation(&self) -> io::Result<Uuid> {
        Ok(self.live_material()?.generation())
    }
    /// 只交付撤销通知，不复制控制句柄或就绪对象。
    pub fn cancellation(&self) -> io::Result<CancellationToken> {
        Ok(self.live_material()?.cancellation())
    }
    /// 配置并存代际所需的核验复制件；调用方仍须及时释放，不能跨退休保留。
    pub fn peer_material(&self) -> io::Result<InterfaceMaterial> {
        self.live_material()?.peer_material()
    }
    pub(crate) fn exit_session(&self) -> io::Result<MacExitSession> {
        let material = self.live_material()?;
        Ok(MacExitSession {
            socket: material.socket_path().to_path_buf(),
            generation: material.generation(),
            credentials: self
                .credentials
                .ok_or_else(|| io::Error::other("正式检测身份缺失"))?,
            revoked: material.cancellation(),
            owner_stop: self.stop.clone(),
            probes: self.probes.clone(),
            _reservation: self.probes.start(),
        })
    }
    /// 候选及活动健康检测复用同一私有工作端；真实请求在独立低权限子进程执行。
    /// 失败、撤销或检测监督错误均撤销代际，调用方仍须显式 shutdown 获取回收证明。
    pub async fn check_exit(
        &self,
        settings: super::exit_probe::ExitProbeSettings,
        stop: CancellationToken,
    ) -> io::Result<crate::probe::ProbeReport> {
        self.exit_session()?.check(settings, stop).await
    }
    /// 先取消并释放所有自有就绪材料，再等待持续监督完成；不对任务调用 abort。
    /// 等待未来被取消后，任务仍保存在本对象内，后续调用继续等待同一任务。
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stop.cancel();
        self.material.take();
        self.receiver.take();
        let probes = self.probes.wait().await;
        if let Some(task) = self.task.as_mut() {
            let result = task.await;
            self.completion = Some(Completion::from_join(result));
            self.task.take();
        }
        let generation = self.completion.as_ref().map_or(Ok(()), Completion::result);
        match (probes, generation) {
            (Ok(()), result) => result,
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(generation)) => {
                Err(io::Error::other(format!("{generation}；检测回收：{error}")))
            }
        }
    }
}
impl Drop for MacGenerationHandle {
    fn drop(&mut self) {
        self.stop.cancel();
        self.material.take();
        self.receiver.take();
        // JoinHandle 丢弃只解除等待；保留运行中的正式回收未来。
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{custody::UtunCustody, management, tunnel::ConfiguredMacInterface};
    use std::{os::unix::net::UnixStream, time::Duration};
    use tokio::sync::oneshot;
    fn material(revoked: CancellationToken) -> (PreparedMacGeneration, UnixStream) {
        let (owner, peer) = UnixStream::pair().unwrap();
        (
            PreparedMacGeneration::test_material(
                ConfiguredMacInterface::test_material(management::test_material(
                    UtunCustody::test_unverified_resource(owner.into()),
                    revoked,
                )),
                "/private/tmp/unused.sock".into(),
            ),
            peer,
        )
    }
    async fn closed(peer: UnixStream) {
        peer.set_nonblocking(true).unwrap();
        let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
        use tokio::io::AsyncReadExt;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[tokio::test]
    async fn shutdown_releases_material_before_waiting_and_is_idempotent() {
        let parent = CancellationToken::new();
        let revoked = CancellationToken::new();
        let (value, peer) = material(revoked.clone());
        let (done, finished) = oneshot::channel();
        let mut handle = MacGenerationHandle::launch(&parent, |ready, stop| async move {
            ready.send(value).ok().unwrap();
            stop.cancelled().await;
            closed(peer).await;
            done.send(()).unwrap();
            Ok(())
        });
        assert!(handle.socket_path().is_err());
        handle.wait_ready().await.unwrap();
        handle.wait_ready().await.unwrap();
        assert!(handle.generation().is_ok());
        let notification = handle.cancellation().unwrap();
        handle.shutdown().await.unwrap();
        finished.await.unwrap();
        assert!(notification.is_cancelled());
        assert!(handle.socket_path().is_err());
        handle.shutdown().await.unwrap();
        assert!(!parent.is_cancelled());
    }
    #[tokio::test]
    async fn cancelled_ready_wait_can_resume_same_supervisor() {
        let (allow, gate) = oneshot::channel();
        let (value, peer) = material(CancellationToken::new());
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                gate.await.unwrap();
                ready.send(value).ok().unwrap();
                stop.cancelled().await;
                closed(peer).await;
                Ok(())
            });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), handle.wait_ready())
                .await
                .is_err()
        );
        allow.send(()).unwrap();
        handle.wait_ready().await.unwrap();
        handle.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn abandoned_owner_keeps_cleanup_running_and_closes_queued_material() {
        for wait_ready in [false, true] {
            let (value, peer) = material(CancellationToken::new());
            let (done, finished) = oneshot::channel();
            let mut handle =
                MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                    let _ = ready.send(value);
                    stop.cancelled().await;
                    closed(peer).await;
                    done.send(()).unwrap();
                    Ok(())
                });
            if wait_ready {
                handle.wait_ready().await.unwrap();
            }
            drop(handle);
            tokio::time::timeout(Duration::from_secs(1), finished)
                .await
                .unwrap()
                .unwrap();
        }
    }
    #[tokio::test]
    async fn cancelled_shutdown_resumes_same_task_and_retains_error() {
        let (value, peer) = material(CancellationToken::new());
        let (allow, gate) = oneshot::channel();
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                ready.send(value).ok().unwrap();
                stop.cancelled().await;
                closed(peer).await;
                gate.await.unwrap();
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "受控回收失败",
                ))
            });
        handle.wait_ready().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), handle.shutdown())
                .await
                .is_err()
        );
        assert!(handle.task.is_some());
        allow.send(()).unwrap();
        for _ in 0..2 {
            let error = handle.shutdown().await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("受控回收失败"));
        }
    }
    #[tokio::test]
    async fn parent_cancellation_during_start_drains_material_and_waits_for_cleanup() {
        let parent = CancellationToken::new();
        let (value, peer) = material(CancellationToken::new());
        let mut handle = MacGenerationHandle::launch(&parent, |ready, stop| async move {
            stop.cancelled().await;
            let _ = ready.send(value);
            closed(peer).await;
            Ok(())
        });
        parent.cancel();
        assert_eq!(
            handle.wait_ready().await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(handle.completion.is_some());
    }
    #[tokio::test]
    async fn ended_or_revoked_generations_never_expose_ready_material() {
        for ended in [false, true] {
            let revoked = CancellationToken::new();
            let (value, peer) = material(revoked.clone());
            let (allow, gate) = oneshot::channel();
            let mut handle =
                MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                    ready.send(value).ok().unwrap();
                    gate.await.unwrap();
                    if ended {
                        return Err(io::Error::other("受控监督退出"));
                    }
                    revoked.cancel();
                    stop.cancelled().await;
                    closed(peer).await;
                    Ok(())
                });
            handle.wait_ready().await.unwrap();
            let token = handle.cancellation().unwrap();
            allow.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while handle.is_live() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(handle.socket_path().is_err());
            assert!(handle.cancellation().is_err());
            assert!(token.is_cancelled());
            assert_eq!(handle.shutdown().await.is_err(), ended);
        }
    }
    #[tokio::test]
    async fn missing_ready_preserves_supervisor_failure() {
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, _| async move {
                drop(ready);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "受控部署拒绝",
                ))
            });
        let error = handle.wait_ready().await.unwrap_err();
        assert!(error.to_string().contains("受控部署拒绝"));
        assert!(handle.shutdown().await.is_err());
    }
    #[tokio::test]
    async fn supervisor_panic_revokes_delivered_notification_without_owner_polling() {
        let (value, peer) = material(CancellationToken::new());
        let (allow, gate) = oneshot::channel();
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, _| async move {
                ready.send(value).ok().unwrap();
                gate.await.unwrap();
                drop(peer);
                panic!("受控监督任务异常");
                #[allow(unreachable_code)]
                Ok(())
            });
        handle.wait_ready().await.unwrap();
        let token = handle.cancellation().unwrap();
        allow.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .unwrap();
        assert!(!handle.is_live());
        assert!(
            handle
                .shutdown()
                .await
                .unwrap_err()
                .to_string()
                .contains("代际监督任务失败")
        );
    }
    #[tokio::test]
    async fn production_handle_runs_the_real_ordinary_user_gate() {
        use super::super::supervisor::WorkerCredentials;
        assert!(!nix::unistd::geteuid().is_root());
        let profile=crate::openvpn::sanitize_openvpn(b"client\ndev tun\nproto tcp\nremote 1.2.3.4 443\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n","1.2.3.4".parse().unwrap()).unwrap();
        let mut handle = MacGenerationHandle::spawn(
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
            },
            Vec::new(),
            &CancellationToken::new(),
        );
        assert!(
            handle
                .wait_ready()
                .await
                .unwrap_err()
                .to_string()
                .contains("代际启动需要管理员身份")
        );
        assert!(!handle.is_live());
        assert!(handle.shutdown().await.is_err());
    }
    #[tokio::test]
    async fn exit_check_deployment_failure_revokes_owned_generation() {
        let (value, peer) = material(CancellationToken::new());
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                ready.send(value).ok().unwrap();
                stop.cancelled().await;
                closed(peer).await;
                Ok(())
            });
        handle.credentials = Some(super::super::supervisor::WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        });
        handle.wait_ready().await.unwrap();
        let revoked = handle.cancellation().unwrap();
        let error = handle
            .check_exit(
                super::super::exit_probe::ExitProbeSettings {
                    urls: vec![url::Url::parse("https://example.com/").unwrap()],
                    max_attempts: 1,
                    budget: Duration::from_secs(1),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(revoked.is_cancelled());
        assert!(!handle.is_live());
        handle.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn shutdown_waits_for_registered_probe_retirement_and_can_resume() {
        let (value, peer) = material(CancellationToken::new());
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                ready.send(value).ok().unwrap();
                stop.cancelled().await;
                closed(peer).await;
                Ok(())
            });
        handle.wait_ready().await.unwrap();
        let activity = handle.probes.start();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), handle.shutdown())
                .await
                .is_err()
        );
        assert!(handle.task.is_some());
        drop(activity);
        handle.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn reserved_session_prevents_cleanup_confirmation_and_rejects_late_checks() {
        let (value, peer) = material(CancellationToken::new());
        let mut handle =
            MacGenerationHandle::launch(&CancellationToken::new(), |ready, stop| async move {
                ready.send(value).ok().unwrap();
                stop.cancelled().await;
                closed(peer).await;
                Ok(())
            });
        handle.test_probe_credentials();
        handle.wait_ready().await.unwrap();
        let session = handle.exit_session().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), handle.shutdown())
                .await
                .is_err()
        );
        assert!(!handle.cleanup_confirmed());
        let error = session
            .check(
                super::super::exit_probe::ExitProbeSettings {
                    urls: vec![url::Url::parse("https://example.com/").unwrap()],
                    max_attempts: 1,
                    budget: Duration::from_secs(1),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        drop(session);
        handle.shutdown().await.unwrap();
        assert!(handle.cleanup_confirmed());
    }
}
