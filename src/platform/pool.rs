//! 特权侧候选代际所有者；不执行来源请求，不自行轮换仍健康的活动出口。
use super::{
    bootstrap::MacGenerationRequest, exit_probe::ExitProbeSettings, lifecycle::MacGenerationHandle,
    supervisor::WorkerCredentials,
};
use crate::{
    domain::{VpnNode, WorkerId},
    openvpn::{self, SanitizedOpenVpn},
    probe::ProbeReport,
    socks::ActiveWorker,
};
use std::{collections::BTreeMap, io, path::PathBuf, time::Duration};
use tokio::{sync::watch, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct MacPoolSettings {
    pub parent: PathBuf,
    pub instance_id: Uuid,
    pub dependency_manifest: PathBuf,
    pub credentials: WorkerCredentials,
    pub startup_budget: Duration,
    pub max_connections: usize,
    /// 候选槽位；活动代际另占一个槽位，回收不明的代际仍占用候选槽位。
    pub candidate_slots: usize,
    pub verification_ttl: Duration,
    pub source_ttl: Duration,
    pub exit: ExitProbeSettings,
}
impl MacPoolSettings {
    fn validate(&self) -> io::Result<()> {
        self.credentials.validate_account()?;
        self.exit.validate()?;
        if !(1..=32).contains(&self.candidate_slots)
            || self.instance_id.is_nil()
            || self.startup_budget.is_zero()
            || self.startup_budget > Duration::from_secs(120)
            || self.max_connections == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.verification_ttl.is_zero()
            || Instant::now().checked_add(self.verification_ttl).is_none()
            || self.source_ttl.is_zero()
            || !self.parent.is_absolute()
            || !self.dependency_manifest.is_absolute()
        {
            return Err(invalid("候选池配置无效或超过上限"));
        }
        Ok(())
    }
}
struct Entry {
    node: VpnNode,
    handle: MacGenerationHandle,
    waiting: bool,
    health: Option<super::health::MacHealthMonitor>,
}
impl Entry {
    async fn shutdown(&mut self) -> io::Result<()> {
        if let Some(health) = &self.health {
            health.cancel();
        }
        let (health, generation) = tokio::join!(
            async {
                match &mut self.health {
                    Some(health) => health.shutdown().await,
                    None => Ok(()),
                }
            },
            self.handle.shutdown()
        );
        match (health, generation) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(health), Err(generation)) => Err(io::Error::other(format!(
                "{generation}；健康调度：{health}"
            ))),
        }
    }
}
/// 只由本池成功检测生成；不支持复制、反序列化或外部构造。
pub struct VerifiedCandidate {
    pool: Uuid,
    worker: WorkerId,
    generation: Uuid,
    digest: String,
    checked: Instant,
}
pub struct CandidateVerification {
    pub report: ProbeReport,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub verified: Option<VerifiedCandidate>,
}
/// 独立检测所有者；丢弃只取消，不中止仍持有会话登记和直属回收凭据的任务。
pub(super) struct OwnedVerification {
    stop: CancellationToken,
    revoked: CancellationToken,
    task: Option<tokio::task::JoinHandle<io::Result<CandidateVerification>>>,
}
impl OwnedVerification {
    fn launch<F, R>(parent: &CancellationToken, revoked: CancellationToken, run: R) -> Self
    where
        F: std::future::Future<Output = io::Result<CandidateVerification>> + Send + 'static,
        R: FnOnce(CancellationToken) -> F,
    {
        let stop = parent.child_token();
        let future = run(stop.clone());
        let failure = revoked.clone().drop_guard();
        Self {
            stop,
            revoked,
            task: Some(tokio::spawn(async move {
                let result = future.await;
                if result
                    .as_ref()
                    .is_ok_and(|value| value.report.success && value.verified.is_some())
                {
                    failure.disarm();
                }
                result
            })),
        }
    }
    pub(super) fn is_finished(&self) -> bool {
        self.task.as_ref().is_some_and(|task| task.is_finished())
    }
    pub(super) async fn wait(&mut self) -> io::Result<CandidateVerification> {
        let task = self
            .task
            .as_mut()
            .ok_or_else(|| invalid("检测结果已取走"))?;
        let result = task.await;
        self.task.take();
        result.map_err(|_| io::Error::other("独立检测任务异常，结果不可采用"))?
    }
    #[cfg(test)]
    pub(super) fn test_launch<F, R>(
        parent: &CancellationToken,
        revoked: CancellationToken,
        run: R,
    ) -> Self
    where
        F: std::future::Future<Output = io::Result<CandidateVerification>> + Send + 'static,
        R: FnOnce(CancellationToken) -> F,
    {
        Self::launch(parent, revoked, run)
    }
}
impl Drop for OwnedVerification {
    fn drop(&mut self) {
        self.stop.cancel();
        if self.task.is_some() {
            self.revoked.cancel();
        }
    }
}
/// 资源确认释放后仍保留原始运行错误；调用方须记录此诊断。
#[derive(Debug)]
pub struct Retirement {
    pub failure: Option<String>,
}
pub struct MacCandidatePool {
    id: Uuid,
    settings: MacPoolSettings,
    entries: BTreeMap<Uuid, Entry>,
    active: watch::Sender<Option<ActiveWorker>>,
    stop: CancellationToken,
    lease: Option<std::sync::Arc<super::lease::ConsumerLease>>,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
impl MacCandidatePool {
    pub(super) fn with_lease(mut self, lease: std::sync::Arc<super::lease::ConsumerLease>) -> Self {
        self.lease = Some(lease);
        self
    }
    #[cfg(test)]
    pub(super) fn test_register_unknown_cleanup(&mut self, node: VpnNode) {
        let handle = MacGenerationHandle::test_launch(&self.stop, |ready, stop| async move {
            drop(ready);
            stop.cancelled().await;
            Ok(())
        });
        handle.test_unconfirmed_cleanup();
        self.entries.insert(
            Uuid::new_v4(),
            Entry {
                node,
                handle,
                waiting: false,
                health: None,
            },
        );
    }
    pub fn new(settings: MacPoolSettings, parent_stop: &CancellationToken) -> io::Result<Self> {
        settings.validate()?;
        Ok(Self {
            id: Uuid::new_v4(),
            settings,
            entries: BTreeMap::new(),
            active: watch::channel(None).0,
            stop: parent_stop.child_token(),
            lease: None,
        })
    }
    /// 接收端必须遵守 ActiveWorker.cancel；监督故障会立即撤销旧引用。
    pub fn subscribe(&self) -> watch::Receiver<Option<ActiveWorker>> {
        self.active.subscribe()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn generation(&self, worker: WorkerId) -> io::Result<Uuid> {
        self.entry(worker)?.handle.generation()
    }
    pub(super) fn worker_socket(&self, worker: WorkerId) -> io::Result<&std::path::Path> {
        self.entry(worker)?.handle.socket_path()
    }
    fn entry(&self, worker: WorkerId) -> io::Result<&Entry> {
        self.entries
            .get(&worker.0)
            .ok_or_else(|| invalid("代际不属于本候选池"))
    }
    fn active_id(&self) -> Option<WorkerId> {
        self.active.borrow().as_ref().map(|a| a.worker_id)
    }
    fn clear_active(&self) {
        if let Some(old) = self.active.send_replace(None) {
            old.cancel.cancel();
        }
    }
    /// 清除已故障的快照；未刷新时旧快照的撤销令牌也禁止继续转发。
    pub fn refresh_active(&mut self) {
        if self.stop.is_cancelled()
            || self
                .active_id()
                .is_some_and(|id| !self.entry(id).is_ok_and(|entry| entry.handle.is_live()))
        {
            self.clear_active();
        }
    }
    pub(super) fn validate_node(&self, node: &VpnNode) -> io::Result<SanitizedOpenVpn> {
        node.validate()
            .map_err(|error| invalid(&error.to_string()))?;
        let age = chrono::Utc::now()
            .signed_duration_since(node.source_fetched_at)
            .to_std()
            .map_err(|_| invalid("节点来源时间位于未来"))?;
        if !node.present || age >= self.settings.source_ttl {
            return Err(invalid("节点来源已失效"));
        }
        openvpn::validate_regenerated(&node.profile, &node.endpoint)
            .map_err(|error| invalid(&error.to_string()))
    }
    fn check_slot(&self, node: &VpnNode) -> io::Result<()> {
        if self.stop.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "候选池已停止"));
        }
        let active = self.active_id();
        if self
            .entries
            .iter()
            .filter(|(id, _)| Some(WorkerId(**id)) != active)
            .count()
            >= self.settings.candidate_slots
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "候选槽位尚未释放",
            ));
        }
        if self.entries.values().any(|entry| entry.node.id == node.id) {
            return Err(invalid("节点已有所属代际"));
        }
        if self
            .entries
            .values()
            .any(|entry| entry.waiting || !entry.handle.is_live())
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "先完成接口配置或回收已失效代际",
            ));
        }
        Ok(())
    }
    /// 先登记所有者再等待就绪；接口配置串行，已就绪代际的检测可以并发。
    pub fn start_candidate(&mut self, node: VpnNode) -> io::Result<WorkerId> {
        self.refresh_active();
        let profile = self.validate_node(&node)?;
        self.check_slot(&node)?;
        let peers = self
            .entries
            .values()
            .map(|entry| entry.handle.peer_material())
            .collect::<io::Result<Vec<_>>>()?;
        let handle = MacGenerationHandle::spawn_with_lease(
            MacGenerationRequest {
                parent: self.settings.parent.clone(),
                instance_id: self.settings.instance_id,
                dependency_manifest: self.settings.dependency_manifest.clone(),
                credentials: self.settings.credentials,
                startup_budget: self.settings.startup_budget,
                max_connections: self.settings.max_connections,
                profile,
            },
            peers,
            &self.stop,
            self.lease.clone(),
        );
        let id = WorkerId::default();
        self.entries.insert(
            id.0,
            Entry {
                node,
                handle,
                waiting: true,
                health: None,
            },
        );
        Ok(id)
    }
    /// 等待被取消后保留同一代际，允许再次等待或显式退休。
    pub async fn wait_ready(&mut self, worker: WorkerId) -> io::Result<()> {
        let entry = self
            .entries
            .get_mut(&worker.0)
            .ok_or_else(|| invalid("代际不属于本候选池"))?;
        entry.handle.wait_ready().await?;
        entry.waiting = false;
        Ok(())
    }
    pub async fn check(
        &self,
        worker: WorkerId,
        stop: CancellationToken,
    ) -> io::Result<CandidateVerification> {
        let entry = self.entry(worker)?;
        let report = entry
            .handle
            .check_exit(self.settings.exit.clone(), stop)
            .await?;
        self.verification(worker, report)
    }
    pub(super) fn begin_check(
        &self,
        worker: WorkerId,
        parent: &CancellationToken,
    ) -> io::Result<OwnedVerification> {
        let entry = self.entry(worker)?;
        let session = entry.handle.exit_session()?;
        let generation = session.generation();
        let pool = self.id;
        let digest = entry.node.profile_digest.clone();
        let settings = self.settings.exit.clone();
        let stopped = self.stop.clone();
        let revoked = session.cancellation();
        Ok(OwnedVerification::launch(
            parent,
            revoked,
            move |stop| async move {
                let report = session.check(settings, stop.clone()).await?;
                let verified = (report.success
                    && !stop.is_cancelled()
                    && !stopped.is_cancelled()
                    && !session.cancellation().is_cancelled())
                .then(|| VerifiedCandidate {
                    pool,
                    worker,
                    generation,
                    digest,
                    checked: Instant::now(),
                });
                Ok(CandidateVerification {
                    report,
                    verified,
                    finished_at: chrono::Utc::now(),
                })
            },
        ))
    }
    /// 活动健康检测独立于候选设置；每个活动代际仅允许一个调度所有者。
    pub fn start_health(
        &mut self,
        worker: WorkerId,
        settings: super::health::MacHealthSettings,
    ) -> io::Result<watch::Receiver<Option<super::health::MacHealthResult>>> {
        self.refresh_active();
        if self.active_id() != Some(worker) {
            return Err(invalid("只有当前活动代际可以启动健康调度"));
        }
        let entry = self
            .entries
            .get_mut(&worker.0)
            .ok_or_else(|| invalid("活动代际缺失"))?;
        if entry.health.is_some() {
            return Err(invalid("活动代际已有健康调度"));
        }
        let monitor =
            super::health::MacHealthMonitor::start(entry.handle.exit_session()?, worker, settings)?;
        let receiver = monitor.subscribe();
        entry.health = Some(monitor);
        Ok(receiver)
    }
    fn verification(
        &self,
        worker: WorkerId,
        report: ProbeReport,
    ) -> io::Result<CandidateVerification> {
        let entry = self.entry(worker)?;
        let verified = if report.success && !self.stop.is_cancelled() {
            Some(VerifiedCandidate {
                pool: self.id,
                worker,
                generation: entry.handle.generation()?,
                digest: entry.node.profile_digest.clone(),
                checked: Instant::now(),
            })
        } else {
            None
        };
        Ok(CandidateVerification {
            report,
            verified,
            finished_at: chrono::Utc::now(),
        })
    }
    /// 不主动替换仍健康的活动代际；必须使用当前来源材料再次核对检测凭据。
    pub fn promote(&mut self, proof: VerifiedCandidate, current: &VpnNode) -> io::Result<()> {
        self.refresh_active();
        self.validate_node(current)?;
        let entry = self.entry(proof.worker)?;
        if self.stop.is_cancelled()
            || self.active_id().is_some()
            || proof.pool != self.id
            || proof.checked.elapsed() >= self.settings.verification_ttl
            || proof.digest != current.profile_digest
            || entry.node.id != current.id
            || entry.node.profile_digest != current.profile_digest
            || entry.waiting
            || entry.handle.generation()? != proof.generation
        {
            return Err(invalid("候选验证已失效或已有活动出口"));
        }
        let active = ActiveWorker {
            socket_path: entry.handle.socket_path()?.to_path_buf(),
            node_id: current.id.clone(),
            worker_id: proof.worker,
            cancel: entry.handle.cancellation()?,
        };
        self.active.send_replace(Some(active));
        Ok(())
    }
    /// 先撤销公开引用；只有直属消费者和所属目录确认回收，才释放槽位。
    pub async fn retire(&mut self, worker: WorkerId) -> io::Result<Retirement> {
        if let Some(health) = &self.entry(worker)?.health {
            health.cancel();
        }
        if self.active_id() == Some(worker) {
            self.clear_active();
        }
        let entry = self
            .entries
            .get_mut(&worker.0)
            .ok_or_else(|| invalid("代际不属于本候选池"))?;
        let result = entry.shutdown().await;
        if !entry.handle.cleanup_confirmed() {
            return Err(io::Error::other(format!(
                "代际回收未确认，保留槽位：{}",
                result
                    .err()
                    .map_or_else(|| "缺少回收凭据".into(), |e| e.to_string())
            )));
        }
        self.entries.remove(&worker.0);
        Ok(Retirement {
            failure: result.err().map(|e| e.to_string()),
        })
    }
    /// 同时取消并等待全部代际，避免逐项等待叠加回收时间；中断后可再次等待。
    pub async fn shutdown(&mut self) -> io::Result<()> {
        for entry in self.entries.values() {
            if let Some(health) = &entry.health {
                health.cancel();
            }
        }
        self.stop.cancel();
        self.clear_active();
        let results =
            futures_util::future::join_all(self.entries.iter_mut().map(|(id, entry)| async move {
                let result = entry.shutdown().await;
                (*id, entry.handle.cleanup_confirmed(), result)
            }))
            .await;
        let mut errors = Vec::new();
        for (id, confirmed, result) in results {
            if confirmed {
                self.entries.remove(&id);
            }
            if let Err(error) = result {
                errors.push(format!("{id}：{error}"));
            }
            if !confirmed {
                errors.push(format!("{id}：回收未确认，保留槽位"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("；")))
        }
    }
}
impl Drop for MacCandidatePool {
    fn drop(&mut self) {
        self.stop.cancel();
        self.clear_active();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        custody::UtunCustody, management, prepared::PreparedMacGeneration,
        tunnel::ConfiguredMacInterface,
    };
    use std::sync::Arc;
    use tokio::sync::{Barrier, oneshot};

    fn settings() -> MacPoolSettings {
        MacPoolSettings {
            parent: "/missing/runtime".into(),
            instance_id: Uuid::new_v4(),
            dependency_manifest: "/missing/dependency".into(),
            credentials: WorkerCredentials {
                uid: nix::unistd::getuid().as_raw(),
                gid: nix::unistd::getgid().as_raw(),
            },
            startup_budget: Duration::from_secs(3),
            max_connections: 5,
            candidate_slots: 2,
            verification_ttl: Duration::from_secs(30),
            source_ttl: Duration::from_secs(300),
            exit: ExitProbeSettings {
                urls: vec![url::Url::parse("https://example.com/").unwrap()],
                max_attempts: 1,
                budget: Duration::from_secs(1),
            },
        }
    }
    fn pool() -> MacCandidatePool {
        MacCandidatePool::new(settings(), &CancellationToken::new()).unwrap()
    }
    fn node(port: u16) -> VpnNode {
        let raw = format!(
            "client\ndev tun\nproto tcp\nremote 1.2.3.4 {port}\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        );
        let profile =
            openvpn::sanitize_openvpn(raw.as_bytes(), "1.2.3.4".parse().unwrap()).unwrap();
        let endpoint = crate::domain::Endpoint {
            ip: *profile.remote().ip(),
            port,
            transport: profile.transport(),
        };
        VpnNode {
            quality: Default::default(),
            id: crate::domain::NodeId::from_endpoint(&endpoint),
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
    // 仅证明普通描述符归属与编排，不将测试材料当作真实隧道身份。
    fn insert(
        pool: &mut MacCandidatePool,
        node: VpnNode,
        gate: Option<oneshot::Receiver<()>>,
        barrier: Option<Arc<Barrier>>,
        fail: bool,
    ) -> WorkerId {
        let (owner, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let material = PreparedMacGeneration::test_material(
            ConfiguredMacInterface::test_material(management::test_material(
                UtunCustody::test_unverified_resource(owner.into()),
                CancellationToken::new(),
            )),
            "/private/tmp/unused.sock".into(),
        );
        let mut handle =
            MacGenerationHandle::test_launch(&pool.stop, move |ready, stop| async move {
                if let Some(gate) = gate {
                    gate.await.unwrap();
                }
                let _ = ready.send(material);
                stop.cancelled().await;
                use tokio::io::AsyncReadExt;
                peer.set_nonblocking(true).unwrap();
                let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
                        .await
                        .unwrap()
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::UnexpectedEof
                );
                if let Some(barrier) = barrier {
                    barrier.wait().await;
                }
                if fail {
                    Err(io::Error::other("受控运行失败，资源已释放"))
                } else {
                    Ok(())
                }
            });
        handle.test_probe_credentials();
        let worker = WorkerId::default();
        pool.entries.insert(
            worker.0,
            Entry {
                node,
                handle,
                waiting: true,
                health: None,
            },
        );
        worker
    }
    fn proof(pool: &MacCandidatePool, worker: WorkerId) -> VerifiedCandidate {
        pool.verification(
            worker,
            ProbeReport {
                success: true,
                attempts: 1,
                status: Some(204),
                failure: None,
                elapsed: Duration::from_millis(1),
            },
        )
        .unwrap()
        .verified
        .unwrap()
    }
    #[test]
    fn invalid_configuration_and_source_are_rejected_before_starting() {
        for slots in [0, 33] {
            let mut config = settings();
            config.candidate_slots = slots;
            assert!(MacCandidatePool::new(config, &CancellationToken::new()).is_err());
        }
        let mut pool = pool();
        for case in 0..5 {
            let mut node = node(443);
            match case {
                0 => node.present = false,
                1 => node.source_fetched_at -= chrono::Duration::seconds(301),
                2 => node.source_fetched_at += chrono::Duration::seconds(30),
                3 => node.profile_digest = "0".repeat(64),
                _ => {
                    node.endpoint.port = 444;
                    node.id = crate::domain::NodeId::from_endpoint(&node.endpoint);
                }
            }
            assert!(pool.start_candidate(node).is_err());
            assert!(pool.is_empty());
        }
    }
    #[tokio::test]
    async fn real_root_gate_failure_releases_slot_but_preserves_diagnostic() {
        assert!(!nix::unistd::geteuid().is_root());
        let mut pool = pool();
        for _ in 0..3 {
            let id = pool.start_candidate(node(443)).unwrap();
            assert!(pool.wait_ready(id).await.is_err());
            assert!(
                pool.retire(id)
                    .await
                    .unwrap()
                    .failure
                    .unwrap()
                    .contains("代际启动需要管理员身份")
            );
            assert!(pool.is_empty());
        }
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn pending_configuration_duplicates_and_slots_are_bounded() {
        let mut pool = pool();
        let (allow, gate) = oneshot::channel();
        let first = insert(&mut pool, node(443), Some(gate), None, false);
        assert_eq!(
            pool.check_slot(&node(444)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pool.wait_ready(first))
                .await
                .is_err()
        );
        allow.send(()).unwrap();
        pool.wait_ready(first).await.unwrap();
        assert!(pool.check_slot(&node(443)).is_err());
        let second = insert(&mut pool, node(444), None, None, false);
        pool.wait_ready(second).await.unwrap();
        assert_eq!(
            pool.check_slot(&node(445)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        pool.promote(proof(&pool, first), &node(443)).unwrap();
        pool.check_slot(&node(445)).unwrap();
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn promotion_rejects_expired_changed_revoked_and_foreign_proofs() {
        let mut pool = pool();
        let id = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(id).await.unwrap();
        for case in 0..6 {
            let mut proof = proof(&pool, id);
            let mut current = node(443);
            match case {
                0 => proof.checked -= Duration::from_secs(31),
                1 => {
                    current.profile = current.profile.replace("CERT", "CHANGED");
                    current.profile_digest = blake3::hash(current.profile.as_bytes())
                        .to_hex()
                        .to_string();
                }
                2 => current.source_fetched_at -= chrono::Duration::seconds(301),
                3 => proof.generation = Uuid::new_v4(),
                4 => proof.pool = Uuid::new_v4(),
                _ => current.present = false,
            }
            assert!(pool.promote(proof, &current).is_err());
            assert!(pool.subscribe().borrow().is_none());
        }
        let proof = proof(&pool, id);
        pool.entry(id)
            .unwrap()
            .handle
            .cancellation()
            .unwrap()
            .cancel();
        assert!(pool.promote(proof, &node(443)).is_err());
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn healthy_active_is_kept_and_fault_revokes_existing_snapshot() {
        let mut pool = pool();
        let first = insert(&mut pool, node(443), None, None, false);
        let second = insert(&mut pool, node(444), None, None, false);
        pool.wait_ready(first).await.unwrap();
        pool.wait_ready(second).await.unwrap();
        pool.promote(proof(&pool, first), &node(443)).unwrap();
        let old = pool.subscribe().borrow().clone().unwrap();
        assert!(pool.promote(proof(&pool, second), &node(444)).is_err());
        old.cancel.cancel();
        pool.refresh_active();
        assert!(pool.subscribe().borrow().is_none());
        pool.promote(proof(&pool, second), &node(444)).unwrap();
        assert!(old.cancel.is_cancelled());
        assert_eq!(
            pool.subscribe().borrow().as_ref().unwrap().worker_id,
            second
        );
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn cancelled_parallel_shutdown_revokes_first_and_resumes_all_consumers() {
        let mut pool = pool();
        let barrier = Arc::new(Barrier::new(3));
        let first = insert(&mut pool, node(443), None, Some(barrier.clone()), false);
        let second = insert(&mut pool, node(444), None, Some(barrier.clone()), false);
        pool.wait_ready(first).await.unwrap();
        pool.wait_ready(second).await.unwrap();
        pool.promote(proof(&pool, first), &node(443)).unwrap();
        let old = pool.subscribe().borrow().clone().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pool.shutdown())
                .await
                .is_err()
        );
        assert!(old.cancel.is_cancelled());
        assert!(pool.subscribe().borrow().is_none());
        assert_eq!(pool.len(), 2);
        // 两个任务均须先抵达回收屏障；串行停止会在这里超时。
        tokio::time::timeout(Duration::from_secs(1), barrier.wait())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), pool.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(pool.is_empty());
        assert!(pool.start_candidate(node(445)).is_err());
    }
    #[tokio::test]
    async fn retirement_distinguishes_logical_failure_and_unknown_cleanup() {
        let mut pool = pool();
        let failed = insert(&mut pool, node(443), None, None, true);
        pool.wait_ready(failed).await.unwrap();
        assert!(
            pool.retire(failed)
                .await
                .unwrap()
                .failure
                .unwrap()
                .contains("资源已释放")
        );
        assert!(pool.is_empty());
        let unknown = insert(&mut pool, node(444), None, None, false);
        pool.wait_ready(unknown).await.unwrap();
        pool.entries
            .get(&unknown.0)
            .unwrap()
            .handle
            .test_unconfirmed_cleanup();
        for _ in 0..2 {
            assert!(
                pool.retire(unknown)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("回收未确认")
            );
        }
        assert_eq!(pool.len(), 1);
        assert!(pool.check_slot(&node(445)).is_err());
        assert!(pool.shutdown().await.is_err());
        assert_eq!(pool.len(), 1);
    }
    #[tokio::test]
    async fn dropping_pool_revokes_live_gateway_snapshot() {
        let mut pool = pool();
        let barrier = Arc::new(Barrier::new(2));
        let id = insert(&mut pool, node(443), None, Some(barrier.clone()), false);
        pool.wait_ready(id).await.unwrap();
        pool.promote(proof(&pool, id), &node(443)).unwrap();
        let old = pool.subscribe().borrow().clone().unwrap();
        drop(pool);
        assert!(old.cancel.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), barrier.wait())
            .await
            .unwrap();
    }
    fn health_settings() -> super::super::health::MacHealthSettings {
        super::super::health::MacHealthSettings {
            interval: Duration::from_secs(10),
            exit: super::super::exit_probe::ExitProbeSettings {
                urls: vec![url::Url::parse("https://example.com/").unwrap()],
                max_attempts: 1,
                budget: Duration::from_secs(5),
            },
        }
    }
    #[tokio::test]
    async fn health_admission_requires_current_active_and_rejects_duplicate_owner() {
        let mut pool = pool();
        let first = insert(&mut pool, node(443), None, None, false);
        let second = insert(&mut pool, node(444), None, None, false);
        pool.wait_ready(first).await.unwrap();
        pool.wait_ready(second).await.unwrap();
        assert!(pool.start_health(first, health_settings()).is_err());
        pool.promote(proof(&pool, first), &node(443)).unwrap();
        assert!(pool.start_health(second, health_settings()).is_err());
        let mut invalid = health_settings();
        invalid.interval = Duration::ZERO;
        assert!(pool.start_health(first, invalid).is_err());
        assert!(
            !pool
                .subscribe()
                .borrow()
                .as_ref()
                .unwrap()
                .cancel
                .is_cancelled()
        );
        let receiver = pool.start_health(first, health_settings()).unwrap();
        assert!(receiver.borrow().is_none());
        assert!(pool.start_health(first, health_settings()).is_err());
        pool.shutdown().await.unwrap();
        assert!(pool.is_empty());
    }
    #[tokio::test(start_paused = true)]
    async fn health_runs_while_candidate_setup_is_pending_and_fault_revokes_snapshot() {
        assert!(!nix::unistd::geteuid().is_root());
        let mut pool = pool();
        let active = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(active).await.unwrap();
        pool.promote(proof(&pool, active), &node(443)).unwrap();
        let old = pool.subscribe().borrow().clone().unwrap();
        let mut receiver = pool.start_health(active, health_settings()).unwrap();
        let (allow, gate) = oneshot::channel();
        let candidate = insert(&mut pool, node(444), Some(gate), None, false);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        receiver.changed().await.unwrap();
        let result = receiver.borrow().clone().unwrap();
        assert_eq!(result.worker_id, active);
        assert!(result.error.unwrap().contains("需要管理员身份"));
        assert!(old.cancel.is_cancelled());
        pool.refresh_active();
        assert!(pool.subscribe().borrow().is_none());
        // 失败不以候选设置完成为前提；释放夹具后，两者均须完成所属回收。
        allow.send(()).unwrap();
        pool.wait_ready(candidate).await.unwrap();
        assert!(pool.shutdown().await.is_err());
        assert!(pool.is_empty());
    }
    #[tokio::test]
    async fn control_disconnect_and_overlapping_request_retire_pending_owner() {
        for overlap in [false, true] {
            let mut pool = pool();
            let (allow, gate) = oneshot::channel();
            let worker = insert(&mut pool, node(443), Some(gate), None, false);
            let stopped = pool.stop.clone();
            let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
            let authorization = Uuid::new_v4();
            let task = tokio::spawn(super::super::control::serve(
                pool,
                server,
                authorization,
                health_settings(),
                CancellationToken::new(),
            ));
            crate::netd::protocol::write_frame(
                &mut client,
                &serde_json::json!({"version":1,"authorization":authorization,"sequence":1,
                "operation":{"command":"ready","worker":worker}}),
            )
            .await
            .unwrap();
            if overlap {
                crate::netd::protocol::write_frame(
                    &mut client,
                    &serde_json::json!({"version":1,"authorization":authorization,"sequence":2,
                    "operation":{"command":"ping"}}),
                )
                .await
                .unwrap();
            } else {
                drop(client);
            }
            tokio::time::timeout(Duration::from_secs(2), stopped.cancelled())
                .await
                .unwrap();
            // 取消等待不放弃正在配置的所有者；随后同一所有者继续完成回收。
            assert!(!task.is_finished());
            allow.send(()).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }
    #[tokio::test]
    async fn abandoned_control_wait_keeps_pending_owner_cleanup_running() {
        let mut pool = pool();
        let (allow, gate) = oneshot::channel();
        let barrier = Arc::new(Barrier::new(2));
        insert(
            &mut pool,
            node(443),
            Some(gate),
            Some(barrier.clone()),
            false,
        );
        let stopped = pool.stop.clone();
        let (server, _client) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(super::super::control::serve(
            pool,
            server,
            Uuid::new_v4(),
            health_settings(),
            CancellationToken::new(),
        ));
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), stopped.cancelled())
            .await
            .unwrap();
        allow.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), barrier.wait())
            .await
            .unwrap();
    }
    fn checked(pool: &MacCandidatePool, worker: WorkerId) -> CandidateVerification {
        CandidateVerification {
            finished_at: chrono::Utc::now(),
            report: ProbeReport {
                success: true,
                attempts: 1,
                status: Some(204),
                failure: None,
                elapsed: Duration::from_millis(1),
            },
            verified: Some(proof(pool, worker)),
        }
    }
    #[tokio::test]
    async fn owned_checks_start_in_parallel_and_collected_success_keeps_generation_live() {
        let mut pool = pool();
        let barrier = Arc::new(Barrier::new(3));
        let mut checks = Vec::new();
        for port in [443, 444] {
            let worker = insert(&mut pool, node(port), None, None, false);
            pool.wait_ready(worker).await.unwrap();
            let session = pool.entry(worker).unwrap().handle.exit_session().unwrap();
            let result = checked(&pool, worker);
            let gate = barrier.clone();
            checks.push(OwnedVerification::test_launch(
                &CancellationToken::new(),
                session.cancellation(),
                move |_| async move {
                    let _session = session;
                    gate.wait().await;
                    Ok(result)
                },
            ));
        }
        tokio::time::timeout(Duration::from_secs(2), barrier.wait())
            .await
            .unwrap();
        let result = checks[0].wait().await.unwrap();
        pool.promote(result.verified.unwrap(), &node(443)).unwrap();
        checks[1].wait().await.unwrap();
        drop(checks);
        assert!(
            !pool
                .subscribe()
                .borrow()
                .as_ref()
                .unwrap()
                .cancel
                .is_cancelled()
        );
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn owned_check_cancelled_wait_resumes_same_task_and_result_is_single_use() {
        let mut pool = pool();
        let worker = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(worker).await.unwrap();
        let session = pool.entry(worker).unwrap().handle.exit_session().unwrap();
        let revoked = session.cancellation();
        let result = checked(&pool, worker);
        let (allow, gate) = oneshot::channel();
        let mut check = OwnedVerification::test_launch(
            &CancellationToken::new(),
            revoked.clone(),
            move |_| async move {
                let _session = session;
                gate.await.unwrap();
                Ok(result)
            },
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), check.wait())
                .await
                .is_err()
        );
        assert!(!revoked.is_cancelled());
        assert!(!check.is_finished());
        allow.send(()).unwrap();
        check.wait().await.unwrap();
        assert_eq!(
            check.wait().await.err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        drop(check);
        assert!(!revoked.is_cancelled());
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn dropping_owned_check_revokes_immediately_and_cleanup_waits_for_session() {
        let mut pool = pool();
        let worker = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(worker).await.unwrap();
        let session = pool.entry(worker).unwrap().handle.exit_session().unwrap();
        let revoked = session.cancellation();
        let (allow, gate) = oneshot::channel();
        let check = OwnedVerification::test_launch(
            &CancellationToken::new(),
            revoked.clone(),
            move |stop| async move {
                let _session = session;
                stop.cancelled().await;
                gate.await.unwrap();
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "受控检测已取消并回收",
                ))
            },
        );
        drop(check);
        assert!(revoked.is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pool.shutdown())
                .await
                .is_err()
        );
        assert!(!pool.is_empty());
        allow.send(()).unwrap();
        pool.shutdown().await.unwrap();
        assert!(pool.is_empty());
    }
    #[tokio::test]
    async fn owned_check_panic_revokes_and_releases_session_reservation() {
        let mut pool = pool();
        let worker = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(worker).await.unwrap();
        let session = pool.entry(worker).unwrap().handle.exit_session().unwrap();
        let revoked = session.cancellation();
        let mut check = OwnedVerification::test_launch(
            &CancellationToken::new(),
            revoked.clone(),
            move |_| async move {
                let _session = session;
                panic!("受控独立检测异常");
                #[allow(unreachable_code)]
                Err(io::Error::other("不可到达"))
            },
        );
        assert!(check.wait().await.is_err());
        assert!(revoked.is_cancelled());
        pool.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn production_owned_check_refuses_unprivileged_spawn_and_revokes() {
        assert!(!nix::unistd::geteuid().is_root());
        let mut pool = pool();
        let worker = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(worker).await.unwrap();
        let revoked = pool.entry(worker).unwrap().handle.cancellation().unwrap();
        let mut check = pool.begin_check(worker, &CancellationToken::new()).unwrap();
        assert_eq!(
            check.wait().await.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(revoked.is_cancelled());
        pool.retire(worker).await.unwrap();
        assert!(pool.is_empty());
    }
    #[tokio::test]
    async fn owned_result_from_retired_worker_cannot_promote() {
        let mut pool = pool();
        let worker = insert(&mut pool, node(443), None, None, false);
        pool.wait_ready(worker).await.unwrap();
        let result = checked(&pool, worker);
        let session = pool.entry(worker).unwrap().handle.exit_session().unwrap();
        let mut check = OwnedVerification::test_launch(
            &CancellationToken::new(),
            session.cancellation(),
            move |_| async move {
                let _session = session;
                Ok(result)
            },
        );
        tokio::task::yield_now().await;
        pool.retire(worker).await.unwrap();
        let result = check.wait().await.unwrap();
        assert!(pool.promote(result.verified.unwrap(), &node(443)).is_err());
        assert!(pool.subscribe().borrow().is_none());
    }
}
