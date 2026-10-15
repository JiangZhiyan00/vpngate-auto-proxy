//! 受控隧道进程监督：固定端点、私有管理通道及有归属的资源回收。
use super::{InstanceLock, ResourceManifest, process_start, system::*};
use crate::{domain::*, openvpn::validate_regenerated_with_policy};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, UnixStream},
    sync::Mutex,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct StageFailure {
    pub checks: Vec<CheckResult>,
    #[source]
    pub cause: anyhow::Error,
}

pub struct ManagedWorker {
    pub record: WorkerRecord,
    pub allocation: NetworkAllocation,
    pub port_result: CheckResult,
    pub tunnel_result: Option<CheckResult>,
    vpn: Option<SupervisedProcess>,
    socks: Option<SupervisedProcess>,
    private_dir: PathBuf,
    manifest: Arc<ManifestStore>,
    executable: PathBuf,
}
pub struct WorkerSlot {
    pub cancel: CancellationToken,
    pub worker: Mutex<ManagedWorker>,
    number: u8,
}
struct ManifestStore {
    lock: Arc<InstanceLock>,
    value: std::sync::Mutex<ResourceManifest>,
}
impl ManifestStore {
    fn update(&self, record: &WorkerRecord) -> Result<()> {
        let mut value = self
            .value
            .lock()
            .map_err(|_| anyhow::anyhow!("资源清单锁失败"))?;
        value
            .workers
            .retain(|worker| worker.worker_id != record.worker_id);
        value.workers.push(record.clone());
        self.lock.write_manifest(&value)
    }
    fn remove(&self, id: WorkerId) -> Result<()> {
        let mut value = self
            .value
            .lock()
            .map_err(|_| anyhow::anyhow!("资源清单锁失败"))?;
        value.workers.retain(|worker| worker.worker_id != id);
        self.lock.write_manifest(&value)
    }
    fn save(&self) -> Result<()> {
        let value = self
            .value
            .lock()
            .map_err(|_| anyhow::anyhow!("资源清单锁失败"))?;
        self.lock.write_manifest(&value)
    }
}
pub struct WorkerManager {
    pub instance_id: Uuid,
    runtime: PathBuf,
    private: PathBuf,
    limit: usize,
    tunnel_timeout: Duration,
    port_timeout: Duration,
    allow_legacy_vpngate_crypto: bool,
    manifest: Arc<ManifestStore>,
    slots: Mutex<HashMap<WorkerId, Arc<WorkerSlot>>>,
    executable: PathBuf,
}
impl WorkerManager {
    pub fn new(
        instance_id: Uuid,
        runtime: &Path,
        limit: usize,
        tunnel_timeout: Duration,
        port_timeout: Duration,
        allow_legacy_vpngate_crypto: bool,
        lock: Arc<InstanceLock>,
    ) -> Result<Self> {
        ensure!((1..=255).contains(&limit), "工作槽数量无效");
        let private: PathBuf = format!("/run/vap-private-{}", instance_id.simple()).into();
        std::fs::create_dir(&private).context("私有隧道目录已存在或不可创建")?;
        let workers = runtime.join("workers");
        let mut workers_created = false;
        let initialized = (|| {
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o750))?;
            std::os::unix::fs::chown(&private, Some(0), Some(OPENVPN_UID))?;
            std::fs::write(private.join("owner"), instance_id.to_string())?;
            std::fs::set_permissions(
                private.join("owner"),
                std::fs::Permissions::from_mode(0o600),
            )?;
            std::fs::create_dir(&workers)?;
            workers_created = true;
            std::fs::set_permissions(&workers, std::fs::Permissions::from_mode(0o750))?;
            std::os::unix::fs::chown(&workers, Some(CONTROL_UID), Some(CONTROL_UID))?;
            Ok(Self {
                instance_id,
                runtime: runtime.to_owned(),
                private: private.clone(),
                limit,
                tunnel_timeout,
                port_timeout,
                allow_legacy_vpngate_crypto,
                manifest: Arc::new(ManifestStore {
                    lock,
                    value: std::sync::Mutex::new(ResourceManifest {
                        schema_version: 1,
                        instance_id,
                        owner_pid: std::process::id(),
                        owner_start: process_start(std::process::id())?,
                        controller: None,
                        workers: vec![],
                    }),
                }),
                slots: Mutex::new(HashMap::new()),
                executable: std::env::current_exe()?,
            })
        })();
        if initialized.is_err() {
            if workers_created {
                std::fs::remove_dir_all(&workers).context("初始化失败后工作目录清理失败")?;
            }
            std::fs::remove_dir_all(&private).context("初始化失败后私有目录清理失败")?;
        }
        initialized
    }
    pub fn with_executable(mut self, executable: PathBuf) -> Self {
        self.executable = executable;
        self
    }
    async fn persist(&self) -> Result<()> {
        self.manifest.save()
    }
    pub async fn start_tunnel(
        &self,
        worker_id: WorkerId,
        node: &VpnNode,
        role: WorkerRole,
    ) -> Result<Arc<WorkerSlot>> {
        node.validate()?;
        validate_regenerated_with_policy(
            &node.profile,
            &node.endpoint,
            self.allow_legacy_vpngate_crypto,
        )
        .context("节点配置拒绝")?;
        ensure!(role != WorkerRole::Active, "未验证的隧道不能以活动角色启动");
        let slot = {
            let mut slots = self.slots.lock().await;
            ensure!(
                slots.len() < self.limit && !slots.contains_key(&worker_id),
                "工作槽已满或工作标识重复"
            );
            let used: Vec<_> = slots.values().map(|s| s.number).collect();
            let number = (0..self.limit as u16)
                .map(|n| n as u8)
                .find(|n| !used.contains(n))
                .context("无法分配工作网段")?;
            let allocation = NetworkAllocation::new(self.instance_id, worker_id, number);
            let private_dir = self.private.join(worker_id.to_string());
            let socket_path = self
                .runtime
                .join("workers")
                .join(format!("{worker_id}.sock"));
            let now = chrono::Utc::now();
            let worker = ManagedWorker {
                record: WorkerRecord {
                    worker_id,
                    instance_id: self.instance_id,
                    node_id: node.id.clone(),
                    profile_digest: node.profile_digest.clone(),
                    role,
                    state: WorkerState::Allocated,
                    namespace: allocation.namespace.clone(),
                    host_veth: allocation.host_veth.clone(),
                    rules_table: allocation.table.clone(),
                    pid: 0,
                    process_start: String::new(),
                    processes: vec![],
                    socket_path,
                },
                allocation,
                private_dir,
                manifest: self.manifest.clone(),
                executable: self.executable.clone(),
                vpn: None,
                socks: None,
                tunnel_result: None,
                port_result: CheckResult {
                    node_id: node.id.clone(),
                    profile_digest: node.profile_digest.clone(),
                    layer: Layer::Port,
                    outcome: Outcome::NotTested,
                    started_at: now,
                    finished_at: now,
                    elapsed_ms: 0,
                    attempts: 0,
                    status: None,
                    expires_at: None,
                    failure_reason: None,
                },
            };
            self.manifest.update(&worker.record)?;
            let slot = Arc::new(WorkerSlot {
                cancel: CancellationToken::new(),
                worker: Mutex::new(worker),
                number,
            });
            slots.insert(worker_id, slot.clone());
            slot
        };
        self.persist().await?;
        let deadline = Instant::now() + self.tunnel_timeout;
        let result = {
            let mut worker = slot.worker.lock().await;
            worker.record.transition(WorkerState::Connecting)?;
            tokio::select! {
                _ = slot.cancel.cancelled() => Err(anyhow::anyhow!("隧道建立已取消")),
                result = tokio::time::timeout_at(deadline, worker.prepare(node, self.port_timeout)) => result.unwrap_or_else(|_| Err(anyhow::anyhow!("隧道建立总时限耗尽"))),
            }
        };
        if let Err(error) = result {
            let checks = slot
                .worker
                .lock()
                .await
                .failed_checks(deadline, self.tunnel_timeout);
            self.stop(worker_id, Instant::now() + Duration::from_secs(10))
                .await
                .context("失败工作进程清理失败")?;
            return Err(StageFailure {
                checks,
                cause: error,
            }
            .into());
        }
        self.persist().await?;
        Ok(slot)
    }
    pub async fn get(&self, id: WorkerId) -> Option<Arc<WorkerSlot>> {
        self.slots.lock().await.get(&id).cloned()
    }
    pub async fn stop(&self, id: WorkerId, deadline: Instant) -> Result<()> {
        let slot = self.get(id).await;
        if let Some(slot) = slot {
            slot.cancel.cancel();
            slot.worker.lock().await.cleanup(deadline).await?;
            self.slots.lock().await.remove(&id);
            self.manifest.remove(id)?;
        }
        Ok(())
    }
    pub async fn stop_all(&self, deadline: Instant) -> Result<()> {
        use futures_util::StreamExt;
        let entries: Vec<_> = self
            .slots
            .lock()
            .await
            .iter()
            .map(|(id, slot)| {
                slot.cancel.cancel();
                *id
            })
            .collect();
        let results: Vec<_> = futures_util::stream::iter(entries)
            .map(|id| self.stop(id, deadline))
            .buffer_unordered(self.limit)
            .collect()
            .await;
        for result in results {
            result?;
        }
        ensure!(
            std::fs::read_to_string(self.private.join("owner"))? == self.instance_id.to_string(),
            "私有目录归属不符"
        );
        std::fs::remove_file(self.private.join("owner"))?;
        std::fs::remove_dir(&self.private)?;
        std::fs::remove_dir(self.runtime.join("workers"))?;
        Ok(())
    }
    pub async fn persist_state(&self) -> Result<()> {
        self.persist().await
    }
    pub fn register_controller(&self, process: &SupervisedProcess) -> Result<()> {
        self.manifest
            .value
            .lock()
            .map_err(|_| anyhow::anyhow!("资源清单锁失败"))?
            .controller = Some(ProcessIdentity {
            pid: process.pid,
            started: process.started.clone(),
        });
        self.manifest.save()
    }
}
impl ManagedWorker {
    pub(crate) fn failed_checks(&self, deadline: Instant, budget: Duration) -> Vec<CheckResult> {
        let mut port = self.port_result.clone();
        let now = chrono::Utc::now();
        let elapsed = budget.saturating_sub(deadline.saturating_duration_since(Instant::now()));
        if port.outcome == Outcome::Running {
            port.outcome = Outcome::Failed;
            port.finished_at = now;
            port.elapsed_ms = elapsed.as_millis() as u64;
            port.failure_reason = Some("端口探测总时限耗尽或已取消".into());
        }
        let reached_tunnel = matches!(port.outcome, Outcome::Succeeded | Outcome::NotApplicable);
        let tunnel = CheckResult {
            node_id: self.record.node_id.clone(),
            profile_digest: self.record.profile_digest.clone(),
            layer: Layer::Tunnel,
            outcome: if reached_tunnel {
                Outcome::Failed
            } else {
                Outcome::NotTested
            },
            started_at: port.finished_at,
            finished_at: now,
            elapsed_ms: elapsed
                .saturating_sub(Duration::from_millis(port.elapsed_ms))
                .as_millis() as u64,
            attempts: u32::from(reached_tunnel),
            status: None,
            expires_at: None,
            failure_reason: reached_tunnel.then(|| "节点配置或隧道建立失败".into()),
        };
        vec![port, tunnel]
    }
    async fn prepare(&mut self, node: &VpnNode, port_timeout: Duration) -> Result<()> {
        let start = Instant::now();
        self.port_result.started_at = chrono::Utc::now();
        if node.endpoint.transport == Transport::Tcp {
            self.port_result.outcome = Outcome::Running;
            self.port_result.attempts = 1;
            let result =
                tokio::time::timeout(port_timeout, TcpStream::connect(node.endpoint.socket()))
                    .await;
            self.port_result.finished_at = chrono::Utc::now();
            self.port_result.elapsed_ms = start.elapsed().as_millis() as u64;
            self.port_result.outcome = if matches!(result, Ok(Ok(_))) {
                Outcome::Succeeded
            } else {
                Outcome::Failed
            };
            self.port_result.failure_reason =
                (self.port_result.outcome == Outcome::Failed).then(|| "节点端口不可达".into());
            ensure!(
                self.port_result.outcome == Outcome::Succeeded,
                "节点端口不可达"
            );
        } else {
            self.port_result.outcome = Outcome::NotApplicable;
            self.port_result.finished_at = chrono::Utc::now();
        }
        let routes = run_command(
            "ip",
            &["-j", "-4", "route", "get", &node.endpoint.ip.to_string()],
        )
        .await?;
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&routes)?;
        let outbound = routes
            .first()
            .and_then(|v| v["dev"].as_str())
            .context("节点缺少管理路由")?;
        setup_with_binary(&self.allocation, &node.endpoint, outbound, &self.executable).await?;
        std::fs::create_dir(&self.private_dir)?;
        std::fs::set_permissions(&self.private_dir, std::fs::Permissions::from_mode(0o700))?;
        std::os::unix::fs::chown(&self.private_dir, Some(OPENVPN_UID), Some(OPENVPN_UID))?;
        let profile_path = self.private_dir.join("node.ovpn");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&profile_path)?;
        use std::io::Write;
        file.write_all(node.profile.as_bytes())?;
        file.sync_all()?;
        std::os::unix::fs::chown(&profile_path, Some(OPENVPN_UID), Some(OPENVPN_UID))?;
        let management = self.private_dir.join("management.sock");
        let mut command = restricted_command(
            Some(&self.allocation.namespace),
            true,
            Path::new("/usr/sbin/openvpn"),
        );
        command
            .arg("--config")
            .arg(&profile_path)
            .args(["--dev", "tun0", "--management"])
            .arg(&management)
            .args(["unix", "--management-hold"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let vpn = SupervisedProcess::spawn(&mut command)?;
        self.record.pid = vpn.pid;
        self.record.process_start = vpn.started.clone();
        self.vpn = Some(vpn);
        self.manifest.update(&self.record)?;
        let stream = loop {
            ensure!(
                self.vpn.as_mut().context("隧道进程缺失")?.is_running()?,
                "隧道进程提前退出"
            );
            if let Ok(stream) = UnixStream::connect(&management).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let mut management = BufReader::new(stream);
        management
            .get_mut()
            .write_all(b"state on\nhold release\n")
            .await?;
        loop {
            let mut line = String::new();
            let bytes = tokio::io::AsyncReadExt::take(&mut management, 4097)
                .read_line(&mut line)
                .await?;
            ensure!(
                bytes > 0 && line.len() <= 4096,
                "隧道管理通道关闭或响应过长"
            );
            if line.starts_with(">STATE:") && line.contains(",CONNECTED,SUCCESS,") {
                break;
            }
            ensure!(
                !line.starts_with(">FATAL:") && !line.contains("AUTH_FAILED"),
                "隧道握手失败"
            );
        }
        install_tunnel_routes(&self.allocation).await?;
        self.record.transition(WorkerState::Validating)?;
        self.manifest.update(&self.record)?;
        let now = chrono::Utc::now();
        self.tunnel_result = Some(CheckResult {
            node_id: node.id.clone(),
            profile_digest: node.profile_digest.clone(),
            layer: Layer::Tunnel,
            outcome: Outcome::Succeeded,
            started_at: self.port_result.started_at,
            finished_at: now,
            elapsed_ms: start.elapsed().as_millis() as u64,
            attempts: 1,
            status: None,
            expires_at: None,
            failure_reason: None,
        });
        Ok(())
    }
    pub fn attach_socks(&mut self, executable: &Path, max_connections: usize) -> Result<()> {
        let mut command = restricted_command(Some(&self.allocation.namespace), false, executable);
        command
            .arg("worker")
            .arg("--socket")
            .arg(&self.record.socket_path)
            .arg("--max-connections")
            .arg(max_connections.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let process = SupervisedProcess::spawn(&mut command)?;
        self.record.processes.push(ProcessIdentity {
            pid: process.pid,
            started: process.started.clone(),
        });
        self.socks = Some(process);
        self.manifest.update(&self.record)?;
        Ok(())
    }
    pub fn promote(&mut self) -> Result<()> {
        self.record.transition(WorkerState::Active)?;
        self.manifest.update(&self.record)
    }
    pub async fn structurally_ready(&mut self) -> Result<bool> {
        if !self.vpn.as_mut().context("隧道进程缺失")?.is_running()? {
            return Ok(false);
        }
        if let Some(worker) = self.socks.as_mut()
            && !worker.is_running()?
        {
            return Ok(false);
        }
        let link = in_namespace(
            &self.allocation,
            "ip",
            &["link", "show", "up", "dev", "tun0"],
        )
        .await;
        if !link.is_ok_and(|output| !output.is_empty()) {
            return Ok(false);
        }
        let routes = in_namespace(&self.allocation, "ip", &["-4", "route", "show"]).await?;
        let routes = String::from_utf8(routes)?;
        Ok(routes
            .lines()
            .any(|line| line.starts_with("0.0.0.0/1 ") && line.contains("dev tun0"))
            && routes
                .lines()
                .any(|line| line.starts_with("128.0.0.0/1 ") && line.contains("dev tun0")))
    }
    async fn cleanup(&mut self, deadline: Instant) -> Result<()> {
        if self.record.state == WorkerState::Cleaned {
            return Ok(());
        }
        if self.record.state != WorkerState::Stopping {
            self.record.transition(WorkerState::Stopping)?;
        }
        let vpn = &mut self.vpn;
        let socks = &mut self.socks;
        let (a, b) = tokio::join!(
            async {
                if let Some(process) = vpn {
                    process.terminate(deadline).await
                } else {
                    Ok(())
                }
            },
            async {
                if let Some(process) = socks {
                    process.terminate(deadline).await
                } else {
                    Ok(())
                }
            }
        );
        a?;
        b?;
        cleanup(&self.allocation).await?;
        if self.private_dir.exists() {
            std::fs::remove_dir_all(&self.private_dir)?;
        }
        if self.record.socket_path.exists() {
            std::fs::remove_file(&self.record.socket_path)?;
        }
        self.record.transition(WorkerState::Cleaned)?;
        Ok(())
    }
}
