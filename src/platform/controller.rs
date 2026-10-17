//! 真实低权限控制进程的私有启动与联合回收；公开实例管理另由服务入口负责。
use super::{
    control::{self, MacControlClient},
    coordinator::{self, CoordinatorRequest},
    deployment::{self, IdentityObservation},
    exit_probe::ExitProbeSettings,
    health::MacHealthSettings,
    pool::{MacCandidatePool, MacPoolSettings},
    process::Receipt,
    runtime::GenerationRuntime,
    supervisor::{WorkerCredentials, force_reap},
};
use crate::{
    cli::{Connections, StatusSnapshot},
    config::AppConfig,
    domain::ServiceState,
    netd::InstanceLock,
    scheduler::{Catalog, Scheduler},
    service, socks,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener as StdListener, UnixStream as StdStream},
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::{Child, Command},
    sync::{Semaphore, watch},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const STARTUP: Duration = Duration::from_secs(3);
const REAP: Duration = Duration::from_secs(2);
const FRAME_LIMIT: usize = 65536;

#[derive(Clone)]
struct OwnedNode {
    path: PathBuf,
    device: u64,
    inode: u64,
    directory: bool,
}
impl OwnedNode {
    fn read(path: PathBuf) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !(metadata.is_dir() || metadata.is_file() || metadata.file_type().is_socket())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "实例节点类型无效",
            ));
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            directory: metadata.is_dir(),
        })
    }
    fn check(&self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.is_dir() != self.directory
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "实例节点归属已改变",
            ));
        }
        Ok(())
    }
}

struct PublicRuntime {
    directory: OwnedNode,
    lock_node: OwnedNode,
    socket: OwnedNode,
    link: Option<OwnedNode>,
    lock: Option<InstanceLock>,
    listener: Option<StdListener>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicGenerationLink {
    format_version: u32,
    instance_id: Uuid,
    generation_id: Uuid,
    generation_root: PathBuf,
    generation_device: u64,
    generation_inode: u64,
}
#[derive(Debug, PartialEq, Eq)]
enum ExistingAudit {
    ActiveInstance,
    ActiveConsumer,
    InactiveNetworkUnproven,
}
impl PublicRuntime {
    fn audit_existing(
        path: &Path,
        runtime_parent: &Path,
        owner_uid: u32,
    ) -> io::Result<ExistingAudit> {
        Self::audit_existing_with(path, runtime_parent, owner_uid, super::launcher::root_chain)
    }
    fn audit_existing_with(
        path: &Path,
        runtime_parent: &Path,
        owner_uid: u32,
        protected_parent: impl Fn(&Path) -> io::Result<()>,
    ) -> io::Result<ExistingAudit> {
        let denied = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "遗留公开实例归属证据不完整",
            )
        };
        protected_parent(path.parent().ok_or_else(denied)?)?;
        let directory = fs::symlink_metadata(path)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != owner_uid
            || directory.mode() & 0o7777 != 0o750
        {
            return Err(denied());
        }
        let lock_path = path.join("instance.lock");
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&lock_path)?;
        let lock_metadata = lock.metadata()?;
        let lock_named = fs::symlink_metadata(&lock_path)?;
        if !lock_metadata.is_file()
            || lock_metadata.uid() != owner_uid
            || lock_metadata.nlink() != 1
            || lock_metadata.mode() & 0o7777 != 0o600
            || lock_metadata.dev() != lock_named.dev()
            || lock_metadata.ino() != lock_named.ino()
        {
            return Err(denied());
        }
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(ExistingAudit::ActiveInstance);
            }
            Err(error) => return Err(error),
        }
        if fs::symlink_metadata(&lock_path)?.ino() != lock_metadata.ino()
            || fs::symlink_metadata(path)?.ino() != directory.ino()
        {
            return Err(denied());
        }
        let socket_path = path.join("control.sock");
        let socket = fs::symlink_metadata(&socket_path)?;
        if !socket.file_type().is_socket()
            || socket.uid() != owner_uid
            || socket.nlink() != 1
            || socket.mode() & 0o7777 != 0o660
        {
            return Err(denied());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !["instance.lock", "control.sock", "generation.json"]
                .iter()
                .any(|name| entry.file_name() == *name)
            {
                return Err(denied());
            }
        }
        let link_path = path.join("generation.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&link_path)?;
        let metadata = file.metadata()?;
        let linked = fs::symlink_metadata(&link_path)?;
        if !metadata.is_file()
            || metadata.uid() != owner_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > FRAME_LIMIT as u64
            || metadata.dev() != linked.dev()
            || metadata.ino() != linked.ino()
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        std::io::Read::take(file, FRAME_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > FRAME_LIMIT {
            return Err(denied());
        }
        let link: PublicGenerationLink = serde_json::from_slice(&bytes)?;
        if link.format_version != 1 || link.instance_id.is_nil() || link.generation_id.is_nil() {
            return Err(denied());
        }
        protected_parent(link.generation_root.parent().ok_or_else(denied)?)?;
        let receipt = GenerationRuntime::audit_recorded_nodes(
            &link.generation_root,
            link.generation_id,
            link.generation_device,
            link.generation_inode,
            owner_uid,
        )?;
        if runtime_parent != link.generation_root.parent().ok_or_else(denied)? {
            return Err(denied());
        }
        let mut active_consumer = receipt.try_quiescent()?.is_none();
        for entry in fs::read_dir(runtime_parent)? {
            let candidate = entry?.path();
            if candidate == link.generation_root {
                continue;
            }
            let receipt =
                GenerationRuntime::audit_candidate(&candidate, link.instance_id, owner_uid)?;
            active_consumer |= receipt.try_quiescent()?.is_none();
        }
        if active_consumer {
            Ok(ExistingAudit::ActiveConsumer)
        } else {
            Ok(ExistingAudit::InactiveNetworkUnproven)
        }
    }
    fn prepare(path: &Path, identity: WorkerCredentials) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("公开运行目录没有父目录"))?;
        super::launcher::root_chain(parent)?;
        Self::prepare_with(path, 0, identity.gid, |path, uid, gid| {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))
        })
    }
    fn prepare_with(
        path: &Path,
        owner_uid: u32,
        owner_gid: u32,
        owner: impl Fn(&Path, u32, u32) -> io::Result<()>,
    ) -> io::Result<Self> {
        if !path.is_absolute()
            || path.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(invalid("公开运行目录必须是无跳转分量的绝对路径"));
        }
        fs::DirBuilder::new().mode(0o750).create(path)?;
        let result = (|| {
            owner(path, owner_uid, owner_gid)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
            let directory = OwnedNode::read(path.to_owned())?;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.uid() != owner_uid
                || metadata.gid() != owner_gid
                || metadata.mode() & 0o777 != 0o750
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "公开运行目录归属或权限无效",
                ));
            }
            let lock = InstanceLock::acquire(path).map_err(io::Error::other)?;
            let lock_node = OwnedNode::read(path.join("instance.lock"))?;
            if fs::read_dir(path)?.count() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "公开运行目录包含未知或遗留节点",
                ));
            }
            let socket_path = path.join("control.sock");
            let listener = StdListener::bind(&socket_path)?;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))?;
            owner(&socket_path, owner_uid, owner_gid)?;
            let socket = OwnedNode::read(socket_path)?;
            if !fs::symlink_metadata(&socket.path)?.file_type().is_socket() {
                return Err(invalid("公开控制节点不是套接字"));
            }
            Ok(Self {
                directory,
                lock_node,
                socket,
                link: None,
                lock: Some(lock),
                listener: Some(listener),
            })
        })();
        if result.is_err() {
            let socket = path.join("control.sock");
            if fs::symlink_metadata(&socket).is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                let _ = fs::remove_file(socket);
            }
            let lock = path.join("instance.lock");
            if fs::symlink_metadata(&lock).is_ok_and(|metadata| metadata.is_file()) {
                let _ = fs::remove_file(lock);
            }
            let _ = fs::remove_dir(path);
        }
        result
    }
    fn take_listener(&mut self) -> io::Result<StdListener> {
        self.listener
            .take()
            .ok_or_else(|| io::Error::other("公开控制监听器已交付"))
    }
    /// 控制子进程派生前持久关联公开实例和本次私有代际；失败保留精确回收责任。
    fn record_generation(
        &mut self,
        instance_id: Uuid,
        runtime: &GenerationRuntime,
    ) -> io::Result<()> {
        if instance_id.is_nil() || self.link.is_some() {
            return Err(invalid("公开实例关联已存在或身份无效"));
        }
        self.directory.check()?;
        let (generation_id, generation_device, generation_inode) = runtime.identity();
        let record = PublicGenerationLink {
            format_version: 1,
            instance_id,
            generation_id,
            generation_root: runtime.root().to_owned(),
            generation_device,
            generation_inode,
        };
        let path = self.directory.path.join("generation.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)?;
        self.link = Some(OwnedNode::read(path)?);
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&serde_json::to_vec(&record)?)?;
        file.sync_all()?;
        File::open(&self.directory.path)?.sync_all()?;
        let link = self.link.as_ref().expect("公开代际关联已登记");
        link.check()?;
        let metadata = file.metadata()?;
        let directory = fs::symlink_metadata(&self.directory.path)?;
        if !metadata.is_file()
            || metadata.uid() != directory.uid()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.dev() != link.device
            || metadata.ino() != link.inode
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "公开代际关联交付前身份无效",
            ));
        }
        Ok(())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.listener.take();
        self.directory.check()?;
        self.socket.check()?;
        self.lock_node.check()?;
        if let Some(link) = &self.link {
            link.check()?;
            let metadata = fs::symlink_metadata(&link.path)?;
            let directory = fs::symlink_metadata(&self.directory.path)?;
            if !metadata.is_file()
                || metadata.uid() != directory.uid()
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "公开代际关联权限或归属已改变",
                ));
            }
        }
        if fs::read_dir(&self.directory.path)?.count() != 2 + usize::from(self.link.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "公开运行目录出现未知节点，拒绝删除",
            ));
        }
        if let Some(link) = &self.link {
            fs::remove_file(&link.path)?;
            self.link = None;
        }
        fs::remove_file(&self.socket.path)?;
        if fs::read_dir(&self.directory.path)?.count() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "公开运行目录出现未知节点，拒绝删除",
            ));
        }
        fs::remove_file(&self.lock_node.path)?;
        self.lock.take();
        fs::remove_dir(&self.directory.path)
    }
}

fn prepare_data_directory(path: &Path, identity: WorkerCredentials) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("苹果数据目录没有父目录"))?;
    super::launcher::root_chain(parent)?;
    prepare_data_directory_with(path, identity, |path, uid, gid| {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
    })
}
fn prepare_data_directory_with(
    path: &Path,
    identity: WorkerCredentials,
    owner: impl FnOnce(&Path, u32, u32) -> io::Result<()>,
) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| {
            !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(invalid("苹果数据目录必须是无跳转分量的绝对路径"));
    }
    let created = match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    let result = (|| {
        if created {
            owner(path, identity.uid, identity.gid)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != identity.uid
            || metadata.gid() != identity.gid
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "苹果数据目录归属或权限无效",
            ));
        }
        Ok(())
    })();
    if result.is_err()
        && created
        && fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
    {
        let _ = fs::remove_dir(path);
    }
    result
}

pub struct MacControllerRequest {
    pub config: AppConfig,
    pub identity: WorkerCredentials,
    pub runtime_parent: PathBuf,
    pub dependency_manifest: PathBuf,
    pub instance_id: Uuid,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u32,
    authorization: Uuid,
    instance_id: Uuid,
    uid: u32,
    gid: u32,
    config: AppConfig,
    listen_scope: crate::logging::ListenScope,
}
impl Bootstrap {
    fn validate(&self, authorization: Uuid) -> io::Result<()> {
        if self.version != 1
            || authorization.is_nil()
            || self.authorization != authorization
            || self.instance_id.is_nil()
            || self.uid == 0
            || self.gid == 0
        {
            return Err(invalid("控制启动身份或版本无效"));
        }
        coordinator::validate_config(&self.config)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    authorization: Uuid,
    instance_id: Uuid,
    observation: IdentityObservation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    version: u32,
    authorization: Uuid,
    instance_id: Uuid,
}
impl Commit {
    fn validate(&self, authorization: Uuid, instance: Uuid) -> io::Result<()> {
        if self.version != 1 || self.authorization != authorization || self.instance_id != instance
        {
            return Err(invalid("控制交付确认归属不符"));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u32,
    authorization: Uuid,
    instance_id: Uuid,
    pid: u32,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
async fn send<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(io::Error::other)?);
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
        return Err(invalid("控制启动帧超过上限"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}
async fn receive<T: DeserializeOwned>(stream: &mut UnixStream) -> io::Result<T> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > FRAME_LIMIT {
        return Err(invalid("控制启动帧长度无效"));
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("控制启动帧格式或字段无效"))
}
fn health(config: &AppConfig) -> MacHealthSettings {
    MacHealthSettings {
        interval: Duration::from_secs(config.health_interval_seconds),
        exit: ExitProbeSettings {
            urls: config.exit_check_urls.clone(),
            max_attempts: config.exit_check_max_attempts,
            budget: Duration::from_secs(config.health_timeout_seconds),
        },
    }
}
fn pool(request: &MacControllerRequest, stop: &CancellationToken) -> io::Result<MacCandidatePool> {
    let config = &request.config;
    MacCandidatePool::new(
        MacPoolSettings {
            parent: request.runtime_parent.clone(),
            instance_id: request.instance_id,
            dependency_manifest: request.dependency_manifest.clone(),
            credentials: request.identity,
            startup_budget: Duration::from_secs(config.tunnel_timeout_seconds),
            max_connections: config.max_connections,
            candidate_slots: config.candidate_concurrency,
            verification_ttl: Duration::from_secs(config.candidate_result_ttl_seconds),
            source_ttl: Duration::from_secs(config.source_cache_ttl_seconds),
            exit: ExitProbeSettings {
                urls: config.exit_check_urls.clone(),
                max_attempts: config.exit_check_max_attempts,
                budget: Duration::from_secs(config.exit_check_timeout_seconds),
            },
        },
        stop,
    )
}

/// 只有明确账户、受保护安装及依赖都通过后才创建材料和直属进程。
/// 丢弃等待会取消同一后台所有者，后台继续等候控制池和直属进程回收。
pub async fn supervise(
    request: MacControllerRequest,
    parent_stop: CancellationToken,
) -> io::Result<()> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "控制进程监督需要管理员身份",
        ));
    }
    request.identity.validate_account()?;
    coordinator::validate_config(&request.config)?;
    if request.instance_id.is_nil() {
        return Err(invalid("控制实例身份为空"));
    }
    let executable = super::program::verify_current()?;
    super::launcher::preflight_dependency(&request.dependency_manifest)?;
    prepare_data_directory(&request.config.data_dir, request.identity)?;
    let parent = request.runtime_parent.clone();
    let identity = request.identity;
    let public_path = request.config.runtime_dir.clone();
    let stop = parent_stop.child_token();
    let _guard = stop.clone().drop_guard();
    tokio::spawn(async move {
        let mut public = match PublicRuntime::prepare(&public_path, identity) {
            Ok(public) => public,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let audit = PublicRuntime::audit_existing(&public_path, &parent, 0);
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "公开实例已存在，拒绝自动接管；只读归属审计：{}",
                        match audit {
                            Ok(ExistingAudit::ActiveInstance) => "实例锁仍被占用".to_owned(),
                            Ok(ExistingAudit::ActiveConsumer) => "消费者锁仍被占用".to_owned(),
                            Ok(ExistingAudit::InactiveNetworkUnproven) => {
                                "静态节点及锁一致，但网络与宿主基线未获证明".to_owned()
                            }
                            Err(reason) => reason.to_string(),
                        },
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        let mut runtime =
            match GenerationRuntime::prepare(&parent, b"controller-identity-only\n", identity) {
                Ok(runtime) => runtime,
                Err(error) => return combine(Err(error), public.cleanup()),
            };
        if let Err(error) = public.record_generation(request.instance_id, &runtime) {
            return combine(Err(error), combine(runtime.cleanup(), public.cleanup()));
        }
        exercise(
            request,
            executable,
            runtime,
            Some(public),
            stop,
            Receipt::default(),
        )
        .await
    })
    .await
    .map_err(|_| io::Error::other("控制进程监督异常，回收未确认"))?
}
#[cfg(test)]
async fn supervise_owned(
    request: MacControllerRequest,
    executable: PathBuf,
    prepare: impl FnOnce() -> io::Result<GenerationRuntime> + Send + 'static,
    parent_stop: CancellationToken,
    receipt: Receipt,
) -> io::Result<()> {
    let stop = parent_stop.child_token();
    let _guard = stop.clone().drop_guard();
    tokio::spawn(
        async move { exercise(request, executable, prepare()?, None, stop, receipt).await },
    )
    .await
    .map_err(|_| io::Error::other("控制进程监督异常，回收未确认"))?
}

fn launch(
    executable: &std::path::Path,
    runtime: &GenerationRuntime,
    request: &MacControllerRequest,
    authorization: Uuid,
    receipt: &Receipt,
    public: Option<&mut PublicRuntime>,
) -> io::Result<(UnixStream, Child)> {
    let (parent, child) = super::spawn::guarded(|| {
        let (parent, child_socket) = StdStream::pair()?;
        parent.set_nonblocking(true)?;
        let parent = UnixStream::from_std(parent)?;
        let public = public.map(PublicRuntime::take_listener).transpose()?;
        let mut command = Command::new(executable);
        command
            .arg("mac-controller")
            .arg("--authorization")
            .arg(authorization.to_string())
            .env_clear()
            .current_dir(runtime.worker())
            .uid(request.identity.uid)
            .gid(request.identity.gid)
            .process_group(0)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_socket)))
            .stdout(match public {
                Some(listener) => Stdio::from(OwnedFd::from(listener)),
                None => Stdio::null(),
            })
            .stderr(receipt.child_stderr()?)
            .kill_on_drop(true);
        let child = command.spawn()?;
        receipt.spawned();
        // 否则父方仍持有子端，父监督退出不会产生所需的通道结束。
        drop(command);
        Ok((parent, child))
    })?;
    Ok((parent, child))
}
async fn handshake(
    stream: &mut UnixStream,
    child: &mut Child,
    request: &MacControllerRequest,
    runtime: &GenerationRuntime,
    authorization: Uuid,
) -> io::Result<()> {
    let bootstrap = Bootstrap {
        version: 1,
        authorization,
        instance_id: request.instance_id,
        uid: request.identity.uid,
        gid: request.identity.gid,
        config: request.config.clone(),
        listen_scope: request.config.listen_scope,
    };
    send(stream, &bootstrap).await?;
    let identity: Identity = receive(stream).await?;
    Commit {
        version: identity.version,
        authorization: identity.authorization,
        instance_id: identity.instance_id,
    }
    .validate(authorization, request.instance_id)?;
    deployment::validate_observation(
        &identity.observation,
        authorization,
        request.identity,
        &runtime.worker(),
    )?;
    if !runtime.deployment_marker_matches(deployment::MARKER)? {
        return Err(invalid("控制身份验证文件内容不符"));
    }
    send(
        stream,
        &Commit {
            version: 1,
            authorization,
            instance_id: request.instance_id,
        },
    )
    .await?;
    let ready: Ready = receive(stream).await?;
    Commit {
        version: ready.version,
        authorization: ready.authorization,
        instance_id: ready.instance_id,
    }
    .validate(authorization, request.instance_id)?;
    if child.id() != Some(ready.pid) || child.try_wait()?.is_some() {
        return Err(invalid("控制就绪不属于存活直属进程"));
    }
    Ok(())
}
async fn exercise(
    request: MacControllerRequest,
    executable: PathBuf,
    mut runtime: GenerationRuntime,
    mut public: Option<PublicRuntime>,
    stop: CancellationToken,
    receipt: Receipt,
) -> io::Result<()> {
    let pool_cleanup = super::bootstrap::CleanupStatus::default();
    let result = async {
        if stop.is_cancelled() { return Err(io::Error::new(io::ErrorKind::Interrupted, "控制启动已取消")); }
        let lease = runtime.consumer_lease()?;
        let inherited_receipt = receipt.clone().with_lease(Some(lease.clone()));
        let pool = pool(&request, &stop)?.with_lease(lease);
        runtime.deployment_marker(request.identity)?;
        let authorization = Uuid::new_v4();
        let (mut stream, mut child) = launch(
            &executable,
            &runtime,
            &request,
            authorization,
            &inherited_receipt,
            public.as_mut(),
        )?;
        let started = tokio::select! {
            biased;
            _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "控制握手已取消")),
            value = tokio::time::timeout(STARTUP, handshake(&mut stream, &mut child, &request, &runtime, authorization)) =>
                value.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "控制身份握手超时"))),
        };
        let startup_failed = started.is_err();
        let result = match started {
            Err(error) => { drop(stream); Err(error) },
            Ok(()) => {
                let server = control::serve_tracked(pool, stream, authorization,
                    health(&request.config), stop.clone(), pool_cleanup.clone());
                tokio::pin!(server);
                let mut server_finished = false;
                let first = tokio::select! {
                    biased;
                    _ = stop.cancelled() => Ok(()),
                    exited = child.wait() => exited.and_then(|s| if s.success() { Ok(()) } else { Err(io::Error::other("低权限控制进程异常退出")) }),
                    value = &mut server => { server_finished = true; value },
                };
                stop.cancel();
                let cleanup = if server_finished { Ok(()) } else { server.await };
                combine(first, cleanup)
            }
        };
        stop.cancel();
        // 撤销通道后先给正常退出机会，再只终止持有句柄的本次直属进程。
        receipt.observe(&mut child);
        let child_cleanup = if receipt.reaped() { Ok(()) } else if startup_failed {
            force_reap(&mut child, REAP).await.map(|_| ())
        } else {
            match tokio::time::timeout(Duration::from_secs(request.config.shutdown_timeout_seconds), child.wait()).await {
                Ok(Ok(status)) if status.success() => Ok(()),
                Ok(Ok(status)) => Err(io::Error::other(format!("低权限控制进程退出失败：{status}"))),
                _ => force_reap(&mut child, REAP).await.map(|_| ()),
            }
        };
        receipt.observe(&mut child);
        combine(result, child_cleanup)
    }.await;
    stop.cancel();
    let cleanup = cleanup_instance(&mut runtime, &mut public, &receipt, &pool_cleanup);
    combine(result, cleanup)
}
fn cleanup_instance(
    runtime: &mut GenerationRuntime,
    public: &mut Option<PublicRuntime>,
    receipt: &Receipt,
    pool_cleanup: &super::bootstrap::CleanupStatus,
) -> io::Result<()> {
    if receipt.reaped() && pool_cleanup.confirmed() {
        runtime.cleanup()?;
        match public {
            Some(public) => public.cleanup(),
            None => Ok(()),
        }
    } else {
        Err(io::Error::other(
            "控制进程或代际池未确认回收，保留身份材料和公开运行目录",
        ))
    }
}
fn combine(first: io::Result<()>, second: io::Result<()>) -> io::Result<()> {
    match (first, second) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(first), Err(second)) => Err(io::Error::other(format!("{first}；回收：{second}"))),
    }
}

struct ControllerChannels {
    request: CoordinatorRequest,
    status: watch::Receiver<StatusSnapshot>,
}
fn coordinator_request(bootstrap: &Bootstrap) -> ControllerChannels {
    let config = &bootstrap.config;
    let (active, _) = watch::channel(None);
    let now = chrono::Utc::now();
    let (status, status_rx) = watch::channel(StatusSnapshot {
        schema_version: 1,
        instance_id: bootstrap.instance_id,
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
            &Scheduler::new(config.candidate_batch_size, config.candidate_concurrency),
            now,
            now,
        ),
        connections: Connections {
            current: 0,
            limit: config.max_connections,
        },
        last_switch_reason: None,
        last_error: None,
    });
    ControllerChannels {
        request: CoordinatorRequest {
            config: config.clone(),
            identity: WorkerCredentials {
                uid: bootstrap.uid,
                gid: bootstrap.gid,
            },
            instance_id: bootstrap.instance_id,
            active,
            status,
            quota: Arc::new(Semaphore::new(config.max_connections)),
        },
        status: status_rx,
    }
}

/// 仅处理私有继承通道；身份和目录校验完成且收到父方确认前，不访问来源、缓存或监听网络。
pub async fn entry(authorization: Uuid) -> io::Result<()> {
    if authorization.is_nil() || nix::unistd::getuid().is_root() || nix::unistd::geteuid().is_root()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "控制子进程拒绝空授权或管理员身份",
        ));
    }
    let descriptor = std::io::stdin().as_fd().try_clone_to_owned()?;
    let inherited = StdStream::from(descriptor);
    inherited.set_nonblocking(true)?;
    let stream = UnixStream::from_std(inherited)?;
    let listener = StdListener::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    listener.set_nonblocking(true)?;
    child_entry(
        stream,
        tokio::net::UnixListener::from_std(listener)?,
        authorization,
    )
    .await
}
async fn child_entry(
    mut stream: UnixStream,
    public: tokio::net::UnixListener,
    authorization: Uuid,
) -> io::Result<()> {
    let bootstrap = tokio::time::timeout(STARTUP, async {
        let mut bootstrap: Bootstrap = receive(&mut stream).await?;
        bootstrap.validate(authorization)?;
        bootstrap.config.listen_scope = bootstrap.listen_scope;
        let channels = coordinator_request(&bootstrap);
        coordinator::validate(&channels.request)?;
        let observation = deployment::identity(authorization)?;
        deployment::validate_observation(
            &observation,
            authorization,
            channels.request.identity,
            &std::env::current_dir()?,
        )?;
        send(
            &mut stream,
            &Identity {
                version: 1,
                authorization,
                instance_id: bootstrap.instance_id,
                observation,
            },
        )
        .await?;
        let commit: Commit = receive(&mut stream).await?;
        commit.validate(authorization, bootstrap.instance_id)?;
        send(
            &mut stream,
            &Ready {
                version: 1,
                authorization,
                instance_id: bootstrap.instance_id,
                pid: std::process::id(),
            },
        )
        .await?;
        Ok::<_, io::Error>(bootstrap)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "控制子进程启动超时"))??;
    let channels = coordinator_request(&bootstrap);
    let active = channels.request.active.clone();
    let quota = channels.request.quota.clone();
    let credentials = bootstrap
        .config
        .credentials_file
        .as_deref()
        .map(crate::config::Credentials::load)
        .transpose()
        .map_err(|_| invalid("控制认证材料读取失败"))?;
    let service_stop = CancellationToken::new();
    let coordinator_stop = CancellationToken::new();
    let client = MacControlClient::new(stream, authorization);
    let _guard = client.cancellation().drop_guard();
    let coordination =
        coordinator::coordinate(channels.request, client.clone(), coordinator_stop.clone());
    let gateway = socks::run_gateway(
        bootstrap.config.listen.into(),
        active.subscribe(),
        credentials,
        quota.clone(),
        service_stop.clone(),
    );
    let management = crate::cli::serve_control(
        public,
        channels.status,
        quota.clone(),
        bootstrap.config.shutdown_timeout_seconds,
        active.clone(),
        service_stop.clone(),
    );
    tokio::pin!(coordination, gateway, management);
    let mut coordination_finished = false;
    let mut gateway_finished = false;
    let mut management_finished = false;
    let result = tokio::select! {
        value = &mut coordination => {coordination_finished = true; value},
        value = &mut gateway => {gateway_finished = true; value.map_err(io::Error::other)},
        value = &mut management => {management_finished = true; value.map_err(io::Error::other)},
    };
    service_stop.cancel();
    let shutdown = if coordination_finished {
        Ok(())
    } else {
        match client
            .request(
                super::control::MacControlCommand::Shutdown,
                Duration::from_secs(5),
            )
            .await
        {
            Ok(super::control::MacControlResponse::Stopped) => Ok(()),
            Ok(_) => Err(invalid("特权控制停止响应类型不符")),
            Err(error) => Err(error),
        }
    };
    coordinator_stop.cancel();
    if let Some(worker) = active.send_replace(None) {
        worker.cancel.cancel();
    }
    client.close();
    let coordination_result = if coordination_finished {
        Ok(())
    } else {
        // 明确停止响应只确认特权池；仍须等待本地来源、检测和状态任务全部收尾。
        // 只消除主动关闭通道带来的预期错误，任务异常或其他错误继续向上传播。
        match coordination.await {
            Err(error)
                if shutdown.is_ok()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::NotConnected
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::Interrupted
                    ) =>
            {
                Ok(())
            }
            result => result,
        }
    };
    let gateway_result = if gateway_finished {
        Ok(())
    } else {
        gateway.await.map_err(io::Error::other)
    };
    let management_result = if management_finished {
        Ok(())
    } else {
        management.await.map_err(io::Error::other)
    };
    combine(
        combine(
            combine(combine(result, shutdown), coordination_result),
            gateway_result,
        ),
        management_result,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn unknown_pool_cleanup_preserves_public_and_identity_materials_until_confirmed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let mut public = Some(
            PublicRuntime::prepare_with(
                &path,
                nix::unistd::getuid().as_raw(),
                nix::unistd::getgid().as_raw(),
                |_, _, _| Ok(()),
            )
            .unwrap(),
        );
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let child = Receipt::default();
        let pool = super::super::bootstrap::CleanupStatus::default();
        pool.unknown();
        assert!(cleanup_instance(&mut runtime, &mut public, &child, &pool).is_err());
        assert!(path.join("control.sock").exists());
        assert!(path.join("instance.lock").exists());
        assert!(root.join("ownership.json").exists());
        pool.confirm();
        cleanup_instance(&mut runtime, &mut public, &child, &pool).unwrap();
        assert!(!path.exists());
        assert!(!root.exists());
    }
    #[test]
    fn confirmed_pool_still_preserves_public_runtime_while_consumer_lock_is_busy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let mut public = Some(
            PublicRuntime::prepare_with(
                &path,
                nix::unistd::getuid().as_raw(),
                nix::unistd::getgid().as_raw(),
                |_, _, _| Ok(()),
            )
            .unwrap(),
        );
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let lease = runtime.consumer_lease().unwrap();
        let consumer = lease.child_stdio().unwrap();
        let child = Receipt::default();
        let pool = super::super::bootstrap::CleanupStatus::default();
        pool.confirm();
        let started = std::time::Instant::now();
        assert!(cleanup_instance(&mut runtime, &mut public, &child, &pool).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(path.join("control.sock").exists());
        assert!(root.join("consumers.lock").exists());
        drop(lease);
        drop(consumer);
        let saved: super::super::lease::LeaseReceipt =
            serde_json::from_slice(&fs::read(root.join("consumers.json")).unwrap()).unwrap();
        assert!(
            saved
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
        cleanup_instance(&mut runtime, &mut public, &child, &pool).unwrap();
        assert!(!path.exists());
        assert!(!root.exists());
    }
    #[test]
    fn public_instance_records_one_exact_controller_generation_before_handoff() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let mut public = PublicRuntime::prepare_with(
            &path,
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
            |_, _, _| Ok(()),
        )
        .unwrap();
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        let instance = Uuid::new_v4();
        public.record_generation(instance, &runtime).unwrap();
        let record: PublicGenerationLink =
            serde_json::from_slice(&fs::read(path.join("generation.json")).unwrap()).unwrap();
        let (generation, device, inode) = runtime.identity();
        assert_eq!(record.format_version, 1);
        assert_eq!(record.instance_id, instance);
        assert_eq!(record.generation_id, generation);
        assert_eq!(record.generation_root, runtime.root());
        assert_eq!(
            (record.generation_device, record.generation_inode),
            (device, inode)
        );
        assert_eq!(
            fs::metadata(path.join("generation.json")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(public.record_generation(Uuid::new_v4(), &runtime).is_err());
        runtime.cleanup().unwrap();
        public.cleanup().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn legacy_audit_distinguishes_instance_and_consumer_locks_without_adoption() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let uid = nix::unistd::getuid().as_raw();
        let mut public =
            PublicRuntime::prepare_with(&path, uid, nix::unistd::getgid().as_raw(), |_, _, _| {
                Ok(())
            })
            .unwrap();
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        let lease = runtime.consumer_lease().unwrap();
        public.record_generation(Uuid::new_v4(), &runtime).unwrap();
        let audit = || {
            PublicRuntime::audit_existing_with(&path, runtime.root().parent().unwrap(), uid, |_| {
                Ok(())
            })
        };
        assert_eq!(audit().unwrap(), ExistingAudit::ActiveInstance);
        drop(public.lock.take());
        assert_eq!(audit().unwrap(), ExistingAudit::ActiveConsumer);
        let foreign = path.join("unrelated");
        fs::write(&foreign, b"preserve").unwrap();
        assert!(audit().is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
        fs::remove_file(&foreign).unwrap();
        drop(lease);
        let unknown_generation = runtime.root().parent().unwrap().join("unowned");
        fs::create_dir(&unknown_generation).unwrap();
        assert!(audit().is_err());
        fs::remove_dir(&unknown_generation).unwrap();
        assert_eq!(audit().unwrap(), ExistingAudit::InactiveNetworkUnproven);
        assert!(path.join("generation.json").exists());
        assert!(runtime.root().join("ownership.json").exists());
        runtime.cleanup().unwrap();
        public.cleanup().unwrap();
    }
    #[test]
    fn changed_public_generation_link_is_preserved_and_prevents_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let mut public = PublicRuntime::prepare_with(
            &path,
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
            |_, _, _| Ok(()),
        )
        .unwrap();
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        public.record_generation(Uuid::new_v4(), &runtime).unwrap();
        let link = path.join("generation.json");
        let saved = path.join("saved.json");
        fs::rename(&link, &saved).unwrap();
        fs::write(&link, b"foreign").unwrap();
        assert!(public.cleanup().is_err());
        assert_eq!(fs::read(&link).unwrap(), b"foreign");
        fs::remove_file(&link).unwrap();
        fs::rename(saved, link).unwrap();
        runtime.cleanup().unwrap();
        public.cleanup().unwrap();
    }
    // 这些子进程报告是协议夹具，不能证明管理员实际降权或额外组被清除。
    const CHILD: &str = r#"#!/usr/bin/python3
import json, os, socket, struct, sys, time
from pathlib import Path
mode = MODE
event = Path(EVENT)
event.write_text('spawned')
consumer_lock = Path.cwd().parent / 'consumers.lock'
if consumer_lock.exists():
    inherited = os.fstat(2)
    recorded = os.stat(consumer_lock)
    assert (inherited.st_dev, inherited.st_ino) == (recorded.st_dev, recorded.st_ino)
socket = socket.socket(fileno=0)
def exact(n):
    data = b''
    while len(data) < n:
        part = socket.recv(n-len(data))
        if not part: raise EOFError()
        data += part
    return data
def receive(): return json.loads(exact(struct.unpack('>I', exact(4))[0]))
def send(data):
    data = json.dumps(data).encode()
    socket.sendall(struct.pack('>I', len(data)) + data)
bootstrap = receive()
assert os.getuid() == bootstrap['uid'] and os.getgid() == bootstrap['gid']
assert os.getpgrp() == os.getpid()
if mode == 'stall': time.sleep(60)
if mode == 'oversized':
    socket.sendall(struct.pack('>I', 65537))
    time.sleep(60)
authorization = bootstrap['authorization']
instance = bootstrap['instance_id']
Path('identity-check').write_bytes(b'deployment-identity-verified\n')
observation = dict(authorization=authorization, uid=bootstrap['uid'], effective_uid=bootstrap['uid'],
    gid=bootstrap['gid'], effective_gid=bootstrap['gid'], groups=[bootstrap['gid']],
    environment_empty=True, directory=os.getcwd(), private_profile_denied=True, owned_marker_written=True)
if mode == 'identity': observation['effective_uid'] = 0
send(dict(version=1, authorization=authorization, instance_id=instance, observation=observation))
commit = receive()
assert commit == dict(version=1, authorization=authorization, instance_id=instance)
event.write_text('committed')
send(dict(version=1, authorization=authorization, instance_id=instance,
    pid=os.getpid() + (1 if mode == 'pid' else 0)))
send(dict(version=1, authorization=authorization, sequence=1, operation=dict(command='ping')))
receive()
event.write_text('pinged')
if mode == 'exit': sys.exit(7)
if mode == 'ignore': time.sleep(60)
if mode in ['public', 'public_exit']:
    public = __import__('socket').socket(fileno=1)
    def public_exact(connection, n):
        data = b''
        while len(data) < n:
            part = connection.recv(n-len(data))
            if not part: raise EOFError()
            data += part
        return data
    def public_request():
        connection, _ = public.accept()
        size = struct.unpack('>I', public_exact(connection, 4))[0]
        return connection, json.loads(public_exact(connection, size))
    connection, request = public_request()
    assert request == dict(schema_version=1, command='status')
    status = dict(schema_version=1, instance_id=instance, state='starting', ready=False,
        listen_address=bootstrap['config']['listen'], active_node=None, last_exit_check=None,
        source=dict(fetched_at=None, age_seconds=None, expired=True, last_error=None),
        candidates=dict(total=0, available=0, expired=0, not_tested=0, round_selected=0,
            round_completed=0, running=0, next_scheduled_at='2026-10-13T00:00:00Z'),
        connections=dict(current=0, limit=bootstrap['config']['max_connections']),
        last_switch_reason=None, last_error=None)
    response = json.dumps(dict(result='status', status=status)).encode()
    connection.sendall(struct.pack('>I', len(response)) + response)
    connection.close()
    connection, request = public_request()
    assert request == dict(schema_version=1, command='stop')
    response = json.dumps(dict(result='accepted', instance_id=instance,
        shutdown_timeout_seconds=bootstrap['config']['shutdown_timeout_seconds'])).encode()
    connection.sendall(struct.pack('>I', len(response)) + response)
    connection.close()
    send(dict(version=1, authorization=authorization, sequence=2,
        operation=dict(command='shutdown')))
    stopped = receive()
    assert stopped['outcome'] == dict(result='stopped')
    event.write_text('stopped')
    sys.exit(7 if mode == 'public_exit' else 0)
try:
    while socket.recv(1024): pass
except OSError: pass
"#;

    fn fixture(mode: &str) -> (tempfile::TempDir, MacControllerRequest, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("controller.py");
        let event = directory.path().join("event");
        let script = CHILD
            .replace("MODE", &serde_json::to_string(mode).unwrap())
            .replace("EVENT", &serde_json::to_string(&event).unwrap());
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let request = MacControllerRequest {
            config: AppConfig {
                data_dir: directory.path().join("data"),
                runtime_dir: directory.path().join("runtime"),
                shutdown_timeout_seconds: 1,
                ..Default::default()
            },
            identity: WorkerCredentials {
                uid: nix::unistd::getuid().as_raw(),
                gid: nix::unistd::getgid().as_raw(),
            },
            runtime_parent: directory.path().into(),
            dependency_manifest: directory.path().join("missing.json"),
            instance_id: Uuid::new_v4(),
        };
        (directory, request, executable, event)
    }
    async fn wait_event(path: &std::path::Path, expected: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if fs::read_to_string(path).is_ok_and(|text| text == expected) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn actual_child_private_handshake_ping_and_stop_reap_before_cleanup() {
        let (_directory, request, executable, event) = fixture("good");
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let stop = CancellationToken::new();
        let receipt = Receipt::default();
        let task = tokio::spawn(exercise(
            request,
            executable,
            runtime,
            None,
            stop.clone(),
            receipt.clone(),
        ));
        wait_event(&event, "pinged").await;
        assert!(!receipt.reaped());
        assert!(root.exists());
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(receipt.reaped());
        assert!(!root.exists());
    }
    #[tokio::test]
    async fn inherited_public_stop_reaps_child_then_removes_exact_runtime() {
        let (_directory, request, executable, event) = fixture("public");
        let public_path = request.config.runtime_dir.clone();
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let public = PublicRuntime::prepare_with(&public_path, uid, gid, |_, _, _| Ok(())).unwrap();
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let receipt = Receipt::default();
        let task = tokio::spawn(exercise(
            request,
            executable,
            runtime,
            Some(public),
            CancellationToken::new(),
            receipt.clone(),
        ));
        wait_event(&event, "pinged").await;
        assert_eq!(
            crate::cli::status(&public_path, true, true).await.unwrap(),
            3
        );
        assert_eq!(crate::cli::stop(&public_path).await.unwrap(), 0);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(receipt.reaped());
        assert!(!public_path.exists());
        assert_eq!(fs::read_to_string(event).unwrap(), "stopped");
    }
    #[tokio::test]
    async fn foreground_reports_child_failure_after_confirmed_pool_shutdown() {
        let (_directory, request, executable, event) = fixture("public_exit");
        let path = request.config.runtime_dir.clone();
        let public = PublicRuntime::prepare_with(
            &path,
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
            |_, _, _| Ok(()),
        )
        .unwrap();
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let receipt = Receipt::default();
        let task = tokio::spawn(exercise(
            request,
            executable,
            runtime,
            Some(public),
            CancellationToken::new(),
            receipt.clone(),
        ));
        wait_event(&event, "pinged").await;
        assert_eq!(crate::cli::status(&path, true, true).await.unwrap(), 3);
        assert_eq!(crate::cli::stop(&path).await.unwrap(), 0);
        let error = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("退出失败"));
        assert!(receipt.reaped());
        assert!(!path.exists());
    }
    #[test]
    fn public_runtime_uses_os_lock_and_refuses_unknown_or_replaced_nodes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let mut runtime = PublicRuntime::prepare_with(&path, uid, gid, |_, _, _| Ok(())).unwrap();
        assert!(InstanceLock::acquire(&path).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o750);
        assert_eq!(
            fs::metadata(path.join("control.sock")).unwrap().mode() & 0o777,
            0o660
        );
        let unknown = path.join("unknown");
        fs::write(&unknown, b"keep").unwrap();
        assert!(runtime.cleanup().is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"keep");
        fs::remove_file(unknown).unwrap();
        let socket = path.join("control.sock");
        let saved = path.join("saved.sock");
        fs::rename(&socket, &saved).unwrap();
        fs::write(&socket, b"replacement").unwrap();
        assert_eq!(
            runtime.cleanup().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read(&socket).unwrap(), b"replacement");
        fs::remove_file(socket).unwrap();
        fs::rename(saved, path.join("control.sock")).unwrap();
        runtime.cleanup().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn public_runtime_preparation_failure_removes_only_new_empty_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("public");
        let error = match PublicRuntime::prepare_with(&path, 1, 1, |_, _, _| {
            Err(io::Error::other("受控归属失败"))
        }) {
            Ok(_) => panic!("受控归属失败不应成功"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "受控归属失败");
        assert!(!path.exists());
        let existing = directory.path().join("existing");
        fs::create_dir(&existing).unwrap();
        fs::write(existing.join("keep"), b"keep").unwrap();
        let error = match PublicRuntime::prepare_with(&existing, 1, 1, |_, _, _| Ok(())) {
            Ok(_) => panic!("既有目录不应被接管"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(existing.join("keep")).unwrap(), b"keep");
    }
    #[test]
    fn persistent_data_directory_is_owned_private_and_not_emptied() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        let identity = WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        };
        prepare_data_directory_with(&path, identity, |_, _, _| Ok(())).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        fs::write(path.join("cache"), b"persist").unwrap();
        prepare_data_directory_with(&path, identity, |_, _, _| panic!("既有目录不应改归属"))
            .unwrap();
        assert_eq!(fs::read(path.join("cache")).unwrap(), b"persist");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prepare_data_directory_with(&path, identity, |_, _, _| Ok(())).is_err());
        assert_eq!(fs::read(path.join("cache")).unwrap(), b"persist");
    }
    #[test]
    fn failed_new_data_directory_ownership_rolls_back_empty_node() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        let identity = WorkerCredentials { uid: 501, gid: 20 };
        assert!(
            prepare_data_directory_with(&path, identity, |_, _, _| {
                Err(io::Error::other("受控归属失败"))
            })
            .is_err()
        );
        assert!(!path.exists());
    }
    #[tokio::test]
    async fn dropping_outer_wait_keeps_same_owner_reaping_child_and_cleaning_materials() {
        let (_directory, request, executable, event) = fixture("ignore");
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let receipt = Receipt::default();
        let outer = tokio::spawn(supervise_owned(
            request,
            executable,
            move || Ok(runtime),
            CancellationToken::new(),
            receipt.clone(),
        ));
        wait_event(&event, "pinged").await;
        assert!(!receipt.reaped());
        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(4), async {
            while !receipt.reaped() || root.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn rejected_identity_oversized_frame_and_wrong_pid_reap_actual_child() {
        for mode in ["identity", "oversized", "pid"] {
            let (_directory, request, executable, event) = fixture(mode);
            let (_parent, runtime) = GenerationRuntime::test_prepare();
            let root = runtime.root().to_owned();
            let receipt = Receipt::default();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                exercise(
                    request,
                    executable,
                    runtime,
                    None,
                    CancellationToken::new(),
                    receipt.clone(),
                ),
            )
            .await
            .unwrap();
            assert!(result.is_err(), "{mode}");
            assert!(receipt.reaped(), "{mode}");
            assert!(
                !root.exists(),
                "{mode}：{result:?}；{:?}",
                fs::read_dir(&root).map(|entries| entries
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<Vec<_>>())
            );
            if mode != "pid" {
                assert_eq!(fs::read_to_string(event).unwrap(), "spawned");
            }
        }
    }
    #[tokio::test]
    async fn startup_cancel_does_not_wait_for_handshake_deadline_or_leave_child() {
        let (_directory, request, executable, event) = fixture("stall");
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let stop = CancellationToken::new();
        let receipt = Receipt::default();
        let task = tokio::spawn(exercise(
            request,
            executable,
            runtime,
            None,
            stop.clone(),
            receipt.clone(),
        ));
        wait_event(&event, "spawned").await;
        stop.cancel();
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(receipt.reaped());
        assert!(!root.exists());
    }
    #[tokio::test]
    async fn handshake_total_deadline_reaps_silent_child() {
        let (_directory, request, executable, _) = fixture("stall");
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let receipt = Receipt::default();
        let start = tokio::time::Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            exercise(
                request,
                executable,
                runtime,
                None,
                CancellationToken::new(),
                receipt.clone(),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= STARTUP);
        assert!(receipt.reaped());
        assert!(!root.exists());
    }
    #[tokio::test]
    async fn abnormal_child_exit_stops_control_and_reaps_before_cleanup() {
        let (_directory, request, executable, _) = fixture("exit");
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let receipt = Receipt::default();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(5),
                exercise(
                    request,
                    executable,
                    runtime,
                    None,
                    CancellationToken::new(),
                    receipt.clone()
                )
            )
            .await
            .unwrap()
            .is_err()
        );
        assert!(receipt.reaped());
        assert!(!root.exists());
    }
    #[tokio::test]
    async fn unresponsive_running_child_is_forced_and_reaped_on_stop() {
        let (_directory, request, executable, event) = fixture("ignore");
        let (_parent, runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_owned();
        let receipt = Receipt::default();
        let stop = CancellationToken::new();
        let task = tokio::spawn(exercise(
            request,
            executable,
            runtime,
            None,
            stop.clone(),
            receipt.clone(),
        ));
        wait_event(&event, "pinged").await;
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(receipt.reaped());
        assert!(!root.exists());
    }
    #[tokio::test]
    async fn ordinary_supervisor_fails_before_materials_or_program_inspection() {
        let (_directory, mut request, _, _) = fixture("good");
        request.identity.uid = 0;
        let error = supervise(request, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    #[tokio::test]
    async fn invalid_bootstrap_cannot_touch_cache_source_or_listener() {
        let (mut parent, child) = UnixStream::pair().unwrap();
        let authorization = Uuid::new_v4();
        let directory = tempfile::tempdir().unwrap();
        let bootstrap = Bootstrap {
            version: 1,
            authorization: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            uid: 501,
            gid: 20,
            config: AppConfig {
                data_dir: directory.path().join("data"),
                runtime_dir: directory.path().join("runtime"),
                ..Default::default()
            },
            listen_scope: crate::logging::ListenScope::ProcessLocal,
        };
        let listener_directory = tempfile::tempdir().unwrap();
        let listener = StdListener::bind(listener_directory.path().join("control.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(listener).unwrap();
        let task = tokio::spawn(child_entry(child, listener, authorization));
        send(&mut parent, &bootstrap).await.unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        assert_eq!(
            parent.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[test]
    fn startup_commit_rejects_wrong_instance_authorization_and_version() {
        let authorization = Uuid::new_v4();
        let instance = Uuid::new_v4();
        for (version, auth, id) in [
            (2, authorization, instance),
            (1, Uuid::new_v4(), instance),
            (1, authorization, Uuid::new_v4()),
        ] {
            assert!(
                Commit {
                    version,
                    authorization: auth,
                    instance_id: id
                }
                .validate(authorization, instance)
                .is_err()
            );
        }
        assert!(serde_json::from_value::<Commit>(serde_json::json!({"version":1,"authorization":authorization,"instance_id":instance,"extra":true})).is_err());
    }
}
