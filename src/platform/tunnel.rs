//! 直属隧道启动、管理连接及本次端点归属；不发布已验证出口。
use super::{
    custody::{self, UtunCustody},
    launcher,
    management::{self, TunnelPeer},
    supervisor::force_reap,
};
use crate::domain::Endpoint;
use std::{
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::UnixStream as StdUnixStream,
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    process::{Child, Command},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod configuration;
pub use configuration::ConfiguredMacInterface;

pub struct TunnelStartup {
    pub runtime: PathBuf,
    pub dependency_manifest: PathBuf,
    pub profile: PathBuf,
    pub endpoint: Endpoint,
    pub startup_budget: Duration,
}

/// 仅清理本次创建的套接字节点；名称被替换后不得删除替代对象。
pub(crate) struct ManagementPath {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    removed: bool,
}

impl ManagementPath {
    fn bind(path: PathBuf) -> io::Result<(UnixListener, Self)> {
        let listener = UnixListener::bind(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let owner = Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            removed: false,
        };
        std::fs::set_permissions(&owner.path, std::fs::Permissions::from_mode(0o600))?;
        Ok((listener, owner))
    }

    pub(crate) fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.removed = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "管理端点归属已改变，拒绝删除",
            ));
        }
        std::fs::remove_file(&self.path)?;
        self.removed = true;
        Ok(())
    }
}
impl Drop for ManagementPath {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

pub struct ManagedMacTunnel {
    child: Option<Child>,
    management: Option<UnixStream>,
    path: Option<ManagementPath>,
    endpoint: Endpoint,
    index: u32,
    uid: u32,
    interface_notifications: bool,
    startup_budget: Duration,
    receipt: super::process::Receipt,
}

impl ManagedMacTunnel {
    /// 只能由可信特权父进程调用；对普通业务不开放可执行路径或任意参数。
    /// 启动成功仅确认直属管理端身份，连接材料与出口仍须联合监督和业务验证。
    pub async fn start(
        request: TunnelStartup,
        custody: &UtunCustody,
        stop: CancellationToken,
    ) -> io::Result<Self> {
        Self::start_mode(
            request,
            custody,
            stop,
            false,
            super::process::Receipt::default(),
        )
        .await
    }

    /// 与严格拓扑配置监督入口配套；不得交给仅处理连接状态的旧联合会话。
    pub async fn start_for_configuration(
        request: TunnelStartup,
        custody: &UtunCustody,
        stop: CancellationToken,
    ) -> io::Result<Self> {
        Self::start_mode(
            request,
            custody,
            stop,
            true,
            super::process::Receipt::default(),
        )
        .await
    }

    pub(crate) async fn start_tracked(
        request: TunnelStartup,
        custody: &UtunCustody,
        stop: CancellationToken,
        receipt: super::process::Receipt,
    ) -> io::Result<Self> {
        Self::start_mode(request, custody, stop, true, receipt).await
    }
    pub(crate) fn receipt(&self) -> super::process::Receipt {
        self.receipt.clone()
    }
    pub(crate) fn management_path(&self) -> io::Result<&Path> {
        self.path
            .as_ref()
            .map(|owned| owned.path.as_path())
            .ok_or_else(|| io::Error::other("隧道管理端点已释放"))
    }

    async fn start_mode(
        request: TunnelStartup,
        custody: &UtunCustody,
        stop: CancellationToken,
        interface_notifications: bool,
        receipt: super::process::Receipt,
    ) -> io::Result<Self> {
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "隧道父进程需要管理员身份",
            ));
        }
        launcher::root_chain(&request.runtime)?;
        let directory = std::fs::symlink_metadata(&request.runtime)?;
        if !directory.is_dir() || directory.mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "隧道管理目录必须为管理员私有目录",
            ));
        }
        let executable = super::program::verify_current()?;
        let program = launcher::root_file(&executable, 256 * 1024 * 1024, false)?;
        if program.metadata()?.mode() & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "本项目程序不可执行",
            ));
        }
        drop(program);
        drop(launcher::root_file(
            &request.dependency_manifest,
            32768,
            false,
        )?);
        drop(launcher::root_file(&request.profile, 256 * 1024, true)?);
        Self::launch_tracked(
            &executable,
            request,
            custody.duplicate_descriptor()?,
            custody.interface_index(),
            0,
            stop,
            interface_notifications,
            receipt,
        )
        .await
    }

    #[cfg(test)]
    async fn launch(
        executable: &Path,
        request: TunnelStartup,
        descriptor: OwnedFd,
        index: u32,
        expected_uid: u32,
        stop: CancellationToken,
    ) -> io::Result<Self> {
        Self::launch_mode(
            executable,
            request,
            descriptor,
            index,
            expected_uid,
            stop,
            false,
        )
        .await
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    async fn launch_mode(
        executable: &Path,
        request: TunnelStartup,
        descriptor: OwnedFd,
        index: u32,
        expected_uid: u32,
        stop: CancellationToken,
        interface_notifications: bool,
    ) -> io::Result<Self> {
        Self::launch_tracked(
            executable,
            request,
            descriptor,
            index,
            expected_uid,
            stop,
            interface_notifications,
            super::process::Receipt::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch_tracked(
        executable: &Path,
        request: TunnelStartup,
        descriptor: OwnedFd,
        index: u32,
        expected_uid: u32,
        stop: CancellationToken,
        interface_notifications: bool,
        receipt: super::process::Receipt,
    ) -> io::Result<Self> {
        request
            .endpoint
            .validate()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "隧道授权端点无效"))?;
        if index == 0
            || request.startup_budget.is_zero()
            || request.startup_budget > Duration::from_secs(120)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "隧道启动索引或截止无效",
            ));
        }
        if stop.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "隧道启动已取消"));
        }
        let deadline = tokio::time::Instant::now() + request.startup_budget;
        // 即使调用方交来的句柄可继承，也只保留执行时关闭的复制件。
        let non_inheritable = descriptor.try_clone()?;
        drop(descriptor);
        let descriptor = non_inheritable;
        let authorization = Uuid::new_v4();
        let (listener, path, parent, child) = super::spawn::guarded(|| {
            let (listener, path) = ManagementPath::bind(
                request
                    .runtime
                    .join(format!("t-{}.sock", authorization.simple())),
            )?;
            let (parent, control) = StdUnixStream::pair()?;
            let mut command = Command::new(executable);
            command
                .arg("mac-tunnel")
                .arg("--dependency-manifest")
                .arg(&request.dependency_manifest)
                .arg("--profile")
                .arg(&request.profile)
                .arg("--management")
                .arg(&path.path)
                .arg("--remote")
                .arg(request.endpoint.socket().to_string())
                .arg("--transport")
                .arg(request.endpoint.transport.to_string())
                .arg("--interface-index")
                .arg(index.to_string())
                .arg("--authorization")
                .arg(authorization.to_string())
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LANG", "C")
                .current_dir(&request.runtime)
                .process_group(0)
                .stdin(Stdio::from(OwnedFd::from(control)))
                .stdout(Stdio::null())
                .stderr(receipt.child_stderr()?)
                .kill_on_drop(true);
            if interface_notifications {
                command.arg("--interface-notifications");
            }
            let child = command.spawn()?;
            receipt.spawned();
            drop(command);
            Ok((listener, path, parent, child))
        })?;
        // 在第一个异步等待前建立独占所有权，取消启动未来也会关闭管理端并终止子进程。
        let mut tunnel = Self {
            child: Some(child),
            management: None,
            path: Some(path),
            endpoint: request.endpoint,
            index,
            uid: expected_uid,
            interface_notifications,
            startup_budget: request.startup_budget,
            receipt,
        };
        let outcome = async {
            let handoff_budget = deadline.saturating_duration_since(tokio::time::Instant::now()).min(Duration::from_secs(3));
            if handoff_budget.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "隧道句柄交接前已超时"));
            }
            custody::send(&parent, descriptor.as_fd(), authorization, index, handoff_budget)?;
            drop(descriptor);
            drop(parent);
            let child = tunnel.child.as_mut().expect("直属子进程已登记");
            let pid = child.id().ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "隧道启动进程已退出"))?;
            let (stream, _) = tokio::select! {
                biased;
                _ = stop.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "隧道启动已取消")),
                status = child.wait() => {
                    status?;
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道在管理连接前退出"));
                }
                result = tokio::time::timeout_at(deadline, super::spawn::accept(&listener)) => {
                    result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "隧道管理连接超时"))??
                }
            };
            management::authenticate(&stream, TunnelPeer { pid, uid: expected_uid })?;
            if child.try_wait()?.is_some() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道管理连接后已退出"));
            }
            if stop.is_cancelled() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "隧道启动已取消"));
            }
            tunnel.management = Some(stream);
            Ok(())
        }.await;
        drop(listener);
        match outcome {
            Ok(()) => Ok(tunnel),
            Err(error) => match tunnel.retire().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}；启动回收：{cleanup}"),
                )),
            },
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }

    #[cfg(test)]
    pub(crate) async fn test_launch(
        executable: &Path,
        request: TunnelStartup,
        descriptor: OwnedFd,
        index: u32,
        expected_uid: u32,
    ) -> io::Result<Self> {
        Self::launch(
            executable,
            request,
            descriptor,
            index,
            expected_uid,
            CancellationToken::new(),
        )
        .await
    }

    #[cfg(test)]
    pub(crate) fn test_require_configuration(&mut self) {
        self.interface_notifications = true;
    }
    pub(crate) fn requires_configuration(&self) -> bool {
        self.interface_notifications
    }
    pub(crate) fn interface_index(&self) -> u32 {
        self.index
    }
    pub(crate) fn ensure_running(&mut self) -> io::Result<()> {
        if self.management.is_none()
            || self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "隧道已退休"))?
                .try_wait()?
                .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "隧道已退休或退出",
            ));
        }
        Ok(())
    }
    pub(crate) fn remote_address(&self) -> std::net::Ipv4Addr {
        self.endpoint.ip
    }

    pub(crate) fn into_parts(mut self) -> io::Result<(Child, UnixStream, ManagementPath, u32)> {
        if self.interface_notifications {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "拓扑通知隧道必须由配置监督入口接管",
            ));
        }
        if self.child.is_none() || self.management.is_none() || self.path.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "隧道已退休或启动未完成",
            ));
        }
        Ok((
            self.child.take().expect("直属子进程存在"),
            self.management.take().expect("管理连接已认证"),
            self.path.take().expect("管理端点已登记"),
            self.uid,
        ))
    }

    /// 关闭管理通道，限时等待正常退出；无响应则通过直属对象强制退出和回收。
    /// 即使回收失败也尝试归属核对后的端点清理，错误不得吞掉。
    pub async fn retire(&mut self) -> io::Result<()> {
        self.management.take();
        let process = if let Some(child) = self.child.as_mut() {
            match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(status)) if status.success() => Ok(()),
                Ok(Ok(_)) => Err(io::Error::other("隧道启动或退出状态异常")),
                result => {
                    let error = match result {
                        Ok(Err(error)) => error,
                        Err(_) => io::Error::new(io::ErrorKind::TimedOut, "隧道退出超时"),
                        _ => unreachable!(),
                    };
                    match force_reap(child, Duration::from_secs(2)).await {
                        Ok(_) => Err(error),
                        Err(reap) => Err(io::Error::new(
                            error.kind(),
                            format!("{error}；强制回收：{reap}"),
                        )),
                    }
                }
            }
        } else {
            Ok(())
        };
        if let Some(child) = self.child.as_mut() {
            self.receipt.observe(child);
        }
        let path = self.path.as_mut().map_or(Ok(()), ManagementPath::remove);
        match (process, path) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(path)) => Err(io::Error::new(
                error.kind(),
                format!("{error}；端点清理：{path}"),
            )),
        }
    }
}

impl Drop for ManagedMacTunnel {
    fn drop(&mut self) {
        self.management.take();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        // Child 的运行时回收不能替代显式等待成功；端点守卫只删除本次节点。
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
        },
    };

    const CHILD: &str = r#"#!/usr/bin/python3
import array, os, socket, stat, sys, time, uuid
from pathlib import Path
import traceback
def report(t, value, tb):
    Path('child.error').write_text(''.join(traceback.format_exception(t, value, tb)))
sys.excepthook = report
args = sys.argv[1:]
assert args[0] == 'mac-tunnel'
assert os.getpgrp() == os.getpid()
assert 'PYTHONPATH' not in os.environ
for fd in range(3, 1024):
    try: item = os.fstat(fd)
    except OSError: continue
    assert not stat.S_ISSOCK(item.st_mode), f'额外套接字：{fd}'
channel = socket.socket(fileno=0)
data, ancillary, flags, _ = channel.recvmsg(24, socket.CMSG_SPACE(4))
auth = uuid.UUID(args[args.index('--authorization') + 1])
index = int(args[args.index('--interface-index') + 1])
assert data == b'VAP1' + auth.bytes + index.to_bytes(4, 'big')
fds = array.array('i'); fds.frombytes(ancillary[0][2])
assert len(fds) == 1
channel.close()
Path('child.pid').write_text(str(os.getpid()))
Path('notifications').write_text(str('--interface-notifications' in args))
if MODE == 'exit': sys.exit(23)
if MODE == 'silent':
    while True: time.sleep(.01)
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.connect(args[args.index('--management') + 1])
if MODE == 'hang':
    while True: time.sleep(.01)
assert connection.recv(1) == b''
os.close(fds[0])
"#;

    pub(crate) fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        TunnelStartup,
        OwnedFd,
        UnixStream,
        u32,
    ) {
        let dir = tempfile::Builder::new()
            .prefix("vap-t-")
            .tempdir_in("/tmp")
            .unwrap();
        let executable = dir.path().join("child.py");
        std::fs::write(
            &executable,
            CHILD.replacen("import array", "MODE = 'normal'\nimport array", 1),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let request = TunnelStartup {
            runtime: dir.path().to_path_buf(),
            dependency_manifest: dir.path().join("dependency.json"),
            profile: dir.path().join("profile.conf"),
            endpoint: Endpoint {
                ip: "8.8.8.8".parse().unwrap(),
                port: 443,
                transport: crate::domain::Transport::Tcp,
            },
            startup_budget: Duration::from_secs(3),
        };
        let uid = dir.path().metadata().unwrap().uid();
        let (owner, peer) = UnixStream::pair().unwrap();
        (dir, executable, request, owner.into(), peer, uid)
    }

    async fn assert_closed(peer: &mut UnixStream) {
        peer.set_nonblocking(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match peer.read(&mut [0]) {
                    Ok(0) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(5)).await
                    }
                    result => panic!("句柄未释放：{result:?}"),
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tunnel_parent_launches_and_reaps_direct_child() {
        let (dir, executable, request, fd, mut peer, uid) = fixture();
        let mut tunnel =
            ManagedMacTunnel::launch(&executable, request, fd, 1, uid, CancellationToken::new())
                .await
                .unwrap();
        assert!(!tunnel.receipt().reaped());
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        tunnel.retire().await.unwrap();
        assert!(tunnel.receipt().reaped());
        assert!(tunnel.into_parts().is_err());
        assert_closed(&mut peer).await;
        let pid = std::fs::read_to_string(dir.path().join("child.pid")).unwrap();
        assert!(
            !std::process::Command::new("/bin/ps")
                .args(["-p", pid.trim(), "-o", "stat="])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(
            !std::fs::read_dir(dir.path()).unwrap().any(|p| p
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "sock"))
        );
    }
    pub(crate) fn set_mode(executable: &Path, mode: &str) {
        std::fs::write(
            executable,
            CHILD.replacen("import array", &format!("MODE = {mode:?}\nimport array"), 1),
        )
        .unwrap();
    }

    pub(super) fn assert_no_socket(runtime: &Path) {
        assert!(!std::fs::read_dir(runtime).unwrap().any(|entry| {
            entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "sock")
        }));
    }

    pub(crate) fn assert_reaped(runtime: &Path) {
        let pid = std::fs::read_to_string(runtime.join("child.pid")).unwrap();
        assert!(
            !std::process::Command::new("/bin/ps")
                .args(["-p", pid.trim(), "-o", "stat="])
                .output()
                .unwrap()
                .status
                .success(),
            "直属子进程仍存在"
        );
    }

    async fn wait_started(runtime: &Path) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !runtime.join("child.pid").exists() {
                if let Ok(error) = std::fs::read_to_string(runtime.join("child.error")) {
                    panic!("测试子进程失败：{error}");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tunnel_parent_reaps_early_exit_and_startup_deadline() {
        for (mode, kind) in [
            ("exit", io::ErrorKind::BrokenPipe),
            ("silent", io::ErrorKind::TimedOut),
        ] {
            let (dir, executable, mut request, fd, mut peer, uid) = fixture();
            set_mode(&executable, mode);
            request.startup_budget = Duration::from_secs(3);
            let error = ManagedMacTunnel::launch(
                &executable,
                request,
                fd,
                1,
                uid,
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(
                error.kind(),
                kind,
                "{error}；子进程诊断：{:?}",
                std::fs::read_to_string(dir.path().join("child.error"))
            );
            assert_closed(&mut peer).await;
            assert_reaped(dir.path());
            assert_no_socket(dir.path());
        }
    }

    #[tokio::test]
    async fn tunnel_parent_refuses_wrong_management_user_and_process() {
        let (dir, executable, request, fd, mut peer, uid) = fixture();
        let error = ManagedMacTunnel::launch(
            &executable,
            request,
            fd,
            1,
            uid + 1,
            CancellationToken::new(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{error}；子进程诊断：{:?}",
            std::fs::read_to_string(dir.path().join("child.error"))
        );
        assert_closed(&mut peer).await;
        assert_reaped(dir.path());
        assert_no_socket(dir.path());

        let (dir, executable, request, fd, mut peer, uid) = fixture();
        set_mode(&executable, "silent");
        let intruder = async {
            wait_started(dir.path()).await;
            let path = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|x| x.unwrap().path())
                .find(|x| x.extension().is_some_and(|s| s == "sock"))
                .unwrap();
            tokio::net::UnixStream::connect(path).await.unwrap()
        };
        let (result, connection) = tokio::join!(
            ManagedMacTunnel::launch(&executable, request, fd, 1, uid, CancellationToken::new()),
            intruder
        );
        assert_eq!(
            result.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(connection);
        assert_closed(&mut peer).await;
        assert_reaped(dir.path());
        assert_no_socket(dir.path());
    }

    #[tokio::test]
    async fn tunnel_parent_rejects_invalid_and_already_cancelled_start_without_spawn() {
        for case in 0..5 {
            let (dir, executable, mut request, fd, mut peer, uid) = fixture();
            let stop = CancellationToken::new();
            let mut index = 1;
            match case {
                0 => stop.cancel(),
                1 => index = 0,
                2 => request.startup_budget = Duration::ZERO,
                3 => request.startup_budget = Duration::from_secs(121),
                _ => request.endpoint.ip = std::net::Ipv4Addr::LOCALHOST,
            }
            let error = ManagedMacTunnel::launch(&executable, request, fd, index, uid, stop)
                .await
                .err()
                .unwrap();
            assert_eq!(
                error.kind(),
                if case == 0 {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
            assert!(!dir.path().join("child.pid").exists());
            assert_closed(&mut peer).await;
            assert_no_socket(dir.path());
        }
    }

    #[tokio::test]
    async fn tunnel_parent_cancelled_start_reaps_before_return() {
        let (dir, executable, request, fd, mut peer, uid) = fixture();
        set_mode(&executable, "silent");
        let stop = CancellationToken::new();
        let cancelling = async {
            wait_started(dir.path()).await;
            stop.cancel();
        };
        let (result, ()) = tokio::join!(
            ManagedMacTunnel::launch(&executable, request, fd, 1, uid, stop.clone()),
            cancelling
        );
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Interrupted);
        assert_closed(&mut peer).await;
        assert_reaped(dir.path());
        assert_no_socket(dir.path());
    }

    #[tokio::test]
    async fn tunnel_parent_aborted_start_kills_child_and_removes_own_endpoint() {
        let (dir, executable, request, fd, mut peer, uid) = fixture();
        set_mode(&executable, "silent");
        let task = tokio::spawn(async move {
            ManagedMacTunnel::launch(&executable, request, fd, 1, uid, CancellationToken::new())
                .await
        });
        wait_started(dir.path()).await;
        task.abort();
        assert!(task.await.err().unwrap().is_cancelled());
        assert_closed(&mut peer).await;
        // 持续运行的异步运行时负责丢弃路径的最终回收；不把取消本身当作回收确认。
        tokio::time::timeout(Duration::from_secs(3), async {
            let pid = std::fs::read_to_string(dir.path().join("child.pid")).unwrap();
            loop {
                let result = std::process::Command::new("/bin/ps")
                    .args(["-p", pid.trim(), "-o", "stat="])
                    .output()
                    .unwrap();
                if !result.status.success() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_no_socket(dir.path());
    }

    #[tokio::test]
    async fn tunnel_parent_forces_unresponsive_tunnel_and_preserves_error() {
        let (dir, executable, request, fd, mut peer, uid) = fixture();
        set_mode(&executable, "hang");
        let mut tunnel =
            ManagedMacTunnel::launch(&executable, request, fd, 1, uid, CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(
            tunnel.retire().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_closed(&mut peer).await;
        assert_reaped(dir.path());
        assert_no_socket(dir.path());
    }

    #[tokio::test]
    async fn tunnel_parent_never_deletes_replaced_or_preexisting_endpoint() {
        let (dir, _, _, fd, _, _) = fixture();
        drop(fd);
        let path = dir.path().join("owned.sock");
        let (listener, mut owner) = ManagementPath::bind(path.clone()).unwrap();
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        std::fs::rename(&path, dir.path().join("moved.sock")).unwrap();
        let replacement = tokio::net::UnixListener::bind(&path).unwrap();
        assert_eq!(
            owner.remove().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(owner);
        assert!(path.exists());
        drop(replacement);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "保留".as_bytes()).unwrap();
        assert!(ManagementPath::bind(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), "保留".as_bytes());
        drop(listener);
    }
}
