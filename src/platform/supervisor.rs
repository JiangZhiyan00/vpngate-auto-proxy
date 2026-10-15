//! 直属苹果业务子进程；仅接纳可信辅助方已经核验的隧道句柄。
use std::{
    io,
    os::{
        fd::AsFd,
        unix::{fs::MetadataExt, net::UnixStream as StdUnixStream},
    },
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::UnixStream,
    process::{Child, Command},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    custody::{self, UtunCustody},
    worker::{WorkerStartup, wait_ready, wait_retired},
};

#[derive(Clone, Copy)]
pub struct WorkerCredentials {
    pub uid: u32,
    pub gid: u32,
}
impl WorkerCredentials {
    pub(crate) fn validate_account(self) -> io::Result<()> {
        use nix::unistd::{Gid, Group, Uid, User};
        if self.uid == 0 || self.gid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "业务身份不得为管理员",
            ));
        }
        let user = User::from_uid(Uid::from_raw(self.uid))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "业务账户不存在"))?;
        if user.gid.as_raw() != self.gid || Group::from_gid(Gid::from_raw(self.gid))?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "业务主组与所选账户不符",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Budgets {
    startup: Duration,
    retirement: Duration,
    reap: Duration,
}
const BUDGETS: Budgets = Budgets {
    startup: Duration::from_secs(3),
    retirement: Duration::from_secs(4),
    reap: Duration::from_secs(2),
};

pub struct ManagedMacWorker {
    // 丢弃时先关闭监督端，再由 Child 的 kill_on_drop 终止直属子进程。
    control: Option<UnixStream>,
    child: Child,
    startup: WorkerStartup,
    generation: Uuid,
    socket_path: PathBuf,
    budgets: Budgets,
    receipt: super::process::Receipt,
}

impl ManagedMacWorker {
    /// 当前程序自身的隐藏命令；外部辅助协议不得提供可执行文件或任意启动参数。
    pub async fn start(
        runtime: &Path,
        custody: UtunCustody,
        credentials: WorkerCredentials,
        max_connections: usize,
    ) -> io::Result<Self> {
        custody.revalidate()?;
        let executable = super::program::verify_current()?;
        let (descriptor, index) = custody.into_descriptor();
        Self::launch(
            &executable,
            runtime,
            descriptor,
            index,
            credentials,
            max_connections,
            BUDGETS,
        )
        .await
    }

    /// 启动取消仍等待直属子进程回收；直接丢弃未来不等于回收成功。
    pub async fn start_cancellable(
        runtime: &Path,
        custody: UtunCustody,
        credentials: WorkerCredentials,
        max_connections: usize,
        stop: CancellationToken,
    ) -> io::Result<Self> {
        Self::start_tracked(
            runtime,
            custody,
            credentials,
            max_connections,
            stop,
            super::process::Receipt::default(),
        )
        .await
    }

    pub(crate) async fn start_tracked(
        runtime: &Path,
        custody: UtunCustody,
        credentials: WorkerCredentials,
        max_connections: usize,
        stop: CancellationToken,
        receipt: super::process::Receipt,
    ) -> io::Result<Self> {
        if stop.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "工作进程启动已经取消",
            ));
        }
        custody.revalidate()?;
        let executable = super::program::verify_current()?;
        let (descriptor, index) = custody.into_descriptor();
        Self::launch_with_stop(
            &executable,
            runtime,
            descriptor,
            index,
            credentials,
            max_connections,
            BUDGETS,
            stop,
            receipt,
        )
        .await
    }

    async fn launch(
        executable: &Path,
        runtime: &Path,
        descriptor: std::os::fd::OwnedFd,
        index: u32,
        credentials: WorkerCredentials,
        max_connections: usize,
        budgets: Budgets,
    ) -> io::Result<Self> {
        Self::launch_with_stop(
            executable,
            runtime,
            descriptor,
            index,
            credentials,
            max_connections,
            budgets,
            CancellationToken::new(),
            super::process::Receipt::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch_with_stop(
        executable: &Path,
        runtime: &Path,
        descriptor: std::os::fd::OwnedFd,
        index: u32,
        credentials: WorkerCredentials,
        max_connections: usize,
        budgets: Budgets,
        stop: CancellationToken,
        receipt: super::process::Receipt,
    ) -> io::Result<Self> {
        if stop.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "工作进程启动已经取消",
            ));
        }
        let directory = std::fs::symlink_metadata(runtime)?;
        let program = std::fs::symlink_metadata(executable)?;
        if !runtime.is_absolute()
            || !program.is_file()
            || program.file_type().is_symlink()
            || program.mode() & 0o6000 != 0
            || !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.mode() & 0o777 != 0o750
            || directory.uid() != credentials.uid
            || directory.gid() != credentials.gid
            || credentials.uid == 0
            || credentials.gid == 0
            || index == 0
            || max_connections == 0
            || max_connections > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "工作进程身份或私有目录无效",
            ));
        }
        // 标准库复制保证新句柄执行时关闭；关闭原件后再派生，避免绕过私有交接继承。
        let non_inheritable = descriptor.try_clone()?;
        drop(descriptor);
        let descriptor = non_inheritable;
        let authorization = Uuid::new_v4();
        let startup = WorkerStartup {
            authorization,
            interface_index: index,
            max_connections,
        };
        let socket_path = runtime.join(format!("w-{}.sock", authorization.simple()));
        let (parent, mut child) = super::spawn::guarded(|| {
            let (parent, child_control) = StdUnixStream::pair()?;
            let mut command = Command::new(executable);
            command
                .arg("mac-worker")
                .arg("--socket")
                .arg(&socket_path)
                .arg("--max-connections")
                .arg(max_connections.to_string())
                .arg("--interface-index")
                .arg(index.to_string())
                .arg("--authorization")
                .arg(authorization.to_string())
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LANG", "C")
                .current_dir(runtime)
                .uid(credentials.uid)
                .gid(credentials.gid)
                .process_group(0)
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_control)))
                .stdout(Stdio::null())
                .stderr(receipt.child_stderr()?)
                .kill_on_drop(true);
            let child = command.spawn()?;
            receipt.spawned();
            // Command 持有标准输入原件；必须立即关闭，不能让父方副本延长子端生命周期。
            drop(command);
            Ok((parent, child))
        })?;
        let sent = custody::send(
            &parent,
            descriptor.as_fd(),
            authorization,
            index,
            budgets.startup,
        );
        drop(descriptor);
        let startup_result = async {
            sent?;
            parent.set_nonblocking(true)?;
            let mut control = UnixStream::from_std(parent)?;
            let generation = tokio::select! {
                biased;
                _ = stop.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted, "工作进程启动已经取消")),
                result = tokio::time::timeout(budgets.startup, wait_ready(&mut control, startup)) =>
                    result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "工作进程启动超时"))??,
            };
            if stop.is_cancelled() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "工作进程就绪时启动已经取消"));
            }
            if child.try_wait()?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "工作进程就绪后已退出",
                ));
            }
            Ok((control, generation))
        }
        .await;
        match startup_result {
            Ok((control, generation)) => Ok(Self {
                control: Some(control),
                child,
                startup,
                generation,
                socket_path,
                budgets,
                receipt,
            }),
            Err(error) => {
                let cleanup = force_reap(&mut child, budgets.reap).await;
                receipt.observe(&mut child);
                match cleanup {
                    Ok(_) => Err(error),
                    Err(cleanup) => Err(io::Error::new(
                        error.kind(),
                        format!("{error}；启动回收：{cleanup}"),
                    )),
                }
            }
        }
    }

    pub fn generation(&self) -> Uuid {
        self.generation
    }
    pub(crate) fn interface_index(&self) -> u32 {
        self.startup.interface_index
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
    pub fn is_running(&mut self) -> io::Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
    pub(crate) async fn wait_for_exit(&mut self) -> io::Result<ExitStatus> {
        self.child.wait().await
    }
    pub(crate) fn close_control(&mut self) {
        self.control.take();
    }

    /// 退休帧与正常直属子进程退出均通过才成功；错误仍尝试限时强制回收。
    pub async fn retire(&mut self) -> io::Result<()> {
        let Some(mut control) = self.control.take() else {
            // 上一次退休等待被取消后，仍可通过直属 Child 句柄完成强制回收。
            let result = force_reap(&mut self.child, self.budgets.reap).await;
            self.receipt.observe(&mut self.child);
            result?;
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "工作进程已经停止",
            ));
        };
        let outcome = tokio::time::timeout(self.budgets.retirement, async {
            control.write_all(b"R").await?;
            wait_retired(&mut control, self.startup, self.generation).await?;
            let status = self.child.wait().await?;
            if !status.success() {
                return Err(io::Error::other("工作进程退休退出失败"));
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "工作进程退休超时")));
        drop(control);
        if outcome.is_err() {
            let result = force_reap(&mut self.child, self.budgets.reap).await;
            self.receipt.observe(&mut self.child);
            result?;
        }
        self.receipt.observe(&mut self.child);
        outcome
    }
}

pub(crate) async fn force_reap(child: &mut Child, budget: Duration) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    if let Err(error) = child.start_kill() {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        return Err(error);
    }
    tokio::time::timeout(budget, child.wait())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "直属子进程强制回收超时"))?
}

#[cfg(test)]
pub(crate) async fn test_launch_cancellable(
    executable: &Path,
    runtime: &Path,
    descriptor: std::os::fd::OwnedFd,
    index: u32,
    credentials: WorkerCredentials,
    stop: CancellationToken,
) -> io::Result<ManagedMacWorker> {
    test_launch_tracked(
        executable,
        runtime,
        descriptor,
        index,
        credentials,
        stop,
        super::process::Receipt::default(),
    )
    .await
}

#[cfg(test)]
pub(crate) async fn test_launch_tracked(
    executable: &Path,
    runtime: &Path,
    descriptor: std::os::fd::OwnedFd,
    index: u32,
    credentials: WorkerCredentials,
    stop: CancellationToken,
    receipt: super::process::Receipt,
) -> io::Result<ManagedMacWorker> {
    ManagedMacWorker::launch_with_stop(
        executable,
        runtime,
        descriptor,
        index,
        credentials,
        1,
        Budgets {
            startup: Duration::from_secs(3),
            retirement: Duration::from_millis(150),
            reap: Duration::from_secs(2),
        },
        stop,
        receipt,
    )
    .await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{io::Read, os::unix::fs::PermissionsExt};
    // 继承标志测试会短暂取消句柄的执行时关闭标志；不与其它派生用例并发。
    static PROCESS_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    const CHILD: &str = r#"#!/usr/bin/python3
import array, os, socket, stat, sys, time, uuid
from pathlib import Path
Path('child.pid').write_text(str(os.getpid()))
args = sys.argv[1:]
authorization = uuid.UUID(args[args.index('--authorization') + 1])
index = int(args[args.index('--interface-index') + 1])
assert os.getuid() != 0 and os.getgid() != 0
assert os.getpgrp() == os.getpid()
assert 'PYTHONPATH' not in os.environ
for fd in range(3, 1024):
    try: metadata = os.fstat(fd)
    except OSError: continue
    assert not stat.S_ISSOCK(metadata.st_mode), '交接前存在隐式继承的套接字'
channel = socket.socket(fileno=0)
data, ancillary, flags, _ = channel.recvmsg(24, socket.CMSG_SPACE(4))
assert data == b'VAP1' + authorization.bytes + index.to_bytes(4, 'big')
fds = array.array('i')
fds.frombytes(ancillary[0][2])
assert len(fds) == 1
descriptor = fds[0]
identity = uuid.uuid4()
frame = b'VWR1' + authorization.bytes + identity.bytes + index.to_bytes(4, 'big')
if MODE == 'silent':
    while True: time.sleep(1)
if MODE == 'wrong': frame = b'FAIL' + frame[4:]
channel.sendall(frame)
if MODE == 'wrong':
    while True: time.sleep(1)
assert channel.recv(1) == b'R'
if MODE == 'hang':
    while True: time.sleep(1)
os.close(descriptor)
if MODE == 'wrong-retirement': identity = uuid.uuid4()
channel.sendall(b'VWT1' + authorization.bytes + identity.bytes + index.to_bytes(4, 'big'))
if MODE in ('noexit', 'wrong-retirement'):
    while True: time.sleep(1)
"#;

    pub(crate) fn fixture(mode: &str) -> (tempfile::TempDir, PathBuf, WorkerCredentials) {
        let directory = tempfile::Builder::new()
            .prefix("vap-sup-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let primary_gid = std::process::Command::new("/usr/bin/id")
            .arg("-g")
            .output()
            .unwrap();
        let gid = String::from_utf8(primary_gid.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::os::unix::fs::chown(directory.path(), None, Some(gid)).unwrap();
        let path = directory.path().join("child.py");
        let script = CHILD.replacen("import array", &format!("MODE = {mode:?}\nimport array"), 1);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = directory.path().metadata().unwrap();
        let credentials = WorkerCredentials {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        (directory, path, credentials)
    }

    async fn launch_test(
        executable: &Path,
        runtime: &Path,
        credentials: WorkerCredentials,
        descriptor: std::os::fd::OwnedFd,
        startup: Duration,
    ) -> io::Result<ManagedMacWorker> {
        ManagedMacWorker::launch(
            executable,
            runtime,
            descriptor,
            1,
            credentials,
            1,
            Budgets {
                startup,
                retirement: Duration::from_millis(150),
                reap: Duration::from_secs(2),
            },
        )
        .await
    }

    fn assert_closed(peer: &mut StdUnixStream) {
        // 并行测试派生的进程在执行替换前可能短暂持有复制件；给其有界执行窗口。
        peer.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match peer.read(&mut [0]) {
                Ok(0) => return,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                value => panic!("回收后仍保留交接描述符：{value:?}"),
            }
        }
    }

    pub(crate) fn assert_reaped(runtime: &Path) {
        let pid = std::fs::read_to_string(runtime.join("child.pid")).unwrap();
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", pid.trim(), "-o", "stat="])
            .output()
            .unwrap();
        assert!(!output.status.success(), "直属子进程仍存活或成为未回收僵尸");
    }

    #[tokio::test]
    async fn launches_real_child_pins_descriptor_and_reaps_after_retirement() {
        let _guard = PROCESS_TESTS.lock().await;
        let (directory, executable, credentials) = fixture("normal");
        let (owner, mut peer) = StdUnixStream::pair().unwrap();
        rustix::io::fcntl_setfd(owner.as_fd(), rustix::io::FdFlags::empty()).unwrap();
        let mut worker = launch_test(
            &executable,
            directory.path(),
            credentials,
            owner.into(),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(worker.is_running().unwrap());
        assert!(!worker.receipt.reaped());
        assert!(!worker.generation().is_nil());
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        worker.retire().await.unwrap();
        assert!(worker.receipt.reaped());
        assert!(!worker.is_running().unwrap());
        assert_closed(&mut peer);
        assert_reaped(directory.path());
    }

    #[tokio::test]
    async fn failed_start_and_forced_retirement_still_prove_direct_child_reaping() {
        for mode in ["wrong", "hang"] {
            let (directory, executable, credentials) = fixture(mode);
            let (owner, mut peer) = StdUnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let receipt = super::super::process::Receipt::default();
            let result = test_launch_tracked(
                &executable,
                directory.path(),
                owner.into(),
                1,
                credentials,
                CancellationToken::new(),
                receipt.clone(),
            )
            .await;
            if mode == "wrong" {
                assert!(result.is_err());
            } else {
                let mut worker = result.unwrap();
                assert!(!receipt.reaped());
                assert!(worker.retire().await.is_err());
            }
            assert!(receipt.reaped());
            assert_reaped(directory.path());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn startup_failure_and_deadline_reap_child_and_close_descriptor() {
        let _guard = PROCESS_TESTS.lock().await;
        for mode in ["wrong", "silent"] {
            let (directory, executable, credentials) = fixture(mode);
            let (owner, mut peer) = StdUnixStream::pair().unwrap();
            let result = launch_test(
                &executable,
                directory.path(),
                credentials,
                owner.into(),
                Duration::from_secs(3),
            )
            .await;
            let error = match result {
                Ok(_) => panic!("无效启动不应返回工作引用"),
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                if mode == "silent" {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::InvalidData
                }
            );
            assert_closed(&mut peer);
            assert_reaped(directory.path());
        }
    }

    #[tokio::test]
    async fn retirement_requires_matching_ack_and_actual_exit_or_forces_reap() {
        let _guard = PROCESS_TESTS.lock().await;
        for mode in ["hang", "noexit", "wrong-retirement"] {
            let (directory, executable, credentials) = fixture(mode);
            let (owner, mut peer) = StdUnixStream::pair().unwrap();
            let mut worker = launch_test(
                &executable,
                directory.path(),
                credentials,
                owner.into(),
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            assert!(worker.retire().await.is_err());
            assert!(!worker.is_running().unwrap());
            assert_closed(&mut peer);
            assert_reaped(directory.path());
        }
    }

    #[tokio::test]
    async fn refuses_root_credentials_before_spawning() {
        let _guard = PROCESS_TESTS.lock().await;
        let (directory, executable, mut credentials) = fixture("normal");
        credentials.uid = 0;
        let (owner, mut peer) = StdUnixStream::pair().unwrap();
        assert!(
            launch_test(
                &executable,
                directory.path(),
                credentials,
                owner.into(),
                Duration::from_secs(1)
            )
            .await
            .is_err()
        );
        assert!(!directory.path().join("child.pid").exists());
        assert_closed(&mut peer);
    }

    #[tokio::test]
    async fn cancelled_retirement_can_retry_forced_reap() {
        let _guard = PROCESS_TESTS.lock().await;
        let (directory, executable, credentials) = fixture("hang");
        let (owner, mut peer) = StdUnixStream::pair().unwrap();
        let mut worker = launch_test(
            &executable,
            directory.path(),
            credentials,
            owner.into(),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), worker.retire())
                .await
                .is_err()
        );
        assert!(worker.retire().await.is_err());
        assert!(!worker.is_running().unwrap());
        assert_closed(&mut peer);
        assert_reaped(directory.path());
    }

    #[tokio::test]
    async fn rejects_insecure_directory_and_privilege_changing_executable() {
        let _guard = PROCESS_TESTS.lock().await;
        for special_program in [false, true] {
            let (directory, executable, credentials) = fixture("normal");
            let target = if special_program {
                &executable
            } else {
                directory.path()
            };
            let mode = if special_program { 0o4700 } else { 0o770 };
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode)).unwrap();
            let (owner, mut peer) = StdUnixStream::pair().unwrap();
            assert!(
                launch_test(
                    &executable,
                    directory.path(),
                    credentials,
                    owner.into(),
                    Duration::from_secs(1)
                )
                .await
                .is_err()
            );
            assert!(!directory.path().join("child.pid").exists());
            assert_closed(&mut peer);
        }
    }

    const TUNNEL: &str = r#"
import socket, sys, time
from pathlib import Path
mode, path = sys.argv[1:]
channel = socket.socket(socket.AF_UNIX)
channel.connect(path)
channel.sendall(b'>HOLD:Waiting for hold release:0\r\n')
reader = channel.makefile('rb')
assert reader.readline() == b'state on\n'
assert reader.readline() == b'hold release\n'
if mode == 'quiet':
    while True: time.sleep(.01)
remote = b'198.51.100.8' if mode == 'wrong-remote' else b'198.51.100.7'
channel.sendall(b'>STATE:1,CONNECTED,SUCCESS,10.231.66.2,' + remote + b'\r\n')
if mode in ('eof', 'reconnect', 'exit'):
    while not Path('fault').exists(): time.sleep(.005)
    if mode == 'exit': sys.exit(2)
    if mode == 'reconnect': channel.sendall(b'>STATE:2,RECONNECTING,ping-restart,,,\r\n')
    else:
        reader.close(); channel.close()
        while True: time.sleep(.01)
if mode == 'hang':
    while True: time.sleep(.01)
assert reader.read(1) == b''
"#;

    struct PairFixture {
        directory: tempfile::TempDir,
        peer: StdUnixStream,
        generation: crate::platform::session::CoupledMacGeneration,
        tunnel_pid: u32,
        worker_pid: u32,
    }

    async fn pair_fixture(mode: &str, worker_mode: &str) -> PairFixture {
        use crate::platform::session::CoupledMacGeneration;
        let (directory, executable, credentials) = fixture(worker_mode);
        let (owner, peer) = StdUnixStream::pair().unwrap();
        let worker = launch_test(
            &executable,
            directory.path(),
            credentials,
            owner.into(),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        let worker_pid = worker.pid().unwrap();
        let path = directory.path().join("manager.sock");
        let listener = crate::netd::protocol::bind_private_socket(&path).unwrap();
        let tunnel = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(TUNNEL)
            .arg(mode)
            .arg(&path)
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let tunnel_pid = tunnel.id().unwrap();
        let (management, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let uid = if mode == "wrong-peer" {
            credentials.uid + 1
        } else {
            credentials.uid
        };
        let mut generation = CoupledMacGeneration::new(
            worker,
            tunnel,
            management,
            uid,
            "198.51.100.7".parse().unwrap(),
            Duration::from_millis(300),
        );
        generation.test_exit_budget(Duration::from_millis(100));
        PairFixture {
            directory,
            peer,
            generation,
            tunnel_pid,
            worker_pid,
        }
    }

    fn assert_pid_reaped(pid: u32) {
        assert!(
            !std::process::Command::new("/bin/ps")
                .args(["-p", &pid.to_string(), "-o", "stat="])
                .output()
                .unwrap()
                .status
                .success(),
            "直属进程仍存活或未回收"
        );
    }

    #[tokio::test]
    async fn coupled_stop_waits_for_both_children_and_custody_release() {
        let _guard = PROCESS_TESTS.lock().await;
        let PairFixture {
            directory: _directory,
            mut peer,
            generation,
            tunnel_pid,
            worker_pid,
        } = pair_fixture("normal", "normal").await;
        let stop = tokio_util::sync::CancellationToken::new();
        let (connected, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(generation.run(connected, stop.clone()));
        receiver.await.unwrap();
        stop.cancel();
        task.await.unwrap().unwrap();
        assert_closed(&mut peer);
        assert_pid_reaped(worker_pid);
        assert_pid_reaped(tunnel_pid);
    }

    #[tokio::test]
    async fn coupled_tunnel_fault_retires_worker_and_reaps_both_children() {
        let _guard = PROCESS_TESTS.lock().await;
        for mode in ["eof", "reconnect", "exit"] {
            let PairFixture {
                directory,
                mut peer,
                generation,
                tunnel_pid,
                worker_pid,
            } = pair_fixture(mode, "normal").await;
            let (connected, receiver) = tokio::sync::oneshot::channel();
            let task =
                tokio::spawn(generation.run(connected, tokio_util::sync::CancellationToken::new()));
            receiver.await.unwrap();
            std::fs::write(directory.path().join("fault"), b"1").unwrap();
            assert!(task.await.unwrap().is_err());
            assert_closed(&mut peer);
            assert_pid_reaped(worker_pid);
            assert_pid_reaped(tunnel_pid);
        }
    }

    #[tokio::test]
    async fn coupled_startup_refusal_reaps_already_started_worker() {
        let _guard = PROCESS_TESTS.lock().await;
        for mode in ["wrong-peer", "wrong-remote", "quiet"] {
            let PairFixture {
                directory: _directory,
                mut peer,
                generation,
                tunnel_pid,
                worker_pid,
            } = pair_fixture(mode, "normal").await;
            let (connected, receiver) = tokio::sync::oneshot::channel();
            assert!(
                generation
                    .run(connected, tokio_util::sync::CancellationToken::new())
                    .await
                    .is_err()
            );
            assert!(receiver.await.is_err());
            assert_closed(&mut peer);
            assert_pid_reaped(worker_pid);
            assert_pid_reaped(tunnel_pid);
        }
    }

    #[tokio::test]
    async fn coupled_worker_crash_closes_management_and_reaps_tunnel() {
        let _guard = PROCESS_TESTS.lock().await;
        let PairFixture {
            directory: _directory,
            mut peer,
            generation,
            tunnel_pid,
            worker_pid,
        } = pair_fixture("normal", "normal").await;
        let (connected, receiver) = tokio::sync::oneshot::channel();
        let task =
            tokio::spawn(generation.run(connected, tokio_util::sync::CancellationToken::new()));
        receiver.await.unwrap();
        assert!(
            Command::new("/bin/kill")
                .args(["-KILL", &worker_pid.to_string()])
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(task.await.unwrap().is_err());
        assert_closed(&mut peer);
        assert_pid_reaped(worker_pid);
        assert_pid_reaped(tunnel_pid);
    }

    #[tokio::test]
    async fn coupled_unresponsive_children_are_forced_and_reaped() {
        let _guard = PROCESS_TESTS.lock().await;
        let PairFixture {
            directory: _directory,
            mut peer,
            generation,
            tunnel_pid,
            worker_pid,
        } = pair_fixture("hang", "hang").await;
        let stop = tokio_util::sync::CancellationToken::new();
        let (connected, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(generation.run(connected, stop.clone()));
        receiver.await.unwrap();
        stop.cancel();
        assert!(task.await.unwrap().is_err());
        assert_closed(&mut peer);
        assert_pid_reaped(worker_pid);
        assert_pid_reaped(tunnel_pid);
    }

    #[tokio::test]
    async fn coupled_aborted_supervision_closes_custody_and_kills_children() {
        let _guard = PROCESS_TESTS.lock().await;
        let PairFixture {
            directory: _directory,
            mut peer,
            generation,
            tunnel_pid,
            worker_pid,
        } = pair_fixture("hang", "hang").await;
        let (connected, receiver) = tokio::sync::oneshot::channel();
        let task =
            tokio::spawn(generation.run(connected, tokio_util::sync::CancellationToken::new()));
        receiver.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_closed(&mut peer);
        for pid in [worker_pid, tunnel_pid] {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::process::Command::new("/bin/ps")
                .args(["-p", &pid.to_string(), "-o", "stat="])
                .output()
                .unwrap()
                .status
                .success()
            {
                assert!(
                    std::time::Instant::now() < deadline,
                    "取消后直属进程未被运行时回收"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    #[tokio::test]
    async fn coupled_already_stopping_never_publishes_connection_material() {
        let _guard = PROCESS_TESTS.lock().await;
        let PairFixture {
            directory: _directory,
            mut peer,
            generation,
            tunnel_pid,
            worker_pid,
        } = pair_fixture("normal", "normal").await;
        let stop = tokio_util::sync::CancellationToken::new();
        stop.cancel();
        let (connected, receiver) = tokio::sync::oneshot::channel();
        // 对端尚在等待，关闭时可能以错误状态结束；无论结果均须完成两种回收。
        let _ = generation.run(connected, stop).await;
        assert!(receiver.await.is_err());
        assert_closed(&mut peer);
        assert_pid_reaped(worker_pid);
        assert_pid_reaped(tunnel_pid);
    }
    #[tokio::test]
    async fn coupled_parent_started_tunnel_transfers_endpoint_and_reaps_both_consumers() {
        use crate::{
            domain::{Endpoint, Transport},
            platform::{
                session::CoupledMacGeneration,
                tunnel::{ManagedMacTunnel, TunnelStartup},
            },
        };
        use tokio_util::sync::CancellationToken;
        let _guard = PROCESS_TESTS.lock().await;
        for (index, budget, notifications) in [
            (1, Duration::from_secs(3), false),
            (2, Duration::from_secs(3), false),
            (1, Duration::ZERO, false),
            (1, Duration::from_secs(3), true),
        ] {
            let (directory, executable, credentials) = fixture("normal");
            let runtime = directory.path().join("tunnel");
            std::fs::create_dir(&runtime).unwrap();
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
            let (owner, mut peer) = StdUnixStream::pair().unwrap();
            let tunnel_owner = owner.try_clone().unwrap();
            let worker = launch_test(
                &executable,
                directory.path(),
                credentials,
                owner.into(),
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            let worker_pid = worker.pid().unwrap();
            let program = runtime.join("tunnel.py");
            let prefix = r#"#!/usr/bin/python3
import array, socket, sys
args = sys.argv[1:]
control = socket.socket(fileno=0)
data, ancillary, flags, _ = control.recvmsg(24, socket.CMSG_SPACE(4))
assert data[:4] == b'VAP1'
fds = array.array('i'); fds.frombytes(ancillary[0][2]); assert len(fds) == 1
control.close()
"#;
            let script = TUNNEL
                .replace(
                    "mode, path = sys.argv[1:]",
                    "mode = 'normal'\npath = args[args.index('--management') + 1]",
                )
                .replace("198.51.100.7", "8.8.8.8");
            std::fs::write(&program, format!("{prefix}{script}")).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut tunnel = ManagedMacTunnel::test_launch(
                &program,
                TunnelStartup {
                    runtime: runtime.clone(),
                    dependency_manifest: runtime.join("dependency.json"),
                    profile: runtime.join("profile.conf"),
                    endpoint: Endpoint {
                        ip: "8.8.8.8".parse().unwrap(),
                        port: 443,
                        transport: Transport::Tcp,
                    },
                    startup_budget: Duration::from_secs(3),
                },
                tunnel_owner.into(),
                index,
                credentials.uid,
            )
            .await
            .unwrap();
            if notifications {
                tunnel.test_require_configuration();
            }
            let tunnel_pid = tunnel.pid().unwrap();
            let result = CoupledMacGeneration::from_tunnel(worker, tunnel, budget).await;
            if index != 1 || budget.is_zero() || notifications {
                assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
                assert_closed(&mut peer);
                assert_pid_reaped(worker_pid);
                assert_pid_reaped(tunnel_pid);
                assert!(!std::fs::read_dir(&runtime).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|x| x == "sock")
                }));
                continue;
            }
            let session = result.unwrap();
            let (ready, connected) = tokio::sync::oneshot::channel();
            let stop = CancellationToken::new();
            let task = tokio::spawn(session.run(ready, stop.clone()));
            let detail = tokio::time::timeout(Duration::from_secs(3), connected)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                detail.remote_address,
                "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap()
            );
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            stop.cancel();
            task.await.unwrap().unwrap();
            assert_closed(&mut peer);
            assert_pid_reaped(worker_pid);
            assert_pid_reaped(tunnel_pid);
            assert!(!std::fs::read_dir(&runtime).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|x| x == "sock")
            }));
        }
    }
}
