//! 低权限独立出口检测；仅通过既有代际私有工作端发送请求。
use super::{
    program, spawn,
    supervisor::{WorkerCredentials, force_reap},
};
use crate::probe::{self, ProbeReport};
use serde::{Deserialize, Serialize};
use std::{
    io,
    os::{
        fd::AsFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct ProbeRegistry(std::sync::Arc<ProbeRegistryInner>);
struct ProbeRegistryInner {
    count: tokio::sync::watch::Sender<usize>,
    failed: std::sync::atomic::AtomicBool,
    lease: tokio::sync::watch::Sender<Option<std::sync::Arc<super::lease::ConsumerLease>>>,
}
impl Default for ProbeRegistry {
    fn default() -> Self {
        Self::with_lease(None)
    }
}
impl ProbeRegistry {
    pub(super) fn with_lease(lease: Option<std::sync::Arc<super::lease::ConsumerLease>>) -> Self {
        Self(std::sync::Arc::new(ProbeRegistryInner {
            count: tokio::sync::watch::channel(0).0,
            failed: std::sync::atomic::AtomicBool::new(false),
            lease: tokio::sync::watch::channel(lease).0,
        }))
    }
}
pub(crate) struct ProbeActivity {
    registry: ProbeRegistry,
    receipt: super::process::Receipt,
}
impl ProbeRegistry {
    pub(super) fn attach_lease(
        &self,
        lease: std::sync::Arc<super::lease::ConsumerLease>,
    ) -> io::Result<()> {
        let mut conflicting = false;
        self.0.lease.send_if_modified(|current| match current {
            Some(existing) => {
                conflicting = !std::sync::Arc::ptr_eq(existing, &lease);
                false
            }
            None => {
                *current = Some(lease);
                true
            }
        });
        if conflicting {
            Err(io::Error::other("检测消费者锁已属于另一个代际"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn confirmed(&self) -> bool {
        *self.0.count.borrow() == 0 && !self.0.failed.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn start(&self) -> ProbeActivity {
        self.0.count.send_modify(|count| *count += 1);
        ProbeActivity {
            registry: self.clone(),
            receipt: super::process::Receipt::default().with_lease(self.0.lease.borrow().clone()),
        }
    }
    pub(crate) async fn wait(&self) -> io::Result<()> {
        self.0
            .count
            .subscribe()
            .wait_for(|count| *count == 0)
            .await
            .map_err(|_| io::Error::other("检测回收登记通道结束"))?;
        if self.0.failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(io::Error::other("存在未确认回收的直属检测子进程"));
        }
        Ok(())
    }
}
impl Drop for ProbeActivity {
    fn drop(&mut self) {
        if !self.receipt.reaped() {
            self.registry
                .0
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.registry.0.count.send_modify(|count| *count -= 1);
    }
}

const MAX_FRAME: usize = 65536;
const IO_BUDGET: Duration = Duration::from_secs(3);
const REAP_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct ExitProbeSettings {
    pub urls: Vec<Url>,
    pub max_attempts: u32,
    pub budget: Duration,
}

impl ExitProbeSettings {
    pub fn validate(&self) -> io::Result<()> {
        if self.urls.is_empty()
            || self.urls.len() > 32
            || !(1..=32).contains(&self.max_attempts)
            || self.budget < Duration::from_millis(1)
            || self.budget > Duration::from_secs(120)
            || self
                .urls
                .iter()
                .map(|url| url.as_str().len())
                .sum::<usize>()
                > 32768
            || self.urls.iter().any(|url| {
                url.as_str().len() > 4096
                    || !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "出口检测设置无效或超过上限",
            ));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    authorization: Uuid,
    generation: Uuid,
    socket: PathBuf,
    urls: Vec<Url>,
    max_attempts: u32,
    budget_ms: u64,
}
impl Request {
    fn settings(&self) -> ExitProbeSettings {
        ExitProbeSettings {
            urls: self.urls.clone(),
            max_attempts: self.max_attempts,
            budget: Duration::from_millis(self.budget_ms),
        }
    }
    fn validate(&self) -> io::Result<()> {
        self.settings().validate()?;
        if self.version != 1
            || self.authorization.is_nil()
            || self.generation.is_nil()
            || !self.socket.is_absolute()
            || self.socket.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "出口检测授权或路径无效",
            ));
        }
        nix::sys::socket::UnixAddr::new(&self.socket)?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    authorization: Uuid,
    generation: Uuid,
    report: ProbeReport,
}
async fn send<T: Serialize>(channel: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "检测帧超过上限"));
    }
    channel.write_u32(bytes.len() as u32).await?;
    channel.write_all(&bytes).await
}
async fn receive<T: serde::de::DeserializeOwned>(channel: &mut UnixStream) -> io::Result<T> {
    let length = channel.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "检测帧长度无效"));
    }
    let mut bytes = vec![0; length];
    channel.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
fn socket_identity(path: &Path, credentials: WorkerCredentials) -> io::Result<()> {
    let socket = std::fs::symlink_metadata(path)?;
    let parent = std::fs::symlink_metadata(
        path.parent()
            .ok_or_else(|| io::Error::other("检测工作目录缺失"))?,
    )?;
    if !socket.file_type().is_socket()
        || socket.uid() != credentials.uid
        || socket.gid() != credentials.gid
        || socket.mode() & 0o7777 != 0o600
        || !parent.is_dir()
        || parent.file_type().is_symlink()
        || parent.mode() & 0o7777 != 0o750
        || parent.uid() != credentials.uid
        || parent.gid() != credentials.gid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "出口检测工作端归属或权限不符",
        ));
    }
    Ok(())
}
fn validate_response(response: &Response, request: &Request) -> io::Result<()> {
    let report = &response.report;
    if response.version != 1
        || response.authorization != request.authorization
        || response.generation != request.generation
        || report.attempts > request.max_attempts
        || report.elapsed > Duration::from_millis(request.budget_ms) + IO_BUDGET
        || report.success
            != (report
                .status
                .is_some_and(|status| (200..300).contains(&status))
                && report.failure.is_none())
        || (report.success && report.attempts == 0)
        || (!report.success && report.failure.is_none())
        || report
            .status
            .is_some_and(|status| !(100..=599).contains(&status))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "出口检测结果身份或内容不符",
        ));
    }
    Ok(())
}
/// 仅供隐藏入口；普通用户、现有私有控制通道，无接口句柄与任意程序参数。
pub async fn serve(mut channel: UnixStream) -> io::Result<()> {
    if nix::unistd::getuid().is_root()
        || nix::unistd::geteuid().is_root()
        || nix::unistd::getgid().as_raw() == 0
        || nix::unistd::getegid().as_raw() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "出口检测进程不得拥有管理员身份",
        ));
    }
    let request: Request = tokio::time::timeout(IO_BUDGET, receive(&mut channel))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "检测启动材料超时"))??;
    request.validate()?;
    socket_identity(
        &request.socket,
        WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        },
    )?;
    let report = tokio::select! {
        biased;
        _=channel.read_u8()=>return Err(io::Error::new(io::ErrorKind::Interrupted,"检测监督通道结束或收到意外输入")),
        report=probe::check_exit(&request.socket,&request.urls,request.max_attempts,Duration::from_millis(request.budget_ms))=>report,
    };
    let response = Response {
        version: 1,
        authorization: request.authorization,
        generation: request.generation,
        report,
    };
    tokio::time::timeout(IO_BUDGET, send(&mut channel, &response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "检测结果交付超时"))?
}
pub async fn entry() -> io::Result<()> {
    let channel =
        std::os::unix::net::UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    channel.set_nonblocking(true)?;
    serve(UnixStream::from_std(channel)?).await
}
pub(crate) async fn check(
    socket: PathBuf,
    generation: Uuid,
    credentials: WorkerCredentials,
    settings: ExitProbeSettings,
    revoked: CancellationToken,
    stop: CancellationToken,
    activity: ProbeActivity,
) -> io::Result<ProbeReport> {
    settings.validate()?;
    let request = Request {
        version: 1,
        authorization: Uuid::new_v4(),
        generation,
        socket,
        urls: settings.urls,
        max_attempts: settings.max_attempts,
        budget_ms: u64::try_from(settings.budget.as_millis())
            .map_err(|_| io::Error::other("检测时限溢出"))?,
    };
    request.validate()?;
    if stop.is_cancelled() || revoked.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "检测已经取消"));
    }
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "派生低权限检测需要管理员身份",
        ));
    }
    credentials.validate_account()?;
    program::verify_current()?;
    socket_identity(&request.socket, credentials)?;
    let executable = std::env::current_exe()?;
    supervised_tracked(
        executable,
        request,
        credentials,
        revoked,
        stop,
        REAP_BUDGET,
        activity,
    )
    .await
}
async fn supervised_tracked(
    executable: PathBuf,
    request: Request,
    credentials: WorkerCredentials,
    revoked: CancellationToken,
    stop: CancellationToken,
    reap_budget: Duration,
    activity: ProbeActivity,
) -> io::Result<ProbeReport> {
    let cancelled = stop.child_token();
    let _cancel_on_drop = cancelled.clone().drop_guard();
    let task = tokio::spawn(async move {
        let failure = revoked.clone().drop_guard();
        let result = run(
            &executable,
            request,
            credentials,
            revoked.clone(),
            cancelled,
            reap_budget,
            activity.receipt.clone(),
        )
        .await;
        drop(activity);
        if result.as_ref().is_ok_and(|report| report.success) {
            failure.disarm();
        }
        result
    });
    task.await
        .map_err(|e| io::Error::other(format!("检测监督任务失败：{e}")))?
}
async fn run(
    executable: &Path,
    request: Request,
    credentials: WorkerCredentials,
    revoked: CancellationToken,
    stop: CancellationToken,
    reap_budget: Duration,
    receipt: super::process::Receipt,
) -> io::Result<ProbeReport> {
    if stop.is_cancelled() || revoked.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "检测派生前已经取消",
        ));
    }
    let (control, mut child) = spawn::guarded(|| {
        let (parent, control) = std::os::unix::net::UnixStream::pair()?;
        let mut command = Command::new(executable);
        command
            .arg("mac-probe")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .current_dir(
                executable
                    .parent()
                    .ok_or_else(|| io::Error::other("检测程序目录缺失"))?,
            )
            .uid(credentials.uid)
            .gid(credentials.gid)
            .process_group(0)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(control)))
            .stdout(Stdio::null())
            .stderr(receipt.child_stderr()?)
            .kill_on_drop(true);
        let child = command.spawn()?;
        receipt.spawned();
        drop(command);
        Ok((parent, child))
    })?;
    let operation=async{
        control.set_nonblocking(true)?;
        let mut control=UnixStream::from_std(control)?;
        let exchange=async{
            send(&mut control,&request).await?;
            let response:Response=receive(&mut control).await?;
            validate_response(&response,&request)?;
            if !response.report.success {revoked.cancel();}
            Ok(response.report)
        };
        tokio::select!{
            biased;
            _=stop.cancelled()=>Err(io::Error::new(io::ErrorKind::Interrupted,"检测已经取消")),
            _=revoked.cancelled()=>Err(io::Error::new(io::ErrorKind::Interrupted,"检测代际已经撤销")),
            result=tokio::time::timeout(Duration::from_millis(request.budget_ms)+IO_BUDGET,exchange)=>
                result.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"检测子进程结果超时"))?,
        }
    }.await;
    if !operation.as_ref().is_ok_and(|report| report.success) {
        revoked.cancel();
    }
    // exchange 结束即关闭控制端；子进程自行结束失败时才强制终止和回收。
    let cleanup = match tokio::time::timeout(reap_budget, child.wait()).await {
        Ok(result) => result,
        Err(_) => {
            revoked.cancel();
            force_reap(&mut child, reap_budget).await
        }
    };
    receipt.observe(&mut child);
    match (operation, cleanup) {
        (Ok(report), Ok(status)) if status.success() && receipt.reaped() => Ok(report),
        (Err(error), Ok(_)) if receipt.reaped() => Err(error),
        (result, cleanup) => {
            let original = result
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "检测子进程退出或回收失败".into());
            Err(io::Error::other(format!(
                "{original}；检测回收：{cleanup:?}；已确认回收：{}",
                receipt.reaped()
            )))
        }
    }
}

#[cfg(test)]
async fn supervised(
    executable: PathBuf,
    request: Request,
    credentials: WorkerCredentials,
    revoked: CancellationToken,
    stop: CancellationToken,
    reap_budget: Duration,
) -> io::Result<ProbeReport> {
    supervised_tracked(
        executable,
        request,
        credentials,
        revoked,
        stop,
        reap_budget,
        ProbeRegistry::default().start(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    fn request(path: PathBuf) -> Request {
        Request {
            version: 1,
            authorization: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            socket: path,
            urls: vec![Url::parse("http://11.54.0.2/empty").unwrap()],
            max_attempts: 1,
            budget_ms: 500,
        }
    }
    fn credentials() -> WorkerCredentials {
        WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }
    fn directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .prefix("vp-")
            .tempdir_in("/private/tmp")
            .unwrap();
        std::os::unix::fs::chown(directory.path(), None, Some(nix::unistd::getgid().as_raw()))
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        directory
    }
    fn channel() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }
    fn response(request: &Request) -> Response {
        Response {
            version: 1,
            authorization: request.authorization,
            generation: request.generation,
            report: ProbeReport {
                success: true,
                attempts: 1,
                status: Some(204),
                failure: None,
                elapsed: Duration::from_millis(1),
            },
        }
    }
    #[test]
    fn request_limits_and_response_identity_are_enforced() {
        let mut input = request("/private/tmp/s".into());
        input.validate().unwrap();
        let mut report = response(&input);
        validate_response(&report, &input).unwrap();
        report.generation = Uuid::new_v4();
        assert!(validate_response(&report, &input).is_err());
        report = response(&input);
        report.report.status = Some(503);
        assert!(validate_response(&report, &input).is_err());
        report = response(&input);
        report.report.attempts = 2;
        assert!(validate_response(&report, &input).is_err());
        report = response(&input);
        report.report.elapsed = Duration::from_secs(5);
        assert!(validate_response(&report, &input).is_err());
        for attempts in [0, 33] {
            input.max_attempts = attempts;
            assert!(input.validate().is_err());
        }
        input = request("relative".into());
        assert!(input.validate().is_err());
        input = request("/private/tmp/s".into());
        input.authorization = Uuid::nil();
        assert!(input.validate().is_err());
        for address in ["file:///tmp/value", "https://user:secret@example.com/"] {
            input = request("/private/tmp/s".into());
            input.urls = vec![Url::parse(address).unwrap()];
            assert!(input.validate().is_err());
        }
        for budget in [0, 120001] {
            input = request("/private/tmp/s".into());
            input.budget_ms = budget;
            assert!(input.validate().is_err());
        }
        input = request("/private/tmp/s".into());
        input.urls = vec![Url::parse("http://example.com/").unwrap(); 33];
        assert!(input.validate().is_err());
        let json = serde_json::to_value(request("/private/tmp/s".into())).unwrap();
        let mut unknown = json.as_object().unwrap().clone();
        unknown.insert("program".into(), "/bin/sh".into());
        assert!(serde_json::from_value::<Request>(unknown.into()).is_err());
    }
    #[tokio::test]
    async fn frames_reject_oversize_truncation_and_unknown_fields() {
        for bytes in [vec![0, 1, 0, 1], vec![0, 0, 0, 0], vec![0, 0, 0, 2, b'{']] {
            let (mut sender, mut receiver) = channel();
            sender.write_all(&bytes).await.unwrap();
            drop(sender);
            assert!(receive::<Request>(&mut receiver).await.is_err());
        }
    }
    async fn worker(
        path: &Path,
        wait: bool,
    ) -> (tokio::task::JoinHandle<()>, oneshot::Receiver<()>) {
        let listener = UnixListener::bind(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (accepted, confirmation) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 4];
            stream.read_exact(&mut head).await.unwrap();
            if head[3] == 1 {
                let mut address = [0; 6];
                stream.read_exact(&mut address).await.unwrap();
            } else {
                assert_eq!(head[3], 3);
                let length = stream.read_u8().await.unwrap();
                let mut address = vec![0; length as usize + 2];
                stream.read_exact(&mut address).await.unwrap();
            }
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut http = Vec::new();
            while !http.ends_with(b"\r\n\r\n") {
                http.push(stream.read_u8().await.unwrap());
                assert!(http.len() < 8192);
            }
            accepted.send(()).unwrap();
            if wait {
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), stream.read_u8())
                        .await
                        .unwrap()
                        .is_err()
                );
            } else {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        (task, confirmation)
    }
    use tokio::sync::oneshot;
    #[tokio::test]
    async fn ordinary_child_handler_reuses_real_probe_through_private_worker() {
        let directory = directory();
        let path = directory.path().join("s");
        let (worker, accepted) = worker(&path, false).await;
        let input = request(path);
        let (mut parent, child) = channel();
        let serving = tokio::spawn(serve(child));
        send(&mut parent, &input).await.unwrap();
        let output: Response = match receive(&mut parent).await {
            Ok(output) => output,
            Err(error) => panic!("检测交付失败：{error}；服务结果：{:?}", serving.await),
        };
        validate_response(&output, &input).unwrap();
        assert!(output.report.success);
        tokio::time::timeout(Duration::from_secs(2), accepted)
            .await
            .unwrap()
            .unwrap();
        worker.await.unwrap();
        serving.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn control_eof_cancels_in_flight_real_probe_and_closes_worker_stream() {
        let directory = directory();
        let path = directory.path().join("s");
        let (worker, accepted) = worker(&path, true).await;
        let mut input = request(path);
        input.budget_ms = 10000;
        let (mut parent, child) = channel();
        let serving = tokio::spawn(serve(child));
        send(&mut parent, &input).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), accepted)
            .await
            .unwrap()
            .unwrap();
        drop(parent);
        assert_eq!(
            serving.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        worker.await.unwrap();
    }
    #[tokio::test]
    async fn wrong_worker_permissions_fail_before_accepting_requests() {
        let directory = directory();
        let path = directory.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let input = request(path);
        let (mut parent, child) = channel();
        let serving = tokio::spawn(serve(child));
        send(&mut parent, &input).await.unwrap();
        assert_eq!(
            serving.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
    const CHILD: &str = r#"#!/usr/bin/python3
import json,os,socket,stat,struct,sys,time,uuid
from pathlib import Path
assert sys.argv[1:]==['mac-probe']
assert os.getuid()!=0 and os.getgid()!=0
assert os.getpgrp()==os.getpid()
assert 'PYTHONPATH' not in os.environ
for fd in range(3,1024):
    try: mode=os.fstat(fd).st_mode
    except OSError: continue
    assert not stat.S_ISSOCK(mode),fd
Path('pid').write_text(str(os.getpid()))
channel=socket.socket(fileno=0)
def exact(n):
    out=b''
    while len(out)<n:
        chunk=channel.recv(n-len(out))
        if not chunk:sys.exit(0)
        out+=chunk
    return out
length=struct.unpack('!I',exact(4))[0]
request=json.loads(exact(length))
if MODE=='silent':
    while True:time.sleep(.01)
report={'success':MODE!='failure','attempts':1,'status':503 if MODE=='failure' else 204,
        'failure':'response' if MODE=='failure' else None,'elapsed':{'secs':0,'nanos':1}}
response={'version':1,'authorization':request['authorization'],'generation':request['generation'],'report':report}
if MODE in ['wrong','wronghang']:response['authorization']=str(uuid.uuid4())
data=json.dumps(response).encode()
if MODE=='oversize':channel.sendall(struct.pack('!I',65537))
else:channel.sendall(struct.pack('!I',len(data))+data)
if MODE in ['hang','wronghang']:
    while True:time.sleep(.01)
if MODE=='exit':sys.exit(23)
"#;
    fn fixture(mode: &str) -> (tempfile::TempDir, PathBuf, Request) {
        let directory = directory();
        let executable = directory.path().join("probe.py");
        std::fs::write(&executable, CHILD.replace("MODE", &format!("{mode:?}"))).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let input = request(directory.path().join("s"));
        (directory, executable, input)
    }
    fn reaped(directory: &Path) {
        let pid = std::fs::read_to_string(directory.join("pid")).unwrap();
        assert!(
            !std::process::Command::new("/bin/ps")
                .args(["-p", pid.trim(), "-o", "pid="])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    #[tokio::test]
    async fn actual_direct_child_reports_success_and_failure_and_is_reaped() {
        for mode in ["success", "failure"] {
            let (directory, executable, input) = fixture(mode);
            let revoked = CancellationToken::new();
            let report = supervised(
                executable,
                input,
                credentials(),
                revoked.clone(),
                CancellationToken::new(),
                Duration::from_millis(300),
            )
            .await
            .unwrap();
            assert_eq!(report.success, mode == "success");
            assert_eq!(revoked.is_cancelled(), mode == "failure");
            reaped(directory.path());
        }
    }
    #[tokio::test]
    async fn wrong_oversized_results_and_abnormal_exit_revoke_and_reap() {
        for mode in ["wrong", "oversize", "exit", "hang"] {
            let (directory, executable, input) = fixture(mode);
            let revoked = CancellationToken::new();
            assert!(
                supervised(
                    executable,
                    input,
                    credentials(),
                    revoked.clone(),
                    CancellationToken::new(),
                    Duration::from_millis(300)
                )
                .await
                .is_err()
            );
            assert!(revoked.is_cancelled());
            reaped(directory.path());
        }
    }
    #[tokio::test]
    async fn cancelled_parent_future_keeps_child_cleanup_running() {
        let (directory, executable, input) = fixture("silent");
        let revoked = CancellationToken::new();
        let registry = ProbeRegistry::default();
        let task = tokio::spawn(supervised_tracked(
            executable,
            input,
            credentials(),
            revoked.clone(),
            CancellationToken::new(),
            Duration::from_millis(100),
            registry.start(),
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !directory.path().join("pid").exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), revoked.cancelled())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), registry.wait())
            .await
            .unwrap()
            .unwrap();
        // 撤销通知必须早于回收完成；单独观测已登记测试子进程消失。
        let pid = std::fs::read_to_string(directory.path().join("pid")).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while std::process::Command::new("/bin/ps")
                .args(["-p", pid.trim(), "-o", "pid="])
                .output()
                .unwrap()
                .status
                .success()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        reaped(directory.path());
    }
    #[tokio::test]
    async fn registry_wait_is_cancellable_and_unconfirmed_receipts_remain_failed() {
        let registry = ProbeRegistry::default();
        let activity = registry.start();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), registry.wait())
                .await
                .is_err()
        );
        drop(activity);
        registry.wait().await.unwrap();
        let unconfirmed = registry.start();
        unconfirmed.receipt.spawned();
        drop(unconfirmed);
        assert!(
            registry
                .wait()
                .await
                .unwrap_err()
                .to_string()
                .contains("未确认回收")
        );
        assert!(registry.wait().await.is_err());
    }
    #[test]
    fn registry_accepts_one_generation_lease_and_rejects_cross_generation_rebinding() {
        let directory = directory();
        let first = std::sync::Arc::new(
            super::super::lease::ConsumerLease::create(&directory.path().join("first.lock"))
                .unwrap(),
        );
        let second = std::sync::Arc::new(
            super::super::lease::ConsumerLease::create(&directory.path().join("second.lock"))
                .unwrap(),
        );
        let registry = ProbeRegistry::default();
        registry.attach_lease(first.clone()).unwrap();
        registry.attach_lease(first.clone()).unwrap();
        assert!(registry.attach_lease(second).is_err());
        let activity = registry.start();
        let inherited = activity.receipt.child_stderr().unwrap();
        drop(inherited);
        drop(activity);
        assert!(registry.confirmed());
        assert!(first.receipt().try_quiescent().unwrap().is_none());
    }
    #[tokio::test]
    async fn invalid_report_revokes_before_waiting_for_hung_child_cleanup() {
        let (directory, executable, input) = fixture("wronghang");
        let revoked = CancellationToken::new();
        let task = tokio::spawn(supervised(
            executable,
            input,
            credentials(),
            revoked.clone(),
            CancellationToken::new(),
            Duration::from_secs(1),
        ));
        tokio::time::timeout(Duration::from_secs(2), revoked.cancelled())
            .await
            .unwrap();
        assert!(!task.is_finished());
        let pid = std::fs::read_to_string(directory.path().join("pid")).unwrap();
        assert!(
            std::process::Command::new("/bin/ps")
                .args(["-p", pid.trim(), "-o", "pid="])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(task.await.unwrap().is_err());
        reaped(directory.path());
    }
    #[tokio::test]
    async fn missing_report_times_out_and_cleans_actual_child() {
        let (directory, executable, mut input) = fixture("silent");
        input.budget_ms = 1;
        let revoked = CancellationToken::new();
        let error = supervised(
            executable,
            input,
            credentials(),
            revoked.clone(),
            CancellationToken::new(),
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(revoked.is_cancelled());
        reaped(directory.path());
    }
    #[tokio::test]
    async fn ordinary_production_gate_rejects_before_missing_worker_access() {
        let input = request("/missing/worker".into());
        let error = check(
            input.socket.clone(),
            input.generation,
            credentials(),
            input.settings(),
            CancellationToken::new(),
            CancellationToken::new(),
            ProbeRegistry::default().start(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
