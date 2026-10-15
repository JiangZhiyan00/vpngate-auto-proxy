//! 苹果业务工作进程专属监督通道；就绪不等于出口验证通过。
use std::{
    io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::network::VerifiedNetworkGeneration;

const FRAME_BYTES: usize = 40;
const BUDGET: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
pub struct WorkerStartup {
    pub authorization: Uuid,
    pub interface_index: u32,
    pub max_connections: usize,
}

impl WorkerStartup {
    fn validate(self) -> io::Result<()> {
        if self.authorization.is_nil()
            || self.interface_index == 0
            || self.max_connections == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "工作进程启动身份无效",
            ));
        }
        Ok(())
    }

    fn frame(self, version: &[u8; 4], generation: Uuid) -> [u8; FRAME_BYTES] {
        let mut frame = [0; FRAME_BYTES];
        frame[..4].copy_from_slice(version);
        frame[4..20].copy_from_slice(self.authorization.as_bytes());
        frame[20..36].copy_from_slice(generation.as_bytes());
        frame[36..].copy_from_slice(&self.interface_index.to_be_bytes());
        frame
    }
}

/// 调用前必须完成真实控制句柄校验；只有监听及就绪帧写入成功后才接纳请求。
pub async fn serve(
    socket_path: &Path,
    generation: VerifiedNetworkGeneration,
    control: UnixStream,
    startup: WorkerStartup,
    shutdown: CancellationToken,
) -> io::Result<()> {
    startup.validate()?;
    let identity = generation.lease().id();
    let (mut reader, mut writer) = control.into_split();
    let ready_published = Arc::new(AtomicBool::new(false));
    let mut closed_before_ready = false;
    let outcome = {
        let ready_sender = ready_published.clone();
        let serving = crate::socks::run_verified_worker_with_ready(
            socket_path,
            generation,
            startup.max_connections,
            shutdown.clone(),
            |id| {
                let writer = &mut writer;
                let ready_sender = ready_sender.clone();
                async move {
                    tokio::time::timeout(BUDGET, writer.write_all(&startup.frame(b"VWR1", id)))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "就绪确认超时"))??;
                    ready_sender.store(true, Ordering::Release);
                    Ok(())
                }
            },
        );
        tokio::pin!(serving);
        let mut byte = [0; 1];
        tokio::select! {
            biased;
            _ = reader.read(&mut byte) => {
                // 对端关闭、读取错误及任何输入都停止；通道不执行任意命令。
                shutdown.cancel();
                let result = serving.await;
                closed_before_ready = !ready_published.load(Ordering::Acquire);
                result
            }
            result = &mut serving => result,
        }
    };
    outcome.map_err(io::Error::other)?;
    if closed_before_ready {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "监督通道在业务就绪前关闭",
        ));
    }
    // 仅在登记操作、控制句柄及私有监听均已释放后确认退休。
    // 对端已退出时发送失败不影响本进程完成本地回收。
    let _ = tokio::time::timeout(BUDGET, writer.write_all(&startup.frame(b"VWT1", identity))).await;
    Ok(())
}

async fn receive_event(
    control: &mut UnixStream,
    startup: WorkerStartup,
    version: &[u8; 4],
    expected_generation: Option<Uuid>,
) -> io::Result<Uuid> {
    startup.validate()?;
    let mut frame = [0; FRAME_BYTES];
    tokio::time::timeout(BUDGET, control.read_exact(&mut frame))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "工作进程确认超时"))??;
    let generation = Uuid::from_slice(&frame[20..36])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "业务代际身份无效"))?;
    if &frame[..4] != version
        || &frame[4..20] != startup.authorization.as_bytes()
        || frame[36..] != startup.interface_index.to_be_bytes()
        || generation.is_nil()
        || expected_generation.is_some_and(|expected| expected != generation)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "工作进程确认身份不符",
        ));
    }
    Ok(generation)
}

/// 可信监督方在发布私有工作端之前等待；此确认只代表工作进程可接受验证请求。
pub async fn wait_ready(control: &mut UnixStream, startup: WorkerStartup) -> io::Result<Uuid> {
    receive_event(control, startup, b"VWR1", None).await
}

/// 退休确认还须结合直属子进程退出及回收，不能替代进程身份核对。
pub async fn wait_retired(
    control: &mut UnixStream,
    startup: WorkerStartup,
    generation: Uuid,
) -> io::Result<()> {
    receive_event(control, startup, b"VWT1", Some(generation)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn startup() -> WorkerStartup {
        WorkerStartup {
            authorization: Uuid::new_v4(),
            interface_index: nix::net::if_::if_nametoindex("lo0").unwrap(),
            max_connections: 1,
        }
    }

    fn generation(startup: WorkerStartup) -> VerifiedNetworkGeneration {
        VerifiedNetworkGeneration::from_parts(
            super::super::macos::InterfaceScope::new(startup.interface_index).unwrap(),
            super::super::generation::WorkerGeneration::new(),
        )
    }

    fn directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        directory
    }

    #[tokio::test]
    async fn ready_requires_listener_and_retired_follows_all_owned_resource_cleanup() {
        let directory = directory();
        let path = directory.path().join("worker.sock");
        let startup = startup();
        let (custody, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut custody_peer = UnixStream::from_std(peer).unwrap();
        let generation = VerifiedNetworkGeneration::from_parts(
            super::super::macos::InterfaceScope::new(startup.interface_index).unwrap(),
            super::super::generation::WorkerGeneration::with_custody(custody.into()),
        );
        let (mut parent, child) = UnixStream::pair().unwrap();
        let worker_path = path.clone();
        let worker = tokio::spawn(async move {
            serve(
                &worker_path,
                generation,
                child,
                startup,
                CancellationToken::new(),
            )
            .await
        });
        let id = wait_ready(&mut parent, startup).await.unwrap();
        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        // 尚未完成的请求也必须在退休确认前关闭。
        parent.write_all(b"!").await.unwrap();
        wait_retired(&mut parent, startup, id).await.unwrap();
        assert!(!path.exists());
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(custody_peer.read(&mut byte).await.unwrap(), 0);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn occupied_listener_never_publishes_ready_or_removes_unowned_file() {
        let directory = directory();
        let path = directory.path().join("worker.sock");
        std::fs::write(&path, b"existing").unwrap();
        let startup = startup();
        let (mut parent, child) = UnixStream::pair().unwrap();
        assert!(
            serve(
                &path,
                generation(startup),
                child,
                startup,
                CancellationToken::new()
            )
            .await
            .is_err()
        );
        let mut byte = [0; 1];
        assert_eq!(parent.read(&mut byte).await.unwrap(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
    }

    #[tokio::test]
    async fn closed_supervisor_before_start_prevents_ready_and_removes_listener() {
        let directory = directory();
        let path = directory.path().join("worker.sock");
        let startup = startup();
        let (parent, child) = UnixStream::pair().unwrap();
        drop(parent);
        assert!(
            serve(
                &path,
                generation(startup),
                child,
                startup,
                CancellationToken::new()
            )
            .await
            .is_err()
        );
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn closing_ready_control_retires_without_observer_signal() {
        let directory = directory();
        let path = directory.path().join("worker.sock");
        let startup = startup();
        let (mut parent, child) = UnixStream::pair().unwrap();
        let worker_path = path.clone();
        let worker = tokio::spawn(async move {
            serve(
                &worker_path,
                generation(startup),
                child,
                startup,
                CancellationToken::new(),
            )
            .await
        });
        wait_ready(&mut parent, startup).await.unwrap();
        drop(parent);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn failed_ready_publication_removes_the_owned_listener() {
        let directory = directory();
        let path = directory.path().join("worker.sock");
        let startup = startup();
        let result = crate::socks::run_verified_worker_with_ready(
            &path,
            generation(startup),
            1,
            CancellationToken::new(),
            |_| async { Err(io::Error::new(io::ErrorKind::BrokenPipe, "监督方已关闭")) },
        )
        .await;
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn ready_rejects_wrong_version_authorization_index_and_nil_generation() {
        let startup = startup();
        for offset in [0, 4, 39, 20] {
            let (mut parent, mut child) = UnixStream::pair().unwrap();
            let mut frame = startup.frame(b"VWR1", Uuid::new_v4());
            if offset == 20 {
                frame[20..36].fill(0);
            } else {
                frame[offset] ^= 1;
            }
            child.write_all(&frame).await.unwrap();
            assert_eq!(
                wait_ready(&mut parent, startup).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn retired_rejects_a_different_generation() {
        let startup = startup();
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        child
            .write_all(&startup.frame(b"VWT1", Uuid::new_v4()))
            .await
            .unwrap();
        assert_eq!(
            wait_retired(&mut parent, startup, Uuid::new_v4())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_event_has_one_total_deadline() {
        let startup = startup();
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        child.write_all(b"VWR1").await.unwrap();
        assert_eq!(
            wait_ready(&mut parent, startup).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
