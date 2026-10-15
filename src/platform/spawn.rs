//! 本进程创建可短暂继承的套接字与派生子进程共用同步临界区；不得跨异步等待。
use std::io;

pub(crate) fn guarded<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SERIAL
        .lock()
        .map_err(|_| io::Error::other("描述符创建与派生串行锁已失效"))?;
    operation()
}

pub(crate) async fn accept(
    listener: &tokio::net::UnixListener,
) -> io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)> {
    // 苹果接受连接后还需设置执行时关闭标志；只包住一次非阻塞轮询，不跨异步等待持锁。
    std::future::poll_fn(|cx| match guarded(|| Ok(listener.poll_accept(cx))) {
        Ok(result) => result,
        Err(error) => std::task::Poll::Ready(Err(error)),
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_creations_and_spawns_share_one_synchronous_section() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            let mut tasks = Vec::new();
            for _ in 0..4 {
                tasks.push(scope.spawn(|| {
                    barrier.wait();
                    guarded(|| {
                        let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum.fetch_max(count, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap();
                }));
            }
            for task in tasks {
                task.join().unwrap();
            }
        });
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
        assert!(guarded(|| Err::<(), _>(io::Error::other("受控失败"))).is_err());
        guarded(|| Ok(())).unwrap();
    }
    #[tokio::test]
    async fn accepting_pending_management_connection_releases_lock_between_polls() {
        use std::{os::fd::AsFd, os::unix::net::UnixListener, time::Duration};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("s");
        let listener = guarded(|| UnixListener::bind(&path)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(listener).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), accept(&listener))
                .await
                .is_err()
        );
        let _client = guarded(|| std::os::unix::net::UnixStream::connect(path)).unwrap();
        let (stream, _) = tokio::time::timeout(Duration::from_secs(1), accept(&listener))
            .await
            .unwrap()
            .unwrap();
        assert!(
            rustix::io::fcntl_getfd(stream.as_fd())
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }
}
