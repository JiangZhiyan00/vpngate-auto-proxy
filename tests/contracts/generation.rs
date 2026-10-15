use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use vpngate_auto_proxy::platform::generation::WorkerGeneration;

fn custody_pair() -> (WorkerGeneration, std::os::unix::net::UnixStream) {
    let (owner, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    (WorkerGeneration::with_custody(owner.into()), peer)
}

fn assert_custody_held(peer: &mut std::os::unix::net::UnixStream) {
    use std::io::Read;
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

async fn assert_custody_closed(peer: &mut std::os::unix::net::UnixStream) {
    // 非阻塞描述符的单次读取不能区分关闭尚未可见与真正泄漏；等待可读事件并保留总截止。
    let mut observed = tokio::net::UnixStream::from_std(peer.try_clone().unwrap()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), observed.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn custody_retirement_releases_descriptor_despite_old_lease_clones() {
    let (generation, mut peer) = custody_pair();
    let old = generation.lease();
    let other = old.clone();
    assert_custody_held(&mut peer);
    generation.retire().await;
    assert_custody_closed(&mut peer).await;
    assert!(old.execute(|| async { Ok(()) }).await.is_err());
    assert!(other.execute(|| async { Ok(()) }).await.is_err());
    generation.retire().await;
}

#[tokio::test]
async fn custody_outlives_registered_network_socket_cleanup() {
    struct Connection {
        socket: Option<TcpStream>,
        custody_peer: std::os::unix::net::UnixStream,
        observed: Arc<AtomicBool>,
    }
    impl Drop for Connection {
        fn drop(&mut self) {
            drop(self.socket.take());
            assert_custody_held(&mut self.custody_peer);
            self.observed.store(true, Ordering::SeqCst);
        }
    }
    let (generation, mut peer) = custody_pair();
    let lease = generation.lease();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let observed = Arc::new(AtomicBool::new(false));
    let evidence = observed.clone();
    let custody_peer = peer.try_clone().unwrap();
    let (started, ready) = oneshot::channel();
    let task = tokio::spawn(async move {
        lease
            .execute(|| async move {
                let socket = TcpStream::connect(address).await?;
                let _connection = Connection {
                    socket: Some(socket),
                    custody_peer,
                    observed: evidence,
                };
                started.send(()).unwrap();
                std::future::pending::<io::Result<()>>().await
            })
            .await
    });
    let (mut network_peer, _) = listener.accept().await.unwrap();
    ready.await.unwrap();
    generation.retire().await;
    assert!(observed.load(Ordering::SeqCst));
    assert_eq!(
        timeout(Duration::from_secs(1), network_peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_custody_closed(&mut peer).await;
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn cancelled_retirement_keeps_custody_until_explicit_retry() {
    let (generation, mut peer) = custody_pair();
    let lease = generation.lease();
    let (started, ready) = oneshot::channel();
    let task = tokio::spawn(async move {
        lease
            .execute(|| async move {
                started.send(()).unwrap();
                std::future::pending::<io::Result<()>>().await
            })
            .await
    });
    ready.await.unwrap();
    let mut retirement = Box::pin(generation.retire());
    assert!(futures_util::poll!(&mut retirement).is_pending());
    assert_custody_held(&mut peer);
    drop(retirement);
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_custody_held(&mut peer);
    generation.retire().await;
    assert_custody_closed(&mut peer).await;
}

#[tokio::test]
async fn abandoned_supervisor_keeps_custody_while_revoked_reference_survives() {
    let (generation, mut peer) = custody_pair();
    let lease = generation.lease();
    drop(generation);
    assert!(lease.execute(|| async { Ok(()) }).await.is_err());
    assert_custody_held(&mut peer);
    drop(lease);
    assert_custody_closed(&mut peer).await;
}

#[tokio::test]
async fn live_generation_preserves_operation_results() {
    let generation = WorkerGeneration::new();
    assert_eq!(
        generation
            .lease()
            .execute(|| async { Ok(42) })
            .await
            .unwrap(),
        42
    );
    let error = generation
        .lease()
        .execute(|| async { Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused)) })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn revoked_clones_never_construct_new_operations() {
    let generation = WorkerGeneration::new();
    let old = generation.lease().clone();
    generation.revoke();
    let called = AtomicBool::new(false);
    let result = old
        .execute(|| {
            called.store(true, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;
    assert!(result.is_err(), "已撤销引用仍执行了操作");
    assert!(!called.load(Ordering::SeqCst), "撤销后不应构造操作");
}

#[tokio::test]
async fn retirement_cancels_operations_and_closes_owned_socket_before_ack() {
    let generation = WorkerGeneration::new();
    let lease = generation.lease();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started, ready) = oneshot::channel();
    let task = tokio::spawn(async move {
        lease
            .execute(|| async move {
                let mut socket = TcpStream::connect(address).await?;
                started.send(()).unwrap();
                let mut data = [0];
                socket.read_exact(&mut data).await?;
                Ok(())
            })
            .await
    });
    let (mut peer, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    ready.await.unwrap();
    let retired = timeout(Duration::from_secs(1), generation.retire())
        .await
        .expect("撤销未取消活动操作");
    assert_eq!(retired.id(), generation.lease().id());
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn new_generation_does_not_reactivate_retired_reference() {
    let old_generation = WorkerGeneration::new();
    let old = old_generation.lease();
    old_generation.retire().await;
    let replacement = WorkerGeneration::new();
    assert_ne!(old.id(), replacement.lease().id());
    assert!(old.execute(|| async { Ok(()) }).await.is_err());
    assert_eq!(
        replacement
            .lease()
            .execute(|| async { Ok(7) })
            .await
            .unwrap(),
        7
    );
}

#[tokio::test]
async fn dropping_supervisor_revokes_all_lease_clones() {
    let generation = WorkerGeneration::new();
    let one = generation.lease();
    let two = one.clone();
    drop(generation);
    assert!(one.execute(|| async { Ok(()) }).await.is_err());
    assert!(two.execute(|| async { Ok(()) }).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_admitted_operations_are_dropped_before_retirement_returns() {
    struct Resource(Arc<AtomicBool>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let generation = WorkerGeneration::new();
    let mut tasks = Vec::new();
    let mut resources = Vec::new();
    for _ in 0..16 {
        let lease = generation.lease();
        let dropped = Arc::new(AtomicBool::new(false));
        resources.push(dropped.clone());
        let (started, ready) = oneshot::channel();
        tasks.push(tokio::spawn(async move {
            lease
                .execute(|| async move {
                    let _resource = Resource(dropped);
                    started.send(()).unwrap();
                    std::future::pending::<io::Result<()>>().await
                })
                .await
        }));
        ready.await.unwrap();
    }
    timeout(Duration::from_secs(1), generation.retire())
        .await
        .expect("未取消全部已登记操作");
    assert!(resources.iter().all(|r| r.load(Ordering::SeqCst)));
    for task in tasks {
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}

#[tokio::test]
async fn cancelling_retirement_wait_does_not_reopen_admission() {
    let generation = WorkerGeneration::new();
    let lease = generation.lease();
    let old = lease.clone();
    let (started, ready) = oneshot::channel();
    let task = tokio::spawn(async move {
        lease
            .execute(|| async move {
                started.send(()).unwrap();
                std::future::pending::<io::Result<()>>().await
            })
            .await
    });
    ready.await.unwrap();
    // 当前线程上的活动任务尚未处理取消，首次轮询退休等待必须挂起。
    let mut retirement = Box::pin(generation.retire());
    assert!(futures_util::poll!(&mut retirement).is_pending());
    drop(retirement);
    assert!(old.execute(|| async { Ok(()) }).await.is_err());
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(generation.retire().await.id(), old.id());
}
