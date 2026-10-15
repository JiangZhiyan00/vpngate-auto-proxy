use super::support::*;
#[tokio::test]
#[ignore = "需要受控 Linux 服务环境"]
async fn authentication_and_protocol_boundaries() {
    let mut service = ServiceFixture::start(true, 50);
    let mut wrong = service.connect().await;
    assert!(!negotiate(&mut wrong, Some("wrong-secret")).await);
    let mut missing = service.connect().await;
    assert!(!negotiate(&mut missing, None).await);
    for (command, target, expected) in [
        (2, "11.54.0.2", 7),
        (3, "11.54.0.2", 7),
        (1, "127.0.0.1", 3),
        (1, "printer.local", 3),
    ] {
        let mut client = service.connect().await;
        assert!(negotiate(&mut client, Some("fixture-secret")).await);
        assert_eq!(request(&mut client, command, target, 80).await, expected);
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut ipv6 = service.connect().await;
    assert!(negotiate(&mut ipv6, Some("fixture-secret")).await);
    ipv6.write_all(&[
        5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80,
    ])
    .await
    .unwrap();
    let mut reply = [0; 10];
    ipv6.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 8);
}

#[tokio::test]
#[ignore = "需要受控 Linux 服务环境"]
async fn no_exit_never_falls_back_to_direct_connect() {
    let mut service = ServiceFixture::start_with(false, 50, |config| {
        config.source_url = "http://127.0.0.1:1/".parse().unwrap();
    });
    let mut client = service.connect().await;
    assert!(negotiate(&mut client, None).await);
    assert_ne!(request(&mut client, 1, "11.54.0.2", 80).await, 0);
}
#[tokio::test]
#[ignore = "需要受控 Linux 服务环境"]
async fn accept_and_authentication_hold_capacity_without_evicting_existing_clients() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut service = ServiceFixture::start(false, 2);
    let mut first = service.connect().await;
    let second = service.connect().await;
    let mut third = service.connect().await;
    let mut buffer = [0; 1];
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(1), third.read(&mut buffer))
        .await
        .unwrap();
    assert!(rejected.is_err() || rejected.unwrap() == 0);
    first.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    first.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    drop(second);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut replacement = service.connect().await;
    assert!(negotiate(&mut replacement, None).await);
}
