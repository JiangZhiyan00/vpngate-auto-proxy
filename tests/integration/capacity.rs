use super::support::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "需要专用 Linux 受控节点及实际五十连接"]
async fn fifty_clients_stay_connected_fifty_first_is_refused_and_internal_probe_has_its_own_capacity()
 {
    let mut service = ServiceFixture::start(false, 50);
    let mut clients = Vec::new();
    for _ in 0..50 {
        loop {
            assert!(service.started.elapsed() < Duration::from_secs(60));
            let mut client = service.connect().await;
            assert!(negotiate(&mut client, None).await);
            if request(&mut client, 1, "11.54.0.2", 19090).await == 0 {
                clients.push(client);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let mut extra = service.connect().await;
    let mut byte = [0; 1];
    let rejected = tokio::time::timeout(Duration::from_secs(1), extra.read(&mut byte))
        .await
        .unwrap();
    assert!(rejected.is_err() || rejected.unwrap() == 0);
    for client in &mut clients {
        client.write_all(b"still-alive").await.unwrap();
        let mut response = [0; 11];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"still-alive");
    }
    let manifest: vpngate_auto_proxy::netd::ResourceManifest = serde_json::from_slice(
        &std::fs::read(service.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    let worker = manifest
        .workers
        .iter()
        .find(|worker| worker.role == vpngate_auto_proxy::domain::WorkerRole::Active)
        .unwrap();
    let report = vpngate_auto_proxy::probe::check_exit(
        &worker.socket_path,
        &service.config.exit_check_urls,
        3,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        report.success,
        "满载时内部检测不能被外部配额阻断：{report:?}"
    );
    drop(clients.pop());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut replacement = service.connect().await;
    assert!(negotiate(&mut replacement, None).await);
    assert_eq!(request(&mut replacement, 1, "11.54.0.2", 19090).await, 0);
}
