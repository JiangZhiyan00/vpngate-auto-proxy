use super::support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
#[ignore = "需要受控 Linux 节点与网络权限"]
async fn first_verified_exit_serves_numeric_and_remote_dns_targets_within_sixty_seconds() {
    let _state = FixtureStateGuard::set(serde_json::json!({"source_protocols":["tcp"]}));
    let mut service = ServiceFixture::start(false, 50);
    for target in ["11.54.0.2", "fixture.example"] {
        loop {
            assert!(
                service.started.elapsed() < std::time::Duration::from_secs(60),
                "首次可用超过六十秒"
            );
            let mut client = service.connect().await;
            assert!(negotiate(&mut client, None).await);
            if request(&mut client, 1, target, 80).await != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            client.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: fixture.example\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut body = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                client.read_to_end(&mut body),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(body.starts_with(b"HTTP/1.0 204"));
            let finished =
                chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap());
            eprintln!(
                "首次请求完成：目标类型={}，完成时间={}，启动后耗时={}毫秒",
                if target == "11.54.0.2" {
                    "数字地址"
                } else {
                    "隧道内域名解析"
                },
                finished.to_rfc3339(),
                service.started.elapsed().as_millis(),
            );
            break;
        }
    }
    let events = std::fs::read_to_string(service.directory.path().join("events.log")).unwrap();
    let pending: Vec<_> = events
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["event_type"] == "pending_started")
        .collect();
    assert_eq!(pending.len(), 1, "首个待启用隧道不得重复建立");
    for event_type in ["tunnel_connected", "active_promoted"] {
        let count = events
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event_type"] == event_type)
            .count();
        assert_eq!(count, 1, "首次启用只允许一次隧道建立与提升");
    }
}

#[tokio::test]
#[ignore = "需要受控 Linux UDP 节点与网络权限"]
async fn udp_transport_becomes_usable_after_actual_exit_validation() {
    let _state = FixtureStateGuard::set(serde_json::json!({"source_protocols":["udp"]}));
    let mut service = ServiceFixture::start(false, 50);
    loop {
        assert!(service.started.elapsed() < std::time::Duration::from_secs(60));
        let mut client = service.connect().await;
        assert!(negotiate(&mut client, None).await);
        if request(&mut client, 1, "11.54.0.2", 80).await == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[tokio::test]
#[ignore = "需要受控 Linux 隧道与 HTTP 故障注入"]
async fn successful_handshake_without_a_working_exit_never_publishes_active_worker() {
    let _state = FixtureStateGuard::set(serde_json::json!({"code":503}));
    let mut service = ServiceFixture::start(false, 50);
    let mut client = service.connect().await;
    assert!(negotiate(&mut client, None).await);
    assert_ne!(request(&mut client, 1, "11.54.0.2", 80).await, 0);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut client = service.connect().await;
    assert!(negotiate(&mut client, None).await);
    assert_ne!(request(&mut client, 1, "11.54.0.2", 80).await, 0);
    let events = std::fs::read_to_string(service.directory.path().join("events.log")).unwrap();
    assert!(events.contains("tunnel_connected"));
    assert!(!events.contains("active_promoted"));
}

#[tokio::test]
#[ignore = "需要受控 Linux 节点及真实空闲等待"]
async fn idle_tunnel_remains_usable_past_server_keepalive_deadline() {
    let _state = FixtureStateGuard::set(serde_json::json!({"source_protocols":["tcp"]}));
    let mut service = ServiceFixture::start(false, 50);
    loop {
        assert!(service.started.elapsed() < std::time::Duration::from_secs(60));
        let mut client = service.connect().await;
        assert!(negotiate(&mut client, None).await);
        if request(&mut client, 1, "11.54.0.2", 80).await == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // 夹具服务器的保活截止为二十秒；此处真实等待，不能用受控时钟替代。
    tokio::time::sleep(std::time::Duration::from_secs(35)).await;
    let mut client = service.connect().await;
    assert!(negotiate(&mut client, None).await);
    assert_eq!(
        request(&mut client, 1, "fixture.example", 80).await,
        0,
        "空闲超过服务器保活截止后，隧道仍须支持代理端域名解析及访问"
    );
}
