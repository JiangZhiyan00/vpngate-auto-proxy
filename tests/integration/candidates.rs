use super::support::*;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(super) fn events(service: &ServiceFixture) -> Vec<Value> {
    std::fs::read_to_string(service.directory.path().join("events.log"))
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}
pub(super) async fn wait_event(service: &ServiceFixture, kind: &str, count: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if events(service)
            .iter()
            .filter(|e| e["event_type"] == kind)
            .count()
            >= count
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "缺少事件 {kind}：{:?}",
            std::fs::read_to_string(service.directory.path().join("events.log")).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
pub(super) async fn http(service: &mut ServiceFixture) {
    let mut connection = service.connect().await;
    assert!(negotiate(&mut connection, None).await);
    assert_eq!(request(&mut connection, 1, "fixture.example", 80).await, 0);
    connection
        .write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: fixture.example\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), connection.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.0 204"));
}
#[tokio::test]
#[ignore = "需要受控 Linux 候选、刷新及长连接"]
async fn background_candidates_release_workers_and_source_removal_keeps_active() {
    let _state = FixtureStateGuard::set(json!({"source_count":5}));
    let routes = vpngate_auto_proxy::netd::system::run_command("ip", &["-4", "route", "show"])
        .await
        .unwrap();
    let dns = std::fs::read("/etc/resolv.conf").unwrap();
    let mut service = ServiceFixture::start_with(false, 50, |c| {
        c.source_refresh_seconds = 2;
        c.candidate_interval_seconds = 2;
        c.candidate_result_ttl_seconds = 1;
    });
    wait_event(&service, "active_promoted", 1).await;
    let active = events(&service)
        .into_iter()
        .find(|e| e["event_type"] == "active_promoted")
        .unwrap();
    let mut echo = service.connect().await;
    assert!(negotiate(&mut echo, None).await);
    assert_eq!(request(&mut echo, 1, "fixture.example", 19090).await, 0);
    wait_event(&service, "round_finished", 2).await;
    for _ in 0..5 {
        echo.write_all(b"stable").await.unwrap();
        let mut reply = [0; 6];
        echo.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"stable");
        http(&mut service).await;
    }
    let checks: Value = serde_json::from_slice(
        &std::fs::read(service.config.data_dir.join("checks.json")).unwrap(),
    )
    .unwrap();
    for layer in ["port", "tunnel", "exit"] {
        assert!(
            checks["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["layer"] == layer)
        );
    }
    let _empty = FixtureStateGuard::set(json!({"source_count":0}));
    tokio::time::sleep(Duration::from_secs(3)).await;
    http(&mut service).await;
    assert_eq!(
        events(&service)
            .iter()
            .filter(|e| e["event_type"] == "active_promoted")
            .count(),
        1
    );
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(service.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["workers"].as_array().unwrap().len(), 1);
    assert_eq!(manifest["workers"][0]["worker_id"], active["worker_id"]);
    drop(echo);
    drop(service);
    assert_eq!(
        routes,
        vpngate_auto_proxy::netd::system::run_command("ip", &["-4", "route", "show"])
            .await
            .unwrap()
    );
    assert_eq!(dns, std::fs::read("/etc/resolv.conf").unwrap());
}
#[tokio::test]
#[ignore = "需要受控 Linux 缓存重启与来源失败"]
async fn source_failure_preserves_cache_age_and_restart_revalidates() {
    let _state = FixtureStateGuard::set(json!({"source_protocols":["tcp"]}));
    let first = ServiceFixture::start_with(false, 50, |c| {
        c.source_refresh_seconds = 1;
        c.retry_initial_seconds = 1;
    });
    wait_event(&first, "active_promoted", 1).await;
    let original = std::fs::read(first.config.data_dir.join("nodes.json")).unwrap();
    let _failure = FixtureStateGuard::set(json!({"source_code":503}));
    wait_event(&first, "source_failed", 1).await;
    assert_eq!(
        original,
        std::fs::read(first.config.data_dir.join("nodes.json")).unwrap()
    );
    let cache = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(cache.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let data = cache.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::copy(
        first.config.data_dir.join("nodes.json"),
        data.join("nodes.json"),
    )
    .unwrap();
    std::fs::write(data.join("checks.json"), b"invalid diagnostics").unwrap();
    for name in ["nodes.json", "checks.json"] {
        std::os::unix::fs::chown(data.join(name), Some(10001), Some(10001)).unwrap();
        std::fs::set_permissions(data.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(first);
    let mut second = ServiceFixture::start_with(false, 50, |c| {
        c.data_dir = data;
    });
    wait_event(&second, "cache_loaded", 1).await;
    wait_event(&second, "active_promoted", 1).await;
    http(&mut second).await;
    assert!(
        events(&second)
            .iter()
            .any(|e| e["event_type"] == "pending_started")
    );
    assert!(
        events(&second)
            .iter()
            .any(|e| e["event_type"] == "diagnostics_ignored")
    );
    assert_eq!(
        original,
        std::fs::read(second.config.data_dir.join("nodes.json")).unwrap()
    );
}

#[tokio::test]
#[ignore = "需要受控 Linux 真实三十分钟候选共存及抓包"]
async fn candidate_soak_preserves_business_dns_and_host_network() {
    use vpngate_auto_proxy::netd::system::run_command;
    let duration: u64 = std::env::var("VAP_CANDIDATE_SOAK_SECONDS")
        .unwrap_or_else(|_| "1800".into())
        .parse()
        .unwrap();
    assert!(
        duration >= 3,
        "持续验收至少三秒；短运行不能替代三十分钟证据"
    );
    let _state = FixtureStateGuard::set(json!({"source_count":45}));
    let routes = run_command("ip", &["-4", "route", "show"]).await.unwrap();
    let rules = run_command("nft", &["-s", "list", "ruleset"])
        .await
        .unwrap();
    let dns = std::fs::read("/etc/resolv.conf").unwrap();
    let forward = std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap();
    let capture = tempfile::tempdir().unwrap();
    let capture_path = capture.path().join("management.pcap");
    let mut tcpdump = tokio::process::Command::new("tcpdump")
        .args(["-ni", "vfixture0", "-U", "-w"])
        .arg(&capture_path)
        .arg("host 11.53.0.2 or host 11.54.0.2 or host 1.1.1.1")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(capture.path().join("capture.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tcpdump.try_wait().unwrap().is_none(),
        "抓包未启动：需要测试专用原始套接字能力"
    );
    let mut service = ServiceFixture::start_with(false, 50, |c| {
        if duration < 1800 {
            c.candidate_interval_seconds = 1;
            c.source_refresh_seconds = 1;
        }
    });
    wait_event(&service, "active_promoted", 1).await;
    let mut echo = service.connect().await;
    assert!(negotiate(&mut echo, None).await);
    assert_eq!(request(&mut echo, 1, "fixture.example", 19090).await, 0);
    let started = tokio::time::Instant::now();
    let mut requests = 0;
    let mut next_report = Duration::from_secs(60);
    loop {
        http(&mut service).await;
        echo.write_all(b"stable").await.unwrap();
        let mut reply = [0; 6];
        tokio::time::timeout(Duration::from_secs(3), echo.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"stable");
        requests += 1;
        if started.elapsed() >= next_report {
            eprintln!(
                "持续验收进度：已运行{}秒，业务请求{}次，已完成候选轮次{}，活动提升{}次",
                started.elapsed().as_secs(),
                requests,
                events(&service)
                    .iter()
                    .filter(|e| e["event_type"] == "round_finished")
                    .count(),
                events(&service)
                    .iter()
                    .filter(|e| e["event_type"] == "active_promoted")
                    .count()
            );
            next_report += Duration::from_secs(60);
        }
        if started.elapsed() >= Duration::from_secs(duration) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        events(&service)
            .iter()
            .filter(|e| e["event_type"] == "round_finished")
            .count()
            >= 2,
        "至少完成两轮候选验证"
    );
    assert_eq!(
        events(&service)
            .iter()
            .filter(|e| e["event_type"] == "active_promoted")
            .count(),
        1,
        "候选不得引发主动切换"
    );
    drop(echo);
    drop(service);
    std::process::Command::new("kill")
        .args(["-INT", &tcpdump.id().unwrap().to_string()])
        .status()
        .unwrap();
    assert!(tcpdump.wait().await.unwrap().success());
    let total = tokio::process::Command::new("tcpdump")
        .args(["-nn", "-r"])
        .arg(&capture_path)
        .output()
        .await
        .unwrap();
    assert!(total.status.success());
    assert!(!total.stdout.is_empty(), "不得以零抓包宣称无泄漏");
    let leaked = tokio::process::Command::new("tcpdump")
        .args(["-nn", "-r"])
        .arg(&capture_path)
        .arg("host 11.54.0.2 or host 1.1.1.1")
        .output()
        .await
        .unwrap();
    assert!(leaked.status.success());
    assert!(leaked.stdout.is_empty(), "业务或域名解析进入管理路径");
    assert_eq!(
        routes,
        run_command("ip", &["-4", "route", "show"]).await.unwrap()
    );
    assert_eq!(
        rules,
        run_command("nft", &["-s", "list", "ruleset"])
            .await
            .unwrap()
    );
    assert_eq!(dns, std::fs::read("/etc/resolv.conf").unwrap());
    assert_eq!(
        forward,
        std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap()
    );
    eprintln!(
        "候选共存验收：持续{}秒，业务请求{}次，管理路径封装包{}条，业务及域名解析明文包零条；网络基线一致",
        started.elapsed().as_secs(),
        requests,
        total
            .stdout
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .count()
    );
}
#[tokio::test]
#[ignore = "需要受控 Linux 候选整体重试和分层诊断"]
async fn candidate_retries_keep_unique_node_budget_and_separate_layers() {
    let _state = FixtureStateGuard::set(json!({"source_count":5,"code":503}));
    let service = ServiceFixture::start_with(false, 50, |c| {
        c.candidate_batch_size = 2;
        c.candidate_retries = 1;
        c.exit_check_max_attempts = 1;
    });
    wait_event(&service, "round_finished", 1).await;
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for event in events(&service)
        .iter()
        .filter(|e| e["event_type"] == "pending_started")
    {
        let id = event["node_id"].as_str().unwrap().to_owned();
        *counts.entry(id).or_default() += 1;
    }
    assert_eq!(counts.len(), 2);
    assert!(counts.values().all(|c| *c == 2));
    let checks: Value = serde_json::from_slice(
        &std::fs::read(service.config.data_dir.join("checks.json")).unwrap(),
    )
    .unwrap();
    for check in checks["checks"].as_array().unwrap() {
        match check["layer"].as_str().unwrap() {
            "exit" => assert_eq!(check["outcome"], "failed"),
            "tunnel" => assert_eq!(check["outcome"], "succeeded"),
            "port" => {
                assert!(check["outcome"] == "succeeded" || check["outcome"] == "not_applicable")
            }
            _ => panic!("未知层次"),
        }
    }
    assert!(
        !events(&service)
            .iter()
            .any(|e| e["event_type"] == "active_promoted")
    );
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(service.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    assert!(manifest["workers"].as_array().unwrap().is_empty());
}
#[tokio::test]
#[ignore = "需要受控 Linux 端口黑洞及总时限"]
async fn port_timeout_preserves_observed_layer_without_inventing_tunnel_results() {
    use vpngate_auto_proxy::netd::system::run_command;
    let _state = FixtureStateGuard::set(json!({"source_protocols":["tcp"],"source_port":19998}));
    run_command(
        "ip",
        &[
            "netns",
            "exec",
            "vap_fixture",
            "nft",
            "add",
            "table",
            "inet",
            "vap_port_timeout",
        ],
    )
    .await
    .unwrap();
    run_command(
        "ip",
        &[
            "netns",
            "exec",
            "vap_fixture",
            "nft",
            "add",
            "chain",
            "inet",
            "vap_port_timeout",
            "input",
            "{ type filter hook input priority 0; }",
        ],
    )
    .await
    .unwrap();
    run_command(
        "ip",
        &[
            "netns",
            "exec",
            "vap_fixture",
            "nft",
            "add",
            "rule",
            "inet",
            "vap_port_timeout",
            "input",
            "tcp",
            "dport",
            "19998",
            "drop",
        ],
    )
    .await
    .unwrap();
    let service = ServiceFixture::start_with(false, 50, |c| {
        c.tunnel_timeout_seconds = 1;
        c.port_probe_timeout_seconds = 3;
    });
    wait_event(&service, "round_finished", 1).await;
    let checks: Value = serde_json::from_slice(
        &std::fs::read(service.config.data_dir.join("checks.json")).unwrap(),
    )
    .unwrap();
    for check in checks["checks"].as_array().unwrap() {
        assert_eq!(
            check["outcome"],
            if check["layer"] == "port" {
                "failed"
            } else {
                "not_tested"
            }
        );
    }
    assert!(
        !events(&service)
            .iter()
            .any(|e| e["event_type"] == "diagnostics_write_failed")
    );
    drop(service);
    run_command(
        "ip",
        &[
            "netns",
            "exec",
            "vap_fixture",
            "nft",
            "delete",
            "table",
            "inet",
            "vap_port_timeout",
        ],
    )
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "需要受控 Linux 空来源退避及恢复"]
async fn empty_source_uses_recovery_backoff_and_detects_new_nodes() {
    let _empty = FixtureStateGuard::set(json!({"source_count":0}));
    let service = ServiceFixture::start_with(false, 50, |c| {
        c.retry_initial_seconds = 1;
        c.retry_max_seconds = 2;
    });
    wait_event(&service, "source_updated", 2).await;
    let times: Vec<_> = events(&service)
        .into_iter()
        .filter(|e| e["event_type"] == "source_fetch")
        .map(|e| chrono::DateTime::parse_from_rfc3339(e["timestamp"].as_str().unwrap()).unwrap())
        .collect();
    assert!(
        times[1].signed_duration_since(times[0]).num_milliseconds() >= 900,
        "空来源不得忙循环"
    );
    let _failure = FixtureStateGuard::set(json!({"source_code":503}));
    wait_event(&service, "source_failed", 2).await;
    let failures: Vec<_> = events(&service)
        .into_iter()
        .filter(|e| e["event_type"] == "source_failed")
        .map(|e| chrono::DateTime::parse_from_rfc3339(e["timestamp"].as_str().unwrap()).unwrap())
        .collect();
    assert!(
        failures[1]
            .signed_duration_since(failures[0])
            .num_milliseconds()
            >= 900,
        "空来源恢复不得绕过来源失败退避"
    );
    let _available = FixtureStateGuard::set(json!({"source_protocols":["tcp"]}));
    wait_event(&service, "active_promoted", 1).await;
}
