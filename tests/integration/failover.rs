use super::{
    candidates::{events, http, wait_event},
    support::*,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpngate_auto_proxy::netd::system::run_command;

struct NetworkObservation {
    directory: tempfile::TempDir,
    capture: tokio::process::Child,
    routes: Vec<u8>,
    rules: Vec<u8>,
    dns: Vec<u8>,
    forwarding: Vec<u8>,
}
impl NetworkObservation {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let capture = tokio::process::Command::new("tcpdump")
            .args(["-ni", "vfixture0", "-U", "-w"])
            .arg(directory.path().join("management.pcap"))
            .arg("host 11.53.0.2 or host 11.54.0.2 or host 1.1.1.1")
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(directory.path().join("capture.log")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut observation = Self {
            directory,
            capture,
            routes: run_command("ip", &["-4", "route", "show"]).await.unwrap(),
            rules: run_command("nft", &["-s", "list", "ruleset"])
                .await
                .unwrap(),
            dns: std::fs::read("/etc/resolv.conf").unwrap(),
            forwarding: std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap(),
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(observation.capture.try_wait().unwrap().is_none());
        observation
    }
    async fn finish(mut self) {
        run_command("kill", &["-INT", &self.capture.id().unwrap().to_string()])
            .await
            .unwrap();
        assert!(self.capture.wait().await.unwrap().success());
        let file = self.directory.path().join("management.pcap");
        let all = tokio::process::Command::new("tcpdump")
            .args(["-nn", "-r"])
            .arg(&file)
            .output()
            .await
            .unwrap();
        assert!(
            all.status.success() && !all.stdout.is_empty(),
            "必须实际抓到管理路径封装包"
        );
        let leaked = tokio::process::Command::new("tcpdump")
            .args(["-nn", "-r"])
            .arg(&file)
            .arg("host 11.54.0.2 or host 1.1.1.1 or (host 11.53.0.2 and tcp port 19090)")
            .output()
            .await
            .unwrap();
        assert!(
            leaked.status.success() && leaked.stdout.is_empty(),
            "故障、等待或恢复期间发生业务或域名解析直连"
        );
        assert_eq!(
            self.routes,
            run_command("ip", &["-4", "route", "show"]).await.unwrap()
        );
        assert_eq!(
            self.rules,
            run_command("nft", &["-s", "list", "ruleset"])
                .await
                .unwrap()
        );
        assert_eq!(self.dns, std::fs::read("/etc/resolv.conf").unwrap());
        assert_eq!(
            self.forwarding,
            std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap()
        );
        eprintln!(
            "故障恢复抓包：封装包{}条，业务及域名解析明文包零条，网络基线一致",
            all.stdout
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .count()
        );
    }
}

fn active_record(service: &ServiceFixture) -> Value {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(service.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    manifest["workers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["role"] == "active")
        .unwrap()
        .clone()
}

#[tokio::test]
#[ignore = "需要受控 Linux 结构故障、旧连接阻断及替代隧道"]
async fn structural_failure_closes_old_connection_before_http_cycle_and_recovers_same_listener() {
    let _state = FixtureStateGuard::set(json!({}));
    let observation = NetworkObservation::start().await;
    let mut service = ServiceFixture::start_debug_with(false, 50, |c| {
        c.health_interval_seconds = 60;
        c.health_timeout_seconds = 1;
    });
    wait_event(&service, "round_finished", 1).await;
    let old = active_record(&service);
    let mut echo = service.connect().await;
    assert!(negotiate(&mut echo, None).await);
    assert_eq!(request(&mut echo, 1, "fixture.example", 19090).await, 0);
    echo.write_all(b"before").await.unwrap();
    let mut reply = [0; 6];
    echo.read_exact(&mut reply).await.unwrap();
    let started = tokio::time::Instant::now();
    run_command(
        "ip",
        &[
            "netns",
            "exec",
            old["namespace"].as_str().unwrap(),
            "ip",
            "route",
            "del",
            "0.0.0.0/1",
        ],
    )
    .await
    .unwrap();
    wait_event(&service, "active_blocked", 1).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "结构故障不等待六十秒 HTTP 周期"
    );
    let closed = tokio::time::timeout(Duration::from_secs(3), echo.read_u8())
        .await
        .unwrap();
    assert!(closed.is_err(), "旧连接必须关闭");
    wait_event(&service, "active_promoted", 2).await;
    assert!(started.elapsed() < Duration::from_secs(120));
    assert_ne!(active_record(&service)["worker_id"], old["worker_id"]);
    assert_ne!(active_record(&service)["node_id"], old["node_id"]);
    http(&mut service).await;
    let sequence = events(&service);
    let blocked = sequence
        .iter()
        .position(|e| e["event_type"] == "active_blocked")
        .unwrap();
    let replacement = sequence
        .iter()
        .rposition(|e| e["event_type"] == "active_promoted")
        .unwrap();
    assert!(blocked < replacement);
    drop(service);
    observation.finish().await;
}

#[tokio::test]
#[ignore = "需要受控 Linux HTTP 故障、无节点退避及恢复"]
async fn all_http_checks_fail_blocks_requests_waits_without_exit_then_revalidates() {
    let _state = FixtureStateGuard::set(json!({}));
    let observation = NetworkObservation::start().await;
    let mut service = ServiceFixture::start_debug_with(false, 50, |c| {
        c.health_interval_seconds = 2;
        c.health_timeout_seconds = 1;
        c.retry_initial_seconds = 1;
        c.retry_max_seconds = 2;
        c.exit_check_max_attempts = 1;
    });
    wait_event(&service, "round_finished", 1).await;
    let old = active_record(&service);
    let tcp =
        vpngate_auto_proxy::domain::NodeId::from_endpoint(&vpngate_auto_proxy::domain::Endpoint {
            ip: "11.53.0.2".parse().unwrap(),
            port: 1194,
            transport: vpngate_auto_proxy::domain::Transport::Tcp,
        });
    let old_transport = if old["node_id"] == tcp.to_string() {
        "tcp"
    } else {
        "udp"
    };
    let _failure = FixtureStateGuard::set(json!({"code":503}));
    wait_event(&service, "active_blocked", 1).await;
    wait_event(&service, "round_finished", 3).await;
    let mut connection = service.connect().await;
    assert!(negotiate(&mut connection, None).await);
    for target in ["fixture.example", "11.53.0.2"] {
        assert_ne!(
            request(&mut connection, 1, target, 19090).await,
            0,
            "等待期间不能直连"
        );
        connection = service.connect().await;
        assert!(negotiate(&mut connection, None).await);
    }
    assert!(service.child.try_wait().unwrap().is_none());
    let _healthy = FixtureStateGuard::set(json!({"transport_codes":{old_transport:503}}));
    wait_event(&service, "active_promoted", 2).await;
    assert_ne!(
        active_record(&service)["node_id"],
        old["node_id"],
        "失败备用不得被提升，必须重新验证成功节点"
    );
    http(&mut service).await;
    drop(connection);
    drop(service);
    observation.finish().await;
}

#[tokio::test]
#[ignore = "需要专用 Linux 无节点等待；默认三十分钟，短时运行不能代替完整验收"]
async fn waiting_without_nodes_stays_alive_with_backoff_and_no_direct_business_or_dns() {
    let duration: u64 = std::env::var("VAP_RECOVERY_WAIT_SECONDS")
        .unwrap_or_else(|_| "1800".into())
        .parse()
        .unwrap();
    assert!(duration >= 3);
    let _state = FixtureStateGuard::set(json!({"code":503}));
    let observation = NetworkObservation::start().await;
    let mut service = ServiceFixture::start_debug_with(false, 50, |c| {
        c.exit_check_max_attempts = 1;
        if duration < 1800 {
            c.retry_initial_seconds = 1;
            c.retry_max_seconds = 2;
        }
    });
    wait_event(&service, "round_finished", 1).await;
    let started = tokio::time::Instant::now();
    let mut next_report = Duration::from_secs(60);
    while started.elapsed() < Duration::from_secs(duration) {
        assert!(
            service.child.try_wait().unwrap().is_none(),
            "无节点时不得退出"
        );
        let mut connection = service.connect().await;
        assert!(negotiate(&mut connection, None).await);
        assert_ne!(request(&mut connection, 1, "fixture.example", 80).await, 0);
        if started.elapsed() >= next_report {
            eprintln!(
                "无节点等待进度：已运行{}秒，进程存活且请求被阻断",
                started.elapsed().as_secs()
            );
            next_report += Duration::from_secs(60);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let records = events(&service);
    assert!(!records.iter().any(|e| e["event_type"] == "active_promoted"));
    let starts: Vec<_> = records
        .iter()
        .filter(|e| e["event_type"] == "round_started")
        .collect();
    let finishes: Vec<_> = records
        .iter()
        .filter(|e| e["event_type"] == "round_finished")
        .collect();
    assert!(finishes.len() >= 2, "至少观测一次实际退避后重新检测");
    for (index, (finish, start)) in finishes.iter().zip(starts.iter().skip(1)).enumerate() {
        let finish =
            chrono::DateTime::parse_from_rfc3339(finish["timestamp"].as_str().unwrap()).unwrap();
        let start =
            chrono::DateTime::parse_from_rfc3339(start["timestamp"].as_str().unwrap()).unwrap();
        let expected = service
            .config
            .retry_initial_seconds
            .saturating_mul(2_u64.saturating_pow(index as u32))
            .min(service.config.retry_max_seconds);
        assert!(
            start.signed_duration_since(finish).num_milliseconds() >= expected as i64 * 1000 - 100,
            "恢复不得忙循环或绕过退避：第{}次，要求至少{}毫秒，实际{}毫秒，完成{}，下次开始{}",
            index + 1,
            expected * 1000,
            start.signed_duration_since(finish).num_milliseconds(),
            finish,
            start
        );
    }
    eprintln!(
        "无节点等待验收：持续{}秒，完成轮次{}，进程未退出、请求被阻断、退避符合配置",
        started.elapsed().as_secs(),
        finishes.len()
    );
    drop(service);
    observation.finish().await;
}

#[tokio::test]
#[ignore = "需要受控 Linux 活动检测总时限"]
async fn active_check_total_timeout_blocks_without_waiting_for_another_round() {
    let _state = FixtureStateGuard::set(json!({"delay":0}));
    let service = ServiceFixture::start_debug_with(false, 50, |c| {
        c.exit_check_urls = vec!["http://11.54.0.2/slow".parse().unwrap()];
        c.health_interval_seconds = 2;
        c.health_timeout_seconds = 1;
        c.exit_check_timeout_seconds = 1;
    });
    wait_event(&service, "active_promoted", 1).await;
    let started = tokio::time::Instant::now();
    let _slow = FixtureStateGuard::set(json!({"delay":20}));
    wait_event(&service, "active_blocked", 1).await;
    assert!(started.elapsed() < Duration::from_secs(5));
    let report = events(&service)
        .into_iter()
        .find(|e| e["event_type"] == "active_check_failed")
        .unwrap();
    let detail: Value = serde_json::from_str(report["reason"].as_str().unwrap()).unwrap();
    assert_eq!(detail["attempts"], 3);
    assert!(detail["elapsed_ms"].as_u64().unwrap() <= 1200);
    assert_eq!(detail["failure"], "出口检测总时限耗尽");
}

#[tokio::test]
#[ignore = "需要受控 Linux 健康检测与候选共存"]
async fn healthy_activity_keeps_existing_connection_and_does_not_rotate() {
    let _state = FixtureStateGuard::set(json!({}));
    let mut service = ServiceFixture::start_debug_with(false, 50, |c| {
        c.health_interval_seconds = 2;
        c.health_timeout_seconds = 1;
        c.candidate_interval_seconds = 1;
    });
    wait_event(&service, "active_promoted", 1).await;
    let old = active_record(&service);
    let mut echo = service.connect().await;
    assert!(negotiate(&mut echo, None).await);
    assert_eq!(request(&mut echo, 1, "fixture.example", 19090).await, 0);
    wait_event(&service, "active_check_succeeded", 2).await;
    echo.write_all(b"stable").await.unwrap();
    let mut reply = [0; 6];
    echo.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"stable");
    assert_eq!(active_record(&service)["worker_id"], old["worker_id"]);
    assert_eq!(
        events(&service)
            .iter()
            .filter(|e| e["event_type"] == "active_promoted")
            .count(),
        1
    );
    http(&mut service).await;
}

#[tokio::test]
#[ignore = "需要受控 Linux 来源刷新与节点退避独立调度"]
async fn identical_source_refresh_does_not_shorten_failed_node_recovery_backoff() {
    let _state = FixtureStateGuard::set(json!({"code":503,"source_count":1}));
    let service = ServiceFixture::start_debug_with(false, 50, |config| {
        config.source_refresh_seconds = 1;
        config.retry_initial_seconds = 4;
        config.retry_max_seconds = 4;
        config.exit_check_max_attempts = 1;
    });
    wait_event(&service, "round_finished", 1).await;
    let first = events(&service)
        .into_iter()
        .find(|event| event["event_type"] == "round_finished")
        .unwrap();
    wait_event(&service, "source_updated", 3).await;
    let current = events(&service);
    let next = current
        .iter()
        .filter(|event| event["event_type"] == "round_started")
        .nth(1);
    if let Some(next) = next {
        let finish =
            chrono::DateTime::parse_from_rfc3339(first["timestamp"].as_str().unwrap()).unwrap();
        let start =
            chrono::DateTime::parse_from_rfc3339(next["timestamp"].as_str().unwrap()).unwrap();
        assert!(
            start.signed_duration_since(finish).num_milliseconds() >= 3900,
            "相同来源刷新绕过节点退避：实际{}毫秒，要求至少3900毫秒",
            start.signed_duration_since(finish).num_milliseconds()
        );
    }
    wait_event(&service, "round_started", 2).await;
    let next = events(&service)
        .into_iter()
        .filter(|event| event["event_type"] == "round_started")
        .nth(1)
        .unwrap();
    let finish =
        chrono::DateTime::parse_from_rfc3339(first["timestamp"].as_str().unwrap()).unwrap();
    let start = chrono::DateTime::parse_from_rfc3339(next["timestamp"].as_str().unwrap()).unwrap();
    assert!(
        start.signed_duration_since(finish).num_milliseconds() >= 3900,
        "相同来源刷新绕过节点退避：实际{}毫秒，要求至少3900毫秒",
        start.signed_duration_since(finish).num_milliseconds()
    );
}
