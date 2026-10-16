use super::{
    candidates::{events, wait_event},
    support::*,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{io::AsyncWriteExt, net::UnixStream};
use vpngate_auto_proxy::cli::*;
fn command(service: &ServiceFixture, args: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vap"));
    command
        .args(args)
        .arg("--runtime-dir")
        .arg(&service.config.runtime_dir);
    command.output().unwrap()
}
async fn exited(service: &mut ServiceFixture) -> std::process::ExitStatus {
    for _ in 0..150 {
        if let Some(status) = service.child.try_wait().unwrap() {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("十五秒内未退出：{:?}", events(service));
}
#[tokio::test]
#[ignore = "需要受控 Linux 状态、认证、控制帧及停止验收"]
async fn status_is_sanitized_invalid_frames_are_rejected_and_stop_waits_for_cleanup() {
    let _state = FixtureStateGuard::set(json!({"source_count":5}));
    let mut service = ServiceFixture::start(true, 50);
    wait_event(&service, "active_promoted", 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let output = command(&service, &["status", "--json", "--check-ready"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    for key in [
        "schema_version",
        "instance_id",
        "state",
        "ready",
        "listen_address",
        "active_node",
        "last_exit_check",
        "source",
        "candidates",
        "connections",
        "last_switch_reason",
        "last_error",
    ] {
        assert!(status.get(key).is_some(), "状态缺少字段：{key}");
    }
    for secret in ["fixture-secret", "BEGIN PRIVATE", "profile", "credentials"] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    }
    for invalid in [
        json!({"schema_version":2,"command":"status"}),
        json!({"schema_version":1,"command":"execute"}),
        json!({"schema_version":1,"command":"status","path":"/etc/passwd"}),
    ] {
        let mut stream = UnixStream::connect(service.config.runtime_dir.join("control.sock"))
            .await
            .unwrap();
        write_control(&mut stream, &invalid).await.unwrap();
        assert!(matches!(
            read_control::<ControlResponse>(&mut stream).await.unwrap(),
            ControlResponse::Error { .. }
        ));
    }
    let mut stream = UnixStream::connect(service.config.runtime_dir.join("control.sock"))
        .await
        .unwrap();
    stream
        .write_u32(MAX_CONTROL_BYTES as u32 + 1)
        .await
        .unwrap();
    assert!(matches!(
        read_control::<ControlResponse>(&mut stream).await.unwrap(),
        ControlResponse::Error { .. }
    ));
    assert!(command(&service, &["status", "--json"]).status.success());
    let started = std::time::Instant::now();
    let output = command(&service, &["stop"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    assert!(!service.config.runtime_dir.exists());
    assert!(exited(&mut service).await.success());
    assert!(service.config.data_dir.join("nodes.json").exists());
    assert!(command(&service, &["stop"]).status.success());
}
#[tokio::test]
#[ignore = "需要受控 Linux 等待状态与信号清理"]
async fn waiting_status_is_successful_but_readiness_is_three_and_sigterm_cleans() {
    let _state = FixtureStateGuard::set(json!({"source_count":0}));
    let mut service = ServiceFixture::start(false, 50);
    wait_event(&service, "source_updated", 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        command(&service, &["status", "--json"]).status.code(),
        Some(0)
    );
    assert_eq!(
        command(&service, &["status", "--check-ready"])
            .status
            .code(),
        Some(3)
    );
    let before = events(&service)
        .iter()
        .filter(|e| e["event_type"] == "source_fetch")
        .count();
    command(&service, &["status", "--check-ready"]);
    assert_eq!(
        before,
        events(&service)
            .iter()
            .filter(|e| e["event_type"] == "source_fetch")
            .count()
    );
    vpngate_auto_proxy::netd::system::run_command(
        "kill",
        &["-TERM", &service.child.id().to_string()],
    )
    .await
    .unwrap();
    assert!(exited(&mut service).await.success());
    assert!(!service.config.runtime_dir.exists());
}
#[tokio::test]
#[ignore = "需要受控 Linux 端口冲突与失败清理"]
async fn occupied_port_fails_without_leaving_owned_runtime_files() {
    let _state = FixtureStateGuard::set(json!({}));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut service = ServiceFixture::start_with(false, 50, |c| {
        c.listen = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        }
    });
    assert_eq!(exited(&mut service).await.code(), Some(1));
    assert!(
        !service.config.runtime_dir.exists(),
        "启动失败须回收本次创建的运行目录"
    );
}

#[tokio::test]
#[ignore = "需要受控 Linux 异常终止后的归属恢复"]
async fn killed_parent_restarts_only_after_reclaiming_recorded_orphans() {
    let _state = FixtureStateGuard::set(json!({}));
    let mut first = ServiceFixture::start(false, 50);
    wait_event(&first, "round_finished", 1).await;
    let old: Value = serde_json::from_slice(
        &std::fs::read(first.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    eprintln!(
        "异常终止前实例：{}，记录工作进程数{}",
        old["instance_id"],
        old["workers"].as_array().unwrap().len()
    );
    vpngate_auto_proxy::netd::system::run_command(
        "kill",
        &["-KILL", &first.child.id().to_string()],
    )
    .await
    .unwrap();
    assert!(!exited(&mut first).await.success());
    let mut second = ServiceFixture::start_with(false, 50, |c| {
        c.runtime_dir = first.config.runtime_dir.clone();
        c.data_dir = first.config.data_dir.clone();
        c.listen = first.config.listen;
    });
    wait_event(&second, "active_promoted", 1).await;
    assert!(
        command(&second, &["status", "--json", "--check-ready"])
            .status
            .success()
    );
    let now: Value = serde_json::from_slice(
        &std::fs::read(second.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    assert_ne!(old["instance_id"], now["instance_id"]);
    for worker in old["workers"].as_array().unwrap() {
        assert!(
            !std::path::Path::new(&format!(
                "/run/netns/{}",
                worker["namespace"].as_str().unwrap()
            ))
            .exists()
        );
    }
    assert!(command(&second, &["stop"]).status.success());
    assert!(exited(&mut second).await.success());
}

#[tokio::test]
#[ignore = "需要受控 Linux 初始化部分失败与归属不明目录"]
async fn partial_initialization_rolls_back_owned_private_directory_and_preserves_unknown_files() {
    let _state = FixtureStateGuard::set(json!({}));
    let owned = || {
        std::fs::read_dir("/run")
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vap-private-")
            })
            .count()
    };
    let before = owned();
    let mut service = ServiceFixture::start_with(false, 50, |c| {
        std::fs::create_dir_all(c.runtime_dir.join("workers")).unwrap();
        std::fs::write(c.runtime_dir.join("workers/unknown"), "不明归属资料").unwrap();
    });
    assert_eq!(exited(&mut service).await.code(), Some(1));
    assert_eq!(before, owned());
    assert_eq!(
        std::fs::read_to_string(service.config.runtime_dir.join("workers/unknown")).unwrap(),
        "不明归属资料"
    );
}

#[tokio::test]
#[ignore = "需要受控 Linux 进程身份复用与未登记进程拒绝"]
async fn unrecorded_process_and_changed_start_identity_prevent_stale_cleanup() {
    let _state = FixtureStateGuard::set(json!({"source_protocols":["tcp"]}));
    let mut service = ServiceFixture::start(false, 50);
    wait_event(&service, "round_finished", 1).await;
    let mut manifest: vpngate_auto_proxy::netd::ResourceManifest = serde_json::from_slice(
        &std::fs::read(service.config.runtime_dir.join("resources.json")).unwrap(),
    )
    .unwrap();
    manifest.owner_pid = u32::MAX;
    manifest.owner_start = "1".into();
    let original = manifest.workers[0].process_start.clone();
    manifest.workers[0].process_start = "不同的启动身份".into();
    let error = vpngate_auto_proxy::netd::system::reclaim_stale_processes(
        &manifest,
        tokio::time::Instant::now() + Duration::from_secs(3),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("身份"));
    manifest.workers[0].process_start = original;
    let mut unknown = vpngate_auto_proxy::netd::system::SupervisedProcess::spawn(
        vpngate_auto_proxy::netd::system::restricted_command(
            Some(&manifest.workers[0].namespace),
            false,
            std::path::Path::new("/bin/sleep"),
        )
        .arg("60"),
    )
    .unwrap();
    let error = vpngate_auto_proxy::netd::system::reclaim_stale_processes(
        &manifest,
        tokio::time::Instant::now() + Duration::from_secs(3),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("未记录"), "{error}");
    assert!(unknown.is_running().unwrap());
    assert!(service.child.try_wait().unwrap().is_none());
    unknown
        .terminate(tokio::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    assert!(
        command(&service, &["status", "--check-ready"])
            .status
            .success()
    );
    assert!(command(&service, &["stop"]).status.success());
    assert!(exited(&mut service).await.success());
}

#[tokio::test]
#[ignore = "需要受控 Linux 缺少能力时的启动预检"]
async fn missing_network_capability_fails_before_waiting_for_nodes() {
    let _state = FixtureStateGuard::set(json!({"source_count":0}));
    let directory = tempfile::tempdir().unwrap();
    let config = vpngate_auto_proxy::config::AppConfig {
        data_dir: directory.path().join("data"),
        runtime_dir: directory.path().join("run"),
        source_url: "http://127.0.0.1:18080/".parse().unwrap(),
        ..Default::default()
    };
    let file = directory.path().join("config.json");
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let operation = tokio::process::Command::new("setpriv")
        .args([
            "--bounding-set=-net_admin",
            "--inh-caps=-net_admin",
            "--ambient-caps=-net_admin",
            env!("CARGO_BIN_EXE_vap"),
            "run",
            "--config",
        ])
        .arg(&file)
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(3), operation)
        .await
        .expect("缺少必要能力必须在预检阶段失败，不能继续等待节点")
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("NET_ADMIN"));
    assert!(!config.runtime_dir.exists());
}

#[tokio::test]
#[ignore = "需要受控 Linux 私有挂载空间模拟缺少系统工具"]
async fn missing_tool_is_reported_before_waiting_and_leaves_no_runtime() {
    require_linux();
    let directory = tempfile::tempdir().unwrap();
    let config = vpngate_auto_proxy::config::AppConfig {
        data_dir: directory.path().join("data"),
        runtime_dir: directory.path().join("run"),
        ..Default::default()
    };
    let file = directory.path().join("config.json");
    std::fs::write(&file, serde_json::to_vec(&config).unwrap()).unwrap();
    let tool = std::process::Command::new("sh")
        .args(["-c", "command -v openvpn"])
        .output()
        .unwrap();
    assert!(tool.status.success());
    let tool = String::from_utf8(tool.stdout).unwrap();
    let operation = tokio::process::Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            "sh",
            "-c",
            "mount --bind /dev/null \"$1\" && exec \"$2\" run --config \"$3\"",
            "sh",
            tool.trim(),
            env!("CARGO_BIN_EXE_vap"),
        ])
        .arg(&file)
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(3), operation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("缺少必要系统工具：openvpn"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!config.runtime_dir.exists());
    assert!(
        std::process::Command::new(tool.trim())
            .arg("--version")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[tokio::test]
#[ignore = "需要受控 Linux 在多个检测任务运行期间停止"]
async fn stop_cancels_concurrent_candidates_and_reaps_every_recorded_process() {
    let _state = FixtureStateGuard::set(json!({"delay":20}));
    let mut service = ServiceFixture::start_with(false, 50, |config| {
        config.exit_check_urls = vec!["http://11.54.0.2/slow".parse().unwrap()];
        config.exit_check_timeout_seconds = 30;
    });
    wait_event(&service, "tunnel_connected", 2).await;
    let mut recorded = None;
    for _ in 0..100 {
        if let Ok(bytes) = std::fs::read(service.config.runtime_dir.join("resources.json")) {
            let manifest: vpngate_auto_proxy::netd::ResourceManifest =
                serde_json::from_slice(&bytes).unwrap();
            if manifest.workers.len() == 2
                && manifest
                    .workers
                    .iter()
                    .all(|worker| worker.pid != 0 && !worker.processes.is_empty())
            {
                recorded = Some(manifest);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let manifest = recorded.expect("停止前两个候选工作进程必须均已启动");
    assert!(
        !events(&service)
            .iter()
            .any(|event| event["event_type"] == "round_finished")
    );
    assert!(command(&service, &["stop"]).status.success());
    assert!(exited(&mut service).await.success());
    assert!(!service.config.runtime_dir.exists());
    for worker in manifest.workers {
        assert!(!std::path::Path::new(&format!("/run/netns/{}", worker.namespace)).exists());
        for pid in std::iter::once(worker.pid)
            .chain(worker.processes.into_iter().map(|process| process.pid))
        {
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "停止后记录子进程仍存在：{pid}"
            );
        }
    }
}
