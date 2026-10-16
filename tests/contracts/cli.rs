use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::Path,
    process::{Command, Output},
    thread,
    time::Duration,
};
fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vap"))
        .args(args)
        .env("PATH", "/不存在的工具目录")
        .output()
        .unwrap()
}
fn response(directory: &Path, value: Value) -> thread::JoinHandle<()> {
    response_with_cleanup(directory, value, false)
}
fn response_with_cleanup(directory: &Path, value: Value, cleanup: bool) -> thread::JoinHandle<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(directory.join("control.sock")).unwrap();
    std::fs::set_permissions(
        directory.join("control.sock"),
        std::fs::Permissions::from_mode(0o660),
    )
    .unwrap();
    let directory = directory.to_path_buf();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
        stream.read_exact(&mut bytes).unwrap();
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["schema_version"], 1);
        assert!(["status", "stop"].contains(&request["command"].as_str().unwrap()));
        let bytes = serde_json::to_vec(&value).unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
        if cleanup {
            thread::sleep(Duration::from_millis(250));
            std::fs::remove_dir_all(directory).unwrap();
        }
    })
}
fn snapshot(ready: bool) -> Value {
    json!({"schema_version":1,"instance_id":"00000000-0000-0000-0000-000000000001","state":if ready {"ready"}else{"waiting"},"ready":ready,"listen_address":"127.0.0.1:1080","timezone":"Asia/Shanghai","active_node":null,"last_exit_check":null,"source":{"fetched_at":null,"age_seconds":null,"expired":true,"last_error":null},"candidates":{"total":0,"available":0,"expired":0,"not_tested":0,"round_selected":0,"round_completed":0,"running":0,"next_scheduled_at":"2026-10-10T00:00:00Z"},"connections":{"current":0,"limit":50},"last_switch_reason":null,"last_error":null})
}

#[test]
fn help_and_version_require_no_tools_or_runtime_and_hide_internal_commands() {
    let help = invoke(&["--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("status") && help.contains("stop"));
    assert!(!help.contains("controller"));
    assert!(!help.contains("mac-deployment"));
    assert!(!help.contains("mac-validate"));
    assert!(invoke(&["--version"]).status.success());
    assert_eq!(
        invoke(&["run", "--config", "/不存在的配置文件"])
            .status
            .code(),
        Some(2)
    );
}
#[test]
fn missing_status_is_communication_failure_but_repeated_stop_is_successful() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing");
    let path = path.to_str().unwrap();
    assert_eq!(
        invoke(&["status", "--runtime-dir", path, "--json"])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        invoke(&["stop", "--runtime-dir", path]).status.code(),
        Some(0)
    );
}
#[test]
fn status_outputs_one_json_object_and_ready_code_does_not_issue_extra_checks() {
    for (ready, check) in [(false, false), (false, true), (true, true)] {
        let directory = tempfile::tempdir().unwrap();
        let status = snapshot(ready);
        let server = response(directory.path(), json!({"result":"status","status":status}));
        let mut args = vec![
            "status",
            "--runtime-dir",
            directory.path().to_str().unwrap(),
            "--json",
        ];
        if check {
            args.push("--check-ready");
        }
        let output = invoke(&args);
        server.join().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if check && !ready { 3 } else { 0 })
        );
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            status
        );
    }
}
#[test]
fn unknown_status_fields_do_not_echo_potential_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let mut status = snapshot(false);
    status["private_key"] = json!("不可输出的私密内容");
    let server = response(directory.path(), json!({"result":"status","status":status}));
    let output = invoke(&[
        "status",
        "--runtime-dir",
        directory.path().to_str().unwrap(),
        "--json",
    ]);
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("不可输出的私密内容"));
}
#[test]
fn stop_acknowledgement_waits_for_cleanup_and_reports_timeout_as_four() {
    for cleaned in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime");
        std::fs::create_dir(&path).unwrap();
        let server = response_with_cleanup(
            &path,
            json!({"result":"accepted","instance_id":"00000000-0000-0000-0000-000000000001","shutdown_timeout_seconds":1}),
            cleaned,
        );
        let started = std::time::Instant::now();
        let output = invoke(&["stop", "--runtime-dir", path.to_str().unwrap()]);
        server.join().unwrap();
        assert_eq!(output.status.code(), Some(if cleaned { 0 } else { 4 }));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

#[tokio::test]
async fn control_frame_size_and_read_timeout_are_bounded() {
    use tokio::{io::AsyncWriteExt, net::UnixStream};
    use vpngate_auto_proxy::cli::*;
    for size in [0, MAX_CONTROL_BYTES as u32 + 1] {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_u32(size).await.unwrap();
        assert!(read_control::<ControlRequest>(&mut receiver).await.is_err());
    }
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = br#"{"schema_version":1,"command":"status"}"#.to_vec();
        bytes.resize(MAX_CONTROL_BYTES, b' ');
        sender.write_u32(bytes.len() as u32).await.unwrap();
        sender.write_all(&bytes).await.unwrap();
    });
    assert!(matches!(
        read_control::<ControlRequest>(&mut receiver)
            .await
            .unwrap()
            .command,
        Operation::Status
    ));
    task.await.unwrap();
    let (_sender, mut receiver) = UnixStream::pair().unwrap();
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    assert!(read_control::<ControlRequest>(&mut receiver).await.is_err());
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(started.elapsed() <= Duration::from_millis(5010));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_deployment_cli_refuses_ordinary_user_before_installation_access() {
    assert!(!nix::unistd::geteuid().is_root());
    let result = invoke(&[
        "mac-deployment",
        "--dependency-manifest",
        "/missing/dependency",
        "--runtime-parent",
        "/missing/runtime",
        "--worker-uid",
        "0",
        "--worker-gid",
        "0",
    ]);
    assert!(!result.status.success());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["checks"], json!({}));
    assert_eq!(value["network_configuration_performed"], false);
    assert!(value["error"].as_str().unwrap().contains("需要管理员身份"));
}

#[cfg(target_os = "macos")]
#[test]
fn actual_deployment_identity_reports_real_user_and_refuses_inherited_environment() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let worker = directory.path().join("w");
    std::fs::create_dir(&worker).unwrap();
    std::os::unix::fs::chown(&worker, None, Some(nix::unistd::getgid().as_raw())).unwrap();
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o750)).unwrap();
    std::fs::write(worker.join("identity-check"), b"").unwrap();
    let authorization = uuid::Uuid::new_v4();
    let result = Command::new(env!("CARGO_BIN_EXE_vap"))
        .args([
            "mac-deployment-identity",
            "--authorization",
            &authorization.to_string(),
        ])
        .env_clear()
        .env("DEPLOYMENT_FIXTURE", "1")
        .current_dir(&worker)
        .output()
        .unwrap();
    assert!(result.status.success());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["authorization"], authorization.to_string());
    assert_eq!(value["uid"], nix::unistd::getuid().as_raw());
    assert_eq!(value["effective_uid"], nix::unistd::geteuid().as_raw());
    assert_eq!(value["gid"], nix::unistd::getgid().as_raw());
    assert_eq!(value["effective_gid"], nix::unistd::getegid().as_raw());
    assert_eq!(value["environment_empty"], false);
    assert_eq!(value["owned_marker_written"], false);
    assert!(
        std::fs::read(worker.join("identity-check"))
            .unwrap()
            .is_empty()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_native_validation_cli_refuses_ordinary_user_before_input_access() {
    assert!(!nix::unistd::geteuid().is_root());
    let result = invoke(&[
        "mac-validate",
        "--input",
        "/missing/input",
        "--sha256",
        "invalid",
        "--dependency-manifest",
        "/missing/dependency",
        "--runtime-parent",
        "/missing/runtime",
        "--worker-uid",
        "0",
        "--worker-gid",
        "0",
    ]);
    assert!(!result.status.success());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["checks"], json!({}));
    assert_eq!(value["native_generation_pipeline_validated"], false);
    assert_eq!(value["full_macos_backend_validated"], false);
    assert_eq!(value["stages"], json!([]));
    assert!(value["error"].as_str().unwrap().contains("需要管理员身份"));
}

#[cfg(target_os = "macos")]
#[test]
fn actual_macos_controller_rejects_empty_authorization_without_output() {
    let result = invoke(&[
        "mac-controller",
        "--authorization",
        "00000000-0000-0000-0000-000000000000",
    ]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn actual_macos_controller_rejects_invalid_inherited_channel() {
    let result = invoke(&[
        "mac-controller",
        "--authorization",
        &uuid::Uuid::new_v4().to_string(),
    ]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_run_requires_explicit_platform_deployment_config() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.json");
    std::fs::write(&config, r#"{"runtime_dir":"run","data_dir":"data"}"#).unwrap();
    let result = invoke(&["run", "--config", config.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("必须提供 macos 部署配置")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_run_uses_privileged_backend_before_reading_low_privilege_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.json");
    let document = serde_json::json!({
        "runtime_dir":"run",
        "data_dir":"data",
        "credentials_file":"missing-secret.json",
        "macos":{
            "dependency_manifest":"missing-dependency.json",
            "runtime_parent":"missing-generations",
            "worker_uid":nix::unistd::getuid().as_raw(),
            "worker_gid":nix::unistd::getgid().as_raw()
        }
    });
    std::fs::write(&config, serde_json::to_vec(&document).unwrap()).unwrap();
    let result = invoke(&["run", "--config", config.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("控制进程监督需要管理员身份"));
    assert!(!stderr.contains("missing-secret"));
}

#[test]
fn human_status_uses_instance_timezone_and_old_payload_defaults_to_shanghai() {
    for (zone, expected) in [
        (None, "2026-07-15T20:00:00+08:00"),
        (Some("America/New_York"), "2026-07-15T08:00:00-04:00"),
        (Some("Australia/Sydney"), "2026-07-15T22:00:00+10:00"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut value = snapshot(true);
        if let Some(zone) = zone {
            value["timezone"] = json!(zone);
        } else {
            value.as_object_mut().unwrap().remove("timezone");
        }
        value["last_exit_check"] = json!({"node_id":"a".repeat(64),
            "worker_id":"00000000-0000-0000-0000-000000000001", "finished_at":"2026-07-15T12:00:00Z",
            "success":true,"attempts":1,"elapsed_ms":1,"status":204,"failure":null});
        let server = response(directory.path(), json!({"result":"status", "status":value}));
        let output = invoke(&[
            "status",
            "--runtime-dir",
            directory.path().to_str().unwrap(),
        ]);
        server.join().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(expected));
    }
}

#[test]
fn public_operations_keep_required_paths() {
    for args in [&["run"][..], &["status"][..], &["stop"][..]] {
        let output = invoke(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn public_help_is_chinese_complete_and_has_no_filesystem_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    for args in [
        vec!["help"],
        vec!["--help"],
        vec!["help", "run"],
        vec!["run", "--help"],
        vec!["help", "status"],
        vec!["status", "--help"],
        vec!["help", "stop"],
        vec!["stop", "--help"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_vap"))
            .args(&args)
            .current_dir(directory.path())
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(0), "{args:?}");
        assert!(result.stderr.is_empty());
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(text.contains("用法：vap"));
        assert!(text.contains("帮助"));
        for hidden in [
            "controller",
            "worker",
            "namespace-setup",
            "container-config",
            "mac-program",
        ] {
            assert!(!text.contains(hidden));
        }
        if args.contains(&"run") {
            assert!(text.contains("--config") && text.contains("必填"));
        }
        if args.contains(&"status") {
            assert!(text.contains("--runtime-dir") && text.contains("--json"));
            assert!(text.contains("--check-ready") && text.contains("3"));
        }
    }
    let version = invoke(&["--version"]);
    let text = String::from_utf8(version.stdout).unwrap();
    assert!(
        text.starts_with("vap ")
            && text.contains(env!("CARGO_PKG_VERSION"))
            && text.contains("自动节点代理")
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn invalid_and_hidden_help_requests_are_chinese_parameter_errors() {
    for args in [
        vec![],
        vec!["unknown"],
        vec!["run"],
        vec!["status"],
        vec!["stop"],
        vec!["status", "--bad"],
        vec!["help", "unknown"],
        vec!["help", "controller"],
        vec!["help", "worker"],
        vec!["help", "namespace-setup"],
        vec!["help", "container-config"],
        vec!["help", "mac-program"],
        vec!["controller", "--help"],
        vec!["help", "run", "extra"],
    ] {
        let result = invoke(&args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(
            error.contains("参数错误") && error.contains("vap help"),
            "{args:?}: {error}"
        );
        assert!(!error.contains("Usage:") && !error.contains("error:"));
        assert!(!error.contains("vap help run/status/stop"));
    }
}

#[test]
fn no_operation_prints_chinese_usage_without_creating_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vap"))
        .current_dir(directory.path())
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("缺少必填参数或操作"));
    assert!(error.contains("用法：vap <操作> [参数]"));
    assert!(error.contains("vap help"));
    assert!(!error.contains("vap help run/status/stop"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn help_flags_after_option_terminator_are_not_help_requests() {
    let directory = tempfile::tempdir().unwrap();
    for args in [
        vec!["run", "--", "--help"],
        vec!["status", "--", "--help"],
        vec!["stop", "--", "-h"],
        vec!["--", "--help"],
        vec!["run", "--config", "/不存在的配置", "--", "--help"],
        vec!["run", "--unknown", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vap"))
            .args(&args)
            .current_dir(directory.path())
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("参数错误") && error.contains("vap help"));
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
