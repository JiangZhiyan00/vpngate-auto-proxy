//! 受保护安装及实际降权部署验证；不创建隧道、不配置网络、不启动公共代理。
use super::{
    launcher,
    process::Receipt,
    program,
    runtime::GenerationRuntime,
    spawn,
    supervisor::{WorkerCredentials, force_reap},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const DEADLINE: Duration = Duration::from_secs(3);
const REAP: Duration = Duration::from_secs(2);
pub(super) const MARKER: &[u8] = b"deployment-identity-verified\n";
pub struct DeploymentRequest {
    pub dependency_manifest: PathBuf,
    pub runtime_parent: PathBuf,
    pub credentials: WorkerCredentials,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityObservation {
    authorization: Uuid,
    uid: u32,
    effective_uid: u32,
    gid: u32,
    effective_gid: u32,
    groups: Vec<u32>,
    environment_empty: bool,
    directory: PathBuf,
    private_profile_denied: bool,
    owned_marker_written: bool,
}
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
/// 隐藏的低权限自检入口；只访问当前所属目录内固定文件，不接收外部文件路径。
pub fn identity(authorization: Uuid) -> io::Result<IdentityObservation> {
    use nix::unistd::{getegid, geteuid, getgid, getuid};
    if authorization.is_nil() || getuid().is_root() || geteuid().is_root() {
        return Err(denied("部署身份自检拒绝管理员身份或空授权"));
    }
    let directory = std::env::current_dir()?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir()
        || metadata.uid() != getuid().as_raw()
        || metadata.gid() != getgid().as_raw()
        || metadata.mode() & 0o777 != 0o750
    {
        return Err(denied("部署业务目录归属或权限不符"));
    }
    let groups = rustix::process::getgroups()?
        .into_iter()
        .map(|g| g.as_raw())
        .collect::<Vec<_>>();
    if groups.len() > 128 {
        return Err(denied("附属组清单超过上限"));
    }
    let mut observed = IdentityObservation {
        authorization,
        uid: getuid().as_raw(),
        effective_uid: geteuid().as_raw(),
        gid: getgid().as_raw(),
        effective_gid: getegid().as_raw(),
        groups,
        environment_empty: std::env::vars_os().next().is_none(),
        directory,
        private_profile_denied: false,
        owned_marker_written: false,
    };
    // 未满足降权及清空要求时只报告身份，不尝试访问验证材料。
    if observed.uid != observed.effective_uid
        || observed.gid != observed.effective_gid
        || observed.gid == 0
        || !no_extra_groups(&observed.groups, observed.gid)
        || !observed.environment_empty
    {
        return Ok(observed);
    }
    let profile = observed
        .directory
        .parent()
        .ok_or_else(|| denied("部署目录没有父目录"))?
        .join("t/profile.ovpn");
    observed.private_profile_denied =
        fs::File::open(profile).is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
    if !observed.private_profile_denied {
        return Ok(observed);
    }
    let mut marker = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(observed.directory.join("identity-check"))?;
    let metadata = marker.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != observed.uid
        || metadata.gid() != observed.gid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 0
    {
        return Err(denied("部署验证文件归属或权限不符"));
    }
    marker.write_all(MARKER)?;
    marker.sync_all()?;
    observed.owned_marker_written = true;
    Ok(observed)
}
pub(super) fn validate_observation(
    value: &IdentityObservation,
    authorization: Uuid,
    credentials: WorkerCredentials,
    directory: &Path,
) -> io::Result<()> {
    if credentials.uid == 0
        || credentials.gid == 0
        || value.authorization != authorization
        || authorization.is_nil()
        || value.uid != credentials.uid
        || value.effective_uid != credentials.uid
        || value.gid != credentials.gid
        || value.effective_gid != credentials.gid
        || !no_extra_groups(&value.groups, credentials.gid)
        || !value.environment_empty
        || value.directory != directory
        || !value.private_profile_denied
        || !value.owned_marker_written
    {
        return Err(denied(&format!(
            "实际降权身份、环境或私有目录检查不符：用户 {}/{}，组 {}/{}，组清单 {:?}，环境清空 {}，私有配置拒绝 {}，所属文件写入 {}",
            value.uid,
            value.effective_uid,
            value.gid,
            value.effective_gid,
            value.groups,
            value.environment_empty,
            value.private_profile_denied,
            value.owned_marker_written
        )));
    }
    Ok(())
}
fn no_extra_groups(groups: &[u32], gid: u32) -> bool {
    // 苹果 getgroups 包含有效主组；允许主组本身，拒绝所有额外组。
    groups.iter().all(|group| *group == gid)
}
async fn child_check(
    executable: &Path,
    directory: &Path,
    credentials: WorkerCredentials,
    stop: CancellationToken,
    receipt: Receipt,
) -> io::Result<IdentityObservation> {
    let authorization = Uuid::new_v4();
    if stop.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "部署验证已取消"));
    }
    let mut command = Command::new(executable);
    command
        .arg("mac-deployment-identity")
        .arg("--authorization")
        .arg(authorization.to_string())
        .env_clear()
        .current_dir(directory)
        .uid(credentials.uid)
        .gid(credentials.gid)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = spawn::guarded(|| command.spawn())?;
    receipt.spawned();
    let mut output = child.stdout.take().map(|output| output.take(8193));
    let outcome = tokio::select! {
        biased;
        _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "部署验证已取消")),
        result = tokio::time::timeout(DEADLINE, async {
            let mut bytes = Vec::new();
            output.as_mut().ok_or_else(|| io::Error::other("部署验证输出缺失"))?.read_to_end(&mut bytes).await?;
            if bytes.len() > 8192 { return Err(io::Error::other("部署验证输出超过上限")); }
            let observed: IdentityObservation = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            validate_observation(&observed, authorization, credentials, directory)?;
            if !child.wait().await?.success() { return Err(io::Error::other("部署验证子进程退出失败")); }
            Ok(observed)
        }) => result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "部署验证子进程超时"))),
    };
    drop(output);
    receipt.observe(&mut child);
    if !receipt.reaped() {
        let cleanup = force_reap(&mut child, REAP).await;
        receipt.observe(&mut child);
        if let Err(cleanup) = cleanup {
            return Err(io::Error::other(format!(
                "{}；部署验证回收：{cleanup}",
                outcome
                    .err()
                    .map_or_else(|| "子进程未结束".into(), |e| e.to_string())
            )));
        }
    }
    outcome
}
/// 调用方丢弃等待只触发取消；所有资源及回收未来继续由同一个任务持有。
pub async fn check(request: DeploymentRequest, parent_stop: CancellationToken) -> Value {
    let stop = parent_stop.child_token();
    let _guard = stop.clone().drop_guard();
    match tokio::spawn(exercise(request, stop)).await {
        Ok(report) => report,
        Err(_) => {
            json!({"case":"macos-deployment","status":"failed","full_macos_backend_validated":false,"error":"部署验证任务异常，回收未确认"})
        }
    }
}
async fn exercise(request: DeploymentRequest, stop: CancellationToken) -> Value {
    let mut report = json!({"case":"macos-deployment","status":"failed","full_macos_backend_validated":false,
        "native_tunnel_validated":false,"network_configuration_performed":false,"service_activated":false,"checks":{},"cleanup_errors":[]});
    let preflight = (|| -> io::Result<PathBuf> {
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            return Err(denied("部署验证需要管理员身份"));
        }
        if stop.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "部署验证已取消"));
        }
        request.credentials.validate_account()?;
        report["checks"]["worker_account_verified"] = json!(true);
        let executable = program::verify_current()?;
        report["checks"]["protected_program_verified"] = json!(true);
        report["program"] = json!(program::inspect(&executable)?);
        launcher::preflight_dependency(&request.dependency_manifest)?;
        report["checks"]["protected_dependency_verified"] = json!(true);
        Ok(executable)
    })();
    let executable = match preflight {
        Ok(path) => path,
        Err(error) => {
            report["error"] = json!(error.to_string());
            return report;
        }
    };
    let mut runtime = match GenerationRuntime::prepare(
        &request.runtime_parent,
        b"deployment-check-only\n",
        request.credentials,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            report["error"] = json!(error.to_string());
            return report;
        }
    };
    report["runtime"] = json!(runtime.root());
    let receipt = Receipt::default();
    let result = async {
        runtime.deployment_marker(request.credentials)?;
        let observed = child_check(
            &executable,
            &runtime.worker(),
            request.credentials,
            stop,
            receipt.clone(),
        )
        .await?;
        report["identity"] = serde_json::to_value(observed)?;
        if !runtime.deployment_marker_matches(MARKER)? {
            return Err(io::Error::other("部署验证文件写入复核失败"));
        }
        report["checks"]["actual_low_privilege_identity_and_private_access"] = json!(true);
        Ok::<(), io::Error>(())
    }
    .await;
    report["checks"]["child_reaped"] = json!(receipt.reaped());
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    let cleanup = if receipt.reaped() {
        runtime.cleanup()
    } else {
        Err(io::Error::other("直属消费者未确认回收，保留目录"))
    };
    report["checks"]["owned_directory_cleaned"] = json!(cleanup.is_ok());
    if let Err(error) = &cleanup {
        report["cleanup_errors"] = json!([error.to_string()]);
    }
    if result.is_ok() && cleanup.is_ok() {
        report["status"] = json!("passed");
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn credentials() -> WorkerCredentials {
        WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }
    fn observed(authorization: Uuid, directory: &Path) -> IdentityObservation {
        let credentials = credentials();
        IdentityObservation {
            authorization,
            uid: credentials.uid,
            effective_uid: credentials.uid,
            gid: credentials.gid,
            effective_gid: credentials.gid,
            groups: Vec::new(),
            environment_empty: true,
            directory: directory.into(),
            private_profile_denied: true,
            owned_marker_written: true,
        }
    }
    fn fixture(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("vd-")
            .tempdir_in("/private/tmp")
            .unwrap();
        let executable = dir.path().join("identity.py");
        fs::write(&executable, format!("#!/usr/bin/python3\nimport os, sys, json, time\nopen('pid','w').write(str(os.getpid()))\n{body}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        (dir, executable)
    }
    fn response() -> String {
        format!(
            "json.dumps(dict(authorization=sys.argv[-1],uid={},effective_uid={},gid={},effective_gid={},groups=[],environment_empty=True,directory=os.getcwd(),private_profile_denied=True,owned_marker_written=True))",
            credentials().uid,
            credentials().uid,
            credentials().gid,
            credentials().gid
        )
    }
    fn assert_reaped(directory: &Path) {
        if let Ok(pid) = fs::read_to_string(directory.join("pid")) {
            let output = std::process::Command::new("/bin/ps")
                .args(["-p", pid.trim(), "-o", "pid="])
                .output()
                .unwrap();
            assert!(output.stdout.is_empty(), "直属测试子进程仍在运行");
        }
    }
    #[test]
    fn observation_rejects_wrong_identity_groups_environment_and_permissions() {
        let authorization = Uuid::new_v4();
        let path = Path::new("/private/var/run/unused");
        for case in 0..10 {
            let mut value = observed(authorization, path);
            match case {
                0 => value.uid = 0,
                1 => value.effective_uid = 0,
                2 => value.gid = 0,
                3 => value.effective_gid = 0,
                4 => value.groups = vec![credentials().gid + 1],
                5 => value.environment_empty = false,
                6 => value.directory = "/wrong".into(),
                7 => value.authorization = Uuid::new_v4(),
                8 => value.private_profile_denied = false,
                _ => value.owned_marker_written = false,
            }
            assert!(validate_observation(&value, authorization, credentials(), path).is_err());
        }
        validate_observation(
            &observed(authorization, path),
            authorization,
            credentials(),
            path,
        )
        .unwrap();
        let mut primary_only = observed(authorization, path);
        primary_only.groups = vec![credentials().gid];
        validate_observation(&primary_only, authorization, credentials(), path).unwrap();
    }
    #[tokio::test]
    async fn ordinary_user_is_rejected_before_material_or_directory_access() {
        assert!(!nix::unistd::geteuid().is_root());
        let report = check(
            DeploymentRequest {
                dependency_manifest: "/missing/dependency".into(),
                runtime_parent: "/missing/runtime".into(),
                credentials: WorkerCredentials { uid: 0, gid: 0 },
            },
            CancellationToken::new(),
        )
        .await;
        assert_eq!(report["status"], "failed");
        assert!(report["error"].as_str().unwrap().contains("需要管理员身份"));
        assert_eq!(report["checks"], json!({}));
        assert_eq!(report["network_configuration_performed"], false);
    }
    #[tokio::test]
    async fn real_child_success_is_correlated_and_reaped() {
        let (dir, executable) = fixture(&format!("print({})", response()));
        let receipt = Receipt::default();
        child_check(
            &executable,
            dir.path(),
            credentials(),
            CancellationToken::new(),
            receipt.clone(),
        )
        .await
        .unwrap();
        assert!(receipt.reaped());
        assert_reaped(dir.path());
    }
    #[tokio::test]
    async fn invalid_oversized_failed_and_hanging_children_are_reaped() {
        for body in [
            "print('{}'); time.sleep(60)".to_string(),
            "print('x'*9000); time.sleep(60)".into(),
            format!("print({}); sys.exit(3)", response()),
            "time.sleep(60)".into(),
            format!("print({}); sys.stdout.flush(); time.sleep(60)", response()),
        ] {
            let (dir, executable) = fixture(&body);
            let receipt = Receipt::default();
            assert!(
                child_check(
                    &executable,
                    dir.path(),
                    credentials(),
                    CancellationToken::new(),
                    receipt.clone()
                )
                .await
                .is_err()
            );
            assert!(receipt.reaped());
            assert_reaped(dir.path());
        }
    }
    #[tokio::test]
    async fn cancellation_waits_for_actual_direct_child_reaping() {
        let (dir, executable) = fixture("time.sleep(60)");
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let path = dir.path().join("pid");
        let canceller = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !path.exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            cancel.cancel();
        });
        let receipt = Receipt::default();
        assert_eq!(
            child_check(
                &executable,
                dir.path(),
                credentials(),
                stop,
                receipt.clone()
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        canceller.await.unwrap();
        assert!(receipt.reaped());
        assert_reaped(dir.path());
    }
    #[test]
    fn owned_marker_is_bounded_and_replacements_are_preserved() {
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        runtime.deployment_marker(credentials()).unwrap();
        let path = runtime.worker().join("identity-check");
        assert!(!runtime.deployment_marker_matches(MARKER).unwrap());
        fs::write(&path, MARKER).unwrap();
        assert!(runtime.deployment_marker_matches(MARKER).unwrap());
        fs::write(&path, [MARKER, b"unexpected"].concat()).unwrap();
        assert!(!runtime.deployment_marker_matches(MARKER).unwrap());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(runtime.profile(), &path).unwrap();
        assert!(runtime.deployment_marker_matches(MARKER).is_err());
        assert!(runtime.cleanup().is_err());
        assert!(runtime.profile().exists());
        fs::remove_file(&path).unwrap();
        runtime.cleanup().unwrap();
    }
    #[test]
    fn marker_and_layout_are_cleaned_after_known_consumer_exit() {
        let (_parent, mut runtime) = GenerationRuntime::test_prepare();
        let root = runtime.root().to_path_buf();
        runtime.deployment_marker(credentials()).unwrap();
        runtime.cleanup().unwrap();
        assert!(!root.exists());
    }
}
