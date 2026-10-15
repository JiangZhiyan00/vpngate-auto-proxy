//! 明确选定节点的正式调用链验证；不自动下载来源、不启动公共代理。
use super::{
    dependency,
    exit_probe::ExitProbeSettings,
    launcher,
    pool::{MacCandidatePool, MacPoolSettings, VerifiedCandidate},
    program,
    supervisor::WorkerCredentials,
};
use crate::{
    domain::{VpnNode, WorkerId},
    socks::ActiveWorker,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use url::Url;

pub struct NativeValidationRequest {
    pub input: PathBuf,
    pub sha256: String,
    pub dependency_manifest: PathBuf,
    pub runtime_parent: PathBuf,
    pub credentials: WorkerCredentials,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationInput {
    nodes: Vec<VpnNode>,
    check_urls: Vec<Url>,
    max_attempts: u32,
    check_budget_seconds: u64,
    startup_budget_seconds: u64,
    source_ttl_seconds: u64,
    verification_ttl_seconds: u64,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn load(path: &Path, expected: &str) -> io::Result<ValidationInput> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid("必须提供所选验证输入的小写摘要"));
    }
    let bytes = dependency::read_file(path, 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected {
        return Err(invalid("验证输入摘要不一致"));
    }
    let input: ValidationInput =
        serde_json::from_slice(&bytes).map_err(|_| invalid("验证输入字段或格式无效"))?;
    if !(1..=3).contains(&input.nodes.len())
        || input
            .nodes
            .iter()
            .map(|node| &node.id)
            .collect::<BTreeSet<_>>()
            .len()
            != input.nodes.len()
    {
        return Err(invalid("验证须明确选择一至三个不同节点"));
    }
    Ok(input)
}
fn settings(request: &NativeValidationRequest, input: &ValidationInput) -> MacPoolSettings {
    MacPoolSettings {
        parent: request.runtime_parent.clone(),
        instance_id: uuid::Uuid::new_v4(),
        dependency_manifest: request.dependency_manifest.clone(),
        credentials: request.credentials,
        startup_budget: Duration::from_secs(input.startup_budget_seconds),
        max_connections: 50,
        candidate_slots: 2,
        verification_ttl: Duration::from_secs(input.verification_ttl_seconds),
        source_ttl: Duration::from_secs(input.source_ttl_seconds),
        exit: ExitProbeSettings {
            urls: input.check_urls.clone(),
            max_attempts: input.max_attempts,
            budget: Duration::from_secs(input.check_budget_seconds),
        },
    }
}
fn inventory() -> io::Result<BTreeMap<String, u32>> {
    super::spawn::guarded(|| {
        nix::net::if_::if_nameindex()?
            .iter()
            .map(|item| {
                let name = item
                    .name()
                    .to_str()
                    .map_err(|_| io::Error::other("接口名称编码无效"))?;
                Ok((name.to_owned(), item.index()))
            })
            .collect()
    })
}
fn record(
    report: &mut Value,
    stage: &str,
    worker: WorkerId,
    generation: uuid::Uuid,
    probe: crate::probe::ProbeReport,
) {
    report["stages"]
        .as_array_mut()
        .expect("阶段数组已创建")
        .push(json!({"stage":stage,"worker":worker,"generation":generation,"probe":probe}));
}
async fn verified(
    pool: &MacCandidatePool,
    worker: WorkerId,
    stop: &CancellationToken,
    report: &mut Value,
    stage: &str,
) -> io::Result<VerifiedCandidate> {
    let generation = pool.generation(worker)?;
    let checked = pool.check(worker, stop.clone()).await?;
    record(report, stage, worker, generation, checked.report);
    checked
        .verified
        .ok_or_else(|| io::Error::other("实际出口检测失败"))
}
fn active_unchanged(pool: &MacCandidatePool, expected: &ActiveWorker) -> io::Result<()> {
    let actual = pool.subscribe().borrow().clone();
    if expected.cancel.is_cancelled()
        || !actual.is_some_and(|value| {
            value.worker_id == expected.worker_id
                && value.socket_path == expected.socket_path
                && !value.cancel.is_cancelled()
        })
    {
        return Err(io::Error::other("候选验证期间活动代际已失效或被替换"));
    }
    Ok(())
}
async fn drive(
    pool: &mut MacCandidatePool,
    input: &ValidationInput,
    stop: &CancellationToken,
    report: &mut Value,
) -> io::Result<()> {
    // 所有输入均在任何接口创建之前核对，不能启动活动隧道后才发现后续材料无效。
    for node in &input.nodes {
        pool.validate_node(node)
            .map_err(|_| invalid("所选节点配置、端点或来源时效无效"))?;
    }
    let active = pool.start_candidate(input.nodes[0].clone())?;
    pool.wait_ready(active).await?;
    let proof = verified(pool, active, stop, report, "活动出口验证").await?;
    pool.promote(proof, &input.nodes[0])?;
    let snapshot = pool
        .subscribe()
        .borrow()
        .clone()
        .ok_or_else(|| io::Error::other("活动提升未交付引用"))?;
    let mut candidates = Vec::new();
    for node in input.nodes.iter().skip(1) {
        active_unchanged(pool, &snapshot)?;
        let candidate = pool.start_candidate(node.clone())?;
        pool.wait_ready(candidate).await?;
        active_unchanged(pool, &snapshot)?;
        verified(pool, active, stop, report, "候选建立后活动出口复核").await?;
        verified(pool, candidate, stop, report, "候选出口验证").await?;
        candidates.push(candidate);
    }
    report["checks"]["all_selected_generations_verified"] = json!(true);
    report["maximum_simultaneous_generations"] = json!(pool.len());
    for candidate in candidates.into_iter().rev() {
        let retired = pool.retire(candidate).await?;
        if let Some(error) = retired.failure {
            return Err(io::Error::other(error));
        }
        active_unchanged(pool, &snapshot)?;
        verified(pool, active, stop, report, "候选退休后活动出口复核").await?;
    }
    report["checks"]["active_reference_preserved"] = json!(true);
    Ok(())
}
/// 外层等待取消后继续由同一任务完成所属回收；运行时须保持存活。
pub async fn check(request: NativeValidationRequest, parent_stop: CancellationToken) -> Value {
    let stop = parent_stop.child_token();
    let _guard = stop.clone().drop_guard();
    match tokio::spawn(exercise(request, stop)).await {
        Ok(report) => report,
        Err(_) => {
            json!({"case":"macos-native-pipeline","status":"failed","full_macos_backend_validated":false,"error":"原生验证任务异常，回收未确认"})
        }
    }
}
async fn exercise(request: NativeValidationRequest, stop: CancellationToken) -> Value {
    let mut report = json!({"case":"macos-native-pipeline","status":"failed","native_generation_pipeline_validated":false,
        "full_macos_backend_validated":false,"public_service_validated":false,"exit_identity_validated":false,
        "continuous_connection_validated":false,"fault_injection_performed":false,"checks":{},"stages":[],"cleanup_errors":[]});
    let preflight = (|| -> io::Result<ValidationInput> {
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "原生调用链验证需要管理员身份",
            ));
        }
        if stop.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "原生验证已取消"));
        }
        request.credentials.validate_account()?;
        let executable = program::verify_current()?;
        report["program"] = serde_json::to_value(program::inspect(&executable)?)?;
        launcher::preflight_dependency(&request.dependency_manifest)?;
        report["checks"]["protected_program_and_dependency_verified"] = json!(true);
        load(&request.input, &request.sha256)
    })();
    let input = match preflight {
        Ok(input) => input,
        Err(error) => {
            report["error"] = json!(error.to_string());
            return report;
        }
    };
    report["selected_nodes"] = json!(
        input
            .nodes
            .iter()
            .map(|node| json!({"id":node.id,"endpoint":node.endpoint}))
            .collect::<Vec<_>>()
    );
    report["input_sha256"] = json!(request.sha256);
    let mut pool = match MacCandidatePool::new(settings(&request, &input), &stop) {
        Ok(pool) => pool,
        Err(error) => {
            report["error"] = json!(error.to_string());
            return report;
        }
    };
    let before = match inventory() {
        Ok(before) => before,
        Err(error) => {
            report["error"] = json!(error.to_string());
            return report;
        }
    };
    let result = drive(&mut pool, &input, &stop, &mut report).await;
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    let cleaning = Instant::now();
    let cleanup = pool.shutdown().await;
    report["cleanup_seconds"] = json!(cleaning.elapsed().as_secs_f64());
    report["checks"]["owned_pool_cleaned"] = json!(cleanup.is_ok() && pool.is_empty());
    if let Err(error) = &cleanup {
        report["cleanup_errors"] = json!([error.to_string()]);
    }
    // 只读比较名称与索引；不删除未知接口，也不把此清单比较当作宿主路由或解析基线。
    let restored = match inventory() {
        Ok(after) => {
            report["new_interface_names_remaining"] = json!(
                after
                    .iter()
                    .filter(|(name, _)| !before.contains_key(*name))
                    .map(|(name, index)| json!({"name":name,"index":index}))
                    .collect::<Vec<_>>()
            );
            after == before
        }
        Err(error) => {
            report["inventory_error"] = json!(error.to_string());
            false
        }
    };
    report["checks"]["interface_inventory_restored"] = json!(restored);
    if result.is_ok() && cleanup.is_ok() && pool.is_empty() && restored {
        report["status"] = json!("passed");
        report["native_generation_pipeline_validated"] = json!(true);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> NativeValidationRequest {
        NativeValidationRequest {
            input: "/missing/input".into(),
            sha256: "0".repeat(64),
            dependency_manifest: "/missing/dependency".into(),
            runtime_parent: "/missing/runtime".into(),
            credentials: WorkerCredentials {
                uid: nix::unistd::getuid().as_raw(),
                gid: nix::unistd::getgid().as_raw(),
            },
        }
    }
    fn node(port: u16) -> VpnNode {
        let raw = format!(
            "client\ndev tun\nproto tcp\nremote 1.2.3.4 {port}\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        );
        let profile =
            crate::openvpn::sanitize_openvpn(raw.as_bytes(), "1.2.3.4".parse().unwrap()).unwrap();
        let endpoint = crate::domain::Endpoint {
            ip: *profile.remote().ip(),
            port,
            transport: profile.transport(),
        };
        VpnNode {
            id: crate::domain::NodeId::from_endpoint(&endpoint),
            endpoint,
            source_hostname: String::new(),
            country: String::new(),
            profile_digest: blake3::hash(profile.as_str().as_bytes())
                .to_hex()
                .to_string(),
            profile: profile.as_str().into(),
            source_fetched_at: chrono::Utc::now(),
            present: true,
            last_attempt_at: None,
        }
    }
    fn input() -> Value {
        json!({"nodes":[node(443)],"check_urls":["https://example.com/"],"max_attempts":1,
            "check_budget_seconds":1,"startup_budget_seconds":3,"source_ttl_seconds":300,"verification_ttl_seconds":30})
    }
    fn selected(value: &Value) -> io::Result<ValidationInput> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        let bytes = serde_json::to_vec(value).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        load(&path, &format!("{:x}", Sha256::digest(&bytes)))
    }
    #[test]
    fn explicit_digest_precedes_read_and_detects_changed_input() {
        assert_eq!(
            load(Path::new("/missing/input"), "bad")
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        std::fs::write(&path, serde_json::to_vec(&input()).unwrap()).unwrap();
        assert!(
            load(&path, &"0".repeat(64))
                .err()
                .unwrap()
                .to_string()
                .contains("摘要不一致")
        );
        assert!(selected(&input()).is_ok());
    }
    #[test]
    fn strict_selection_rejects_unknown_missing_duplicate_and_excess_nodes() {
        for case in 0..5 {
            let mut value = input();
            match case {
                0 => value["unknown"] = json!(true),
                1 => {
                    value.as_object_mut().unwrap().remove("check_urls");
                }
                2 => value["nodes"] = json!([]),
                3 => value["nodes"] = json!([node(443), node(443)]),
                _ => value["nodes"] = json!([node(443), node(444), node(445), node(446)]),
            }
            assert!(selected(&value).is_err());
        }
    }
    #[test]
    fn invalid_budgets_and_urls_fail_before_resources() {
        for (field, value) in [
            ("startup_budget_seconds", json!(121)),
            ("source_ttl_seconds", json!(0)),
            ("verification_ttl_seconds", json!(0)),
            ("max_attempts", json!(0)),
            ("check_urls", json!(["file:///tmp/check"])),
        ] {
            let mut data = input();
            data[field] = value;
            let data = selected(&data).unwrap();
            assert!(
                MacCandidatePool::new(settings(&request(), &data), &CancellationToken::new())
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn later_invalid_node_prevents_even_first_generation_start() {
        let mut value = input();
        let mut invalid = node(444);
        invalid.profile_digest = "0".repeat(64);
        value["nodes"] = json!([node(443), invalid]);
        let input = selected(&value).unwrap();
        let stop = CancellationToken::new();
        let mut pool = MacCandidatePool::new(settings(&request(), &input), &stop).unwrap();
        let mut report = json!({"stages":[]});
        assert!(drive(&mut pool, &input, &stop, &mut report).await.is_err());
        assert!(pool.is_empty());
        assert_eq!(report["stages"], json!([]));
        pool.shutdown().await.unwrap();
    }
    #[test]
    fn inventory_is_read_only_and_includes_loopback() {
        assert!(inventory().unwrap().contains_key("lo0"));
    }
}
