use chrono::{Duration as TimeDelta, Utc};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use vpngate_auto_proxy::{domain::*, storage::*};

pub fn snapshot(count: usize) -> SourceSnapshot {
    let now = Utc::now();
    let nodes=(0..count).map(|index| {
  let endpoint=Endpoint {ip:"11.53.0.2".parse().unwrap(),port:u16::try_from(20000+index).unwrap(),transport:Transport::Tcp};
  let profile=format!("client\ndev tun\nproto tcp\nremote {} {}\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n",endpoint.ip,endpoint.port);
  let profile=vpngate_auto_proxy::openvpn::sanitize_openvpn(profile.as_bytes(),endpoint.ip).unwrap();
  VpnNode { quality: Default::default(),id:NodeId::from_endpoint(&endpoint),endpoint,source_hostname:"测试节点".into(),country:"ZZ".into(),profile:profile.as_str().into(),profile_digest:profile.digest().to_hex().to_string(),source_fetched_at:now,present:true,last_attempt_at:None}
 }).collect();
    SourceSnapshot {
        schema_version: 1,
        source_url: "http://fixture.example/".into(),
        fetched_at: now,
        nodes,
        stats: SourceStats {
            accepted: count,
            ..Default::default()
        },
    }
}
pub fn check(node: &VpnNode, layer: Layer) -> CheckResult {
    let now = Utc::now();
    CheckResult {
        node_id: node.id.clone(),
        profile_digest: node.profile_digest.clone(),
        layer,
        outcome: Outcome::Succeeded,
        started_at: now,
        finished_at: now,
        elapsed_ms: 1,
        attempts: 1,
        status: Some(204),
        expires_at: Some(now + TimeDelta::minutes(15)),
        failure_reason: None,
    }
}

#[test]
fn legacy_cache_cannot_be_loaded_after_opt_in_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let mut source = snapshot(1);
    let node = &mut source.nodes[0];
    let raw = format!(
        "client\ndev tun\nproto tcp\nremote {} {}\ncipher AES-128-CBC\ndata-ciphers AES-128-CBC\nauth SHA1\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n",
        node.endpoint.ip, node.endpoint.port
    );
    let profile = vpngate_auto_proxy::openvpn::sanitize_openvpn_with_policy(
        raw.as_bytes(),
        node.endpoint.ip,
        true,
    )
    .unwrap();
    node.profile = profile.as_str().into();
    node.profile_digest = profile.digest().to_hex().to_string();
    assert!(store.save_source(&source).is_err());
    store.save_source_with_policy(&source, true).unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_err()
    );
    assert!(
        store
            .load_source_with_policy(
                &source.source_url,
                Duration::from_secs(86400),
                Utc::now(),
                true
            )
            .is_ok()
    );
}
#[test]
fn source_round_trip_preserves_age_and_atomic_replacement_and_empty_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let mut source = snapshot(1);
    source.fetched_at -= TimeDelta::hours(2);
    source.nodes[0].source_fetched_at = source.fetched_at;
    store.save_source(&source).unwrap();
    let restored = store
        .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
        .unwrap();
    assert_eq!(restored.fetched_at, source.fetched_at);
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(1), Utc::now())
            .is_err()
    );
    assert!(
        store
            .load_source(
                "http://different.example/",
                Duration::from_secs(86400),
                Utc::now()
            )
            .is_err()
    );
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(dir.path().join("nodes.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let original = fs::read(dir.path().join("nodes.json")).unwrap();
    let mut invalid = source.clone();
    invalid.schema_version = 2;
    assert!(store.save_source(&invalid).is_err());
    assert_eq!(original, fs::read(dir.path().join("nodes.json")).unwrap());
    let old = fs::File::open(dir.path().join("nodes.json")).unwrap();
    store.save_source(&snapshot(0)).unwrap();
    let old: SourceSnapshot = serde_json::from_reader(old).unwrap();
    assert_eq!(old.nodes.len(), 1);
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .unwrap()
            .nodes
            .is_empty()
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
#[test]
fn cache_rejects_corruption_version_future_time_size_and_tampered_profile() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let original = snapshot(1);
    let path = dir.path().join("nodes.json");
    for mutate in [0, 1, 2, 3, 4] {
        let mut source = original.clone();
        match mutate {
            0 => source.schema_version = 2,
            1 => source.fetched_at += TimeDelta::days(1),
            2 => source.nodes[0].profile.push_str("up /tmp/script\n"),
            3 => source.nodes[0].id = snapshot(2).nodes[1].id.clone(),
            _ => {}
        }
        fs::write(
            &path,
            if mutate == 4 {
                b"broken".to_vec()
            } else {
                serde_json::to_vec(&source).unwrap()
            },
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            store
                .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
                .is_err()
        );
    }
    fs::File::create(&path)
        .unwrap()
        .set_len(MAX_SOURCE_BYTES + 1)
        .unwrap();
    assert!(
        store
            .load_source(&original.source_url, Duration::from_secs(86400), Utc::now())
            .is_err()
    );
}
#[test]
fn diagnostics_are_latest_bounded_and_pruned_without_affecting_source() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let source = snapshot(2100);
    store.save_source(&source).unwrap();
    let ids: Vec<_> = source.nodes.iter().map(|n| n.id.clone()).collect();
    let mut checks: Vec<_> = source.nodes.iter().map(|n| check(n, Layer::Exit)).collect();
    let mut latest = checks[0].clone();
    latest.finished_at += TimeDelta::minutes(1);
    latest.failure_reason = Some("失败说明".repeat(300));
    checks.push(latest.clone());
    store.save_checks(&checks, &ids, None).unwrap();
    let loaded = store.load_checks().unwrap();
    assert_eq!(loaded.len(), MAX_CHECKS);
    assert_eq!(loaded[0].finished_at, latest.finished_at);
    let reason = loaded[0].failure_reason.as_ref().unwrap();
    assert!(reason.len() <= 512);
    assert!(reason.len() > 500);
    assert!(fs::metadata(dir.path().join("checks.json")).unwrap().len() <= MAX_CHECK_BYTES);
    store
        .save_checks(&checks, &ids[1..2], Some(&ids[0]))
        .unwrap();
    assert_eq!(store.load_checks().unwrap().len(), 2);
    fs::File::create(dir.path().join("checks.json"))
        .unwrap()
        .set_len(MAX_CHECK_BYTES + 1)
        .unwrap();
    assert!(store.load_checks().is_err());
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_ok()
    );
    for bytes in [b"broken".as_slice(), br#"{"schema_version":2,"checks":[]}"#] {
        fs::write(dir.path().join("checks.json"), bytes).unwrap();
        assert!(store.load_checks().is_err());
    }
}
#[test]
fn exact_byte_limits_are_accepted_but_one_more_byte_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let source = snapshot(0);
    store.save_source(&source).unwrap();
    let path = dir.path().join("nodes.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.resize(MAX_SOURCE_BYTES as usize, b' ');
    fs::write(&path, &bytes).unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_ok()
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_SOURCE_BYTES + 1)
        .unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_err()
    );
    store.save_checks(&[], &[], None).unwrap();
    let path = dir.path().join("checks.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.resize(MAX_CHECK_BYTES as usize, b' ');
    fs::write(&path, &bytes).unwrap();
    assert!(store.load_checks().unwrap().is_empty());
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_CHECK_BYTES + 1)
        .unwrap();
    assert!(store.load_checks().is_err());
}
#[test]
fn diagnostic_ties_have_stable_order_and_insecure_cache_paths_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let source = snapshot(3);
    let now = Utc::now();
    let ids: Vec<_> = source.nodes.iter().map(|n| n.id.clone()).collect();
    let mut checks = Vec::new();
    for node in &source.nodes {
        for layer in [Layer::Exit, Layer::Tunnel, Layer::Port] {
            let mut c = check(node, layer);
            c.started_at = now;
            c.finished_at = now;
            checks.push(c);
        }
    }
    store.save_checks(&checks, &ids, None).unwrap();
    let restored = store.load_checks().unwrap();
    assert!(
        restored
            .windows(2)
            .all(|pair| (&pair[0].node_id, pair[0].layer) < (&pair[1].node_id, pair[1].layer))
    );
    store.save_source(&source).unwrap();
    let path = dir.path().join("nodes.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_err()
    );
    let target = dir.path().join("original.json");
    fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_err()
    );
}

#[test]
fn region_changes_filter_full_cache_and_refresh_before_scheduling() {
    use vpngate_auto_proxy::{
        config::AppConfig,
        scheduler::{Catalog, Scheduler},
    };
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(dir.path()).unwrap();
    let mut source = snapshot(3);
    for (node, country) in source.nodes.iter_mut().zip(["JP", "SG", "US"]) {
        node.country = country.into();
    }
    store.save_source(&source).unwrap();
    let cached = store
        .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
        .unwrap();
    let mut config = AppConfig {
        countries: vec!["jp".into(), "SG".into()],
        ..Default::default()
    };
    let mut catalog = Catalog::default();
    catalog.merge(&config.selected_source(&cached), None);
    assert_eq!(catalog.nodes.len(), 2);
    let mut scheduler = Scheduler::new(20, 3);
    assert!(scheduler.begin(&catalog, None));
    while let Some(node) = scheduler.next(&mut catalog, Utc::now()) {
        assert!(config.accepts_country(&node.country));
        scheduler.finish(&node.id);
    }
    config.countries = vec!["US".into()];
    catalog.merge(&config.selected_source(&cached), None);
    assert_eq!(catalog.nodes.len(), 1);
    assert_eq!(catalog.nodes.values().next().unwrap().country, "US");
    config.countries = vec!["AU".into()];
    catalog.merge(&config.selected_source(&cached), None);
    assert!(catalog.nodes.is_empty());
    assert!(
        config
            .source_empty_reason(&cached)
            .unwrap()
            .contains("国家/地区筛选")
    );
    assert_eq!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .unwrap()
            .nodes
            .len(),
        3
    );
}

#[test]
fn quality_upgrade_accepts_old_cache_and_normalizes_only_metric_values() {
    let directory = tempfile::tempdir().unwrap();
    let store = Storage::new(directory.path()).unwrap();
    let source = snapshot(1);
    store.save_source(&source).unwrap();
    let path = directory.path().join("nodes.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["nodes"][0].as_object_mut().unwrap().remove("quality");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_ok()
    );
    value["nodes"][0]["quality"] = serde_json::json!({"score": "bad", "uptime_ms": 86400000});
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let restored = store
        .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
        .unwrap();
    let normalized = serde_json::to_value(&restored.nodes[0]).unwrap();
    assert!(normalized["quality"]["score"].is_null());
    assert_eq!(normalized["quality"]["uptime_ms"], 86400000);
    value["nodes"][0]["quality"]["unexpected"] = serde_json::json!(1);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        store
            .load_source(&source.source_url, Duration::from_secs(86400), Utc::now())
            .is_err()
    );
}
