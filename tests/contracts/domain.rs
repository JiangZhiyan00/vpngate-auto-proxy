use vpngate_auto_proxy::domain::*;
#[test]
fn identity_includes_protocol_but_not_display_or_profile() {
    let mut endpoint = Endpoint {
        ip: "8.8.8.8".parse().unwrap(),
        port: 443,
        transport: Transport::Tcp,
    };
    let tcp = NodeId::from_endpoint(&endpoint);
    assert_eq!(tcp, NodeId::from_endpoint(&endpoint));
    endpoint.transport = Transport::Udp;
    assert_ne!(tcp, NodeId::from_endpoint(&endpoint));
    assert!(serde_json::from_str::<NodeId>("\"not-an-id\"").is_err());
}
#[test]
fn rejects_nonpublic_addresses() {
    for ip in [
        "0.0.0.0",
        "127.0.0.1",
        "10.1.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
    ] {
        assert!(!is_public_ipv4(ip.parse().unwrap()), "{ip}");
    }
    assert!(is_public_ipv4("1.1.1.1".parse().unwrap()));
    assert!(is_public_ipv4("192.2.1.1".parse().unwrap()));
    assert!(is_public_ipv4("192.0.3.1".parse().unwrap()));
}
#[test]
fn instance_lock_rejects_duplicate_owner() {
    let directory = tempfile::tempdir().unwrap();
    let lock = vpngate_auto_proxy::netd::InstanceLock::acquire(directory.path()).unwrap();
    assert!(vpngate_auto_proxy::netd::InstanceLock::acquire(directory.path()).is_err());
    drop(lock);
    assert!(vpngate_auto_proxy::netd::InstanceLock::acquire(directory.path()).is_ok());
}

#[test]
fn lifecycle_rejects_skipping_exit_validation() {
    assert!(!WorkerState::Allocated.permits(WorkerState::Active));
    assert!(!WorkerState::Connecting.permits(WorkerState::Active));
    assert!(WorkerState::Connecting.permits(WorkerState::Validating));
    assert!(WorkerState::Validating.permits(WorkerState::Active));
    assert!(WorkerState::Validating.permits(WorkerState::Completed));
    assert!(!WorkerState::Cleaned.permits(WorkerState::Active));
}

#[test]
fn availability_is_bound_to_layer_version_and_expiry() {
    let now = chrono::Utc::now();
    let endpoint = Endpoint {
        ip: "11.53.0.2".parse().unwrap(),
        port: 1194,
        transport: Transport::Tcp,
    };
    let mut node = VpnNode {
        id: NodeId::from_endpoint(&endpoint),
        endpoint,
        source_hostname: "display".into(),
        country: "ZZ".into(),
        profile: "private".into(),
        profile_digest: "a".repeat(64),
        source_fetched_at: now,
        present: true,
        last_attempt_at: None,
    };
    let mut result = CheckResult {
        node_id: node.id.clone(),
        profile_digest: node.profile_digest.clone(),
        layer: Layer::Exit,
        outcome: Outcome::Succeeded,
        started_at: now,
        finished_at: now,
        elapsed_ms: 1,
        attempts: 1,
        status: Some(204),
        expires_at: Some(now + chrono::Duration::minutes(15)),
        failure_reason: None,
    };
    assert!(result.is_usable_for(&node, now));
    result.layer = Layer::Tunnel;
    assert!(!result.is_usable_for(&node, now));
    result.layer = Layer::Exit;
    node.profile_digest = "b".repeat(64);
    assert!(!result.is_usable_for(&node, now));
    assert_eq!(
        result.current_outcome(now + chrono::Duration::minutes(15)),
        Outcome::Expired
    );
}
