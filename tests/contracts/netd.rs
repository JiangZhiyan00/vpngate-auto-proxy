use tokio::{io::AsyncWriteExt, net::UnixStream};
use vpngate_auto_proxy::{
    domain::*,
    netd::{protocol::*, system::*},
};
#[tokio::test]
async fn bounded_protocol_round_trip_and_oversize_rejection() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move {
        write_frame(&mut sender, &NetdResponse::Pong).await.unwrap();
    });
    assert!(matches!(
        read_frame::<NetdResponse>(&mut receiver).await.unwrap(),
        NetdResponse::Pong
    ));
    task.await.unwrap();
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender.write_u32(MAX_FRAME_BYTES as u32 + 1).await.unwrap();
    assert!(read_frame::<NetdRequest>(&mut receiver).await.is_err());
    assert!(serde_json::from_str::<NetdRequest>(r#"{"command":"exec","program":"sh"}"#).is_err());
    assert!(serde_json::from_str::<NetdRequest>(r#"{"command":"ping","instance_id":"00000000-0000-0000-0000-000000000000","path":"/etc/passwd"}"#).is_err());
}

#[tokio::test]
async fn private_socket_requires_private_directory_and_rejects_replacement() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("netd.sock");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(bind_private_socket(&path).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    let _listener = bind_private_socket(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o660
    );
    assert!(bind_private_socket(&path).is_err());
}
#[test]
fn guards_pin_endpoint_protocol_user_and_interface_without_host_policy_changes() {
    let allocation = NetworkAllocation::new(uuid::Uuid::new_v4(), WorkerId::default(), 7);
    for transport in [Transport::Tcp, Transport::Udp] {
        let endpoint = Endpoint {
            ip: "8.8.8.8".parse().unwrap(),
            port: 1194,
            transport,
        };
        let worker = worker_guard_script(&allocation, &endpoint);
        let root = root_guard_script(&allocation, &endpoint, "eth0").unwrap();
        assert!(worker.contains("meta skuid 10002"));
        assert!(worker.contains(&format!("{transport} dport 1194")));
        assert!(worker.contains("meta nfproto ipv6 drop"));
        assert!(!root.contains("chain input"));
        assert!(!root.contains("chain output"));
        assert!(!root.contains("policy drop"));
        assert!(root.contains("10.231.7.2"));
        assert!(root_guard_script(&allocation, &endpoint, "eth0\"; drop").is_err());
    }
    assert!(route_overlaps_pool("10.0.0.0/8"));
    assert!(route_overlaps_pool("10.231.1.0/24"));
    assert!(!route_overlaps_pool("0.0.0.0/0"));
    assert!(!route_overlaps_pool("192.168.1.0/24"));
}
