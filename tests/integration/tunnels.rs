use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use vpngate_auto_proxy::{
    domain::*,
    netd::{InstanceLock, system::*, workers::WorkerManager},
    vpngate::*,
};
#[tokio::test]
#[ignore = "需要专用 Linux 受控 TCP/UDP 节点"]
async fn managed_tcp_udp_tunnels_validate_routes_and_release_every_owned_resource() {
    super::support::require_linux();
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let runtime = directory.path().join("run");
    let lock = Arc::new(InstanceLock::acquire(&runtime).unwrap());
    std::os::unix::fs::chown(&runtime, Some(0), Some(CONTROL_UID)).unwrap();
    let instance = uuid::Uuid::new_v4();
    let manager = WorkerManager::new(
        instance,
        &runtime,
        3,
        Duration::from_secs(30),
        Duration::from_secs(3),
        false,
        lock.clone(),
    )
    .unwrap()
    .with_executable(env!("CARGO_BIN_EXE_vap").into());
    let snapshot = fetch_snapshot(
        &"http://127.0.0.1:18080/".parse().unwrap(),
        Duration::from_secs(5),
        CsvLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(snapshot.nodes.len(), 2);
    for node in snapshot.nodes {
        let id = WorkerId::default();
        let result = manager.start_tunnel(id, &node, WorkerRole::Pending).await;
        if let Err(error) = &result {
            let _ = manager
                .stop_all(tokio::time::Instant::now() + Duration::from_secs(10))
                .await;
            panic!("受控隧道建立失败：{error:#}");
        }
        let slot = result.unwrap();
        {
            let mut worker = slot.worker.lock().await;
            assert_eq!(worker.record.state, WorkerState::Validating);
            assert!(worker.structurally_ready().await.unwrap());
            in_namespace(&worker.allocation, "ip", &["link", "set", "tun0", "down"])
                .await
                .unwrap();
            assert!(
                !worker.structurally_ready().await.unwrap(),
                "接口关闭必须立即判定结构故障"
            );
            in_namespace(&worker.allocation, "ip", &["link", "set", "tun0", "up"])
                .await
                .unwrap();
            install_tunnel_routes(&worker.allocation).await.unwrap();
            assert!(worker.structurally_ready().await.unwrap());
            assert_eq!(
                worker.port_result.outcome,
                if node.endpoint.transport == Transport::Tcp {
                    Outcome::Succeeded
                } else {
                    Outcome::NotApplicable
                }
            );
            let mut command = restricted_command(
                Some(&worker.allocation.namespace),
                false,
                std::path::Path::new("/usr/bin/curl"),
            );
            let output = command
                .args([
                    "--noproxy",
                    "*",
                    "--max-time",
                    "3",
                    "-sS",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "http://11.54.0.2/generate_204",
                ])
                .output()
                .await
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, b"204");
            worker
                .attach_socks(std::path::Path::new(env!("CARGO_BIN_EXE_vap")), 58)
                .unwrap();
        }
        let socket = slot.worker.lock().await.record.socket_path.clone();
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(socket.exists(), "工作进程套接字未建立");
        let report = vpngate_auto_proxy::probe::check_exit(
            &socket,
            &["http://fixture.example/generate_204".parse().unwrap()],
            3,
            Duration::from_secs(10),
        )
        .await;
        assert!(report.success, "真实工作空间出口检测失败：{report:?}");
        slot.worker.lock().await.promote().unwrap();
        manager
            .stop(id, tokio::time::Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(manager.get(id).await.is_none());
    }
    manager
        .stop_all(tokio::time::Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    assert!(lock.read_manifest().unwrap().unwrap().workers.is_empty());
    assert!(!std::path::Path::new(&format!("/run/vap-private-{}", instance.simple())).exists());
}
