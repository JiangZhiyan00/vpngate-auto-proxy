use vpngate_auto_proxy::{domain::*, netd::system::*};

#[tokio::test]
#[ignore = "需要专用 Linux 降权及进程组权限"]
async fn drops_control_capabilities_and_supervises_process_identity() {
    super::support::require_linux();
    let output = restricted_command(None, false, std::path::Path::new("/bin/cat"))
        .arg("/proc/self/status")
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let status = String::from_utf8(output.stdout).unwrap();
    assert!(status.contains("Uid:\t10001\t10001\t10001\t10001"));
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert!(
            status.contains(&format!("{key}:\t0000000000000000")),
            "{key}"
        );
    }
    assert!(status.contains("NoNewPrivs:\t1"));
    let mut process = SupervisedProcess::spawn(
        restricted_command(None, false, std::path::Path::new("/bin/sleep")).arg("60"),
    )
    .unwrap();
    assert!(process.is_running().unwrap());
    process
        .terminate(tokio::time::Instant::now() + std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert!(!process.is_running().unwrap());
    process
        .terminate(tokio::time::Instant::now() + std::time::Duration::from_secs(3))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "需要专用 Linux 资源归属验证环境"]
async fn refuses_unowned_namespaces_and_mismatched_owner_markers() {
    super::support::require_linux();
    let a = NetworkAllocation::new(uuid::Uuid::new_v4(), WorkerId::default(), 249);
    run_command("ip", &["netns", "add", &a.namespace])
        .await
        .unwrap();
    assert!(cleanup(&a).await.is_err());
    assert!(std::path::Path::new(&format!("/run/netns/{}", a.namespace)).exists());
    std::fs::write(a.marker_path(), "another-instance").unwrap();
    assert!(cleanup(&a).await.is_err());
    std::fs::remove_file(a.marker_path()).unwrap();
    run_command("ip", &["netns", "delete", &a.namespace])
        .await
        .unwrap();
    cleanup(&a).await.unwrap();
    let manifest = vpngate_auto_proxy::netd::ResourceManifest {
        schema_version: 1,
        instance_id: uuid::Uuid::new_v4(),
        owner_pid: std::process::id(),
        owner_start: "wrong-start-identity".into(),
        controller: None,
        workers: vec![],
    };
    assert!(vpngate_auto_proxy::netd::validate_manifest_identity(&manifest).is_err());
}

#[tokio::test]
#[ignore = "需要专用 Linux 网络权限；不能用本机单元测试替代"]
async fn creates_guarded_namespace_and_cleans_only_owned_resources() {
    super::support::require_linux();
    let original_routes = run_command("ip", &["-4", "route", "show"]).await.unwrap();
    let original_dns = std::fs::read("/etc/resolv.conf").unwrap();
    let original_forward = std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap();
    for transport in [Transport::Tcp, Transport::Udp] {
        let a = NetworkAllocation::new(uuid::Uuid::new_v4(), WorkerId::default(), 250);
        let endpoint = Endpoint {
            ip: "11.53.0.2".parse().unwrap(),
            port: 19090,
            transport,
        };
        // 测试进程路径由 Cargo 提供，独立调用程序完成命名空间设置。
        let binary = std::path::Path::new(env!("CARGO_BIN_EXE_vap"));
        let result = setup_with_binary(&a, &endpoint, "vfixture0", binary).await;
        if result.is_err() {
            let _ = cleanup(&a).await;
        }
        result.unwrap();
        let guard = String::from_utf8(
            in_namespace(&a, "nft", &["list", "table", "inet", "vap_guard"])
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(guard.contains("skuid 10002"));
        let probe = format!(
            "{}/tests/fixtures/probe_socket.py",
            env!("CARGO_MANIFEST_DIR")
        );
        let permitted = restricted_command(
            Some(&a.namespace),
            true,
            std::path::Path::new("/usr/bin/python3"),
        )
        .args([&probe, &transport.to_string(), "11.53.0.2", "19090"])
        .status()
        .await
        .unwrap();
        assert!(permitted.success(), "固定端点管理连接应成功");
        for (openvpn, protocol, port) in [
            (false, transport.to_string(), "19090"),
            (true, transport.to_string(), "19091"),
            (
                true,
                if transport == Transport::Tcp {
                    "udp"
                } else {
                    "tcp"
                }
                .to_owned(),
                "19090",
            ),
        ] {
            let rejected = restricted_command(
                Some(&a.namespace),
                openvpn,
                std::path::Path::new("/usr/bin/python3"),
            )
            .args([&probe, &protocol, "11.53.0.2", port])
            .status()
            .await
            .unwrap();
            assert!(
                !rejected.success(),
                "不允许的用户、端口或承载不得通过管理路径"
            );
        }
        let routes = in_namespace(&a, "ip", &["-4", "route", "show"])
            .await
            .unwrap();
        assert!(String::from_utf8(routes).unwrap().contains("11.53.0.2"));
        assert!(
            in_namespace(&a, "ip", &["route", "get", "8.8.8.8"])
                .await
                .is_err()
        );
        cleanup(&a).await.unwrap();
        assert!(!std::path::Path::new(&format!("/run/netns/{}", a.namespace)).exists());
    }
    assert_eq!(
        original_routes,
        run_command("ip", &["-4", "route", "show"]).await.unwrap()
    );
    assert_eq!(original_dns, std::fs::read("/etc/resolv.conf").unwrap());
    assert_eq!(
        original_forward,
        std::fs::read("/proc/sys/net/ipv4/ip_forward").unwrap()
    );
}
