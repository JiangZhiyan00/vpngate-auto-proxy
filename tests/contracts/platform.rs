#[cfg(target_os = "macos")]
mod macos {
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    use vpngate_auto_proxy::platform::macos::InterfaceScope;

    #[test]
    fn rejects_zero_and_nonexistent_interfaces() {
        assert!(InterfaceScope::new(0).is_err());
        let invalid = InterfaceScope::new(u32::MAX).unwrap();
        assert!(invalid.bind_udp().is_err());
    }

    #[tokio::test]
    async fn invalid_interface_never_falls_back_to_reachable_default() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let invalid = InterfaceScope::new(u32::MAX).unwrap();
        assert!(invalid.connect_tcp(address).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fixed_loopback_interface_supports_tcp_and_udp() {
        // 苹果系统的回环接口索引从系统路由工具读取，不依赖管理员权限。
        let output = std::process::Command::new("/sbin/ifconfig")
            .args(["-v", "lo0"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let words: Vec<_> = text.split_whitespace().collect();
        let index: u32 = words
            .windows(2)
            .find(|v| v[0] == "index")
            .expect("回环接口索引缺失")[1]
            .parse()
            .unwrap();
        let scope = InterfaceScope::new(index).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        });
        let mut client = scope.connect_tcp(address).await.unwrap();
        client.write_all(b"test").await.unwrap();
        let mut bytes = [0; 4];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"test");
        echo.await.unwrap();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = scope.bind_udp().unwrap();
        client
            .send_to(b"dns", server.local_addr().unwrap())
            .await
            .unwrap();
        let mut bytes = [0; 3];
        let (count, peer) =
            tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&bytes[..count], b"dns");
        server.send_to(b"ok", peer).await.unwrap();
        let count = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..count], b"ok");
        assert_eq!(scope.index(), index);
    }
}
