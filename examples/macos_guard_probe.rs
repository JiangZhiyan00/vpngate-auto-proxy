//! 仅向受控端点发送标记，供外部抓包核对；不判断完整后端安全性。
#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::{net::SocketAddrV4, time::Duration};
    use tokio::io::AsyncWriteExt;
    use vpngate_auto_proxy::platform::macos::InterfaceScope;

    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() == 5, "需要接口索引、受控目标 IPv4、端口和标记");
    let scope = InterfaceScope::new(args[1].parse()?)?;
    let address = SocketAddrV4::new(args[2].parse()?, args[3].parse()?);
    let marker = &args[4];
    anyhow::ensure!(
        !marker.is_empty()
            && marker.len() <= 100
            && marker
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "受控标记无效"
    );
    let mut connected = false;
    let tcp = tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = scope.connect_tcp(address).await?;
        connected = true;
        stream.write_all(format!("{marker}-tcp").as_bytes()).await
    })
    .await;
    let udp = tokio::time::timeout(Duration::from_secs(2), async {
        let socket = scope.bind_udp()?;
        socket.connect(address).await?;
        socket.send(format!("{marker}-udp").as_bytes()).await
    })
    .await;
    println!(
        "{}",
        serde_json::json!({"interface_index":scope.index(),"tcp_connected":connected,
            "tcp_written":matches!(tcp, Ok(Ok(()))),"udp_sent":matches!(udp, Ok(Ok(_)))})
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("此探针只能在苹果系统原生运行");
    std::process::exit(2);
}
