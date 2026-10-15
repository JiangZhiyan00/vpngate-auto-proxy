//! 仅用于受控原生实验；不是项目交付程序。
#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    use std::{net::SocketAddrV4, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vpngate_auto_proxy::platform::macos::InterfaceScope;

    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        (5..=8).contains(&args.len()),
        "需要接口索引、目标 IPv4、端口、随机标记，以及可选的远端标记、轮数和保留模式"
    );
    let scope = InterfaceScope::new(args[1].parse()?)?;
    let address = SocketAddrV4::new(args[2].parse()?, args[3].parse()?);
    let payload = args[4].as_bytes();
    anyhow::ensure!(!payload.is_empty() && payload.len() <= 128, "标记长度无效");
    let identity = args.get(5).map(String::as_str).unwrap_or("");
    anyhow::ensure!(
        identity.len() <= 64
            && identity
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "远端标记无效"
    );
    let rounds: usize = args.get(6).map(|s| s.parse()).transpose()?.unwrap_or(1);
    anyhow::ensure!((1..=600).contains(&rounds), "轮数必须在 1 到 600 之间");
    let retained = args.get(7).map(String::as_str);
    anyhow::ensure!(
        retained.is_none() || (retained == Some("retained") && rounds == 1),
        "保留模式必须使用单轮且参数有效"
    );
    let prefix = if identity.is_empty() {
        Vec::new()
    } else {
        format!("{identity}:").into_bytes()
    };
    let mut tcp =
        tokio::time::timeout(Duration::from_secs(5), scope.connect_tcp(address)).await??;
    if !prefix.is_empty() {
        let mut actual = vec![0; prefix.len()];
        tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut actual)).await??;
        anyhow::ensure!(actual == prefix, "流式远端标记不匹配");
    }
    let udp = scope.bind_udp()?;
    udp.connect(address).await?;
    for round in 1..=rounds {
        tokio::time::timeout(Duration::from_secs(5), async {
            tcp.write_all(payload).await?;
            let mut reply = vec![0; payload.len()];
            tcp.read_exact(&mut reply).await?;
            anyhow::ensure!(reply == payload, "流式回显不匹配");
            udp.send(payload).await?;
            let mut reply = [0; 256];
            let count = udp.recv(&mut reply).await?;
            let expected = [prefix.as_slice(), payload].concat();
            anyhow::ensure!(reply[..count] == expected, "数据报远端标记或回显不匹配");
            anyhow::Ok(())
        })
        .await??;
        println!(
            "{}",
            serde_json::json!({"tcp":true,"udp":true,"interface_index":scope.index(),"identity":identity,"round":round})
        );
        if round < rounds {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    if retained.is_some() {
        // 正向往返已全部读完；等待监督进程删除接口后，在原套接字上发送独立挑战。
        let mut command = [0; 1];
        tokio::time::timeout(
            Duration::from_secs(90),
            tokio::io::stdin().read_exact(&mut command),
        )
        .await??;
        anyhow::ensure!(command == [b'c'], "保留套接字探针收到未知指令");
        let challenge = [payload, b"-after-removal"].concat();
        let tcp_check = async {
            let mut written = false;
            let result = tokio::time::timeout(Duration::from_secs(2), async {
                tcp.write_all(&challenge).await?;
                written = true;
                let mut reply = [0; 256];
                let count = tcp.read(&mut reply).await?;
                Ok::<_, std::io::Error>(
                    (count > 0).then(|| format!("{:x}", Sha256::digest(&reply[..count]))),
                )
            })
            .await;
            (written, result.ok().and_then(Result::ok).flatten())
        };
        let udp_check = async {
            let mut sent = false;
            let result = tokio::time::timeout(Duration::from_secs(2), async {
                udp.send(&challenge).await?;
                sent = true;
                let mut reply = [0; 256];
                let count = udp.recv(&mut reply).await?;
                Ok::<_, std::io::Error>(format!("{:x}", Sha256::digest(&reply[..count])))
            })
            .await;
            (sent, result.ok().and_then(Result::ok))
        };
        let ((written, tcp_response), (sent, udp_response)) = tokio::join!(tcp_check, udp_check);
        println!(
            "{}",
            serde_json::json!({"interface_index":scope.index(),"identity":identity,
                "retained_tcp_write_succeeded":written,"retained_udp_send_succeeded":sent,
                "retained_tcp_response":tcp_response.is_some(),"retained_udp_response":udp_response.is_some(),
                "retained_tcp_response_sha256":tcp_response,"retained_udp_response_sha256":udp_response})
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("此探针只能在苹果系统原生运行");
    std::process::exit(2);
}
