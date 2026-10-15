//! 仅识别专属夹具的固定响应，不是通用解析器或交付程序。
#[cfg(target_os = "macos")]
mod probe {
    use std::{net::SocketAddrV4, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vpngate_auto_proxy::platform::macos::InterfaceScope;

    fn query(name: &str) -> Vec<u8> {
        let mut query = rand::random::<u16>().to_be_bytes().to_vec();
        query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        query
    }

    fn expected(query: &[u8], truncated: bool) -> Vec<u8> {
        let mut result = query[..2].to_vec();
        result.extend_from_slice(&[
            if truncated { 0x83 } else { 0x81 },
            0x80,
            0,
            1,
            0,
            u8::from(!truncated),
            0,
            0,
            0,
            0,
        ]);
        result.extend_from_slice(&query[12..]);
        if !truncated {
            result.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 10, 231, 66, 1]);
        }
        result
    }

    async fn resolve(
        scope: InterfaceScope,
        server: SocketAddrV4,
        name: &str,
        truncated: bool,
    ) -> anyhow::Result<()> {
        let query = query(name);
        let udp = scope.bind_udp()?;
        udp.connect(server).await?;
        udp.send(&query).await?;
        let mut buffer = [0; 512];
        let count = udp.recv(&mut buffer).await?;
        anyhow::ensure!(
            buffer[..count] == expected(&query, truncated),
            "受控数据报解析响应的事务、远端名称、状态或地址不匹配"
        );
        if truncated {
            // 截断后仍使用同一固定接口，绝不调用系统解析或普通连接。
            let mut tcp = scope.connect_tcp(server).await?;
            tcp.write_u16(query.len() as u16).await?;
            tcp.write_all(&query).await?;
            let count = usize::from(tcp.read_u16().await?);
            anyhow::ensure!(count <= 512, "受控流式解析响应超限");
            let mut reply = vec![0; count];
            tcp.read_exact(&mut reply).await?;
            anyhow::ensure!(
                reply == expected(&query, false),
                "受控流式解析响应的事务、远端名称、状态或地址不匹配"
            );
        }
        Ok(())
    }

    pub async fn run() -> anyhow::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        anyhow::ensure!(args.len() == 5, "需要接口索引、解析器 IPv4、端口和远端标记");
        let scope = InterfaceScope::new(args[1].parse()?)?;
        let server = SocketAddrV4::new(args[2].parse()?, args[3].parse()?);
        let identity = &args[4];
        anyhow::ensure!(
            !identity.is_empty()
                && identity.len() <= 63
                && identity
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "受控解析远端标记无效"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            resolve(scope, server, &format!("{identity}.test"), false).await?;
            resolve(scope, server, &format!("truncated.{identity}.test"), true).await
        })
        .await??;
        println!(
            "{}",
            serde_json::json!({"dns_udp":true,"dns_tcp_fallback":true,
                "interface_index":scope.index(),"identity":identity,"resolved_ipv4":"10.231.66.1"})
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    probe::run().await
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("此探针只能在苹果系统原生运行");
    std::process::exit(2);
}
