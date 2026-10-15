//! 受控实验工作进程；固定接口及端点，只接受继承管道上的有限命令。
#[cfg(target_os = "macos")]
mod experiment {
    use anyhow::{Context, ensure};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::{
        io::{BufRead, Read, Write},
        net::SocketAddrV4,
        os::{fd::AsFd, unix::net::UnixStream},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
        task::JoinSet,
    };
    use uuid::Uuid;
    use vpngate_auto_proxy::platform::{
        custody, generation::WorkerGeneration, macos::InterfaceScope,
    };

    #[derive(Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Command {
        Probe { generation: Uuid },
        Revoke { generation: Uuid },
    }
    fn emit(value: Value) -> anyhow::Result<()> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        serde_json::to_writer(&mut output, &value)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }
    pub async fn run() -> anyhow::Result<()> {
        let args: Vec<_> = std::env::args().collect();
        ensure!(
            args.len() == 5
                || (args.len() == 7
                    && matches!(args[5].as_str(), "--custody-stdin" | "--utun-custody-stdin")),
            "需要固定接口、目标 IPv4、端口与远端标记，可选私有启动授权"
        );
        let scope = InterfaceScope::new(args[1].parse()?)?;
        let address = SocketAddrV4::new(args[2].parse()?, args[3].parse()?);
        let identity = args[4].clone();
        ensure!(
            !identity.is_empty()
                && identity.len() <= 64
                && identity
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "远端标记无效"
        );
        let mut custody_interface = None;
        let generation = if args.len() == 7 {
            // 该实验由可信父进程将专属套接字对映射到标准输入。
            // 接收完成前不派生子进程；授权与索引只核对交接材料，不证明描述符是隧道。
            let channel = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
            let descriptor = custody::receive(
                &channel,
                args[6].parse()?,
                scope.index(),
                Duration::from_secs(3),
            )?;
            if args[5] == "--utun-custody-stdin" {
                let verified = custody::UtunCustody::verify(descriptor, scope.index())?;
                custody_interface = Some(verified.interface_name().to_owned());
                let (_, generation) = verified.into_generation();
                generation
            } else {
                // 仅供普通套接字生命周期测试；不得作为真实隧道启动入口。
                WorkerGeneration::with_custody(descriptor)
            }
        } else {
            WorkerGeneration::new()
        };
        let id = generation.lease().id();
        let (commands, mut input) = mpsc::channel::<anyhow::Result<Command>>(4);
        // 独立普通线程读取管道；避免异步标准输入的阻塞读取拖延运行时退出。
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(std::io::stdin());
            loop {
                let mut frame = Vec::new();
                let command = match (&mut reader).take(4097).read_until(b'\n', &mut frame) {
                    Ok(0) => return,
                    Ok(_) if frame.len() <= 4096 && frame.ends_with(b"\n") => {
                        serde_json::from_slice(&frame).context("工作命令无效")
                    }
                    Ok(_) => Err(anyhow::anyhow!("工作命令缺少结束符或超过上限")),
                    Err(error) => Err(error.into()),
                };
                let failed = command.is_err();
                if commands.blocking_send(command).is_err() || failed {
                    return;
                }
            }
        });
        let (events, mut results) = mpsc::channel::<Value>(4);
        let mut jobs = JoinSet::new();
        emit(
            json!({"event":"ready","generation":id,"interface_index":scope.index(),"custody_interface":custody_interface}),
        )?;
        let outcome: anyhow::Result<()> = async {
            loop {
                tokio::select! {
                    command = input.recv() => {
                        let Some(command) = command else { break; };
                        let command = command?;
                        let requested = match command { Command::Probe {generation} | Command::Revoke {generation} => generation };
                        if requested != id {
                            emit(json!({"event":"rejected","reason":"stale_generation","generation":id}))?;
                            continue;
                        }
                        match command {
                            Command::Revoke {..} => break,
                            Command::Probe {..} => {
                                ensure!(jobs.is_empty(), "只允许一个受控保留操作");
                                let lease = generation.lease();
                                let identity = identity.clone();
                                let events = events.clone();
                                jobs.spawn(async move {
                                    let verified_events = events.clone();
                                    let result = lease.execute(|| async move {
                                        let payload = Uuid::new_v4().to_string().into_bytes();
                                        let prefix = format!("{identity}:").into_bytes();
                                        let (tcp, udp) = tokio::time::timeout(Duration::from_secs(5), async {
                                            let mut tcp = scope.connect_tcp(address).await?;
                                            let mut actual = vec![0; prefix.len()];
                                            tcp.read_exact(&mut actual).await?;
                                            ensure!(actual == prefix, "流式远端身份不符");
                                            tcp.write_all(&payload).await?;
                                            let mut reply = vec![0; payload.len()];
                                            tcp.read_exact(&mut reply).await?;
                                            ensure!(reply == payload, "流式回显不符");
                                            let udp = scope.bind_udp()?;
                                            udp.connect(address).await?;
                                            udp.send(&payload).await?;
                                            let mut reply = [0; 256];
                                            let count = udp.recv(&mut reply).await?;
                                            ensure!(reply[..count] == [prefix, payload].concat(), "数据报身份或回显不符");
                                            anyhow::Ok((tcp, udp))
                                        }).await.map_err(std::io::Error::other)?
                                          .map_err(std::io::Error::other)?;
                                        verified_events.send(json!({"event":"verified","generation":id,"interface_index":scope.index(),"identity":identity,"tcp":true,"udp":true})).await.map_err(std::io::Error::other)?;
                                        // 两个套接字都由本登记操作拥有；撤销会丢弃整个异步体。
                                        let result = std::future::pending::<std::io::Result<()>>().await;
                                        drop((tcp, udp));
                                        result
                                    }).await;
                                    if let Err(error) = result
                                        && error.kind() != std::io::ErrorKind::Interrupted {
                                        let _ = events.send(json!({"event":"failed","error":error.to_string()})).await;
                                    }
                                });
                            }
                        }
                    }
                    value = results.recv() => {
                        let value = value.context("工作结果通道关闭")?;
                        let failed = value["event"] == "failed";
                        emit(value)?;
                        ensure!(!failed, "工作操作失败");
                    }
                }
            }
            Ok(())
        }.await;
        let retired = tokio::time::timeout(Duration::from_secs(3), generation.retire()).await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(result) = jobs.join_next().await {
                result?;
            }
            anyhow::Ok(())
        })
        .await??;
        outcome?;
        emit(json!({"event":"retired","generation":retired.id()}))?;
        Ok(())
    }
}
#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    experiment::run().await
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("此工作进程只用于苹果原生实验");
    std::process::exit(2);
}
