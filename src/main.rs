use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "自动节点代理",
    help_template = "{about}\n\n用法：{usage}\n\n{all-args}"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    ContainerConfig,
    /// 前台启动代理
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// 查询本地实例状态
    Status {
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        check_ready: bool,
    },
    /// 正常停止实例并等待资源回收
    Stop {
        #[arg(long)]
        runtime_dir: PathBuf,
    },
    #[command(hide = true)]
    NamespaceSetup,
    #[command(hide = true)]
    Controller,
    #[command(hide = true)]
    Worker {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        max_connections: usize,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacController {
        #[arg(long)]
        authorization: uuid::Uuid,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacProbe,
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacValidate {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        dependency_manifest: PathBuf,
        #[arg(long)]
        runtime_parent: PathBuf,
        #[arg(long)]
        worker_uid: u32,
        #[arg(long)]
        worker_gid: u32,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacDeploymentIdentity {
        #[arg(long)]
        authorization: uuid::Uuid,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacDeployment {
        #[arg(long)]
        dependency_manifest: PathBuf,
        #[arg(long)]
        runtime_parent: PathBuf,
        #[arg(long)]
        worker_uid: u32,
        #[arg(long)]
        worker_gid: u32,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacWorker {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        max_connections: usize,
        #[arg(long)]
        interface_index: u32,
        #[arg(long)]
        authorization: uuid::Uuid,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacProgram {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        install: bool,
        #[arg(long, requires = "install")]
        sha256: Option<String>,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacDependency {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        install: bool,
    },
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    MacTunnel {
        #[arg(long)]
        interface_notifications: bool,
        #[arg(long)]
        dependency_manifest: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        management: PathBuf,
        #[arg(long)]
        remote: std::net::SocketAddrV4,
        #[arg(long, value_parser = ["tcp", "udp"])]
        transport: String,
        #[arg(long)]
        interface_index: u32,
        #[arg(long)]
        authorization: uuid::Uuid,
    },
}
fn main() -> std::process::ExitCode {
    let arguments = Arguments::parse();
    if matches!(arguments.command, Command::ContainerConfig) {
        let result = vpngate_auto_proxy::config::AppConfig::container_from_environment(|name| {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(_) => anyhow::bail!("{name} 必须为有效 UTF-8"),
            }
        })
        .and_then(|config| Ok(serde_json::to_string(&config)?));
        return match result {
            Ok(config) => {
                println!("{config}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("容器配置无效：{error:#}");
                std::process::ExitCode::from(2)
            }
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacDeploymentIdentity { authorization } = arguments.command {
        return match vpngate_auto_proxy::platform::deployment::identity(authorization) {
            Ok(observed) => {
                println!(
                    "{}",
                    serde_json::to_string(&observed).expect("身份报告可序列化")
                );
                std::process::ExitCode::SUCCESS
            }
            Err(_) => std::process::ExitCode::FAILURE,
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacProgram {
        program,
        install,
        sha256,
    } = arguments.command
    {
        let result = if install {
            sha256
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "安装必须明确提供所选程序摘要",
                    )
                })
                .and_then(|hash| vpngate_auto_proxy::platform::program::install(&program, &hash))
                .map(|path| serde_json::json!({"program":path,"service_activated":false}))
        } else {
            vpngate_auto_proxy::platform::program::inspect(&program)
                .and_then(|summary| serde_json::to_value(summary).map_err(std::io::Error::other))
        };
        return match result {
            Ok(value) => {
                println!("{value}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("主程序材料处理失败：{error}");
                std::process::ExitCode::from(2)
            }
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacDependency { bundle, install } = arguments.command {
        let result: std::io::Result<serde_json::Value> = if install {
            vpngate_auto_proxy::platform::dependency::install(&bundle).map(
                |path| serde_json::json!({"dependency_manifest": path, "service_activated": false}),
            )
        } else {
            vpngate_auto_proxy::platform::dependency::inspect(&bundle)
                .and_then(|summary| serde_json::to_value(summary).map_err(std::io::Error::other))
        };
        return match result {
            Ok(value) => {
                println!("{value}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("苹果依赖材料处理失败：{error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacTunnel {
        interface_notifications,
        dependency_manifest,
        profile,
        management,
        remote,
        transport,
        interface_index,
        authorization,
    } = arguments.command
    {
        let Some(port) = std::num::NonZeroU16::new(remote.port()) else {
            eprintln!("隧道端口无效");
            return std::process::ExitCode::FAILURE;
        };
        // 此分支必须早于运行时、信号任务及其它线程的创建。
        let error = vpngate_auto_proxy::platform::launcher::execute(
            vpngate_auto_proxy::platform::launcher::TunnelLaunch {
                interface_notifications,
                dependency_manifest,
                profile,
                management,
                authorization,
                interface_index,
                endpoint: vpngate_auto_proxy::domain::Endpoint {
                    ip: *remote.ip(),
                    port: port.get(),
                    transport: if transport == "tcp" {
                        vpngate_auto_proxy::domain::Transport::Tcp
                    } else {
                        vpngate_auto_proxy::domain::Transport::Udp
                    },
                },
            },
        );
        eprintln!("苹果隧道启动失败：{error}");
        return std::process::ExitCode::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("异步运行时初始化失败");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(application(arguments))
}

async fn application(arguments: Arguments) -> std::process::ExitCode {
    #[cfg(target_os = "macos")]
    if let Command::MacValidate {
        input,
        sha256,
        dependency_manifest,
        runtime_parent,
        worker_uid,
        worker_gid,
    } = arguments.command
    {
        let stop = tokio_util::sync::CancellationToken::new();
        let checking = vpngate_auto_proxy::platform::native_validation::check(
            vpngate_auto_proxy::platform::native_validation::NativeValidationRequest {
                input,
                sha256,
                dependency_manifest,
                runtime_parent,
                credentials: vpngate_auto_proxy::platform::supervisor::WorkerCredentials {
                    uid: worker_uid,
                    gid: worker_gid,
                },
            },
            stop.clone(),
        );
        tokio::pin!(checking);
        let report = tokio::select! {
            report = &mut checking => report,
            _ = vpngate_auto_proxy::service::wait_signal() => { stop.cancel(); checking.await },
        };
        let passed = report["status"] == "passed";
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("原生报告可序列化")
        );
        return if passed {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacDeployment {
        dependency_manifest,
        runtime_parent,
        worker_uid,
        worker_gid,
    } = arguments.command
    {
        let stop = tokio_util::sync::CancellationToken::new();
        let checking = vpngate_auto_proxy::platform::deployment::check(
            vpngate_auto_proxy::platform::deployment::DeploymentRequest {
                dependency_manifest,
                runtime_parent,
                credentials: vpngate_auto_proxy::platform::supervisor::WorkerCredentials {
                    uid: worker_uid,
                    gid: worker_gid,
                },
            },
            stop.clone(),
        );
        tokio::pin!(checking);
        let report = tokio::select! {
            report = &mut checking => report,
            _ = tokio::signal::ctrl_c() => { stop.cancel(); checking.await },
        };
        let passed = report["status"] == "passed";
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("部署报告可序列化")
        );
        return if passed {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        };
    }
    let management = match &arguments.command {
        Command::Status {
            runtime_dir,
            json,
            check_ready,
        } => Some(vpngate_auto_proxy::cli::status(runtime_dir, *json, *check_ready).await),
        Command::Stop { runtime_dir } => Some(vpngate_auto_proxy::cli::stop(runtime_dir).await),
        _ => None,
    };
    if let Some(result) = management {
        return match result {
            Ok(code) => std::process::ExitCode::from(code),
            Err(error) => {
                eprintln!("{error}");
                std::process::ExitCode::from(error.code)
            }
        };
    }
    if matches!(arguments.command, Command::Controller) {
        return match vpngate_auto_proxy::service::controller().await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("控制进程失败：{error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacController { authorization } = arguments.command {
        return match vpngate_auto_proxy::platform::controller::entry(authorization).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(_) => std::process::ExitCode::FAILURE,
        };
    }
    #[cfg(target_os = "macos")]
    if matches!(arguments.command, Command::MacProbe) {
        return match vpngate_auto_proxy::platform::exit_probe::entry().await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(_) => std::process::ExitCode::FAILURE,
        };
    }
    if let Command::Worker {
        socket,
        max_connections,
    } = arguments.command
    {
        if max_connections == 0 || max_connections > tokio::sync::Semaphore::MAX_PERMITS {
            return std::process::ExitCode::FAILURE;
        }
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        tokio::spawn(async move {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("停止信号注册失败");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}};
            stop.cancel();
        });
        return match vpngate_auto_proxy::socks::run_worker(&socket, true, max_connections, cancel)
            .await
        {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(_) => std::process::ExitCode::FAILURE,
        };
    }
    #[cfg(target_os = "macos")]
    if let Command::MacWorker {
        socket,
        max_connections,
        interface_index,
        authorization,
    } = arguments.command
    {
        use std::{os::fd::AsFd, time::Duration};
        if max_connections == 0 || max_connections > tokio::sync::Semaphore::MAX_PERMITS {
            return std::process::ExitCode::FAILURE;
        }
        let outcome: anyhow::Result<()> = async {
            // 只有专属标准输入控制通道可以交接句柄；交接错误立即结束独立进程。
            let channel = std::os::unix::net::UnixStream::from(
                std::io::stdin().as_fd().try_clone_to_owned()?,
            );
            let descriptor = vpngate_auto_proxy::platform::custody::receive(
                &channel,
                authorization,
                interface_index,
                Duration::from_secs(3),
            )?;
            let custody = vpngate_auto_proxy::platform::custody::UtunCustody::verify(
                descriptor,
                interface_index,
            )?;
            let generation =
                vpngate_auto_proxy::platform::network::VerifiedNetworkGeneration::from_custody(
                    custody,
                );
            channel.set_nonblocking(true)?;
            let control = tokio::net::UnixStream::from_std(channel)?;
            let cancel = tokio_util::sync::CancellationToken::new();
            let stop = cancel.clone();
            tokio::spawn(async move {
                let _ = vpngate_auto_proxy::service::wait_signal().await;
                stop.cancel();
            });
            vpngate_auto_proxy::platform::worker::serve(
                &socket,
                generation,
                control,
                vpngate_auto_proxy::platform::worker::WorkerStartup {
                    authorization,
                    interface_index,
                    max_connections,
                },
                cancel,
            )
            .await?;
            Ok(())
        }
        .await;
        return match outcome {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("苹果工作进程失败：{error:#}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    if matches!(arguments.command, Command::NamespaceSetup) {
        return match vpngate_auto_proxy::netd::system::configure_namespace().await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("命名空间配置失败：{error:#}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    if let Command::Run { config } = arguments.command {
        #[cfg(target_os = "macos")]
        {
            let config = match vpngate_auto_proxy::config::AppConfig::load_config(&config) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("配置无效：{error}");
                    return std::process::ExitCode::from(2);
                }
            };
            let Some(macos) = config.macos.clone() else {
                eprintln!("配置无效：苹果原生运行必须提供 macos 部署配置");
                return std::process::ExitCode::from(2);
            };
            let stop = tokio_util::sync::CancellationToken::new();
            let running = vpngate_auto_proxy::platform::controller::supervise(
                vpngate_auto_proxy::platform::controller::MacControllerRequest {
                    config,
                    identity: vpngate_auto_proxy::platform::supervisor::WorkerCredentials {
                        uid: macos.worker_uid,
                        gid: macos.worker_gid,
                    },
                    runtime_parent: macos.runtime_parent,
                    dependency_manifest: macos.dependency_manifest,
                    instance_id: uuid::Uuid::new_v4(),
                },
                stop.clone(),
            );
            tokio::pin!(running);
            let result = tokio::select! {
                result = &mut running => result,
                _ = vpngate_auto_proxy::service::wait_signal() => {
                    stop.cancel();
                    running.await
                }
            };
            return match result {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("苹果实例运行失败：{error}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(target_os = "macos"))]
        {
            let (config, credentials) = match vpngate_auto_proxy::config::AppConfig::load(&config) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("配置无效：{error}");
                    return std::process::ExitCode::from(2);
                }
            };
            return match vpngate_auto_proxy::service::run(config, credentials).await {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("实例运行失败：{error}");
                    std::process::ExitCode::from(
                        if error.is::<vpngate_auto_proxy::service::ShutdownFailure>()
                            || error
                                .is::<vpngate_auto_proxy::netd::system::PreflightCleanupFailure>()
                        {
                            4
                        } else {
                            1
                        },
                    )
                }
            };
        }
    }
    std::process::ExitCode::FAILURE
}
