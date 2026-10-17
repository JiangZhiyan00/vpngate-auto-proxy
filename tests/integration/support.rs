pub fn require_linux() {
    assert!(cfg!(target_os = "linux"), "此用例必须在专用 Linux 环境运行");
    assert_eq!(
        std::env::var("VAP_NETWORK_TEST").as_deref(),
        Ok("1"),
        "须显式设置 VAP_NETWORK_TEST=1"
    );
}

/// 独立持续排空器：不持有业务控制句柄，单行与保留事件均有上限。
/// 时间由接收方单调时钟记录，测试不能用子进程的墙上时钟推算监听时机。
#[allow(dead_code)]
pub struct JsonLogCapture {
    pub events: std::sync::Arc<
        std::sync::Mutex<std::collections::VecDeque<(std::time::Instant, serde_json::Value)>>,
    >,
    task: tokio::task::JoinHandle<()>,
    stop: tokio_util::sync::CancellationToken,
}
#[allow(dead_code)]
impl JsonLogCapture {
    pub fn spawn(reader: impl tokio::io::AsyncRead + Unpin + Send + 'static) -> Self {
        use tokio::io::AsyncReadExt;
        let events = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let collected = events.clone();
        let stop = tokio_util::sync::CancellationToken::new();
        let cancelled = stop.clone();
        let task = tokio::spawn(async move {
            let mut reader = reader;
            let mut buffer = [0; 4096];
            let mut line = Vec::new();
            let mut oversized = false;
            loop {
                let size = tokio::select! {
                    () = cancelled.cancelled() => break,
                    result = reader.read(&mut buffer) => match result {
                        Ok(0) | Err(_) => break,
                        Ok(size) => size,
                    }
                };
                for byte in &buffer[..size] {
                    if *byte == b'\n' {
                        if !oversized && let Ok(event) = serde_json::from_slice(&line) {
                            let mut output = collected.lock().unwrap();
                            if output.len() == 1024 {
                                output.pop_front();
                            }
                            output.push_back((std::time::Instant::now(), event));
                        }
                        line.clear();
                        oversized = false;
                    } else if line.len() < 65536 && !oversized {
                        line.push(*byte);
                    } else {
                        oversized = true;
                        line.clear();
                    }
                }
            }
        });
        Self { events, task, stop }
    }

    pub async fn close(self) {
        self.stop.cancel();
        // 取消只影响读者；ServiceFixture 仍按原十五秒预算停止并回收子进程。
        while !self.task.is_finished() {
            tokio::task::yield_now().await;
        }
    }
}
impl Drop for JsonLogCapture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

pub struct ServiceFixture {
    pub child: std::process::Child,
    pub config: vpngate_auto_proxy::config::AppConfig,
    pub directory: tempfile::TempDir,
    #[allow(dead_code)] // 两个测试入口共用，启动故事读取该时刻。
    pub started: std::time::Instant,
}
impl ServiceFixture {
    pub fn start(auth: bool, max_connections: usize) -> Self {
        Self::start_with(auth, max_connections, |_| {})
    }
    #[allow(dead_code)]
    pub fn start_debug(auth: bool, max_connections: usize) -> Self {
        Self::start_debug_with(auth, max_connections, |_| {})
    }
    #[allow(dead_code)]
    pub fn start_debug_with(
        auth: bool,
        max_connections: usize,
        change: impl FnOnce(&mut vpngate_auto_proxy::config::AppConfig),
    ) -> Self {
        Self::start_with(auth, max_connections, |config| {
            config.log_level = vpngate_auto_proxy::logging::LogLevel::Debug;
            change(config);
        })
    }
    pub fn start_with(
        auth: bool,
        max_connections: usize,
        change: impl FnOnce(&mut vpngate_auto_proxy::config::AppConfig),
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        require_linux();
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut config = vpngate_auto_proxy::config::AppConfig {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            source_url: "http://127.0.0.1:18080/".parse().unwrap(),
            exit_check_urls: vec!["http://11.54.0.2/generate_204".parse().unwrap()],
            data_dir: directory.path().join("data"),
            runtime_dir: directory.path().join("run"),
            max_connections,
            ..Default::default()
        };
        if auth {
            let path = directory.path().join("credentials.json");
            std::fs::write(
                &path,
                br#"{"username":"tester","password":"fixture-secret"}"#,
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            config.credentials_file = Some(path);
        }
        change(&mut config);
        let path = directory.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let stderr = std::fs::File::create(directory.path().join("events.log")).unwrap();
        let started = std::time::Instant::now();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_vap"))
            .args(["run", "--config"])
            .arg(path)
            .stderr(stderr)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            config,
            directory,
            started,
        }
    }
    pub async fn connect(&mut self) -> tokio::net::TcpStream {
        for _ in 0..100 {
            if let Ok(stream) = tokio::net::TcpStream::connect(self.config.listen).await {
                return stream;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "服务提前退出：{}",
                std::fs::read_to_string(self.directory.path().join("events.log")).unwrap()
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("代理入口未启动")
    }
}
impl Drop for ServiceFixture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status();
            for _ in 0..150 {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub async fn request(
    stream: &mut tokio::net::TcpStream,
    command: u8,
    target: &str,
    port: u16,
) -> u8 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut frame = vec![5, command, 0];
    if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
        frame.push(1);
        frame.extend_from_slice(&ip.octets());
    } else {
        frame.extend_from_slice(&[3, target.len() as u8]);
        frame.extend_from_slice(target.as_bytes());
    }
    frame.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&frame).await.unwrap();
    let mut reply = [0; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(12),
        stream.read_exact(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    reply[1]
}
pub async fn negotiate(stream: &mut tokio::net::TcpStream, password: Option<&str>) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(&[5, 1, if password.is_some() { 2 } else { 0 }])
        .await
        .unwrap();
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.unwrap();
    if let Some(password) = password {
        if reply != [5, 2] {
            return false;
        }
        let mut frame = vec![1, 6];
        frame.extend_from_slice(b"tester");
        frame.push(password.len() as u8);
        frame.extend_from_slice(password.as_bytes());
        stream.write_all(&frame).await.unwrap();
        stream.read_exact(&mut reply).await.unwrap();
        reply == [1, 0]
    } else {
        reply == [5, 0]
    }
}

#[allow(dead_code)] // 契约入口与集成入口共用本文件。
pub struct FixtureStateGuard {
    path: std::path::PathBuf,
    previous: Option<Vec<u8>>,
}
impl FixtureStateGuard {
    #[allow(dead_code)]
    pub fn set(state: serde_json::Value) -> Self {
        require_linux();
        let directory = std::env::var_os("VAP_FIXTURE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/tmp/vap-fixture".into());
        let path = directory.join("state.json");
        let previous = std::fs::read(&path).ok();
        let temporary = directory.join("state.test-tmp");
        std::fs::write(&temporary, serde_json::to_vec(&state).unwrap()).unwrap();
        std::fs::rename(&temporary, &path).unwrap();
        Self { path, previous }
    }
}
impl Drop for FixtureStateGuard {
    fn drop(&mut self) {
        if let Some(bytes) = &self.previous {
            let _ = std::fs::write(&self.path, bytes);
        } else {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[tokio::test]
async fn bounded_capture_drains_oversized_lines_and_keeps_following_json() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, reader) = tokio::io::duplex(4096);
    let capture = JsonLogCapture::spawn(reader);
    let task = tokio::spawn(async move {
        writer.write_all(&vec![b'x'; 70000]).await.unwrap();
        writer
            .write_all(b"\n{\"event_type\":\"safe\"}\n")
            .await
            .unwrap();
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..100 {
        if !capture.events.lock().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(capture.events.lock().unwrap().len(), 1);
    assert_eq!(capture.events.lock().unwrap()[0].1["event_type"], "safe");
    capture.close().await;
}
