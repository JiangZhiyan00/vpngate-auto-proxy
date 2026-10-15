use std::{cell::RefCell, rc::Rc, time::Duration};
use url::Url;
use vpngate_auto_proxy::probe::*;

#[cfg(target_os = "macos")]
#[tokio::test]
async fn actual_hidden_macos_probe_uses_the_private_worker_and_correlates_result() {
    use std::{
        os::{fd::OwnedFd, unix::fs::PermissionsExt},
        process::Stdio,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
        process::Command,
    };
    let (directory, path, worker) = mock_worker().await;
    std::os::unix::fs::chown(directory.path(), None, Some(nix::unistd::getgid().as_raw())).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    std::os::unix::fs::chown(&path, None, Some(nix::unistd::getgid().as_raw())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (parent, control) = std::os::unix::net::UnixStream::pair().unwrap();
    let authorization = uuid::Uuid::new_v4();
    let generation = uuid::Uuid::new_v4();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vpngate-auto-proxy"))
        .arg("mac-probe")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::from(OwnedFd::from(control)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    parent.set_nonblocking(true).unwrap();
    let mut parent = UnixStream::from_std(parent).unwrap();
    let input = serde_json::to_vec(&serde_json::json!({
        "version":1,"authorization":authorization,"generation":generation,"socket":path,
        "urls":["http://11.54.0.2/empty"],"max_attempts":1,"budget_ms":1000
    }))
    .unwrap();
    parent.write_u32(input.len() as u32).await.unwrap();
    parent.write_all(&input).await.unwrap();
    let output = tokio::time::timeout(Duration::from_secs(3), async {
        let length = parent.read_u32().await.unwrap() as usize;
        assert!((1..=65536).contains(&length));
        let mut output = vec![0; length];
        parent.read_exact(&mut output).await.unwrap();
        output
    })
    .await
    .unwrap();
    let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(output["authorization"], authorization.to_string());
    assert_eq!(output["generation"], generation.to_string());
    assert_eq!(output["report"]["success"], true);
    assert_eq!(output["report"]["status"], 204);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    worker.abort();
    let _ = worker.await;
}

fn urls() -> Vec<Url> {
    ["http://example.com/", "https://example.net/generate_204"]
        .into_iter()
        .map(|v| Url::parse(v).unwrap())
        .collect()
}

async fn mock_worker() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    tokio::task::JoinHandle<()>,
) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("worker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 4];
                stream.read_exact(&mut header).await.unwrap();
                match header[3] {
                    1 => {
                        let mut target = [0; 6];
                        stream.read_exact(&mut target).await.unwrap();
                    }
                    3 => {
                        let length = stream.read_u8().await.unwrap();
                        let mut target = vec![0; length as usize + 2];
                        stream.read_exact(&mut target).await.unwrap();
                    }
                    _ => panic!("不支持的测试地址族"),
                }
                stream
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                    let Ok(byte) = stream.read_u8().await else {
                        return;
                    };
                    request.push(byte);
                }
                let request = String::from_utf8_lossy(&request);
                let path = request.split_whitespace().nth(1).unwrap_or("/");
                let response = match path {
                    "/redirect" => {
                        "HTTP/1.1 302 Found\r\nLocation: http://11.54.0.2/empty\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    }
                    "/loop" => {
                        "HTTP/1.1 302 Found\r\nLocation: http://11.54.0.2/loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    }
                    "/empty" => "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                    "/body-never" => {
                        "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\n"
                    }
                    _ => {
                        "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    }
                };
                let _ = stream.write_all(response.as_bytes()).await;
                if path == "/body-never" {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });
        }
    });
    (directory, path, task)
}

#[tokio::test]
async fn real_bridge_follows_redirects_and_stops_at_headers_without_reading_body() {
    let (_directory, path, worker) = mock_worker().await;
    for endpoint in ["redirect", "empty", "body-never"] {
        let address = Url::parse(&format!("http://11.54.0.2/{endpoint}")).unwrap();
        let report = tokio::time::timeout(
            Duration::from_secs(1),
            check_exit(&path, &[address], 1, Duration::from_secs(1)),
        )
        .await
        .unwrap();
        assert!(report.success, "{endpoint}：{report:?}");
    }
    worker.abort();
}

#[tokio::test]
async fn real_bridge_rejects_more_than_five_redirects_and_invalid_tls() {
    let (_directory, path, worker) = mock_worker().await;
    for address in ["http://11.54.0.2/loop", "https://11.54.0.2/empty"] {
        let report = check_exit(
            &path,
            &[address.parse().unwrap()],
            1,
            Duration::from_millis(500),
        )
        .await;
        assert!(!report.success);
        assert_eq!(report.attempts, 1);
        assert_ne!(report.failure, Some(ProbeFailure::NotImplemented));
    }
    worker.abort();
}
#[tokio::test]
async fn arbitrary_final_2xx_including_empty_204_stops_immediately() {
    for code in [200, 201, 204, 299] {
        let result = run_checks(
            &urls(),
            3,
            Duration::from_secs(10),
            |_| 0,
            |_, _| async move { Ok(code) },
        )
        .await;
        assert!(result.success);
        assert_eq!(result.attempts, 1);
        assert_eq!(result.status, Some(code));
    }
}
#[tokio::test]
async fn independent_choices_can_repeat_and_success_stops_later_attempts() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let mut choices = [1, 1, 0].into_iter();
    let mut statuses = [503, 500, 200].into_iter();
    let captured = seen.clone();
    let result = run_checks(
        &urls(),
        5,
        Duration::from_secs(10),
        |_| choices.next().unwrap(),
        move |url, _| {
            captured.borrow_mut().push(url);
            let code = statuses.next().unwrap();
            async move { Ok(code) }
        },
    )
    .await;
    assert!(result.success);
    assert_eq!(result.attempts, 3);
    assert_eq!(
        *seen.borrow(),
        vec![urls()[1].clone(), urls()[1].clone(), urls()[0].clone()]
    );
}
#[tokio::test]
async fn attempts_one_three_five_and_single_url_are_honored() {
    for attempts in [1, 3, 5] {
        let result = run_checks(
            &urls()[..1],
            attempts,
            Duration::from_secs(10),
            |count| {
                assert_eq!(count, 1);
                0
            },
            |_, _| async { Ok(503) },
        )
        .await;
        assert!(!result.success);
        assert_eq!(result.attempts, attempts);
        assert_eq!(result.status, Some(503));
    }
}
#[tokio::test(start_paused = true)]
async fn each_attempt_uses_remaining_budget_divided_by_remaining_opportunities() {
    let budgets = Rc::new(RefCell::new(Vec::new()));
    let captured = budgets.clone();
    let result = run_checks(
        &urls(),
        3,
        Duration::from_secs(9),
        |_| 0,
        move |_, budget| {
            captured.borrow_mut().push(budget);
            async {
                tokio::time::sleep(Duration::from_secs(20)).await;
                Ok(200)
            }
        },
    )
    .await;
    assert!(!result.success);
    assert_eq!(result.attempts, 3);
    assert_eq!(result.failure, Some(ProbeFailure::Timeout));
    assert!(result.elapsed <= Duration::from_secs(9));
    assert_eq!(budgets.borrow().len(), 3);
    assert!(
        budgets
            .borrow()
            .iter()
            .all(|v| *v <= Duration::from_secs(3))
    );
}
#[tokio::test]
async fn tls_and_transport_errors_are_failures_but_another_url_can_succeed() {
    let mut results = [
        Err(ProbeFailure::Tls),
        Err(ProbeFailure::Transport),
        Ok(204),
    ]
    .into_iter();
    let result = run_checks(
        &urls(),
        3,
        Duration::from_secs(10),
        |_| 0,
        |_, _| {
            let value = results.next().unwrap();
            async move { value }
        },
    )
    .await;
    assert!(result.success);
    assert_eq!(result.attempts, 3);
}
