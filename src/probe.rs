//! 复用原临时桥接思路；每次使用带随机认证的独立有界桥接，目标解析留在工作空间。
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFailure {
    Timeout,
    Tls,
    Response,
    Transport,
    NotImplemented,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub success: bool,
    pub attempts: u32,
    pub status: Option<u16>,
    pub failure: Option<ProbeFailure>,
    pub elapsed: Duration,
}
pub async fn run_checks<C, R, F>(
    urls: &[Url],
    max_attempts: u32,
    budget: Duration,
    mut choose: C,
    mut request: R,
) -> ProbeReport
where
    C: FnMut(usize) -> usize,
    R: FnMut(Url, Duration) -> F,
    F: std::future::Future<Output = Result<u16, ProbeFailure>>,
{
    let start = Instant::now();
    let deadline = start + budget;
    let mut report = ProbeReport {
        success: false,
        attempts: 0,
        status: None,
        failure: Some(ProbeFailure::Response),
        elapsed: Duration::ZERO,
    };
    if urls.is_empty() || max_attempts == 0 {
        return report;
    }
    while report.attempts < max_attempts {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            report.failure = Some(ProbeFailure::Timeout);
            break;
        }
        let per_request = remaining / (max_attempts - report.attempts);
        let index = choose(urls.len());
        let Some(url) = urls.get(index) else {
            report.failure = Some(ProbeFailure::Transport);
            break;
        };
        report.attempts += 1;
        let result = tokio::time::timeout_at(
            (Instant::now() + per_request).min(deadline),
            request(url.clone(), per_request),
        )
        .await;
        report.status = None;
        match result {
            Ok(Ok(status)) => {
                report.status = Some(status);
                report.success = (200..300).contains(&status);
                report.failure = if report.success {
                    None
                } else {
                    Some(ProbeFailure::Response)
                };
            }
            Ok(Err(failure)) => report.failure = Some(failure),
            Err(_) => report.failure = Some(ProbeFailure::Timeout),
        }
        if report.success {
            break;
        }
    }
    report.elapsed = start.elapsed();
    report
}
pub async fn check_exit(
    worker_socket: &Path,
    urls: &[Url],
    max_attempts: u32,
    budget: Duration,
) -> ProbeReport {
    let path = worker_socket.to_owned();
    run_checks(
        urls,
        max_attempts,
        budget,
        |count| rand::random_range(0..count),
        move |url, timeout| {
            let path = path.clone();
            async move { request_head(&path, url, timeout).await }
        },
    )
    .await
}

async fn request_head(path: &Path, url: Url, timeout: Duration) -> Result<u16, ProbeFailure> {
    let bridge = ProbeBridge::start(path.to_owned())
        .await
        .map_err(|_| ProbeFailure::Transport)?;
    let proxy = reqwest::Proxy::all(&bridge.proxy_url).map_err(|_| ProbeFailure::Transport)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .pool_max_idle_per_host(0)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|_| ProbeFailure::Transport)?;
    let result = client.get(url).header("Connection", "close").send().await;
    let status = result
        .map(|response| response.status().as_u16())
        .map_err(classify_request_error);
    drop(bridge);
    status
}
fn classify_request_error(error: reqwest::Error) -> ProbeFailure {
    if error.is_timeout() {
        return ProbeFailure::Timeout;
    }
    if error.is_redirect() {
        return ProbeFailure::Response;
    }
    use std::error::Error;
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.is::<native_tls::Error>() {
            return ProbeFailure::Tls;
        }
        source = cause.source();
    }
    ProbeFailure::Transport
}
struct ProbeBridge {
    proxy_url: String,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl ProbeBridge {
    async fn start(path: PathBuf) -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let secret = uuid::Uuid::new_v4().simple().to_string();
        let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        let proxy_url = format!("socks5h://probe:{secret}@{address}");
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(8));
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _=shutdown.cancelled()=>break,
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                    accepted=listener.accept()=>{
                        let Ok((mut client,_))=accepted else {break;};
                        let Ok(permit)=permits.clone().try_acquire_owned() else {continue;};
                        let path=path.clone();let stop=shutdown.clone();
                        tasks.spawn(async move {
                            let _permit=permit;
                            let operation=async {
                                let version=client.read_u8().await?;let count=client.read_u8().await?;
                                let mut methods=vec![0;count as usize];client.read_exact(&mut methods).await?;
                                if version!=5 || !methods.contains(&2) {return Err(std::io::Error::other("检测桥接要求认证"));}
                                client.write_all(&[5,2]).await?;
                                let version=client.read_u8().await?;let length=client.read_u8().await?;
                                let mut user=vec![0;length as usize];client.read_exact(&mut user).await?;
                                let length=client.read_u8().await?;let mut password=zeroize::Zeroizing::new(vec![0;length as usize]);client.read_exact(&mut password).await?;
                                let actual:[u8;32]=Sha256::digest(&*password).into();
                                if version!=1 || user!=b"probe" || !bool::from(actual.ct_eq(&digest)) {client.write_all(&[1,1]).await?;return Err(std::io::Error::other("检测桥接认证失败"));}
                                client.write_all(&[1,0]).await?;
                                let mut worker=UnixStream::connect(path).await?;
                                worker.write_all(&[5,1,0]).await?;let mut response=[0;2];worker.read_exact(&mut response).await?;
                                if response!=[5,0] {return Err(std::io::Error::other("检测工作进程协议错误"));}
                                tokio::io::copy_bidirectional(&mut client,&mut worker).await?;Ok::<_,std::io::Error>(())
                            };
                            tokio::select! {_=stop.cancelled()=>{},_=operation=>{}}
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        Ok(Self {
            proxy_url,
            cancel,
            task,
        })
    }
}
impl Drop for ProbeBridge {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
