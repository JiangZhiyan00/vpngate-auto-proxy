//! Local SOCKS5 gateway and the isolated worker-side SOCKS5 server.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket, UnixStream},
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{config::Credentials, domain::is_public_ipv4};

const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_NONE: u8 = 0;
const METHOD_PASSWORD: u8 = 2;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;
const REPLY_SUCCEEDED: u8 = 0;
const REPLY_GENERAL_FAILURE: u8 = 1;
const REPLY_NETWORK_UNREACHABLE: u8 = 3;
const REPLY_COMMAND_UNSUPPORTED: u8 = 7;
const REPLY_ADDRESS_UNSUPPORTED: u8 = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_SERVERS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
const MAX_DNS_MESSAGE_BYTES: usize = 4096;
static NEXT_DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

/// Errors returned while serving a listener rather than individual client failures.
#[derive(Debug, Error)]
pub enum SocksServerError {
    #[error("failed to bind SOCKS listener")]
    Bind(#[source] io::Error),
    #[error("SOCKS listener failed")]
    Accept(#[source] io::Error),
    #[error("failed to prepare worker socket")]
    Socket(#[source] io::Error),
}

#[derive(Debug, Error)]
enum SocksConnectionError {
    #[error("SOCKS protocol error")]
    Protocol,
    #[error("SOCKS command is not supported")]
    CommandUnsupported,
    #[error("不支持此地址族")]
    AddressUnsupported,
    #[error("SOCKS authentication failed")]
    Authentication,
    #[error("no active VPN worker")]
    NotReady,
    #[error("target is not a public IPv4 address")]
    ForbiddenTarget,
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("operation timed out")]
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Ipv4(Ipv4Addr, u16),
    Domain(String, u16),
}

#[derive(Clone)]
pub struct ActiveWorker {
    pub socket_path: PathBuf,
    pub node_id: crate::domain::NodeId,
    pub worker_id: crate::domain::WorkerId,
    pub cancel: CancellationToken,
}

pub async fn run_gateway(
    bind: SocketAddr,
    active_worker: watch::Receiver<Option<ActiveWorker>>,
    credentials: Option<Credentials>,
    semaphore: Arc<Semaphore>,
    shutdown: CancellationToken,
) -> Result<(), SocksServerError> {
    let listener = bind_gateway(bind, credentials.as_ref()).await?;
    serve_gateway(listener, active_worker, credentials, semaphore, shutdown).await
}

pub async fn bind_gateway(
    bind: SocketAddr,
    credentials: Option<&Credentials>,
) -> Result<TcpListener, SocksServerError> {
    if !bind.ip().is_loopback() && credentials.is_none() {
        return Err(SocksServerError::Bind(io::Error::other(
            "非回环监听必须配置认证",
        )));
    }
    TcpListener::bind(bind)
        .await
        .map_err(SocksServerError::Bind)
}

pub async fn serve_gateway(
    listener: TcpListener,
    active_worker: watch::Receiver<Option<ActiveWorker>>,
    credentials: Option<Credentials>,
    semaphore: Arc<Semaphore>,
    shutdown: CancellationToken,
) -> Result<(), SocksServerError> {
    if !listener
        .local_addr()
        .map_err(SocksServerError::Bind)?
        .ip()
        .is_loopback()
        && credentials.is_none()
    {
        return Err(SocksServerError::Bind(io::Error::other(
            "非回环监听必须配置认证",
        )));
    }
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(SocksServerError::Accept)?;
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    continue;
                };
                let active_worker = active_worker.clone();
                let credentials = credentials.clone();
                let stop=shutdown.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    tokio::select! {_=stop.cancelled()=>{}, _=handle_gateway_connection(stream, &active_worker, credentials.as_ref())=>{}}
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Runs the no-auth SOCKS endpoint from inside a VPN worker network namespace.
pub async fn run_worker(
    socket_path: &Path,
    require_tun: bool,
    max_connections: usize,
    shutdown: CancellationToken,
) -> Result<(), SocksServerError> {
    let listener = crate::netd::protocol::bind_private_socket(socket_path)
        .map_err(|_| SocksServerError::Socket(io::Error::other("无法绑定私有工作套接字")))?;
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(SocksServerError::Accept)?;
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    continue;
                };
                let stop=shutdown.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    tokio::select! {_=stop.cancelled()=>{},_=handle_worker_connection(stream, require_tun)=>{}}
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(listener);
    if let Err(error) = tokio::fs::remove_file(socket_path).await
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(SocksServerError::Socket(error));
    }
    Ok(())
}

/// 苹果工作进程的私有 SOCKS 入口；所有出口操作均由已核验的代际租约执行。
#[cfg(target_os = "macos")]
pub async fn run_verified_worker(
    socket_path: &Path,
    generation: crate::platform::network::VerifiedNetworkGeneration,
    max_connections: usize,
    shutdown: CancellationToken,
) -> Result<(), SocksServerError> {
    let servers = DNS_SERVERS.map(|server| std::net::SocketAddrV4::new(server, 53));
    run_verified_worker_with_servers(
        socket_path,
        generation,
        max_connections,
        shutdown,
        servers,
        |_| async { Ok(()) },
    )
    .await
}

#[cfg(target_os = "macos")]
pub(crate) async fn run_verified_worker_with_ready<F, R>(
    socket_path: &Path,
    generation: crate::platform::network::VerifiedNetworkGeneration,
    max_connections: usize,
    shutdown: CancellationToken,
    on_ready: F,
) -> Result<(), SocksServerError>
where
    F: FnOnce(uuid::Uuid) -> R,
    R: std::future::Future<Output = io::Result<()>>,
{
    let servers = DNS_SERVERS.map(|server| std::net::SocketAddrV4::new(server, 53));
    run_verified_worker_with_servers(
        socket_path,
        generation,
        max_connections,
        shutdown,
        servers,
        on_ready,
    )
    .await
}

#[cfg(target_os = "macos")]
async fn run_verified_worker_with_servers<F, R>(
    socket_path: &Path,
    generation: crate::platform::network::VerifiedNetworkGeneration,
    max_connections: usize,
    shutdown: CancellationToken,
    dns_servers: [std::net::SocketAddrV4; 2],
    on_ready: F,
) -> Result<(), SocksServerError>
where
    F: FnOnce(uuid::Uuid) -> R,
    R: std::future::Future<Output = io::Result<()>>,
{
    if max_connections == 0 || max_connections > Semaphore::MAX_PERMITS {
        return Err(SocksServerError::Socket(io::Error::new(
            io::ErrorKind::InvalidInput,
            "工作进程连接上限无效",
        )));
    }
    let listener = crate::netd::protocol::bind_private_socket(socket_path)
        .map_err(|_| SocksServerError::Socket(io::Error::other("无法绑定私有工作套接字")))?;
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let mut tasks = JoinSet::new();
    let serving: Result<(), SocksServerError> = async {
        if shutdown.is_cancelled() {
            return Err(SocksServerError::Socket(io::Error::new(
                io::ErrorKind::Interrupted,
                "工作进程启动已取消",
            )));
        }
        on_ready(generation.lease().id())
            .await
            .map_err(SocksServerError::Socket)?;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break Ok(()),
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) => break Err(SocksServerError::Accept(error)),
                    };
                    let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                        continue;
                    };
                    let lease = generation.lease();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _ = handle_verified_worker_connection(stream, lease, dns_servers).await;
                    });
                }
            }
        }
    }
    .await;
    generation.revoke();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    generation.retire().await;
    drop(listener);
    if let Err(error) = tokio::fs::remove_file(socket_path).await
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(SocksServerError::Socket(error));
    }
    serving
}

#[cfg(target_os = "macos")]
async fn handle_verified_worker_connection(
    mut client: UnixStream,
    lease: crate::platform::network::VerifiedNetworkLease,
    dns_servers: [std::net::SocketAddrV4; 2],
) -> Result<(), SocksConnectionError> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_method(&mut client, None).await?;
        read_request(&mut client).await
    })
    .await
    .map_err(|_| SocksConnectionError::Timeout)?;
    let target = match request {
        Ok(target) => target,
        Err(SocksConnectionError::ForbiddenTarget) => {
            send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
            return Err(SocksConnectionError::ForbiddenTarget);
        }
        Err(SocksConnectionError::CommandUnsupported) => {
            send_reply(&mut client, REPLY_COMMAND_UNSUPPORTED, None).await?;
            return Err(SocksConnectionError::CommandUnsupported);
        }
        Err(error) => {
            send_reply(&mut client, REPLY_ADDRESS_UNSUPPORTED, None).await?;
            return Err(error);
        }
    };
    let address = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        resolve_public_target_verified_with_servers(&target, &lease, &dns_servers),
    )
    .await
    {
        Ok(Ok(address)) => address,
        Ok(Err(error)) => {
            send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
            return Err(error);
        }
        Err(_) => {
            send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
            return Err(SocksConnectionError::Timeout);
        }
    };
    const READY: [u8; 10] = [
        SOCKS_VERSION,
        REPLY_SUCCEEDED,
        0,
        ADDRESS_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    const FAILURE: [u8; 10] = [
        SOCKS_VERSION,
        REPLY_NETWORK_UNREACHABLE,
        0,
        ADDRESS_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    lease
        .relay_tcp_with_replies(client, address, &READY, &FAILURE)
        .await?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn resolve_public_target_verified_with_servers(
    target: &Target,
    lease: &crate::platform::network::VerifiedNetworkLease,
    servers: &[std::net::SocketAddrV4],
) -> Result<std::net::SocketAddrV4, SocksConnectionError> {
    match target {
        Target::Ipv4(ip, port) => Ok(std::net::SocketAddrV4::new(*ip, *port)),
        Target::Domain(domain, port) => {
            let query_id = NEXT_DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
            let query = encode_dns_query(domain, query_id)?;
            for &server in servers {
                if let Ok(response) = lease.query_dns(server, &query).await
                    && let Ok(addresses) = parse_dns_a_response(&response, query_id)
                    && let Some(ip) = addresses.into_iter().find(|ip| {
                        lease.allows_destination(std::net::SocketAddrV4::new(*ip, *port))
                    })
                {
                    return Ok(std::net::SocketAddrV4::new(ip, *port));
                }
            }
            Err(SocksConnectionError::ForbiddenTarget)
        }
    }
}

async fn handle_gateway_connection(
    mut client: TcpStream,
    active_worker: &watch::Receiver<Option<ActiveWorker>>,
    credentials: Option<&Credentials>,
) -> Result<(), SocksConnectionError> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_method(&mut client, credentials).await?;
        read_request(&mut client).await
    })
    .await
    .map_err(|_| SocksConnectionError::Timeout)?;
    let target = match request {
        Ok(target) => target,
        Err(SocksConnectionError::ForbiddenTarget) => {
            send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
            return Err(SocksConnectionError::ForbiddenTarget);
        }
        Err(SocksConnectionError::CommandUnsupported) => {
            send_reply(&mut client, REPLY_COMMAND_UNSUPPORTED, None).await?;
            return Err(SocksConnectionError::CommandUnsupported);
        }
        Err(error) => {
            send_reply(&mut client, REPLY_ADDRESS_UNSUPPORTED, None).await?;
            return Err(error);
        }
    };
    let active = active_worker
        .borrow()
        .clone()
        .ok_or(SocksConnectionError::NotReady);
    let active = match active {
        Ok(path) => path,
        Err(error) => {
            send_reply(&mut client, REPLY_GENERAL_FAILURE, None).await?;
            return Err(error);
        }
    };
    let worker = tokio::select! {
        _=active.cancel.cancelled()=>return Err(SocksConnectionError::NotReady),
        result=tokio::time::timeout(CONNECT_TIMEOUT,connect_worker(&active.socket_path,&target))=>result.map_err(|_| SocksConnectionError::Timeout),
    };
    let mut worker = match worker {
        Ok(Ok(worker)) => worker,
        Ok(Err(error)) | Err(error) => {
            send_reply(&mut client, REPLY_GENERAL_FAILURE, None).await?;
            return Err(error);
        }
    };
    send_reply(&mut client, REPLY_SUCCEEDED, None).await?;
    tokio::select! {
        _=active.cancel.cancelled()=>{},
        result=tokio::io::copy_bidirectional(&mut client,&mut worker)=>{result?;},
    }
    Ok(())
}

async fn handle_worker_connection(
    mut client: UnixStream,
    require_tun: bool,
) -> Result<(), SocksConnectionError> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate_method(&mut client, None).await?;
        read_request(&mut client).await
    })
    .await
    .map_err(|_| SocksConnectionError::Timeout)?;
    let target = match request {
        Ok(target) => target,
        Err(SocksConnectionError::ForbiddenTarget) => {
            send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
            return Err(SocksConnectionError::ForbiddenTarget);
        }
        Err(SocksConnectionError::CommandUnsupported) => {
            send_reply(&mut client, REPLY_COMMAND_UNSUPPORTED, None).await?;
            return Err(SocksConnectionError::CommandUnsupported);
        }
        Err(error) => {
            send_reply(&mut client, REPLY_ADDRESS_UNSUPPORTED, None).await?;
            return Err(error);
        }
    };
    let connect_deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    if require_tun && !tun_routes_cover_public_ipv4().await {
        send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
        return Err(SocksConnectionError::NotReady);
    }

    let resolved = tokio::time::timeout_at(connect_deadline, resolve_public_target(&target))
        .await
        .map_err(|_| SocksConnectionError::Timeout);
    let address = match resolved {
        Ok(Ok(address)) => address,
        Ok(Err(error)) | Err(error) => {
            send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
            return Err(error);
        }
    };
    let mut target_stream =
        match tokio::time::timeout_at(connect_deadline, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
                return Err(SocksConnectionError::Io(error));
            }
            Err(_) => {
                send_reply(&mut client, REPLY_NETWORK_UNREACHABLE, None).await?;
                return Err(SocksConnectionError::Timeout);
            }
        };
    let bound = target_stream.local_addr().ok();
    send_reply(&mut client, REPLY_SUCCEEDED, bound).await?;
    let _transferred = tokio::io::copy_bidirectional(&mut client, &mut target_stream).await?;
    Ok(())
}

async fn negotiate_method<S>(
    stream: &mut S,
    credentials: Option<&Credentials>,
) -> Result<(), SocksConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    let method_count = usize::from(stream.read_u8().await?);
    if version != SOCKS_VERSION || method_count == 0 || method_count > 16 {
        return Err(SocksConnectionError::Protocol);
    }
    let mut methods = vec![0_u8; method_count];
    stream.read_exact(&mut methods).await?;
    let selected = if credentials.is_some() && methods.contains(&METHOD_PASSWORD) {
        METHOD_PASSWORD
    } else if credentials.is_none() && methods.contains(&METHOD_NONE) {
        METHOD_NONE
    } else {
        METHOD_UNACCEPTABLE
    };
    stream.write_all(&[SOCKS_VERSION, selected]).await?;
    if selected == METHOD_UNACCEPTABLE {
        return Err(SocksConnectionError::Authentication);
    }
    if selected == METHOD_PASSWORD {
        authenticate(
            stream,
            credentials.ok_or(SocksConnectionError::Authentication)?,
        )
        .await?;
    }
    Ok(())
}

async fn authenticate<S>(
    stream: &mut S,
    credentials: &Credentials,
) -> Result<(), SocksConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.read_u8().await? != AUTH_VERSION {
        return Err(SocksConnectionError::Authentication);
    }
    let user_length = usize::from(stream.read_u8().await?);
    let mut username = vec![0_u8; user_length];
    stream.read_exact(&mut username).await?;
    let password_length = usize::from(stream.read_u8().await?);
    let mut password = Zeroizing::new(vec![0_u8; password_length]);
    stream.read_exact(&mut password).await?;

    let supplied_user = Sha256::digest(&username);
    let expected_user = Sha256::digest(credentials.username.as_bytes());
    let supplied_password = Sha256::digest(&password);
    let expected_password = Sha256::digest(credentials.password.as_bytes());
    let valid = supplied_user.ct_eq(&expected_user) & supplied_password.ct_eq(&expected_password);
    let status = u8::from(!bool::from(valid));
    stream.write_all(&[AUTH_VERSION, status]).await?;
    password.fill(0);
    if status == 0 {
        Ok(())
    } else {
        Err(SocksConnectionError::Authentication)
    }
}

async fn read_request<S>(stream: &mut S) -> Result<Target, SocksConnectionError>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    let address_type = stream.read_u8().await?;
    if version != SOCKS_VERSION || reserved != 0 {
        return Err(SocksConnectionError::Protocol);
    }
    if command != COMMAND_CONNECT {
        return Err(SocksConnectionError::CommandUnsupported);
    }

    let target = match address_type {
        ADDRESS_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Target::Ipv4(Ipv4Addr::from(octets), stream.read_u16().await?)
        }
        ADDRESS_DOMAIN => {
            let length = usize::from(stream.read_u8().await?);
            if length == 0 {
                return Err(SocksConnectionError::Protocol);
            }
            let mut domain = vec![0_u8; length];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| SocksConnectionError::Protocol)?;
            Target::Domain(domain, stream.read_u16().await?)
        }
        ADDRESS_IPV6 => return Err(SocksConnectionError::AddressUnsupported),
        _ => return Err(SocksConnectionError::Protocol),
    };
    validate_target(&target)?;
    Ok(target)
}

fn validate_target(target: &Target) -> Result<(), SocksConnectionError> {
    let port = match target {
        Target::Ipv4(ip, port) => {
            if !is_public_ipv4(*ip) {
                return Err(SocksConnectionError::ForbiddenTarget);
            }
            *port
        }
        Target::Domain(domain, port) => {
            let lower = domain.to_ascii_lowercase();
            if domain.len() > 253
                || !domain.is_ascii()
                || lower == "localhost"
                || lower.ends_with(".localhost")
                || has_domain_suffix(&lower, "local")
                || has_domain_suffix(&lower, "internal")
                || domain.split('.').any(str::is_empty)
            {
                return Err(SocksConnectionError::ForbiddenTarget);
            }
            *port
        }
    };
    if port == 0 {
        return Err(SocksConnectionError::ForbiddenTarget);
    }
    Ok(())
}

async fn resolve_public_target(target: &Target) -> Result<SocketAddr, SocksConnectionError> {
    match target {
        Target::Ipv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
        Target::Domain(domain, port) => {
            for server in DNS_SERVERS {
                if let Ok(addresses) = query_dns_a(domain, server).await
                    && let Some(ip) = addresses.into_iter().find(|ip| is_public_ipv4(*ip))
                {
                    return Ok(SocketAddr::new(IpAddr::V4(ip), *port));
                }
            }
            Err(SocksConnectionError::ForbiddenTarget)
        }
    }
}

async fn tun_routes_cover_public_ipv4() -> bool {
    let Ok(routes) = tokio::fs::read_to_string("/proc/net/route").await else {
        return false;
    };
    proc_route_table_covers_public_ipv4(&routes)
}

fn proc_route_table_covers_public_ipv4(routes: &str) -> bool {
    let mut default = false;
    let mut lower_half = false;
    let mut upper_half = false;
    for fields in routes
        .lines()
        .skip(1)
        .map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
    {
        if fields.first().copied() != Some("tun0") || fields.len() < 8 {
            continue;
        }
        match (fields[1], fields[7]) {
            ("00000000", "00000000") => default = true,
            ("00000000", "00000080") => lower_half = true,
            ("00000080", "00000080") => upper_half = true,
            _ => {}
        }
    }
    default || (lower_half && upper_half)
}

async fn query_dns_a(domain: &str, server: Ipv4Addr) -> io::Result<Vec<Ipv4Addr>> {
    let query_id = NEXT_DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = encode_dns_query(domain, query_id)?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect((server, 53)).await?;
    socket.send(&query).await?;
    let mut response = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
    let length = tokio::time::timeout(DNS_TIMEOUT, socket.recv(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
    response.truncate(length);
    if dns_response_is_truncated(&response, query_id) {
        return query_dns_a_tcp(&query, query_id, server).await;
    }
    parse_dns_a_response(&response, query_id)
}

async fn query_dns_a_tcp(
    query: &[u8],
    query_id: u16,
    server: Ipv4Addr,
) -> io::Result<Vec<Ipv4Addr>> {
    let mut stream = tokio::time::timeout(DNS_TIMEOUT, TcpStream::connect((server, 53)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP connect timed out"))??;
    let query_length = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query is too large"))?;
    stream.write_u16(query_length).await?;
    stream.write_all(query).await?;
    let response_length = tokio::time::timeout(DNS_TIMEOUT, stream.read_u16())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP response timed out"))??;
    let response_length = usize::from(response_length);
    if response_length == 0 || response_length > MAX_DNS_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response exceeds the configured limit",
        ));
    }
    let mut response = vec![0_u8; response_length];
    tokio::time::timeout(DNS_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS TCP response timed out"))??;
    parse_dns_a_response(&response, query_id)
}

fn encode_dns_query(domain: &str, query_id: u16) -> io::Result<Vec<u8>> {
    let mut query = Vec::with_capacity(domain.len().saturating_add(18));
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    for label in domain.split('.') {
        let length = u8::try_from(label.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "DNS label exceeds 255 bytes")
        })?;
        if length == 0 || length > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS label must contain 1 to 63 bytes",
            ));
        }
        query.push(length);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn dns_response_is_truncated(response: &[u8], query_id: u16) -> bool {
    response.len() >= 4 && response[..2] == query_id.to_be_bytes() && response[2] & 0x02 != 0
}

fn parse_dns_a_response(response: &[u8], query_id: u16) -> io::Result<Vec<Ipv4Addr>> {
    if response.len() < 12 || response[..2] != query_id.to_be_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response header is invalid",
        ));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS server returned an unsuccessful response",
        ));
    }
    let question_count = usize::from(u16::from_be_bytes([response[4], response[5]]));
    let answer_count = usize::from(u16::from_be_bytes([response[6], response[7]]));
    if question_count > 8 || answer_count > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response contains too many records",
        ));
    }
    let mut offset = 12;
    for _ in 0..question_count {
        offset = skip_dns_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS question is truncated")
            })?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        offset = skip_dns_name(response, offset)?;
        let header_end = offset
            .checked_add(10)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DNS answer is truncated"))?;
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let data_length = usize::from(u16::from_be_bytes([
            response[offset + 8],
            response[offset + 9],
        ]));
        let data_end = header_end
            .checked_add(data_length)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS record data is truncated")
            })?;
        if record_type == 1 && class == 1 && data_length == 4 {
            addresses.push(Ipv4Addr::new(
                response[header_end],
                response[header_end + 1],
                response[header_end + 2],
                response[header_end + 3],
            ));
        }
        offset = data_end;
    }
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS response contains no IPv4 address",
        ));
    }
    Ok(addresses)
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> io::Result<usize> {
    for _ in 0..128 {
        let length = *message
            .get(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DNS name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            let low = *message.get(offset + 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "DNS pointer is truncated")
            })?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            if pointer >= message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS pointer is out of bounds",
                ));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS label length is invalid",
            ));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|end| *end <= message.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DNS label is truncated"))?;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "DNS name contains too many labels",
    ))
}

fn has_domain_suffix(domain: &str, suffix: &str) -> bool {
    domain
        .rsplit_once('.')
        .is_some_and(|(_, candidate)| candidate == suffix)
}

async fn connect_worker(
    socket_path: &Path,
    target: &Target,
) -> Result<UnixStream, SocksConnectionError> {
    let mut worker = UnixStream::connect(socket_path).await?;
    worker.write_all(&[SOCKS_VERSION, 1, METHOD_NONE]).await?;
    let mut method_response = [0_u8; 2];
    worker.read_exact(&mut method_response).await?;
    if method_response != [SOCKS_VERSION, METHOD_NONE] {
        return Err(SocksConnectionError::Protocol);
    }
    worker.write_all(&encode_request(target)?).await?;
    let reply = read_reply(&mut worker).await?;
    if reply != REPLY_SUCCEEDED {
        return Err(SocksConnectionError::NotReady);
    }
    Ok(worker)
}

fn encode_request(target: &Target) -> Result<Vec<u8>, SocksConnectionError> {
    let mut request = vec![SOCKS_VERSION, COMMAND_CONNECT, 0];
    match target {
        Target::Ipv4(ip, port) => {
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&ip.octets());
            request.extend_from_slice(&port.to_be_bytes());
        }
        Target::Domain(domain, port) => {
            let length = u8::try_from(domain.len()).map_err(|_| SocksConnectionError::Protocol)?;
            request.push(ADDRESS_DOMAIN);
            request.push(length);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(request)
}

async fn read_reply<S>(stream: &mut S) -> Result<u8, SocksConnectionError>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    let reply = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    let address_type = stream.read_u8().await?;
    if version != SOCKS_VERSION || reserved != 0 {
        return Err(SocksConnectionError::Protocol);
    }
    match address_type {
        ADDRESS_IPV4 => {
            let mut ignored = [0_u8; 6];
            stream.read_exact(&mut ignored).await?;
        }
        ADDRESS_DOMAIN => {
            let length = usize::from(stream.read_u8().await?);
            let mut ignored = vec![0_u8; length.saturating_add(2)];
            stream.read_exact(&mut ignored).await?;
        }
        ADDRESS_IPV6 => {
            let mut ignored = [0_u8; 18];
            stream.read_exact(&mut ignored).await?;
        }
        _ => return Err(SocksConnectionError::Protocol),
    }
    Ok(reply)
}

async fn send_reply<S>(
    stream: &mut S,
    reply: u8,
    bound: Option<SocketAddr>,
) -> Result<(), SocksConnectionError>
where
    S: AsyncWrite + Unpin,
{
    let mut response = vec![SOCKS_VERSION, reply, 0, ADDRESS_IPV4];
    match bound {
        Some(SocketAddr::V4(address)) => {
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        _ => response.extend_from_slice(&[0, 0, 0, 0, 0, 0]),
    }
    stream.write_all(&response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn verified_worker_rejects_private_target_and_removes_listener_on_stop() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let path = directory.path().join("worker.sock");
        let index = nix::net::if_::if_nametoindex("lo0").unwrap();
        let scope = crate::platform::macos::InterfaceScope::new(index).unwrap();
        let generation = crate::platform::network::VerifiedNetworkGeneration::from_parts(
            scope,
            crate::platform::generation::WorkerGeneration::new(),
        );
        let outbound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = outbound.local_addr().unwrap().port();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let socket = path.clone();
        let task =
            tokio::spawn(async move { run_verified_worker(&socket, generation, 1, stop).await });
        let mut client = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(stream) = UnixStream::connect(&path).await {
                    break stream;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8])
            .await
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REPLY_NETWORK_UNREACHABLE);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), outbound.accept())
                .await
                .is_err()
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!path.exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn verified_worker_domain_resolution_uses_generation_bound_dns() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_address = match server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let responder = tokio::spawn(async move {
            let mut query = [0; 512];
            let (count, peer) = server.recv_from(&mut query).await.unwrap();
            let mut response = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            response.extend_from_slice(&query[12..count]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            server.send_to(&response, peer).await.unwrap();
        });
        let index = nix::net::if_::if_nametoindex("lo0").unwrap();
        let scope = crate::platform::macos::InterfaceScope::new(index).unwrap();
        let generation = crate::platform::network::VerifiedNetworkGeneration::from_parts(
            scope,
            crate::platform::generation::WorkerGeneration::new(),
        );
        let result = resolve_public_target_verified_with_servers(
            &Target::Domain("example.com".to_owned(), 443),
            &generation.lease(),
            &[server_address],
        )
        .await
        .unwrap();
        assert_eq!(*result.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(result.port(), 443);
        responder.await.unwrap();
        generation.retire().await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn verified_worker_relays_domain_request_through_private_socket() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = directory.path().join("worker.sock");
        let dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dns_address = match dns.local_addr().unwrap() {
            SocketAddr::V4(value) => value,
            _ => unreachable!(),
        };
        let dns_task = tokio::spawn(async move {
            let mut query = [0; 512];
            let (count, peer) = dns.recv_from(&mut query).await.unwrap();
            let mut response = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
            response.extend_from_slice(&query[12..count]);
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            dns.send_to(&response, peer).await.unwrap();
        });
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").await.unwrap();
            let mut final_byte = [0; 1];
            assert_eq!(stream.read(&mut final_byte).await.unwrap(), 0);
        });
        let index = nix::net::if_::if_nametoindex("lo0").unwrap();
        let scope = crate::platform::macos::InterfaceScope::new(index).unwrap();
        let generation = crate::platform::network::VerifiedNetworkGeneration::from_parts(
            scope,
            crate::platform::generation::WorkerGeneration::new(),
        );
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let worker_path = socket_path.clone();
        let worker = tokio::spawn(async move {
            run_verified_worker_with_servers(
                &worker_path,
                generation,
                1,
                stop,
                [dns_address, dns_address],
                |_| async { Ok(()) },
            )
            .await
        });
        let mut client = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(stream) = UnixStream::connect(&socket_path).await {
                    break stream;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let request =
            encode_request(&Target::Domain("example.com".to_owned(), target_port)).unwrap();
        client.write_all(&request).await.unwrap();
        let mut ready = [0; 10];
        client.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready[..4], &[5, REPLY_SUCCEEDED, 0, 1]);
        client.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        dns_task.await.unwrap();
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        target_task.await.unwrap();
        assert!(!socket_path.exists());
    }

    #[test]
    fn rejects_private_and_special_targets() {
        assert!(validate_target(&Target::Ipv4(Ipv4Addr::LOCALHOST, 443)).is_err());
        assert!(validate_target(&Target::Domain("localhost".to_owned(), 443)).is_err());
        assert!(validate_target(&Target::Domain("printer.local".to_owned(), 443)).is_err());
        assert!(validate_target(&Target::Domain("example.com".to_owned(), 443)).is_ok());
    }

    #[test]
    fn request_encoding_uses_remote_dns_for_domains() {
        let request = encode_request(&Target::Domain("example.com".to_owned(), 443))
            .expect("valid domain encodes");
        assert_eq!(request[3], ADDRESS_DOMAIN);
        assert_eq!(request[4], 11);
    }

    #[tokio::test]
    async fn rfc1929_authentication_is_required_and_checked() {
        let credentials = Credentials {
            username: "user".to_owned(),
            password: "secret".to_owned(),
        };
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task =
            tokio::spawn(async move { negotiate_method(&mut server, Some(&credentials)).await });

        client
            .write_all(&[SOCKS_VERSION, 1, METHOD_PASSWORD])
            .await
            .expect("method request");
        let mut method = [0_u8; 2];
        client
            .read_exact(&mut method)
            .await
            .expect("method response");
        assert_eq!(method, [SOCKS_VERSION, METHOD_PASSWORD]);
        client
            .write_all(&[
                AUTH_VERSION,
                4,
                b'u',
                b's',
                b'e',
                b'r',
                6,
                b's',
                b'e',
                b'c',
                b'r',
                b'e',
                b't',
            ])
            .await
            .expect("credential request");
        let mut auth = [0_u8; 2];
        client
            .read_exact(&mut auth)
            .await
            .expect("credential response");
        assert_eq!(auth, [AUTH_VERSION, 0]);
        assert!(server_task.await.expect("server task").is_ok());
    }

    #[test]
    fn parses_a_bounded_dns_a_response() {
        let query = encode_dns_query("example.com", 0x1234).expect("valid query");
        let mut response = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        assert_eq!(
            parse_dns_a_response(&response, 0x1234).expect("valid response"),
            vec![Ipv4Addr::new(93, 184, 216, 34)]
        );
        assert!(parse_dns_a_response(&response, 0x9999).is_err());
    }

    #[test]
    fn proc_route_table_requires_a_full_tunnel_route() {
        let header =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n";
        let def1 = format!(
            "{header}tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n\
             tun0\t00000080\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n"
        );
        assert!(proc_route_table_covers_public_ipv4(&def1));
        let root_default =
            format!("{header}tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n");
        assert!(proc_route_table_covers_public_ipv4(&root_default));
        let partial =
            format!("{header}tun0\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n");
        assert!(!proc_route_table_covers_public_ipv4(&partial));
    }
}
