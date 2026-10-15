//! 网络空间、命令执行及护栏由原核心对应实现裁剪改造；不修改宿主全局策略。
use crate::domain::{Endpoint, WorkerId};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};
use uuid::Uuid;

pub const CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const CONTROL_UID: u32 = 10001;
pub const OPENVPN_UID: u32 = 10002;

/// 只由特权辅助进程调用；外部辅助协议不暴露程序或参数选择。
pub fn restricted_command(
    namespace: Option<&str>,
    openvpn: bool,
    program: &std::path::Path,
) -> Command {
    let mut command = if let Some(namespace) = namespace {
        let mut command = Command::new("nsenter");
        command
            .arg(format!("--net=/run/netns/{namespace}"))
            .arg("setpriv");
        command
    } else {
        Command::new("setpriv")
    };
    let uid = if openvpn { OPENVPN_UID } else { CONTROL_UID };
    command.args([format!("--reuid={uid}"), format!("--regid={uid}")]);
    command.args(["--clear-groups", "--no-new-privs"]);
    if openvpn {
        command.args([
            "--bounding-set=-all,+net_admin",
            "--inh-caps=-all,+net_admin",
            "--ambient-caps=-all,+net_admin",
        ]);
    } else {
        command.args([
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
        ]);
    }
    command
        .arg(program)
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("LANG", "C")
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    // 每个受监督子进程使用独立进程组，停止时按已记录身份回收。
    command.process_group(0);
    command
}

pub struct SupervisedProcess {
    child: tokio::process::Child,
    pub pid: u32,
    pub started: String,
}
impl SupervisedProcess {
    pub fn spawn(command: &mut Command) -> Result<Self> {
        let child = command.spawn().context("无法创建受监督进程")?;
        let pid = child.id().context("子进程标识缺失")?;
        let started = super::process_start(pid)?;
        Ok(Self {
            child,
            pid,
            started,
        })
    }
    pub fn is_running(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        Ok(self.child.wait().await?)
    }
    pub async fn terminate(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        if !self.is_running()? {
            return Ok(());
        }
        ensure!(
            super::process_start(self.pid)? == self.started,
            "进程启动身份改变，拒绝终止"
        );
        // 参数来自受监督的数字 pid，负值仅指向该子进程自己创建的进程组。
        let group = format!("-{}", self.pid);
        let _ = run_command("kill", &["-TERM", "--", &group]).await;
        let grace = deadline.min(tokio::time::Instant::now() + Duration::from_millis(500));
        if tokio::time::timeout_at(grace, self.child.wait())
            .await
            .is_err()
        {
            if std::path::Path::new(&format!("/proc/{}", self.pid)).exists() {
                ensure!(
                    super::process_start(self.pid)? == self.started,
                    "进程启动身份改变，拒绝强制终止"
                );
                let _ = run_command("kill", &["-KILL", "--", &group]).await;
            }
            tokio::time::timeout_at(deadline, self.child.wait())
                .await
                .context("子进程回收超时")??;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAllocation {
    pub instance_id: Uuid,
    pub worker_id: WorkerId,
    pub namespace: String,
    pub host_veth: String,
    pub worker_veth: String,
    pub table: String,
    pub host_ip: Ipv4Addr,
    pub worker_ip: Ipv4Addr,
}
fn recorded_running(process: &crate::domain::ProcessIdentity) -> Result<bool> {
    let stat = match std::fs::read_to_string(format!("/proc/{}/stat", process.pid)) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let (_, fields) = stat.rsplit_once(')').context("遗留进程身份格式无效")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        fields.get(19).copied() == Some(process.started.as_str()),
        "遗留进程启动身份改变，拒绝终止"
    );
    ensure!(
        fields.get(2).and_then(|group| group.parse::<u32>().ok()) == Some(process.pid),
        "遗留进程组归属不一致"
    );
    Ok(fields
        .first()
        .is_some_and(|state| *state != "Z" && *state != "X"))
}
async fn namespace_identity(pid: u32) -> Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    let path = format!("/proc/{pid}/ns/net");
    match std::fs::metadata(&path) {
        Ok(metadata) => return Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error.into()),
    }
    // 不增加跨用户追踪能力；使用既定降权身份读取同身份进程的命名空间元数据。
    let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if status
        .lines()
        .any(|line| line.starts_with("State:") && (line.contains("Z ") || line.contains("X ")))
    {
        return Ok(None);
    }
    let uid = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|uid| uid.parse::<u32>().ok())
        })
        .context("进程用户身份无法核对")?;
    ensure!(
        [CONTROL_UID, OPENVPN_UID].contains(&uid),
        "无法安全核对进程网络空间，拒绝遗留清理"
    );
    let output = restricted_command(None, uid == OPENVPN_UID, std::path::Path::new("stat"))
        .args(["-Lc", "%d:%i", "--", &path])
        .output()
        .await?;
    if !output.status.success() {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return Ok(None);
        }
        anyhow::bail!("降权核对进程网络空间失败，拒绝遗留清理");
    }
    let value = String::from_utf8(output.stdout)?;
    let (device, inode) = value
        .trim()
        .split_once(':')
        .context("网络空间身份格式无效")?;
    Ok(Some((device.parse()?, inode.parse()?)))
}
/// 只用于已取得独占锁且原父进程已死亡的清单；先验证全部归属，再发送任何信号。
pub async fn reclaim_stale_processes(
    manifest: &super::ResourceManifest,
    deadline: tokio::time::Instant,
) -> Result<()> {
    use std::{collections::BTreeMap, os::unix::fs::MetadataExt};
    super::validate_stale_manifest(manifest)?;
    let mut processes = BTreeMap::<u32, crate::domain::ProcessIdentity>::new();
    let mut add = |process: crate::domain::ProcessIdentity| -> Result<()> {
        ensure!(process.pid > 1, "遗留进程标识无效");
        if let Some(old) = processes.insert(process.pid, process.clone()) {
            ensure!(old.started == process.started, "遗留进程记录冲突");
        }
        Ok(())
    };
    if let Some(controller) = &manifest.controller {
        add(controller.clone())?;
    }
    let mut namespaces = std::collections::BTreeSet::new();
    for worker in &manifest.workers {
        if worker.pid > 0 {
            add(crate::domain::ProcessIdentity {
                pid: worker.pid,
                started: worker.process_start.clone(),
            })?;
        }
        for process in &worker.processes {
            add(process.clone())?;
        }
    }
    for process in processes.values() {
        recorded_running(process)?;
    }
    for worker in &manifest.workers {
        let allocation = NetworkAllocation::new(manifest.instance_id, worker.worker_id, 0);
        let namespace = std::path::PathBuf::from(format!("/run/netns/{}", allocation.namespace));
        if let Ok(marker) = std::fs::symlink_metadata(allocation.marker_path()) {
            ensure!(
                marker.is_file()
                    && marker.uid() == 0
                    && marker.mode() & 0o777 == 0o600
                    && std::fs::read_to_string(allocation.marker_path())? == allocation.owner_tag(),
                "遗留网络空间归属凭据不一致"
            );
        } else {
            ensure!(
                !namespace.exists()
                    && !std::path::Path::new(&format!("/sys/class/net/{}", allocation.host_veth))
                        .exists()
                    && run_command("nft", &["list", "table", "inet", &allocation.table])
                        .await
                        .is_err(),
                "遗留资源缺少归属凭据"
            );
        }
        if namespace.exists() {
            let expected = std::fs::metadata(&namespace)?;
            namespaces.insert((expected.dev(), expected.ino()));
            for process in worker
                .processes
                .iter()
                .cloned()
                .chain((worker.pid > 0).then(|| crate::domain::ProcessIdentity {
                    pid: worker.pid,
                    started: worker.process_start.clone(),
                }))
            {
                if recorded_running(&process)? {
                    let actual = namespace_identity(process.pid).await?;
                    ensure!(
                        actual == Some((expected.dev(), expected.ino())),
                        "遗留进程网络空间归属不一致"
                    );
                }
            }
        } else {
            for process in worker
                .processes
                .iter()
                .cloned()
                .chain((worker.pid > 0).then(|| crate::domain::ProcessIdentity {
                    pid: worker.pid,
                    started: worker.process_start.clone(),
                }))
            {
                ensure!(
                    !recorded_running(&process)?,
                    "遗留工作进程缺少可核对的网络空间"
                );
            }
        }
    }
    if !namespaces.is_empty() {
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if let Some(identity) = namespace_identity(pid).await?
                && namespaces.contains(&identity)
            {
                ensure!(
                    processes.contains_key(&pid),
                    "遗留网络空间有未记录进程，拒绝回收"
                );
            }
        }
    }
    for signal in ["-TERM", "-KILL"] {
        for process in processes.values() {
            if recorded_running(process)? {
                let result = tokio::time::timeout_at(
                    deadline,
                    run_command("kill", &[signal, "--", &format!("-{}", process.pid)]),
                )
                .await
                .context("遗留进程回收总时限耗尽")?;
                if result.is_err() {
                    ensure!(!recorded_running(process)?, "遗留进程无法终止");
                }
            }
        }
        let until = if signal == "-TERM" {
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(500))
        } else {
            deadline
        };
        loop {
            let mut running = false;
            for process in processes.values() {
                running |= recorded_running(process)?;
            }
            if !running {
                return Ok(());
            }
            if tokio::time::Instant::now() >= until {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    anyhow::bail!("遗留进程回收超时")
}
impl NetworkAllocation {
    pub fn new(instance: Uuid, worker: WorkerId, slot: u8) -> Self {
        let instance_text = instance.simple().to_string();
        let short = worker.short();
        Self {
            instance_id: instance,
            worker_id: worker,
            namespace: format!("vap_{}_{}", &instance_text[..8], short),
            host_veth: format!("vh{short}"),
            worker_veth: format!("vw{short}"),
            table: format!("vap_{}_{}", &instance_text[..8], short),
            host_ip: Ipv4Addr::new(10, 231, slot, 1),
            worker_ip: Ipv4Addr::new(10, 231, slot, 2),
        }
    }
    pub fn owner_tag(&self) -> String {
        format!("vpngate-auto-proxy:{}:{}", self.instance_id, self.worker_id)
    }
    pub fn marker_path(&self) -> std::path::PathBuf {
        format!("/run/netns/{}.vap-owner", self.namespace).into()
    }
}
pub fn worker_guard_script(a: &NetworkAllocation, endpoint: &Endpoint) -> String {
    format!(
        r#"table inet vap_guard {{
 chain input {{
  type filter hook input priority filter; policy drop;
  iifname "lo" accept
  ct state established,related accept
 }}
 chain output {{
  type filter hook output priority filter; policy drop;
  oifname "lo" accept
  meta nfproto ipv6 drop
  oifname "{veth}" meta skuid {uid} ip daddr {host} {proto} dport {port} accept
  oifname "tun0" accept
 }}
}}
"#,
        veth = a.worker_veth,
        uid = OPENVPN_UID,
        host = endpoint.ip,
        proto = endpoint.transport,
        port = endpoint.port
    )
}
pub fn root_guard_script(
    a: &NetworkAllocation,
    endpoint: &Endpoint,
    outbound: &str,
) -> Result<String> {
    ensure!(
        !outbound.is_empty()
            && outbound.len() <= 15
            && outbound
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)),
        "外联网卡名称无效"
    );
    Ok(format!(
        r#"table inet {table} {{
 comment "{owner}"
 chain forward {{
  type filter hook forward priority filter; policy accept;
  iifname "{veth}" ip saddr {source} ip daddr {host} {proto} dport {port} oifname "{outbound}" accept
  oifname "{veth}" ip daddr {source} ip saddr {host} {proto} sport {port} ct state established,related accept
  iifname "{veth}" drop
  oifname "{veth}" drop
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr {source} oifname "{outbound}" ip daddr {host} {proto} dport {port} masquerade
 }}
}}
"#,
        table = a.table,
        owner = a.owner_tag(),
        veth = a.host_veth,
        source = a.worker_ip,
        host = endpoint.ip,
        proto = endpoint.transport,
        port = endpoint.port
    ))
}
pub fn route_overlaps_pool(dst: &str) -> bool {
    let Some((ip, prefix)) = dst.split_once('/') else {
        return dst
            .parse::<Ipv4Addr>()
            .is_ok_and(|ip| ip.octets()[..2] == [10, 231]);
    };
    let (Ok(ip), Ok(prefix)) = (ip.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return false;
    };
    if prefix == 0 || prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix.min(16));
    u32::from(ip) & mask == u32::from(Ipv4Addr::new(10, 231, 0, 0)) & mask
}
#[derive(Debug, thiserror::Error)]
#[error("预检资源清理失败：{0}")]
pub struct PreflightCleanupFailure(pub String);
pub async fn preflight() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "服务端仅支持 Linux");
    let status = std::fs::read_to_string("/proc/self/status")?;
    let capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .context("无法核对进程能力")?;
    for (bit, name) in [
        (0, "CHOWN"),
        (1, "DAC_OVERRIDE"),
        (3, "FOWNER"),
        (5, "KILL"),
        (6, "SETGID"),
        (7, "SETUID"),
        (8, "SETPCAP"),
        (12, "NET_ADMIN"),
        (21, "SYS_ADMIN"),
    ] {
        ensure!(capabilities & (1_u64 << bit) != 0, "缺少必要能力：{name}");
    }
    ensure!(
        tokio::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .await?
            .trim()
            == "1",
        "宿主尚未准备 IPv4 转发，请由部署者显式设置"
    );
    ensure!(
        std::path::Path::new("/dev/net/tun").exists(),
        "缺少 TUN 设备"
    );
    for tool in [
        "ip", "nft", "openvpn", "setpriv", "nsenter", "unshare", "mount", "umount", "chown",
        "stat", "id", "kill",
    ] {
        let command = Command::new("sh")
            .args(["-c", "command -v \"$1\"", "sh", tool])
            .env_clear()
            .env("PATH", CHILD_PATH)
            .output()
            .await?;
        ensure!(command.status.success(), "缺少必要系统工具：{tool}");
    }
    let routes = run_command("ip", &["-j", "-4", "route", "show", "table", "all"]).await?;
    let routes: Vec<serde_json::Value> = serde_json::from_slice(&routes)?;
    ensure!(
        !routes
            .iter()
            .filter_map(|v| v["dst"].as_str())
            .any(route_overlaps_pool),
        "工作地址池与既有路由冲突"
    );
    let allocation = NetworkAllocation::new(Uuid::new_v4(), WorkerId::default(), 254);
    ensure!(
        !allocation.marker_path().exists()
            && !std::path::Path::new(&format!("/run/netns/{}", allocation.namespace)).exists()
            && !std::path::Path::new(&format!("/sys/class/net/{}", allocation.host_veth)).exists()
            && run_command("nft", &["list", "table", "inet", &allocation.table])
                .await
                .is_err(),
        "预检资源名称已存在，拒绝覆盖"
    );
    std::fs::create_dir_all("/run/netns")?;
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(allocation.marker_path())?;
    marker.write_all(allocation.owner_tag().as_bytes())?;
    marker.sync_all()?;
    drop(marker);
    let result: Result<()> = async {
        run_command("ip", &["netns", "add", &allocation.namespace]).await?;
        in_namespace(
            &allocation,
            "ip",
            &["tuntap", "add", "dev", "vap_probe", "mode", "tun"],
        )
        .await?;
        let executable = std::env::current_exe()?;
        run_command(
            "nsenter",
            &[
                &format!("--net=/run/netns/{}", allocation.namespace),
                "unshare",
                "--mount",
                "--propagation",
                "private",
                executable.to_str().context("程序路径编码无效")?,
                "namespace-setup",
            ],
        )
        .await?;
        Ok(())
    }
    .await;
    cleanup(&allocation)
        .await
        .map_err(|error| PreflightCleanupFailure(error.to_string()))?;
    result.context("网络空间或私有挂载预检失败，请检查能力和专用安全配置")?;
    Ok(())
}
pub async fn run_command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("LANG", "C")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("系统命令超时")??;
    ensure!(
        output.status.success(),
        "系统命令 {program} 失败，状态 {}",
        output.status
    );
    Ok(output.stdout)
}
pub async fn run_with_stdin(program: &str, args: &[&str], input: &[u8]) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let operation = async {
        let mut stdin = child.stdin.take().context("系统命令输入不可用")?;
        stdin.write_all(input).await?;
        drop(stdin);
        ensure!(child.wait().await?.success(), "系统命令 {program} 失败");
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .context("系统命令超时")?
}
pub async fn in_namespace(a: &NetworkAllocation, program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let namespace = format!("--net=/run/netns/{}", a.namespace);
    let mut full = vec![namespace.as_str(), program];
    full.extend_from_slice(args);
    run_command("nsenter", &full).await
}
pub async fn setup(a: &NetworkAllocation, endpoint: &Endpoint, outbound: &str) -> Result<()> {
    setup_with_binary(a, endpoint, outbound, &std::env::current_exe()?).await
}
pub async fn setup_with_binary(
    a: &NetworkAllocation,
    endpoint: &Endpoint,
    outbound: &str,
    executable: &std::path::Path,
) -> Result<()> {
    endpoint.validate()?;
    let root = root_guard_script(a, endpoint, outbound)?;
    ensure!(
        !std::path::Path::new(&format!("/run/netns/{}", a.namespace)).exists()
            && !std::path::Path::new(&format!("/sys/class/net/{}", a.host_veth)).exists()
            && run_command("nft", &["list", "table", "inet", &a.table])
                .await
                .is_err(),
        "资源名称已存在，拒绝修改或接管"
    );
    std::fs::create_dir_all("/run/netns")?;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(a.marker_path())?;
    marker.write_all(a.owner_tag().as_bytes())?;
    marker.sync_all()?;
    // 先拒绝端点之外的转发，再创建网络路径；失败由调用者按归属回收。
    run_with_stdin("nft", &["-f", "-"], root.as_bytes()).await?;
    run_command("ip", &["netns", "add", &a.namespace]).await?;
    run_command(
        "ip",
        &[
            "link",
            "add",
            &a.host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &a.worker_veth,
        ],
    )
    .await?;
    run_command(
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/30", a.host_ip),
            "dev",
            &a.host_veth,
        ],
    )
    .await?;
    run_command("ip", &["link", "set", &a.host_veth, "up"]).await?;
    run_command(
        "ip",
        &["link", "set", &a.host_veth, "alias", &a.owner_tag()],
    )
    .await?;
    run_command(
        "ip",
        &["link", "set", &a.worker_veth, "netns", &a.namespace],
    )
    .await?;
    // 私有挂载空间中的 procfs 确保 IPv6 sysctl 指向工作网络空间。
    let namespace = format!("--net=/run/netns/{}", a.namespace);
    let exe = executable.to_str().context("程序路径不是 UTF-8")?;
    run_command(
        "nsenter",
        &[
            &namespace,
            "unshare",
            "--mount",
            "--propagation",
            "private",
            exe,
            "namespace-setup",
        ],
    )
    .await?;
    in_namespace(a, "ip", &["link", "set", "lo", "up"]).await?;
    in_namespace(
        a,
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/30", a.worker_ip),
            "dev",
            &a.worker_veth,
        ],
    )
    .await?;
    in_namespace(a, "ip", &["link", "set", &a.worker_veth, "up"]).await?;
    in_namespace(
        a,
        "ip",
        &[
            "route",
            "add",
            &format!("{}/32", endpoint.ip),
            "via",
            &a.host_ip.to_string(),
        ],
    )
    .await?;
    let guard = worker_guard_script(a, endpoint);
    run_with_stdin("nsenter", &[&namespace, "nft", "-f", "-"], guard.as_bytes()).await?;
    Ok(())
}
pub async fn configure_namespace() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::metadata("/proc/self/ns/net")?;
    let root = std::fs::metadata("/proc/1/ns/net")?;
    ensure!(
        current.ino() != root.ino() || current.dev() != root.dev(),
        "拒绝在初始网络空间配置内核参数"
    );
    let mut owned = false;
    for entry in std::fs::read_dir("/run/netns")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("vap_") || name.ends_with(".vap-owner") {
            continue;
        }
        let marker = entry.path().with_file_name(format!("{name}.vap-owner"));
        let Ok(metadata) = std::fs::symlink_metadata(&marker) else {
            continue;
        };
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o600 {
            continue;
        }
        let ns = std::fs::metadata(entry.path())?;
        if ns.ino() == current.ino() && ns.dev() == current.dev() {
            owned = true;
            break;
        }
    }
    ensure!(owned, "当前网络空间缺少实例归属凭据");
    run_command("mount", &["-t", "proc", "proc", "/proc"]).await?;
    for name in ["all", "default", "lo"] {
        tokio::fs::write(
            format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"),
            b"1\n",
        )
        .await?;
    }
    Ok(())
}
pub async fn install_tunnel_routes(a: &NetworkAllocation) -> Result<()> {
    in_namespace(a, "ip", &["route", "replace", "0.0.0.0/1", "dev", "tun0"]).await?;
    in_namespace(a, "ip", &["route", "replace", "128.0.0.0/1", "dev", "tun0"]).await?;
    Ok(())
}
pub async fn cleanup(a: &NetworkAllocation) -> Result<()> {
    if !a.marker_path().exists() {
        ensure!(
            !std::path::Path::new(&format!("/run/netns/{}", a.namespace)).exists()
                && !std::path::Path::new(&format!("/sys/class/net/{}", a.host_veth)).exists()
                && run_command("nft", &["list", "table", "inet", &a.table])
                    .await
                    .is_err(),
            "缺少归属凭据，拒绝删除现有资源"
        );
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(a.marker_path())?;
    ensure!(metadata.is_file() && metadata.len() < 256, "归属凭据非法");
    ensure!(
        std::fs::read_to_string(a.marker_path())? == a.owner_tag(),
        "资源归属不一致，拒绝清理"
    );
    let mut errors = Vec::new();
    if std::path::Path::new(&format!("/sys/class/net/{}", a.host_veth)).exists()
        && let Err(e) = run_command("ip", &["link", "delete", &a.host_veth]).await
    {
        errors.push(e.to_string());
    }
    if std::path::Path::new(&format!("/run/netns/{}", a.namespace)).exists() {
        let pids = run_command("ip", &["netns", "pids", &a.namespace]).await?;
        ensure!(
            pids.iter().all(u8::is_ascii_whitespace),
            "网络空间仍有存活进程，拒绝仅删除名称"
        );
        if let Err(e) = run_command("ip", &["netns", "delete", &a.namespace]).await {
            errors.push(e.to_string());
        }
    }
    if run_command("nft", &["list", "table", "inet", &a.table])
        .await
        .is_ok()
        && let Err(e) = run_command("nft", &["delete", "table", "inet", &a.table]).await
    {
        errors.push(e.to_string());
    }
    ensure!(errors.is_empty(), "资源清理失败：{}", errors.join("；"));
    std::fs::remove_file(a.marker_path())?;
    Ok(())
}
