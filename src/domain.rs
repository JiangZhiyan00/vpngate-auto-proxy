//! 节点、验证状态及资源归属。公网地址判定参考固定上游提交的同名函数。
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeId(String);
impl NodeId {
    pub fn from_endpoint(endpoint: &Endpoint) -> Self {
        Self(
            blake3::hash(
                format!(
                    "vpngate:{}:{}:{}",
                    endpoint.ip, endpoint.port, endpoint.transport
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string(),
        )
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for NodeId {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(s))
        } else {
            Err("节点标识须为 64 位小写十六进制")
        }
    }
}
impl From<NodeId> for String {
    fn from(id: NodeId) -> Self {
        id.0
    }
}
impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}
impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub transport: Transport,
}
impl Endpoint {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            is_public_ipv4(self.ip) && self.port != 0,
            "节点端点不是有效的公网 IPv4 地址与端口"
        );
        Ok(())
    }
    pub fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

/// 来源指标不是本机实测结果；缺失及非法单项保持未知。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQualityMetrics {
    #[serde(default, deserialize_with = "quality_integer")]
    pub score: Option<u64>,
    #[serde(default, deserialize_with = "quality_positive")]
    pub speed_bps: Option<u64>,
    #[serde(default, deserialize_with = "quality_positive")]
    pub ping_ms: Option<u64>,
    #[serde(default, deserialize_with = "quality_integer")]
    pub sessions: Option<u64>,
    #[serde(default, deserialize_with = "quality_integer")]
    pub uptime_ms: Option<u64>,
}
fn quality_integer<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Ok(serde_json::Value::deserialize(deserializer)?.as_u64())
}
fn quality_positive<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Ok(quality_integer(deserializer)?.filter(|value| *value > 0))
}
impl SourceQualityMetrics {
    pub fn values(self) -> [Option<u64>; 5] {
        [
            self.score,
            self.speed_bps.filter(|v| *v > 0),
            self.ping_ms.filter(|v| *v > 0),
            self.sessions,
            self.uptime_ms,
        ]
    }
    pub fn parse(value: &str, positive: bool) -> Option<u64> {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        value.parse::<u64>().ok().filter(|v| !positive || *v > 0)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnNode {
    #[serde(default)]
    pub quality: SourceQualityMetrics,
    pub id: NodeId,
    pub endpoint: Endpoint,
    pub source_hostname: String,
    pub country: String,
    pub profile: String,
    pub profile_digest: String,
    pub source_fetched_at: DateTime<Utc>,
    pub present: bool,
    pub last_attempt_at: Option<DateTime<Utc>>,
}
impl fmt::Debug for VpnNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnNode")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}
impl VpnNode {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.endpoint.validate()?;
        anyhow::ensure!(
            self.id == NodeId::from_endpoint(&self.endpoint),
            "节点标识与端点不一致"
        );
        anyhow::ensure!(self.profile.len() <= 256 * 1024, "节点配置超过限额");
        anyhow::ensure!(
            self.profile_digest.len() == 64
                && self
                    .profile_digest
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
            "配置摘要无效"
        );
        anyhow::ensure!(
            blake3::hash(self.profile.as_bytes()).to_hex().as_str() == self.profile_digest,
            "配置内容与摘要不一致"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Port,
    Tunnel,
    Exit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    NotTested,
    Running,
    Succeeded,
    Failed,
    Expired,
    NotApplicable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub node_id: NodeId,
    pub profile_digest: String,
    pub layer: Layer,
    pub outcome: Outcome,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub attempts: u32,
    pub status: Option<u16>,
    pub expires_at: Option<DateTime<Utc>>,
    pub failure_reason: Option<String>,
}
impl CheckResult {
    pub fn is_usable_for(&self, node: &VpnNode, now: DateTime<Utc>) -> bool {
        self.node_id == node.id
            && self.profile_digest == node.profile_digest
            && self.layer == Layer::Exit
            && self.current_outcome(now) == Outcome::Succeeded
            && self.expires_at.is_some_and(|time| time > now)
    }
    pub fn current_outcome(&self, now: DateTime<Utc>) -> Outcome {
        if self.outcome == Outcome::Succeeded && self.expires_at.is_some_and(|v| v <= now) {
            Outcome::Expired
        } else {
            self.outcome
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub schema_version: u32,
    pub source_url: String,
    pub fetched_at: DateTime<Utc>,
    pub nodes: Vec<VpnNode>,
    pub stats: SourceStats,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStats {
    pub rows_seen: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub unsupported: usize,
    pub conflicts: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerId(pub Uuid);
impl Default for WorkerId {
    fn default() -> Self {
        Self(Uuid::new_v4())
    }
}
impl WorkerId {
    pub fn short(self) -> String {
        self.0.simple().to_string()[..8].into()
    }
}
impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRole {
    Candidate,
    Pending,
    Active,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Allocated,
    Connecting,
    Validating,
    Active,
    Completed,
    Stopping,
    Cleaned,
}
impl WorkerState {
    pub fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Allocated, Self::Connecting | Self::Stopping)
                | (Self::Connecting, Self::Validating | Self::Stopping)
                | (
                    Self::Validating,
                    Self::Active | Self::Completed | Self::Stopping
                )
                | (Self::Active | Self::Completed, Self::Stopping)
                | (Self::Stopping, Self::Cleaned)
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub started: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRecord {
    pub worker_id: WorkerId,
    pub instance_id: Uuid,
    pub node_id: NodeId,
    pub profile_digest: String,
    pub role: WorkerRole,
    pub state: WorkerState,
    pub namespace: String,
    pub host_veth: String,
    pub rules_table: String,
    pub pid: u32,
    pub process_start: String,
    pub processes: Vec<ProcessIdentity>,
    pub socket_path: PathBuf,
}
impl WorkerRecord {
    pub fn transition(&mut self, next: WorkerState) -> anyhow::Result<()> {
        anyhow::ensure!(self.state.permits(next), "工作进程状态转换非法");
        if next == WorkerState::Active {
            anyhow::ensure!(
                self.role == WorkerRole::Pending,
                "只有待启用工作进程可提升为活动"
            );
            self.role = WorkerRole::Active;
        }
        self.state = next;
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Starting,
    Fetching,
    Validating,
    Ready,
    Waiting,
    Switching,
    Stopping,
    Stopped,
}
#[derive(Debug, Serialize)]
pub struct Event {
    pub level: crate::logging::LogLevel,
    pub timestamp: DateTime<chrono::FixedOffset>,
    pub event_type: String,
    pub node_id: Option<NodeId>,
    pub worker_id: Option<WorkerId>,
    pub state: ServiceState,
    pub reason: Option<String>,
    pub elapsed_ms: u64,
}

pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}
