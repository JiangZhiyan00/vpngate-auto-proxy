//! 来源获取和有界 CSV 解析裁剪自固定参考提交，直接访问显式来源。
use crate::{
    domain::{Endpoint, NodeId, SourceSnapshot, SourceStats, VpnNode, is_public_ipv4},
    openvpn::sanitize_openvpn_with_policy,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use futures_util::StreamExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    time::Duration,
};
use thiserror::Error;
use zeroize::Zeroizing;

const EXPECTED_HEADERS: [&str; 15] = [
    "HostName",
    "IP",
    "Score",
    "Ping",
    "Speed",
    "CountryLong",
    "CountryShort",
    "NumVpnSessions",
    "Uptime",
    "TotalUsers",
    "TotalTraffic",
    "LogType",
    "Operator",
    "Message",
    "OpenVPN_ConfigData_Base64",
];
#[derive(Debug, Clone, Copy)]
pub struct CsvLimits {
    pub max_body_bytes: usize,
    pub max_rows: usize,
    pub max_profile_bytes: usize,
}
impl Default for CsvLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 16 * 1024 * 1024,
            max_rows: 20_000,
            max_profile_bytes: 256 * 1024,
        }
    }
}
pub struct ParsedSnapshot {
    pub nodes: Vec<VpnNode>,
    pub stats: SourceStats,
}
#[derive(Debug, Error)]
pub enum VpnGateError {
    #[error("来源网络或响应失败")]
    Request(#[source] reqwest::Error),
    #[error("来源返回 HTTP {0}")]
    Http(reqwest::StatusCode),
    #[error("来源超过响应大小限额")]
    BodyTooLarge,
    #[error("来源不是有效 UTF-8")]
    InvalidUtf8,
    #[error("来源缺少正确的十五字段表头")]
    InvalidHeader,
    #[error("来源超过行数限额")]
    TooManyRows,
    #[error("来源中的单个配置超过解码限额")]
    ProfileTooLarge,
}
pub async fn fetch_snapshot(
    endpoint: &url::Url,
    timeout: Duration,
    limits: CsvLimits,
) -> Result<SourceSnapshot, VpnGateError> {
    fetch_snapshot_with_policy(endpoint, timeout, limits, false).await
}

pub async fn fetch_snapshot_with_policy(
    endpoint: &url::Url,
    timeout: Duration,
    limits: CsvLimits,
    allow_legacy_vpngate_crypto: bool,
) -> Result<SourceSnapshot, VpnGateError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(VpnGateError::Request)?;
    let response = client
        .get(endpoint.clone())
        .send()
        .await
        .map_err(VpnGateError::Request)?;
    if !response.status().is_success() {
        return Err(VpnGateError::Http(response.status()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > limits.max_body_bytes as u64)
    {
        return Err(VpnGateError::BodyTooLarge);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(limits.max_body_bytes.min(256 * 1024)));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(VpnGateError::Request)?;
        if body.len().saturating_add(chunk.len()) > limits.max_body_bytes {
            return Err(VpnGateError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let parsed = parse_snapshot_with_policy(&body, limits, allow_legacy_vpngate_crypto)?;
    let fetched_at = Utc::now();
    let mut nodes = parsed.nodes;
    for node in &mut nodes {
        node.source_fetched_at = fetched_at;
    }
    Ok(SourceSnapshot {
        schema_version: 1,
        source_url: endpoint.to_string(),
        fetched_at,
        nodes,
        stats: parsed.stats,
    })
}
pub fn parse_snapshot(input: &[u8], limits: CsvLimits) -> Result<ParsedSnapshot, VpnGateError> {
    parse_snapshot_with_policy(input, limits, false)
}

pub fn parse_snapshot_with_policy(
    input: &[u8],
    limits: CsvLimits,
    allow_legacy_vpngate_crypto: bool,
) -> Result<ParsedSnapshot, VpnGateError> {
    if input.len() > limits.max_body_bytes {
        return Err(VpnGateError::BodyTooLarge);
    }
    let input = std::str::from_utf8(input).map_err(|_| VpnGateError::InvalidUtf8)?;
    if input.lines().count() > limits.max_rows.saturating_add(3) {
        return Err(VpnGateError::TooManyRows);
    }
    let offset = input
        .find("#HostName,")
        .ok_or(VpnGateError::InvalidHeader)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(&input.as_bytes()[offset + 1..]);
    if reader
        .headers()
        .map_err(|_| VpnGateError::InvalidHeader)?
        .iter()
        .ne(EXPECTED_HEADERS)
    {
        return Err(VpnGateError::InvalidHeader);
    }
    let mut nodes = BTreeMap::<NodeId, VpnNode>::new();
    let mut conflicts = BTreeSet::new();
    let mut stats = SourceStats::default();
    for record in reader.records() {
        if record
            .as_ref()
            .is_ok_and(|r| r.len() == 1 && r.get(0) == Some("*"))
        {
            break;
        }
        stats.rows_seen += 1;
        if stats.rows_seen > limits.max_rows {
            return Err(VpnGateError::TooManyRows);
        }
        let Ok(record) = record else {
            stats.rejected += 1;
            continue;
        };
        if record.len() != 15 {
            stats.rejected += 1;
            continue;
        }
        let encoded = record[14].trim();
        // 在解码前限制最大分配；超限属于整次来源失败，不能静默跳过。
        if encoded.len() > limits.max_profile_bytes.saturating_add(2) / 3 * 4 + 4 {
            return Err(VpnGateError::ProfileTooLarge);
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            stats.rejected += 1;
            continue;
        };
        let decoded = Zeroizing::new(decoded);
        if decoded.len() > limits.max_profile_bytes {
            return Err(VpnGateError::ProfileTooLarge);
        }
        let Ok(ip) = record[1].parse::<Ipv4Addr>() else {
            stats.rejected += 1;
            continue;
        };
        if !is_public_ipv4(ip) {
            stats.rejected += 1;
            continue;
        }
        let Ok(profile) = sanitize_openvpn_with_policy(&decoded, ip, allow_legacy_vpngate_crypto)
        else {
            stats.rejected += 1;
            stats.unsupported += 1;
            continue;
        };
        let endpoint = Endpoint {
            ip,
            port: profile.remote().port(),
            transport: profile.transport(),
        };
        let id = NodeId::from_endpoint(&endpoint);
        let digest = profile.digest().to_hex().to_string();
        if conflicts.contains(&id) {
            stats.rejected += 1;
            continue;
        }
        if let Some(previous) = nodes.get(&id) {
            if previous.profile_digest != digest {
                nodes.remove(&id);
                conflicts.insert(id);
                stats.conflicts += 1;
                stats.rejected += 1;
            }
            continue;
        }
        let Some(hostname) = bounded_text(&record[0], 255) else {
            stats.rejected += 1;
            continue;
        };
        let Some(country) = bounded_text(&record[6], 8) else {
            stats.rejected += 1;
            continue;
        };
        nodes.insert(
            id.clone(),
            VpnNode {
                id,
                endpoint,
                source_hostname: hostname,
                country,
                profile: profile.as_str().to_owned(),
                profile_digest: digest,
                source_fetched_at: Utc::now(),
                present: true,
                last_attempt_at: None,
            },
        );
    }
    stats.accepted = nodes.len();
    Ok(ParsedSnapshot {
        nodes: nodes.into_values().collect(),
        stats,
    })
}
fn bounded_text(value: &str, limit: usize) -> Option<String> {
    (value.len() <= limit && !value.chars().any(char::is_control)).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(protocol: &str) -> String {
        format!(
            "client\ndev tun\nproto {protocol}\nremote 11.53.0.2 1194\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        )
    }
    fn row(host: &str, profile: &str) -> String {
        format!(
            "{host},11.53.0.2,100,20,0,Test,ZZ,0,0,0,0,,,,{}\n",
            STANDARD.encode(profile)
        )
    }
    fn doc(rows: &str) -> String {
        format!("*vpn_servers\n#{}\n{rows}*\n", EXPECTED_HEADERS.join(","))
    }
    #[test]
    fn parses_markers_deduplicates_and_rejects_conflicts() {
        let a = profile("tcp");
        let b = a.replace("CERT", "OTHER-CERT");
        let result = parse_snapshot(
            doc(&(row("one", &a) + &row("display-changed", &a))).as_bytes(),
            CsvLimits::default(),
        )
        .unwrap();
        assert_eq!(result.nodes.len(), 1);
        let result = parse_snapshot(
            doc(&(row("one", &a) + &row("two", &b) + &row("three", &a))).as_bytes(),
            CsvLimits::default(),
        )
        .unwrap();
        assert!(result.nodes.is_empty());
        assert_eq!(result.stats.conflicts, 1);
    }
    #[test]
    fn malformed_rows_are_skipped_but_global_limits_fail_refresh() {
        let input = doc(&("bad,row\n".to_owned() + &row("one", &profile("tcp"))));
        assert_eq!(
            parse_snapshot(input.as_bytes(), CsvLimits::default())
                .unwrap()
                .stats
                .rejected,
            1
        );
        assert!(matches!(
            parse_snapshot(
                input.as_bytes(),
                CsvLimits {
                    max_rows: 1,
                    ..Default::default()
                }
            ),
            Err(VpnGateError::TooManyRows)
        ));
        assert!(matches!(
            parse_snapshot(
                input.as_bytes(),
                CsvLimits {
                    max_profile_bytes: 5,
                    ..Default::default()
                }
            ),
            Err(VpnGateError::ProfileTooLarge)
        ));
        assert!(matches!(
            parse_snapshot(
                input.as_bytes(),
                CsvLimits {
                    max_body_bytes: 5,
                    ..Default::default()
                }
            ),
            Err(VpnGateError::BodyTooLarge)
        ));
        assert!(parse_snapshot(b"#wrong\n", CsvLimits::default()).is_err());
        assert!(
            parse_snapshot(doc("").as_bytes(), CsvLimits::default())
                .unwrap()
                .nodes
                .is_empty()
        );
    }
    #[test]
    fn legacy_source_rows_are_visible_only_with_explicit_policy() {
        let legacy = profile("tcp") + "cipher AES-128-CBC\ndata-ciphers AES-128-CBC\nauth SHA1\n";
        let input = doc(&row("legacy", &legacy));
        let strict = parse_snapshot(input.as_bytes(), CsvLimits::default()).unwrap();
        assert!(strict.nodes.is_empty());
        assert_eq!(strict.stats.unsupported, 1);
        let empty = SourceSnapshot {
            schema_version: 1,
            source_url: "https://www.vpngate.net/api/iphone/".into(),
            fetched_at: Utc::now(),
            nodes: strict.nodes,
            stats: strict.stats,
        };
        assert!(
            crate::service::empty_source_reason(&empty)
                .unwrap()
                .contains("1 条配置不受支持")
        );
        let allowed =
            parse_snapshot_with_policy(input.as_bytes(), CsvLimits::default(), true).unwrap();
        assert_eq!(allowed.nodes.len(), 1);
        assert_eq!(allowed.stats.unsupported, 0);
        let populated = SourceSnapshot {
            nodes: allowed.nodes,
            stats: allowed.stats,
            ..empty
        };
        assert!(crate::service::empty_source_reason(&populated).is_none());
    }
    #[test]
    #[ignore = "需要将公开来源原始响应路径置于 VAP_LIVE_SOURCE_PATH"]
    fn live_source_fixture_has_usable_rows_with_explicit_policy() {
        let path = std::env::var_os("VAP_LIVE_SOURCE_PATH").expect("缺少公开来源样本路径");
        let body = std::fs::read(path).unwrap();
        let strict = parse_snapshot(&body, CsvLimits::default()).unwrap();
        let parsed = parse_snapshot_with_policy(&body, CsvLimits::default(), true).unwrap();
        println!(
            "严格模式：{} 行、{} 个候选、{} 个不兼容；兼容模式：{} 个候选",
            strict.stats.rows_seen,
            strict.stats.accepted,
            strict.stats.unsupported,
            parsed.stats.accepted
        );
        assert!(parsed.stats.rows_seen > 0);
        assert!(
            !parsed.nodes.is_empty(),
            "当前公开来源没有通过配置白名单的节点"
        );
    }
    #[test]
    fn protocol_is_part_of_identity_and_regenerated_material_is_valid() {
        let result = parse_snapshot(
            doc(&(row("tcp", &profile("tcp")) + &row("udp", &profile("udp")))).as_bytes(),
            CsvLimits::default(),
        )
        .unwrap();
        assert_eq!(result.nodes.len(), 2);
        assert_ne!(result.nodes[0].id, result.nodes[1].id);
        for node in result.nodes {
            node.validate().unwrap();
            crate::openvpn::validate_regenerated(&node.profile, &node.endpoint).unwrap();
        }
    }
}
