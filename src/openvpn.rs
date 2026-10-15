//! 白名单配置解析移植自固定参考提交，连接端点由来源与辅助协议共同固定。

use crate::domain::{Endpoint, Transport, is_public_ipv4};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
};

use thiserror::Error;
use zeroize::Zeroize as _;

const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const MAX_BLOCK_BYTES: usize = 96 * 1024;
pub const GENERATED_SAFETY: &str = "script-security 1\nroute-noexec\nroute-nopull\nallow-compression no\nping 5\npull-filter accept \"ifconfig \"\npull-filter accept \"topology \"\npull-filter accept \"peer-id \"\npull-filter accept \"cipher \"\npull-filter accept \"protocol-flags \"\npull-filter ignore \"\"\n";

/// A locally regenerated profile that contains no external file or script references.
#[derive(Clone)]
pub struct SanitizedOpenVpn {
    rendered: String,
    remote: SocketAddrV4,
    transport: Transport,
    digest: blake3::Hash,
}

impl SanitizedOpenVpn {
    /// Returns the complete sanitized profile for the privileged helper.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }

    /// Returns the validated TCP VPN endpoint.
    #[must_use]
    pub const fn remote(&self) -> SocketAddrV4 {
        self.remote
    }
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Returns the digest used in stable node identity.
    #[must_use]
    pub const fn digest(&self) -> blake3::Hash {
        self.digest
    }
}

impl fmt::Debug for SanitizedOpenVpn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedOpenVpn")
            .field("remote", &self.remote)
            .field("digest", &self.digest.to_hex().as_str())
            .finish_non_exhaustive()
    }
}

impl Drop for SanitizedOpenVpn {
    fn drop(&mut self) {
        self.rendered.zeroize();
    }
}

/// Why an untrusted `OpenVPN` profile was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OpenVpnConfigError {
    #[error("profile exceeds the {MAX_PROFILE_BYTES}-byte limit")]
    TooLarge,
    #[error("profile is not valid UTF-8")]
    InvalidUtf8,
    #[error("profile line exceeds the {MAX_LINE_BYTES}-byte limit")]
    LineTooLong,
    #[error("unsupported OpenVPN directive: {0}")]
    UnsupportedDirective(String),
    #[error("dangerous OpenVPN directive: {0}")]
    DangerousDirective(String),
    #[error("OpenVPN profile references an external file: {0}")]
    ExternalFile(String),
    #[error("仅支持一致的 IPv4 TCP 或 UDP 承载协议")]
    UnsupportedProtocol,
    #[error("OpenVPN profile must use dev tun")]
    InvalidDevice,
    #[error("OpenVPN profile has an invalid remote directive")]
    InvalidRemote,
    #[error("OpenVPN remote does not match the VPN Gate CSV address")]
    RemoteMismatch,
    #[error("missing required inline block: {0}")]
    MissingInlineBlock(&'static str),
    #[error("invalid or unterminated inline block: {0}")]
    InvalidInlineBlock(String),
    #[error("invalid value for OpenVPN directive: {0}")]
    InvalidValue(String),
}

/// Parses and regenerates a downloaded `OpenVPN` profile using a fixed directive allowlist.
pub fn sanitize_openvpn(
    input: &[u8],
    expected_ip: Ipv4Addr,
) -> Result<SanitizedOpenVpn, OpenVpnConfigError> {
    sanitize_openvpn_with_policy(input, expected_ip, false)
}

/// 仅在部署者明确启用时接受 VPN Gate 的固定旧算法组合。
pub fn sanitize_openvpn_with_policy(
    input: &[u8],
    expected_ip: Ipv4Addr,
    allow_legacy_vpngate_crypto: bool,
) -> Result<SanitizedOpenVpn, OpenVpnConfigError> {
    if input.len() > MAX_PROFILE_BYTES {
        return Err(OpenVpnConfigError::TooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| OpenVpnConfigError::InvalidUtf8)?;
    if text.lines().any(|line| line.len() > MAX_LINE_BYTES) {
        return Err(OpenVpnConfigError::LineTooLong);
    }

    let mut blocks = BTreeMap::<String, String>::new();
    let mut options = BTreeSet::<String>::new();
    let mut remote = None;
    let mut top_protocol = None;
    let mut remote_protocol = None;
    let mut saw_tun = false;
    let mut lines = text.lines();

    while let Some(raw_line) = lines.next() {
        let line = raw_line.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(block_name) = opening_block(line) {
            if !matches!(block_name, "ca" | "cert" | "key" | "tls-auth" | "tls-crypt") {
                return Err(OpenVpnConfigError::UnsupportedDirective(format!(
                    "<{block_name}>"
                )));
            }
            let close = format!("</{block_name}>");
            let mut body = String::new();
            let mut closed = false;
            for block_line in lines.by_ref() {
                let block_line = block_line.trim_end_matches('\r');
                if block_line.trim() == close {
                    closed = true;
                    break;
                }
                if opening_block(block_line.trim()).is_some() || block_line.as_bytes().contains(&0)
                {
                    return Err(OpenVpnConfigError::InvalidInlineBlock(
                        block_name.to_owned(),
                    ));
                }
                if body
                    .len()
                    .saturating_add(block_line.len())
                    .saturating_add(1)
                    > MAX_BLOCK_BYTES
                {
                    return Err(OpenVpnConfigError::InvalidInlineBlock(
                        block_name.to_owned(),
                    ));
                }
                body.push_str(block_line);
                body.push('\n');
            }
            if !closed
                || body.trim().is_empty()
                || blocks.insert(block_name.to_owned(), body).is_some()
            {
                return Err(OpenVpnConfigError::InvalidInlineBlock(
                    block_name.to_owned(),
                ));
            }
            continue;
        }

        let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
        let Some(directive) = tokens.first().copied() else {
            continue;
        };
        let directive = directive.to_ascii_lowercase();

        if is_dangerous(&directive) {
            return Err(OpenVpnConfigError::DangerousDirective(directive));
        }

        match directive.as_str() {
            "proto" => {
                let protocol = parse_transport(exactly_one_value(&tokens, "proto")?)?;
                if top_protocol.is_some_and(|previous| previous != protocol) {
                    return Err(OpenVpnConfigError::UnsupportedProtocol);
                }
                top_protocol = Some(protocol);
            }
            "dev" => {
                if exactly_one_value(&tokens, "dev")? != "tun" {
                    return Err(OpenVpnConfigError::InvalidDevice);
                }
                saw_tun = true;
            }
            "dev-type" => {
                if exactly_one_value(&tokens, "dev-type")? != "tun" {
                    return Err(OpenVpnConfigError::InvalidDevice);
                }
            }
            "remote" => {
                if remote.is_some() || !(3..=4).contains(&tokens.len()) {
                    return Err(OpenVpnConfigError::InvalidRemote);
                }
                let host = tokens[1]
                    .parse::<Ipv4Addr>()
                    .map_err(|_| OpenVpnConfigError::InvalidRemote)?;
                if host != expected_ip || !is_public_ipv4(host) {
                    return Err(OpenVpnConfigError::RemoteMismatch);
                }
                let port = tokens[2]
                    .parse::<u16>()
                    .ok()
                    .and_then(NonZeroU16::new)
                    .ok_or(OpenVpnConfigError::InvalidRemote)?;
                remote_protocol = tokens
                    .get(3)
                    .map(|value| parse_transport(value))
                    .transpose()?;
                remote = Some(SocketAddrV4::new(host, port.get()));
            }
            "ca" | "cert" | "key" | "tls-auth" | "tls-crypt" | "pkcs12" => {
                return Err(OpenVpnConfigError::ExternalFile(directive));
            }
            "cipher"
            | "auth"
            | "data-ciphers"
            | "data-ciphers-fallback"
            | "tls-version-min"
            | "tls-cipher" => {
                let value = exactly_one_value(&tokens, &directive)?;
                if !is_safe_crypto_value(value)
                    || !(crypto_allowed(&directive, value)
                        || (allow_legacy_vpngate_crypto
                            && matches!(
                                (directive.as_str(), value),
                                ("cipher" | "data-ciphers", "AES-128-CBC") | ("auth", "SHA1")
                            )))
                {
                    return Err(OpenVpnConfigError::InvalidValue(directive));
                }
                options.insert(format!("{directive} {value}"));
            }
            "key-direction" => {
                let value = exactly_one_value(&tokens, "key-direction")?;
                if !matches!(value, "0" | "1") {
                    return Err(OpenVpnConfigError::InvalidValue(directive));
                }
                options.insert(format!("key-direction {value}"));
            }
            "remote-cert-tls" => {
                if exactly_one_value(&tokens, "remote-cert-tls")? != "server" {
                    return Err(OpenVpnConfigError::InvalidValue(directive));
                }
                options.insert("remote-cert-tls server".to_owned());
            }
            "client" | "tls-client" | "nobind" | "persist-key" | "persist-tun" | "pull"
            | "auth-nocache" => ensure_no_values(&tokens, &directive)?,
            "resolv-retry"
            | "connect-retry"
            | "connect-retry-max"
            | "connect-timeout"
            | "server-poll-timeout"
            | "verb"
            | "mute" => {
                validate_ignored_scalar(&tokens, &directive)?;
            }
            "setenv" if tokens.as_slice() == ["setenv", "opt", "block-outside-dns"] => {}
            _ => return Err(OpenVpnConfigError::UnsupportedDirective(directive)),
        }
    }

    let legacy = [
        "cipher AES-128-CBC",
        "data-ciphers AES-128-CBC",
        "auth SHA1",
    ];
    if options
        .iter()
        .any(|option| legacy.contains(&option.as_str()))
        && (!allow_legacy_vpngate_crypto
            || !legacy.iter().all(|option| options.contains(*option))
            || options.iter().any(|option| {
                (option.starts_with("cipher ")
                    || option.starts_with("data-ciphers ")
                    || option.starts_with("auth "))
                    && !legacy.contains(&option.as_str())
            }))
    {
        return Err(OpenVpnConfigError::InvalidValue("旧算法组合".into()));
    }
    if top_protocol
        .zip(remote_protocol)
        .is_some_and(|(a, b)| a != b)
    {
        return Err(OpenVpnConfigError::UnsupportedProtocol);
    }
    let transport = remote_protocol.or(top_protocol).unwrap_or(Transport::Udp);
    if !saw_tun {
        return Err(OpenVpnConfigError::InvalidDevice);
    }
    let remote = remote.ok_or(OpenVpnConfigError::InvalidRemote)?;
    for required in ["ca", "cert", "key"] {
        if !blocks.contains_key(required) {
            return Err(OpenVpnConfigError::MissingInlineBlock(required));
        }
    }

    let protocol = if transport == Transport::Tcp {
        "tcp4-client"
    } else {
        "udp4"
    };
    let mut rendered = format!(
        "client\ndev tun\nproto {protocol}\nremote {} {} {protocol}\nnobind\npersist-key\npersist-tun\nauth-nocache\nverb 0\n",
        remote.ip(),
        remote.port()
    );
    if !options.iter().any(|v| v.starts_with("tls-version-min ")) {
        options.insert("tls-version-min 1.2".to_owned());
    }
    if !options.iter().any(|v| v.starts_with("data-ciphers ")) {
        options.insert("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305".to_owned());
    }
    options.insert("remote-cert-tls server".to_owned());
    if !options.iter().any(|v| v.starts_with("auth ")) {
        options.insert("auth SHA256".to_owned());
    }
    for option in options {
        rendered.push_str(&option);
        rendered.push('\n');
    }
    for block_name in ["ca", "cert", "key", "tls-auth", "tls-crypt"] {
        if let Some(body) = blocks.get(block_name) {
            rendered.push('<');
            rendered.push_str(block_name);
            rendered.push_str(">\n");
            rendered.push_str(body);
            rendered.push_str("</");
            rendered.push_str(block_name);
            rendered.push_str(">\n");
        }
    }
    rendered.push_str(GENERATED_SAFETY);
    let digest = blake3::hash(rendered.as_bytes());

    Ok(SanitizedOpenVpn {
        rendered,
        remote,
        transport,
        digest,
    })
}

pub fn validate_regenerated(
    input: &str,
    endpoint: &Endpoint,
) -> Result<SanitizedOpenVpn, OpenVpnConfigError> {
    validate_regenerated_with_policy(input, endpoint, false)
}

pub fn validate_regenerated_with_policy(
    input: &str,
    endpoint: &Endpoint,
    allow_legacy_vpngate_crypto: bool,
) -> Result<SanitizedOpenVpn, OpenVpnConfigError> {
    let original = input
        .strip_suffix(GENERATED_SAFETY)
        .ok_or_else(|| OpenVpnConfigError::InvalidValue("本地安全配置缺失".into()))?;
    let parsed = sanitize_openvpn_with_policy(
        original.as_bytes(),
        endpoint.ip,
        allow_legacy_vpngate_crypto,
    )?;
    if parsed.remote().port() != endpoint.port
        || parsed.transport() != endpoint.transport
        || parsed.as_str() != input
    {
        return Err(OpenVpnConfigError::RemoteMismatch);
    }
    Ok(parsed)
}
fn parse_transport(value: &str) -> Result<Transport, OpenVpnConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => Ok(Transport::Tcp),
        "udp" | "udp4" => Ok(Transport::Udp),
        _ => Err(OpenVpnConfigError::UnsupportedProtocol),
    }
}
fn crypto_allowed(directive: &str, value: &str) -> bool {
    match directive {
        "cipher" | "data-ciphers" | "data-ciphers-fallback" => value
            .split(':')
            .all(|v| matches!(v, "AES-128-GCM" | "AES-256-GCM" | "CHACHA20-POLY1305")),
        "auth" => matches!(value, "SHA256" | "SHA384" | "SHA512"),
        "tls-version-min" => matches!(value, "1.2" | "1.3"),
        "tls-cipher" => value.split(':').all(|v| {
            v.starts_with("ECDHE-")
                && v.contains("-GCM-")
                && (v.ends_with("SHA256") || v.ends_with("SHA384"))
        }),
        _ => false,
    }
}

fn opening_block(line: &str) -> Option<&str> {
    line.strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .filter(|value| !value.starts_with('/') && !value.is_empty())
}

fn exactly_one_value<'a>(
    tokens: &'a [&str],
    directive: &str,
) -> Result<&'a str, OpenVpnConfigError> {
    match tokens {
        [_, value] => Ok(value),
        _ => Err(OpenVpnConfigError::InvalidValue(directive.to_owned())),
    }
}

fn ensure_no_values(tokens: &[&str], directive: &str) -> Result<(), OpenVpnConfigError> {
    if tokens.len() == 1 {
        Ok(())
    } else {
        Err(OpenVpnConfigError::InvalidValue(directive.to_owned()))
    }
}

fn validate_ignored_scalar(tokens: &[&str], directive: &str) -> Result<(), OpenVpnConfigError> {
    if tokens.len() == 2
        && tokens[1].len() <= 16
        && tokens[1]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(OpenVpnConfigError::InvalidValue(directive.to_owned()))
    }
}

fn is_safe_crypto_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b',' | b'.')
        })
}

fn is_dangerous(directive: &str) -> bool {
    matches!(
        directive,
        "up" | "down"
            | "route-up"
            | "route-pre-down"
            | "ipchange"
            | "client-connect"
            | "client-disconnect"
            | "learn-address"
            | "auth-user-pass-verify"
            | "tls-verify"
            | "plugin"
            | "script-security"
            | "management"
            | "management-client"
            | "management-external-key"
            | "management-external-cert"
            | "management-query-passwords"
            | "management-hold"
            | "daemon"
            | "log"
            | "log-append"
            | "status"
            | "writepid"
            | "chroot"
            | "cd"
            | "user"
            | "group"
            | "route"
            | "route-ipv6"
            | "redirect-gateway"
            | "ifconfig"
            | "ifconfig-ipv6"
            | "socks-proxy"
            | "http-proxy"
            | "auth-user-pass"
    )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

    fn valid_profile() -> String {
        "client\ndev tun\nproto tcp\nremote 1.2.3.4 443\ncipher AES-128-GCM\nauth SHA256\n<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n".to_owned()
    }

    #[test]
    fn sanitizes_tcp_profile_and_is_stable() {
        let first = sanitize_openvpn(valid_profile().as_bytes(), IP).expect("valid profile");
        let second = sanitize_openvpn(valid_profile().as_bytes(), IP).expect("valid profile");
        assert_eq!(first.remote(), SocketAddrV4::new(IP, 443));
        assert_eq!(first.digest(), second.digest());
        assert!(first.as_str().contains("script-security 1"));
        let endpoint = Endpoint {
            ip: IP,
            port: 443,
            transport: Transport::Tcp,
        };
        assert!(validate_regenerated(first.as_str(), &endpoint).is_ok());
    }

    #[test]
    fn legacy_vpngate_crypto_requires_opt_in_and_exact_combination() {
        let legacy = valid_profile()
            .replace(
                "cipher AES-128-GCM",
                "cipher AES-128-CBC\ndata-ciphers AES-128-CBC",
            )
            .replace("auth SHA256", "auth SHA1");
        let endpoint = Endpoint {
            ip: IP,
            port: 443,
            transport: Transport::Tcp,
        };
        assert!(sanitize_openvpn(legacy.as_bytes(), IP).is_err());
        let accepted = sanitize_openvpn_with_policy(legacy.as_bytes(), IP, true).unwrap();
        assert!(validate_regenerated(accepted.as_str(), &endpoint).is_err());
        assert!(validate_regenerated_with_policy(accepted.as_str(), &endpoint, true).is_ok());
        for rejected in [
            legacy.replace("auth SHA1", "auth SHA256"),
            legacy.replace("data-ciphers AES-128-CBC", "data-ciphers AES-128-GCM"),
            format!("{legacy}up /tmp/unsafe\n"),
        ] {
            assert!(sanitize_openvpn_with_policy(rejected.as_bytes(), IP, true).is_err());
        }
    }

    #[test]
    fn rejects_scripts_and_external_files() {
        let scripted = valid_profile().replace("client\n", "client\nup /tmp/pwn\n");
        assert!(matches!(
            sanitize_openvpn(scripted.as_bytes(), IP),
            Err(OpenVpnConfigError::DangerousDirective(_))
        ));

        let external = valid_profile().replace("<ca>\nCA\n</ca>", "ca /tmp/ca.pem");
        assert!(matches!(
            sanitize_openvpn(external.as_bytes(), IP),
            Err(OpenVpnConfigError::ExternalFile(_))
        ));
    }

    #[test]
    fn normalizes_udp_and_rejects_contradictory_or_multiple_remotes() {
        let udp = valid_profile().replace("proto tcp", "proto udp");
        assert_eq!(
            sanitize_openvpn(udp.as_bytes(), IP).unwrap().transport(),
            Transport::Udp
        );
        let implicit = valid_profile().replace("proto tcp\n", "");
        assert_eq!(
            sanitize_openvpn(implicit.as_bytes(), IP)
                .unwrap()
                .transport(),
            Transport::Udp
        );
        for input in [
            valid_profile().replace("443\n", "443 udp\n"),
            valid_profile() + "remote 1.2.3.4 444\n",
            valid_profile().replace("remote 1.2.3.4", "remote example.com"),
        ] {
            assert!(sanitize_openvpn(input.as_bytes(), IP).is_err());
        }
    }
    #[test]
    fn rejects_crypto_downgrades_compression_and_external_effects() {
        for line in [
            "tls-version-min 1.0",
            "cipher BF-CBC",
            "data-ciphers-fallback AES-128-CBC",
            "auth SHA1",
            "comp-lzo",
            "plugin exploit",
            "management /tmp/x unix",
            "route 0.0.0.0 0.0.0.0",
            "http-proxy 8.8.8.8 80",
        ] {
            assert!(
                sanitize_openvpn((valid_profile() + line + "\n").as_bytes(), IP).is_err(),
                "{line}"
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_profiles_never_panic(input in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _result = sanitize_openvpn(&input, IP);
        }
    }
}
