//! 原生配置读取显式文件；容器环境转换仅由专用入口调用，不采用系统代理环境。
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddrV4,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    pub listen: SocketAddrV4,
    pub credentials_file: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub source_url: Url,
    pub countries: Vec<String>,
    pub timezone: chrono_tz::Tz,
    pub allow_legacy_vpngate_crypto: bool,
    pub source_refresh_seconds: u64,
    pub source_timeout_seconds: u64,
    pub source_cache_ttl_seconds: u64,
    pub candidate_interval_seconds: u64,
    pub candidate_result_ttl_seconds: u64,
    pub candidate_batch_size: usize,
    pub candidate_concurrency: usize,
    pub port_probe_timeout_seconds: u64,
    pub tunnel_timeout_seconds: u64,
    pub exit_check_timeout_seconds: u64,
    pub exit_check_max_attempts: u32,
    pub health_interval_seconds: u64,
    pub health_timeout_seconds: u64,
    pub candidate_retries: u32,
    pub retry_initial_seconds: u64,
    pub retry_max_seconds: u64,
    pub max_connections: usize,
    pub shutdown_timeout_seconds: u64,
    pub exit_check_urls: Vec<Url>,
    pub macos: Option<MacOsConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacOsConfig {
    pub dependency_manifest: PathBuf,
    pub runtime_parent: PathBuf,
    pub worker_uid: u32,
    pub worker_gid: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            listen: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1080),
            credentials_file: None,
            data_dir: "/var/lib/vpngate-auto-proxy".into(),
            runtime_dir: "/run/vpngate-auto-proxy".into(),
            source_url: Url::parse("https://www.vpngate.net/api/iphone/").expect("固定地址有效"),
            countries: Vec::new(),
            timezone: chrono_tz::Asia::Shanghai,
            allow_legacy_vpngate_crypto: false,
            source_refresh_seconds: 1800,
            source_timeout_seconds: 15,
            source_cache_ttl_seconds: 86400,
            candidate_interval_seconds: 900,
            candidate_result_ttl_seconds: 900,
            candidate_batch_size: 20,
            candidate_concurrency: 2,
            port_probe_timeout_seconds: 3,
            tunnel_timeout_seconds: 30,
            exit_check_timeout_seconds: 10,
            exit_check_max_attempts: 3,
            health_interval_seconds: 10,
            health_timeout_seconds: 5,
            candidate_retries: 0,
            retry_initial_seconds: 30,
            retry_max_seconds: 300,
            max_connections: 50,
            shutdown_timeout_seconds: 15,
            exit_check_urls: [
                "https://www.gstatic.com/generate_204",
                "https://cp.cloudflare.com/generate_204",
            ]
            .into_iter()
            .map(|s| Url::parse(s).expect("固定地址有效"))
            .collect(),
            macos: None,
        }
    }
}

impl AppConfig {
    /// 显式容器入口适配环境；原生文件加载不调用此方法。
    pub fn container_from_environment(
        read: impl Fn(&str) -> Result<Option<String>>,
    ) -> Result<Self> {
        let mut value = serde_json::to_value(Self {
            listen: "0.0.0.0:1080".parse().expect("固定容器地址有效"),
            credentials_file: Some("/run/secrets/proxy_credentials".into()),
            data_dir: "/var/lib/vap".into(),
            runtime_dir: "/run/vap".into(),
            ..Self::default()
        })?;
        let fields = value.as_object_mut().expect("配置序列化为对象");
        for (field, current) in fields.iter_mut() {
            let numeric = current.is_number() && field != "schema_version";
            if !numeric
                && !matches!(
                    field.as_str(),
                    "countries"
                        | "timezone"
                        | "source_url"
                        | "exit_check_urls"
                        | "allow_legacy_vpngate_crypto"
                )
            {
                continue;
            }
            let name = format!("VAP_{}", field.to_ascii_uppercase());
            let Some(raw) = read(&name)? else { continue };
            if raw.is_empty() {
                continue;
            }
            if raw.len() > 256 * 1024 {
                bail!("{name} 超过配置长度限制");
            }
            *current = if numeric {
                if !raw.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("{name} 必须为无符号十进制整数");
                }
                serde_json::Value::from(
                    raw.parse::<u64>()
                        .with_context(|| format!("{name} 数值超出范围"))?,
                )
            } else if field == "allow_legacy_vpngate_crypto" {
                serde_json::Value::Bool(match raw.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => bail!("{name} 必须为 true 或 false"),
                })
            } else if field == "countries" || field == "exit_check_urls" {
                let parts: Vec<_> = raw.split(',').map(str::trim).collect();
                if parts.iter().any(|part| part.is_empty()) {
                    bail!("{name} 不允许空列表项");
                }
                serde_json::to_value(parts)?
            } else {
                serde_json::Value::String(raw)
            };
        }
        let config: Self = serde_json::from_value(value).context("容器环境配置格式无效")?;
        config.validate()?;
        Ok(config)
    }

    /// 空列表保持全部来源；配置值和来源代码按大小写不敏感比较。
    pub fn accepts_country(&self, country: &str) -> bool {
        self.countries.is_empty()
            || self
                .countries
                .iter()
                .any(|value| value.eq_ignore_ascii_case(country))
    }
    /// 缓存保留完整来源；只有筛选结果可进入候选目录。
    pub fn selected_source(
        &self,
        source: &crate::domain::SourceSnapshot,
    ) -> crate::domain::SourceSnapshot {
        let mut selected = source.clone();
        selected
            .nodes
            .retain(|node| self.accepts_country(&node.country));
        selected
    }
    pub fn source_empty_reason(&self, source: &crate::domain::SourceSnapshot) -> Option<String> {
        let selected = self.selected_source(source);
        if !source.nodes.is_empty() && selected.nodes.is_empty() {
            Some(format!(
                "来源已获取，但没有符合国家/地区筛选的节点：{}",
                self.countries.join(",")
            ))
        } else {
            crate::service::empty_source_reason(&selected)
        }
    }

    pub fn load(path: &Path) -> Result<(Self, Option<Credentials>)> {
        let config = Self::load_config(path)?;
        let credentials = config
            .credentials_file
            .as_deref()
            .map(Credentials::load)
            .transpose()?;
        Ok((config, credentials))
    }
    /// 受保护父进程只解析公开配置；凭据由降权后的控制进程自行读取。
    pub fn load_config(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).context("无法读取配置文件")?;
        if bytes.len() > 1024 * 1024 {
            bail!("配置文件超过 1 MiB");
        }
        let mut config: Self = serde_json::from_slice(&bytes).context("配置格式或字段无效")?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut config.data_dir, &mut config.runtime_dir] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        if let Some(p) = &mut config.credentials_file
            && p.is_relative()
        {
            *p = base.join(&*p);
        }
        if let Some(macos) = &mut config.macos {
            for path in [&mut macos.dependency_manifest, &mut macos.runtime_parent] {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.countries.len() > 256 {
            bail!("countries 最多允许 256 个国家/地区代码");
        }
        for country in &self.countries {
            if country.len() != 2 || !country.bytes().all(|value| value.is_ascii_alphabetic()) {
                bail!("countries 必须使用两个英文字母的国家/地区代码，例如 JP、SG");
            }
        }

        if self.schema_version != 1 {
            bail!("不支持的配置版本");
        }
        if self.listen.port() == 0
            || self.listen.ip().is_multicast()
            || self.listen.ip().is_broadcast()
        {
            bail!("监听地址或端口无效");
        }
        if !self.listen.ip().is_loopback() && self.credentials_file.is_none() {
            bail!("非回环监听必须提供凭据文件");
        }
        if self.data_dir.as_os_str().is_empty()
            || self.runtime_dir.as_os_str().is_empty()
            || self.data_dir == self.runtime_dir
        {
            bail!("数据目录与运行目录必须非空且不同");
        }
        for (name, value) in [
            ("来源刷新间隔", self.source_refresh_seconds),
            ("来源请求超时", self.source_timeout_seconds),
            ("来源缓存有效期", self.source_cache_ttl_seconds),
            ("候选检测间隔", self.candidate_interval_seconds),
            ("候选有效期", self.candidate_result_ttl_seconds),
            ("端口超时", self.port_probe_timeout_seconds),
            ("隧道超时", self.tunnel_timeout_seconds),
            ("出口超时", self.exit_check_timeout_seconds),
            ("健康间隔", self.health_interval_seconds),
            ("健康超时", self.health_timeout_seconds),
            ("初始退避", self.retry_initial_seconds),
            ("退避上限", self.retry_max_seconds),
            ("停止超时", self.shutdown_timeout_seconds),
        ] {
            if value == 0
                || Instant::now()
                    .checked_add(Duration::from_secs(value))
                    .is_none()
                || i64::try_from(value)
                    .ok()
                    .and_then(chrono::Duration::try_seconds)
                    .and_then(|duration| chrono::Utc::now().checked_add_signed(duration))
                    .is_none()
            {
                bail!("{name}必须为可表示的正整数秒");
            }
        }
        if self.candidate_batch_size == 0
            || self.candidate_concurrency == 0
            || self.candidate_concurrency > 254
            || self.max_connections == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS - 8
            || self.exit_check_max_attempts == 0
        {
            bail!("数量或并发配置无效，网络池最多支持 254 个候选槽");
        }
        if self.health_timeout_seconds >= self.health_interval_seconds {
            bail!("健康检测超时必须小于间隔");
        }
        if self.retry_max_seconds < self.retry_initial_seconds {
            bail!("退避上限不能小于初始值");
        }
        if self.exit_check_urls.is_empty() {
            bail!("检测地址列表不能为空");
        }
        if let Some(macos) = &self.macos
            && (macos.worker_uid == 0
                || macos.worker_gid == 0
                || !normal_absolute_path(&macos.dependency_manifest)
                || !normal_absolute_path(&macos.runtime_parent))
        {
            bail!("苹果部署配置须使用非管理员账户及无跳转分量的绝对路径");
        }
        if self.macos.is_some() && self.allow_legacy_vpngate_crypto {
            bail!("旧算法兼容开关目前仅支持 Linux 后端");
        }
        validate_url(&self.source_url)?;
        for url in &self.exit_check_urls {
            validate_url(url)?;
        }
        Ok(())
    }
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn validate_url(url: &Url) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("仅接受不含凭据的 HTTP/HTTPS 地址");
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}
impl Credentials {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).context("无法读取凭据文件信息")?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o7777 & !0o200 != 0o400
            || metadata.len() > 4096
        {
            bail!("凭据必须是权限 0400 或 0600 且不超过 4 KiB 的普通文件");
        }
        let credentials: Self =
            serde_json::from_slice(&std::fs::read(path)?).context("凭据格式无效")?;
        if !(1..=255).contains(&credentials.username.len())
            || !(1..=255).contains(&credentials.password.len())
        {
            bail!("用户名和密码须各为 1—255 个 UTF-8 字节");
        }
        Ok(credentials)
    }
}
