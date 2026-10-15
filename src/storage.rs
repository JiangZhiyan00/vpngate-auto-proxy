//! 单写入者的私有来源快照与有界诊断；诊断永不恢复运行可用性。
use crate::{domain::*, openvpn::validate_regenerated_with_policy};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;
pub const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_CHECK_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CHECKS: usize = 2048;
#[derive(Clone)]
pub struct Storage {
    directory: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Diagnostics {
    schema_version: u32,
    checks: Vec<CheckResult>,
}
impl Storage {
    pub fn new(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)?;
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "缓存目录必须为普通目录"
        );
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            directory: directory.into(),
        })
    }
    pub fn save_source(&self, snapshot: &SourceSnapshot) -> Result<()> {
        self.save_source_with_policy(snapshot, false)
    }
    pub fn save_source_with_policy(
        &self,
        snapshot: &SourceSnapshot,
        allow_legacy_vpngate_crypto: bool,
    ) -> Result<()> {
        validate_snapshot(snapshot, allow_legacy_vpngate_crypto)?;
        self.atomic_write("nodes.json", snapshot, MAX_SOURCE_BYTES)
    }
    pub fn load_source(
        &self,
        url: &str,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<SourceSnapshot> {
        self.load_source_with_policy(url, ttl, now, false)
    }
    pub fn load_source_with_policy(
        &self,
        url: &str,
        ttl: Duration,
        now: DateTime<Utc>,
        allow_legacy_vpngate_crypto: bool,
    ) -> Result<SourceSnapshot> {
        let mut snapshot: SourceSnapshot = self.read("nodes.json", MAX_SOURCE_BYTES)?;
        validate_snapshot(&snapshot, allow_legacy_vpngate_crypto)?;
        ensure!(snapshot.source_url == url, "缓存来源地址与当前配置不一致");
        let age = now
            .signed_duration_since(snapshot.fetched_at)
            .to_std()
            .context("缓存时间在未来或系统时间回拨")?;
        ensure!(age < ttl, "来源缓存已过期");
        // 只恢复来源；运行期公平性和可用性均从新实例重新建立。
        for node in &mut snapshot.nodes {
            node.last_attempt_at = None;
        }
        Ok(snapshot)
    }
    pub fn save_checks(
        &self,
        checks: &[CheckResult],
        present: &[NodeId],
        active: Option<&NodeId>,
    ) -> Result<()> {
        let owners: BTreeSet<_> = present.iter().collect();
        let mut latest = BTreeMap::<(NodeId, Layer), CheckResult>::new();
        for check in checks {
            if !owners.contains(&check.node_id) && active != Some(&check.node_id) {
                continue;
            }
            let mut check = check.clone();
            if let Some(reason) = check.failure_reason.as_mut() {
                let mut boundary = reason.len().min(512);
                while !reason.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                reason.truncate(boundary);
            }
            validate_check(&check)?;
            let key = (check.node_id.clone(), check.layer);
            if latest
                .get(&key)
                .is_none_or(|old| old.finished_at <= check.finished_at)
            {
                latest.insert(key, check);
            }
        }
        let mut checks: Vec<_> = latest.into_values().collect();
        checks.sort_by(|a, b| {
            b.finished_at
                .cmp(&a.finished_at)
                .then_with(|| a.node_id.cmp(&b.node_id))
                .then_with(|| a.layer.cmp(&b.layer))
        });
        checks.truncate(MAX_CHECKS);
        let mut diagnostics = Diagnostics {
            schema_version: 1,
            checks,
        };
        while serde_json::to_vec(&diagnostics)?.len() as u64 > MAX_CHECK_BYTES {
            ensure!(diagnostics.checks.pop().is_some(), "诊断头部超过限额");
        }
        self.atomic_write("checks.json", &diagnostics, MAX_CHECK_BYTES)
    }
    pub fn load_checks(&self) -> Result<Vec<CheckResult>> {
        let diagnostics: Diagnostics = self.read("checks.json", MAX_CHECK_BYTES)?;
        ensure!(
            diagnostics.schema_version == 1 && diagnostics.checks.len() <= MAX_CHECKS,
            "诊断模式版本或条目数无效"
        );
        let mut seen = BTreeSet::new();
        for check in &diagnostics.checks {
            validate_check(check)?;
            ensure!(
                seen.insert((&check.node_id, check.layer)),
                "诊断含重复节点层次"
            );
        }
        Ok(diagnostics.checks)
    }
    fn read<T: DeserializeOwned>(&self, name: &str, limit: u64) -> Result<T> {
        let path = self.directory.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.len() <= limit,
            "缓存不是普通文件或超过大小限额"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= limit, "缓存读取超过大小限额");
        // 不传播反序列化错误中的不可信值，避免私钥出现在错误消息。
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("缓存格式无效"))
    }
    fn atomic_write<T: Serialize>(&self, name: &str, value: &T, limit: u64) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        ensure!(bytes.len() as u64 <= limit, "缓存写入超过大小限额");
        let temp = self
            .directory
            .join(format!(".{name}.{}", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp, self.directory.join(name))?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if temp.exists() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}
fn validate_snapshot(snapshot: &SourceSnapshot, allow_legacy_vpngate_crypto: bool) -> Result<()> {
    ensure!(
        snapshot.schema_version == 1 && snapshot.nodes.len() <= 20_000,
        "来源模式版本或节点数无效"
    );
    let url = url::Url::parse(&snapshot.source_url).context("来源地址无效")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none(),
        "来源地址无效"
    );
    let mut seen = BTreeSet::new();
    for node in &snapshot.nodes {
        node.validate()?;
        validate_regenerated_with_policy(
            &node.profile,
            &node.endpoint,
            allow_legacy_vpngate_crypto,
        )?;
        ensure!(
            node.present && node.source_fetched_at == snapshot.fetched_at && seen.insert(&node.id),
            "来源节点时间、归属或去重无效"
        );
        ensure!(
            node.source_hostname.len() <= 255 && node.country.len() <= 8,
            "来源显示字段超过限额"
        );
    }
    Ok(())
}
fn validate_check(check: &CheckResult) -> Result<()> {
    ensure!(
        check.profile_digest.len() == 64
            && check
                .profile_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "诊断配置摘要无效"
    );
    ensure!(
        check.failure_reason.as_ref().is_none_or(|v| v.len() <= 512),
        "诊断说明超过限额"
    );
    ensure!(check.finished_at >= check.started_at, "诊断时间顺序无效");
    Ok(())
}
