//! 特权辅助的共用基础；实际隧道进程管理由后续工作进程任务接入。
pub mod protocol;
pub mod server;
pub mod system;
pub mod workers;
use crate::domain::WorkerRecord;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceManifest {
    pub schema_version: u32,
    pub instance_id: Uuid,
    pub owner_pid: u32,
    pub owner_start: String,
    #[serde(default)]
    pub controller: Option<crate::domain::ProcessIdentity>,
    pub workers: Vec<WorkerRecord>,
}
pub struct InstanceLock {
    pub file: File,
    pub manifest_path: PathBuf,
}
impl InstanceLock {
    pub fn acquire(runtime: &Path) -> Result<Self> {
        std::fs::create_dir_all(runtime)?;
        let metadata = std::fs::symlink_metadata(runtime)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "运行目录不是普通目录"
        );
        std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o750))?;
        let path = runtime.join("instance.lock");
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "实例锁不是普通文件"
            );
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        fs2::FileExt::try_lock_exclusive(&file).context("实例已运行或无法取得独占锁")?;
        Ok(Self {
            file,
            manifest_path: runtime.join("resources.json"),
        })
    }
    pub fn read_manifest(&self) -> Result<Option<ResourceManifest>> {
        if !self.manifest_path.exists() {
            return Ok(None);
        }
        let metadata = std::fs::symlink_metadata(&self.manifest_path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 1024 * 1024 && {
                use std::os::unix::fs::MetadataExt;
                metadata.uid() == 0 && metadata.mode() & 0o777 == 0o600
            },
            "资源清单非法或过大"
        );
        let manifest: ResourceManifest =
            serde_json::from_slice(&std::fs::read(&self.manifest_path)?)?;
        ensure!(manifest.schema_version == 1, "资源清单版本不支持");
        ensure!(manifest.workers.len() <= 255, "资源清单超过工作槽限额");
        Ok(Some(manifest))
    }
    pub fn write_manifest(&self, manifest: &ResourceManifest) -> Result<()> {
        let tmp = self.manifest_path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .context("临时资源清单已存在或不可写")?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec(manifest)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.manifest_path)?;
        File::open(self.manifest_path.parent().context("资源目录缺失")?)?.sync_all()?;
        Ok(())
    }
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}
pub fn process_start(pid: u32) -> Result<String> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).map_err(|error| {
        let code = error
            .raw_os_error()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "未知".to_owned());
        anyhow::Error::new(error).context(format!(
            "无法确认进程启动身份（进程 {pid}，系统错误 {code}）"
        ))
    })?;
    parse_process_start(&stat)
}
fn parse_process_start(stat: &[u8]) -> Result<String> {
    // 内核进程名是任意字节，且可以包含括号；只有最后右括号后的字段参与身份核验。
    let end = stat
        .iter()
        .rposition(|value| *value == b')')
        .context("进程身份格式无效")?;
    let fields = std::str::from_utf8(&stat[end + 1..]).context("进程身份字段格式无效")?;
    let started = fields
        .split_ascii_whitespace()
        .nth(19)
        .context("进程身份字段缺失")?;
    ensure!(
        started.bytes().all(|value| value.is_ascii_digit()) && started.parse::<u64>().is_ok(),
        "进程启动时间无效"
    );
    Ok(started.to_owned())
}

pub fn validate_manifest_identity(manifest: &ResourceManifest) -> Result<()> {
    validate_manifest(manifest, false)
}
pub fn validate_stale_manifest(manifest: &ResourceManifest) -> Result<()> {
    validate_manifest(manifest, true)
}
fn validate_manifest(manifest: &ResourceManifest, allow_orphans: bool) -> Result<()> {
    ensure!(manifest.schema_version == 1, "资源清单版本不支持");
    ensure!(manifest.workers.len() <= 255, "资源清单超过工作槽限额");
    if Path::new(&format!("/proc/{}", manifest.owner_pid)).exists() {
        ensure!(
            process_start(manifest.owner_pid)? == manifest.owner_start,
            "资源所属进程身份不一致"
        );
        anyhow::bail!("资源所属进程仍在运行，拒绝回收");
    }
    if let Some(controller) = &manifest.controller
        && Path::new(&format!("/proc/{}", controller.pid)).exists()
    {
        ensure!(
            process_start(controller.pid)? == controller.started,
            "控制进程启动身份不一致"
        );
        ensure!(allow_orphans, "发现仍存活的控制进程，拒绝未经监督回收");
    }
    for worker in &manifest.workers {
        for process in &worker.processes {
            if Path::new(&format!("/proc/{}", process.pid)).exists() {
                ensure!(
                    process_start(process.pid)? == process.started,
                    "子进程启动身份不一致"
                );
                ensure!(
                    allow_orphans,
                    "发现仍存活的子进程，拒绝在未监督时删除网络资源"
                );
            }
        }
        let expected = system::NetworkAllocation::new(manifest.instance_id, worker.worker_id, 0);
        ensure!(
            worker.instance_id == manifest.instance_id
                && worker.namespace == expected.namespace
                && worker.host_veth == expected.host_veth
                && worker.rules_table == expected.table,
            "资源名称与实例归属不一致"
        );
        if worker.pid > 0 && Path::new(&format!("/proc/{}", worker.pid)).exists() {
            ensure!(
                process_start(worker.pid)? == worker.process_start,
                "工作进程启动身份不一致"
            );
            ensure!(
                allow_orphans,
                "发现仍存活的工作进程，拒绝在未监督时删除网络资源"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod process_identity_tests {
    use super::*;
    fn stat(name: &[u8], start: &[u8]) -> Vec<u8> {
        let mut value = b"67 (".to_vec();
        value.extend_from_slice(name);
        value.extend_from_slice(b") S ");
        for _ in 0..18 {
            value.extend_from_slice(b"0 ");
        }
        value.extend_from_slice(start);
        value.extend_from_slice(b" 0\n");
        value
    }
    #[test]
    fn process_identity_accepts_arbitrary_name_bytes_and_parentheses() {
        assert_eq!(
            parse_process_start(&stat(b"ordinary", b"12345")).unwrap(),
            "12345"
        );
        assert_eq!(
            parse_process_start(&stat(b"bad\xff) name(", b"12345")).unwrap(),
            "12345"
        );
    }
    #[test]
    fn process_identity_rejects_missing_nonnumeric_and_overflow_start_time() {
        assert!(parse_process_start(b"67 (missing)").is_err());
        assert!(parse_process_start(&stat(b"ordinary", b"unknown")).is_err());
        assert!(parse_process_start(&stat(b"ordinary", b"18446744073709551616")).is_err());
    }
}
