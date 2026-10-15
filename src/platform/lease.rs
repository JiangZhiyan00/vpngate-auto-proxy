//! 继承文件锁作为消费者存活凭据；调用方必须先核验目录并将描述符交给全部消费者。
//! 丢弃所有者只关闭描述符，不主动解锁或删除文件；尚未接入正式服务恢复清单。
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Mutex,
    time::{Duration, Instant},
};

/// 独占锁的原件；各消费者只继承复制件，不独立解锁。
pub struct ConsumerLease {
    file: Mutex<Option<File>>,
    receipt: LeaseReceipt,
}
/// 必须来自可信且受保护的资源清单；反序列化本身不提供归属证明。
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseReceipt {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
}
/// 对原文件的独立排他锁；持有它期间才能进一步核验并清理该代际的登记资源。
pub struct QuiescentLease {
    _file: File,
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "消费者锁文件归属、类型或权限已改变",
    )
}
fn normal_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "消费者锁必须使用无跳转分量的绝对路径",
        ));
    }
    Ok(())
}
fn lock(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(Into::into)
}
impl ConsumerLease {
    /// 只创建新文件。父目录的管理员归属及访问控制须由部署入口事先核验。
    pub fn create(path: &Path) -> io::Result<Self> {
        normal_path(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let metadata = file.metadata()?;
        let receipt = LeaseReceipt {
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        receipt.check(&metadata)?;
        lock(&file)?;
        file.sync_all()?;
        File::open(path.parent().ok_or_else(denied)?)?.sync_all()?;
        Ok(Self {
            file: Mutex::new(Some(file)),
            receipt,
        })
    }
    pub fn receipt(&self) -> LeaseReceipt {
        self.receipt.clone()
    }
    /// 复制件在执行时默认关闭，只有显式标准描述符映射才交付到直属子进程。
    pub fn child_stdio(&self) -> io::Result<Stdio> {
        let file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("消费者锁状态损坏"))?;
        let file = file
            .as_ref()
            .ok_or_else(|| io::Error::other("消费者锁已经关闭"))?;
        self.receipt.check(&file.metadata()?)?;
        Ok(Stdio::from(file.try_clone()?))
    }
    /// 完成派生后关闭本进程原件；已交付副本仍独立维持同一把锁。
    pub(crate) fn close_owner(&self) -> io::Result<()> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("消费者锁状态损坏"))?
            .take();
        Ok(())
    }
}
impl LeaseReceipt {
    pub(crate) fn matches_recorded_lock(
        &self,
        path: &Path,
        device: u64,
        inode: u64,
        uid: u32,
        gid: u32,
    ) -> bool {
        self.path == path
            && self.device == device
            && self.inode == inode
            && self.uid == uid
            && self.gid == gid
    }
    fn check(&self, metadata: &fs::Metadata) -> io::Result<()> {
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(denied());
        }
        Ok(())
    }
    /// 未获得锁表示至少还有原锁引用；错误或文件缺失都不能被当作消费者已退出。
    /// 成功仅适用于已按协议交付锁副本的消费者，不覆盖未登记进程或任意网络资源。
    pub fn try_quiescent(&self) -> io::Result<Option<QuiescentLease>> {
        normal_path(&self.path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&self.path)?;
        self.check(&file.metadata()?)?;
        match lock(&file) {
            Ok(()) => {
                self.check(&fs::symlink_metadata(&self.path)?)?;
                Ok(Some(QuiescentLease { _file: file }))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
    /// 对短暂继承窗口作有界等待；持续占用仍返回 None，文件身份错误立即返回错误。
    pub fn wait_quiescent(&self, budget: Duration) -> io::Result<Option<QuiescentLease>> {
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "消费者锁等待预算无效"))?;
        loop {
            if let Some(guard) = self.try_quiescent()? {
                return Ok(Some(guard));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            std::thread::sleep(remaining.min(Duration::from_millis(5)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    #[test]
    fn original_and_recovery_owner_exclude_other_open_file_descriptions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("consumers.lock");
        let lease = ConsumerLease::create(&path).unwrap();
        let receipt = lease.receipt();
        assert!(receipt.try_quiescent().unwrap().is_none());
        drop(lease);
        let recovery = receipt.try_quiescent().unwrap().unwrap();
        assert!(receipt.try_quiescent().unwrap().is_none());
        drop(recovery);
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
        assert!(path.exists());
    }
    #[tokio::test]
    async fn actual_child_holds_lock_after_parent_descriptor_closes_until_child_exit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("consumers.lock");
        let lease = ConsumerLease::create(&path).unwrap();
        let receipt: LeaseReceipt =
            serde_json::from_slice(&serde_json::to_vec(&lease.receipt()).unwrap()).unwrap();
        let mut child = super::super::spawn::guarded(|| {
            tokio::process::Command::new("/usr/bin/python3")
                .args(["-c", "import os,sys; os.fstat(2); print('ready',flush=True); sys.stdin.buffer.read(1)"])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(lease.child_stdio()?)
                .kill_on_drop(true).spawn()
        }).unwrap();
        let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            output.read_line(&mut ready),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ready, "ready\n");
        drop(lease);
        assert!(receipt.try_quiescent().unwrap().is_none());
        child.stdin.take().unwrap().write_all(b"x").await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn forced_exit_releases_last_inherited_lock_without_explicit_unlock() {
        let directory = tempfile::tempdir().unwrap();
        let lease = ConsumerLease::create(&directory.path().join("consumers.lock")).unwrap();
        let receipt = lease.receipt();
        let mut child = super::super::spawn::guarded(|| {
            tokio::process::Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import sys; print('ready',flush=True); sys.stdin.buffer.read(1)",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(lease.child_stdio()?)
                .kill_on_drop(true)
                .spawn()
        })
        .unwrap();
        let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            output.read_line(&mut ready),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ready, "ready\n");
        drop(lease);
        assert!(receipt.try_quiescent().unwrap().is_none());
        child.start_kill().unwrap();
        assert!(
            !tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn independent_consumers_keep_lock_until_the_last_exits() {
        let directory = tempfile::tempdir().unwrap();
        let lease = ConsumerLease::create(&directory.path().join("consumers.lock")).unwrap();
        let receipt = lease.receipt();
        let mut children = Vec::new();
        for _ in 0..2 {
            let mut child = super::super::spawn::guarded(|| {
                tokio::process::Command::new("/usr/bin/python3")
                    .args([
                        "-c",
                        "import os,sys; os.fstat(2); print('ready',flush=True); sys.stdin.buffer.read(1)",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(lease.child_stdio()?)
                    .kill_on_drop(true)
                    .spawn()
            })
            .unwrap();
            let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
            let mut ready = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                output.read_line(&mut ready),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(ready, "ready\n");
            children.push(child);
        }
        drop(lease);
        assert!(receipt.try_quiescent().unwrap().is_none());
        for (index, mut child) in children.into_iter().enumerate() {
            child.stdin.take().unwrap().write_all(b"x").await.unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
                    .await
                    .unwrap()
                    .unwrap()
                    .success()
            );
            if index == 0 {
                assert!(receipt.try_quiescent().unwrap().is_none());
            } else {
                assert!(
                    receipt
                        .wait_quiescent(Duration::from_millis(100))
                        .unwrap()
                        .is_some()
                );
            }
        }
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn exec_replacement_retains_the_inherited_standard_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let lease = ConsumerLease::create(&directory.path().join("consumers.lock")).unwrap();
        let receipt = lease.receipt();
        let mut child = super::super::spawn::guarded(|| {
            tokio::process::Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import os; os.execv('/bin/sleep', ['/bin/sleep', '60'])",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(lease.child_stdio()?)
                .kill_on_drop(true)
                .spawn()
        })
        .unwrap();
        drop(lease);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(child.try_wait().unwrap().is_none());
        assert!(receipt.try_quiescent().unwrap().is_none());
        child.start_kill().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn duplicate_handles_keep_same_lock_and_default_to_close_on_exec() {
        let directory = tempfile::tempdir().unwrap();
        let lease = ConsumerLease::create(&directory.path().join("consumers.lock")).unwrap();
        let receipt = lease.receipt();
        let duplicate = lease
            .file
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap();
        assert!(
            rustix::io::fcntl_getfd(duplicate.as_fd())
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        drop(lease);
        assert!(receipt.try_quiescent().unwrap().is_none());
        drop(duplicate);
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn closing_owner_blocks_new_handoffs_but_existing_consumer_keeps_lock() {
        let directory = tempfile::tempdir().unwrap();
        let lease = ConsumerLease::create(&directory.path().join("consumers.lock")).unwrap();
        let receipt = lease.receipt();
        let inherited = lease.child_stdio().unwrap();
        lease.close_owner().unwrap();
        lease.close_owner().unwrap();
        assert!(lease.child_stdio().is_err());
        assert!(receipt.try_quiescent().unwrap().is_none());
        drop(inherited);
        assert!(
            receipt
                .wait_quiescent(Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn missing_replaced_linked_and_repermissioned_files_never_prove_quiescence() {
        for change in ["missing", "replacement", "symlink", "hardlink", "mode"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("consumers.lock");
            let lease = ConsumerLease::create(&path).unwrap();
            let receipt = lease.receipt();
            drop(lease);
            let saved = directory.path().join("saved");
            match change {
                "missing" => fs::remove_file(&path).unwrap(),
                "replacement" | "symlink" => {
                    fs::rename(&path, &saved).unwrap();
                    if change == "symlink" {
                        std::os::unix::fs::symlink(&saved, &path).unwrap();
                    } else {
                        fs::write(&path, b"keep").unwrap();
                    }
                }
                "hardlink" => fs::hard_link(&path, &saved).unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                _ => unreachable!(),
            }
            assert!(receipt.try_quiescent().is_err(), "{change}");
            if change == "replacement" {
                assert_eq!(fs::read(path).unwrap(), b"keep");
            }
        }
    }
    #[test]
    fn creation_rejects_existing_files_without_truncation_and_relative_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing");
        fs::write(&path, b"keep").unwrap();
        assert!(ConsumerLease::create(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        assert!(ConsumerLease::create(Path::new("relative")).is_err());
    }
}
