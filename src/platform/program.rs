//! 管理员显式安装本项目程序；安装不执行候选、不激活服务或修改现有版本。
use super::{dependency, launcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

// 与依赖的管理员私有目录分开：业务子进程需要搜索目录并执行同一程序。
const PARENT: &str = "/Library/Application Support/vpngate-auto-proxy-programs";
const NAME: &str = "vpngate-auto-proxy";
const LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format_version: u32,
    version: String,
    binary_path: PathBuf,
    binary_sha256: String,
    system_libraries: Vec<PathBuf>,
}
#[derive(Serialize)]
pub struct Summary {
    pub version: String,
    pub binary_sha256: String,
    pub system_libraries: Vec<PathBuf>,
    pub service_activated: bool,
}
struct Snapshot {
    bytes: Vec<u8>,
    hash: String,
    libraries: Vec<PathBuf>,
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
impl Snapshot {
    fn read(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || path.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(invalid("程序材料须为无跳转分量的绝对路径"));
        }
        Self::from_bytes(dependency::read_file(path, LIMIT)?)
    }
    fn from_bytes(bytes: Vec<u8>) -> io::Result<Self> {
        let libraries = dependency::static_program_libraries(&bytes)?;
        if libraries.len() > 32 {
            return Err(invalid("主程序系统加载库数量超限"));
        }
        Ok(Self {
            hash: hash(&bytes),
            bytes,
            libraries,
        })
    }
    fn target(&self, parent: &Path) -> PathBuf {
        parent.join(format!("{}-{}", env!("CARGO_PKG_VERSION"), self.hash))
    }
    fn record(&self, parent: &Path) -> Record {
        Record {
            format_version: 1,
            version: env!("CARGO_PKG_VERSION").into(),
            binary_path: self.target(parent).join(NAME),
            binary_sha256: self.hash.clone(),
            system_libraries: self.libraries.clone(),
        }
    }
    fn check_hash(&self, expected: &str) -> io::Result<()> {
        if !valid_hash(expected) || self.hash != expected {
            return Err(invalid("本地程序摘要与明确选定材料不符"));
        }
        Ok(())
    }
}
fn decode(bytes: &[u8]) -> io::Result<Record> {
    let record: Record =
        serde_json::from_slice(bytes).map_err(|_| invalid("程序安装记录格式无效"))?;
    if record.format_version != 1
        || record.version != env!("CARGO_PKG_VERSION")
        || !valid_hash(&record.binary_sha256)
        || record.system_libraries.is_empty()
        || record.system_libraries.len() > 32
        || record.system_libraries.iter().any(|path| {
            !path.is_absolute()
                || path.components().any(|c| {
                    !matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
                || !(path.starts_with("/usr/lib") || path.starts_with("/System/Library"))
        })
        || record.binary_path
            != Path::new(PARENT)
                .join(format!("{}-{}", record.version, record.binary_sha256))
                .join(NAME)
    {
        return Err(invalid("程序安装记录版本、摘要或路径无效"));
    }
    Ok(record)
}
pub fn inspect(path: &Path) -> io::Result<Summary> {
    let snapshot = Snapshot::read(path)?;
    Ok(Summary {
        version: env!("CARGO_PKG_VERSION").into(),
        binary_sha256: snapshot.hash,
        system_libraries: snapshot.libraries,
        service_activated: false,
    })
}

fn commit_with(
    parent: &Path,
    snapshot: &Snapshot,
    mut write: impl FnMut(&Path, &[u8], u32) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let guard = dependency::PendingDirectory::create(parent)?;
    let result = (|| {
        fs::set_permissions(guard.path(), fs::Permissions::from_mode(0o700))?;
        write(&guard.path().join(NAME), &snapshot.bytes, 0o755)?;
        write(
            &guard.path().join("program.json"),
            &serde_json::to_vec_pretty(&snapshot.record(parent))?,
            0o644,
        )?;
        // 只含公开程序与摘要记录，消费者需要搜索并读取；文件均不可被普通用户修改。
        fs::set_permissions(guard.path(), fs::Permissions::from_mode(0o755))?;
        File::open(guard.path())?.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            guard.path(),
            rustix::fs::CWD,
            snapshot.target(parent),
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        File::open(parent)?.sync_all()?;
        Ok(snapshot.target(parent).join(NAME))
    })();
    match result {
        Err(error) => match guard.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(io::Error::new(
                error.kind(),
                format!("{error}；程序暂存回收：{cleanup}"),
            )),
        },
        success => success,
    }
}
/// 只安装管理员明确核准的本地程序和摘要，不能用摘要代替来源审核或发布签名。
pub fn install(path: &Path, expected_sha256: &str) -> io::Result<PathBuf> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "主程序安装需要管理员身份",
        ));
    }
    let snapshot = Snapshot::read(path)?;
    snapshot.check_hash(expected_sha256)?;
    let parent = Path::new(PARENT);
    launcher::root_chain(parent.parent().expect("固定系统目录"))?;
    match fs::DirBuilder::new().mode(0o755).create(parent) {
        Ok(()) => fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    launcher::root_chain(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o755 {
        return Err(invalid("程序安装父目录权限不符"));
    }
    commit_with(parent, &snapshot, dependency::write_file)
}

/// 正式父进程派生任何特权或业务子进程前核对自身安装记录。
pub(crate) fn verify_current() -> io::Result<PathBuf> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "正式程序启动需要管理员身份",
        ));
    }
    let path = std::env::current_exe()?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("当前程序没有安装父目录"))?;
    let file = launcher::root_file(&parent.join("program.json"), 32768, false)?;
    let mut bytes = Vec::new();
    file.take(32769).read_to_end(&mut bytes)?;
    if bytes.len() > 32768 {
        return Err(invalid("程序安装记录超过上限"));
    }
    let record = decode(&bytes)?;
    if record.binary_path != path {
        return Err(invalid("当前程序与安装记录路径不符"));
    }
    let program = launcher::root_file(&path, LIMIT, false)?;
    if program.metadata()?.mode() & 0o777 != 0o755 {
        return Err(invalid("正式程序执行权限不符"));
    }
    let mut bytes = Vec::new();
    program.take(LIMIT + 1).read_to_end(&mut bytes)?;
    let snapshot = Snapshot::from_bytes(bytes)?;
    snapshot.check_hash(&record.binary_sha256)?;
    if snapshot.libraries != record.system_libraries {
        return Err(invalid("程序加载记录与安装记录不符"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Snapshot {
        let library = b"/usr/lib/libSystem.B.dylib";
        let size = (24 + library.len() + 1).div_ceil(8) * 8;
        let mut bytes = vec![0; 32 + size];
        for (offset, value) in [
            (0, 0xfeedfacfu32),
            (4, 0x0100000c),
            (12, 2),
            (16, 1),
            (20, size as u32),
            (32, 0xc),
            (36, size as u32),
            (40, 24),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[56..56 + library.len()].copy_from_slice(library);
        Snapshot::from_bytes(bytes).unwrap()
    }
    #[test]
    fn normal_user_cannot_install_or_verify_protected_program() {
        assert!(!nix::unistd::geteuid().is_root());
        assert_eq!(
            install(Path::new("/missing"), "bad").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            verify_current().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[test]
    fn selected_hash_and_record_are_bound_to_fixed_version_and_target() {
        let snapshot = fixture();
        snapshot.check_hash(&snapshot.hash).unwrap();
        for value in [
            "0".repeat(64),
            "f".repeat(63),
            "g".repeat(64),
            "a".repeat(64),
        ] {
            assert!(snapshot.check_hash(&value).is_err());
        }
        let bytes = serde_json::to_vec(&snapshot.record(Path::new(PARENT))).unwrap();
        assert!(decode(&bytes).is_ok());
        for field in [
            "format_version",
            "version",
            "binary_path",
            "binary_sha256",
            "system_libraries",
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value[field] = serde_json::json!("invalid");
            assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(decode(text.replacen('{', "{\"extra\":true,", 1).as_bytes()).is_err());
        assert!(decode(text.replacen('{', "{\"format_version\":1,", 1).as_bytes()).is_err());
    }
    #[test]
    fn complete_transaction_installs_searchable_program_without_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = fixture();
        let path = commit_with(directory.path(), &snapshot, dependency::write_file).unwrap();
        assert_eq!(fs::read(&path).unwrap(), snapshot.bytes);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o755
        );
        let record: Record =
            serde_json::from_slice(&fs::read(path.parent().unwrap().join("program.json")).unwrap())
                .unwrap();
        assert_eq!(record.binary_path, path);
        assert_eq!(record.binary_sha256, snapshot.hash);
        assert_eq!(
            commit_with(directory.path(), &snapshot, dependency::write_file)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), snapshot.bytes);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    #[test]
    fn failed_write_removes_partial_program_and_preserves_existing_targets() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = fixture();
        let mut count = 0;
        let result = commit_with(directory.path(), &snapshot, |p, b, m| {
            count += 1;
            if count == 2 {
                return Err(io::Error::other("受控写入失败"));
            }
            dependency::write_file(p, b, m)
        });
        assert!(result.is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        fs::write(snapshot.target(directory.path()), b"keep").unwrap();
        assert_eq!(
            commit_with(directory.path(), &snapshot, dependency::write_file)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(snapshot.target(directory.path())).unwrap(),
            b"keep"
        );
    }
    #[test]
    fn actual_running_test_program_uses_only_supported_system_libraries() {
        let summary = inspect(&std::env::current_exe().unwrap()).unwrap();
        assert!(valid_hash(&summary.binary_sha256));
        assert!(!summary.system_libraries.is_empty());
        assert!(!summary.service_activated);
    }

    #[test]
    fn program_source_refuses_links_relative_paths_and_non_program_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, &fixture().bytes).unwrap();
        Snapshot::read(&path).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(Snapshot::read(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(Snapshot::read(&path).is_err());
        assert!(Snapshot::read(Path::new("relative")).is_err());
        assert!(Snapshot::from_bytes(b"invalid".to_vec()).is_err());
        let original = fixture().bytes;
        let commands = original[32..].repeat(33);
        let mut excessive = original[..32].to_vec();
        excessive[16..20].copy_from_slice(&33u32.to_le_bytes());
        excessive[20..24].copy_from_slice(&(commands.len() as u32).to_le_bytes());
        excessive.extend(commands);
        assert!(Snapshot::from_bytes(excessive).is_err());
    }

    #[test]
    fn concurrent_program_install_has_one_winner_and_preserves_symlink_target() {
        let directory = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                barrier.wait();
                commit_with(directory.path(), &fixture(), dependency::write_file)
            });
            let second = scope.spawn(|| {
                barrier.wait();
                commit_with(directory.path(), &fixture(), dependency::write_file)
            });
            let results = [first.join().unwrap(), second.join().unwrap()];
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            assert_eq!(
                results
                    .iter()
                    .filter(|r| r
                        .as_ref()
                        .is_err_and(|e| e.kind() == io::ErrorKind::AlreadyExists))
                    .count(),
                1
            );
        });
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        let other = tempfile::tempdir().unwrap();
        let target = fixture().target(other.path());
        std::os::unix::fs::symlink("untouched", &target).unwrap();
        assert_eq!(
            commit_with(other.path(), &fixture(), dependency::write_file)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_link(target).unwrap(), PathBuf::from("untouched"));
        assert_eq!(fs::read_dir(other.path()).unwrap().count(), 1);
    }
}
