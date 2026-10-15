//! 本地管理员显式安装固定依赖；不编译、不运行待安装程序、不启动服务。
use super::launcher::{self, PATCH, SOURCE};
use nix::fcntl::OFlag;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const PARENT: &str = "/Library/Application Support/vpngate-auto-proxy/dependencies";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileDigests {
    openvpn: String,
    #[serde(rename = "openvpn-source.tar.gz")]
    source: String,
    #[serde(rename = "utun-fd.patch")]
    patch: String,
    #[serde(rename = "COPYING")]
    copying: String,
    #[serde(rename = "COPYRIGHT.GPL")]
    gpl: String,
    #[serde(rename = "AUTHORS")]
    authors: String,
    #[serde(rename = "openssl-LICENSE.txt")]
    crypto_license: String,
    #[serde(rename = "libssl.a")]
    ssl: String,
    #[serde(rename = "libcrypto.a")]
    crypto: String,
}
impl FileDigests {
    fn entries(&self) -> [(&str, &str, u64); 9] {
        [
            ("openvpn", &self.openvpn, 64 * 1024 * 1024),
            ("openvpn-source.tar.gz", &self.source, 8 * 1024 * 1024),
            ("utun-fd.patch", &self.patch, 256 * 1024),
            ("COPYING", &self.copying, 256 * 1024),
            ("COPYRIGHT.GPL", &self.gpl, 256 * 1024),
            ("AUTHORS", &self.authors, 256 * 1024),
            ("openssl-LICENSE.txt", &self.crypto_license, 256 * 1024),
            ("libssl.a", &self.ssl, 16 * 1024 * 1024),
            ("libcrypto.a", &self.crypto, 32 * 1024 * 1024),
        ]
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    format_version: u32,
    version: String,
    source_sha256: String,
    patch_sha256: String,
    crypto_version: String,
    files: FileDigests,
}

#[derive(Serialize)]
pub struct BundleSummary {
    version: String,
    binary_sha256: String,
    source_sha256: String,
    patch_sha256: String,
    crypto_version: String,
    system_libraries: Vec<PathBuf>,
    native_tunnel_validated: bool,
}

struct BundleSnapshot {
    record: BundleManifest,
    files: Vec<(String, Vec<u8>)>,
    libraries: Vec<PathBuf>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn decode(data: &[u8]) -> io::Result<BundleManifest> {
    let record: BundleManifest =
        serde_json::from_slice(data).map_err(|_| invalid("依赖材料清单格式无效"))?;
    if record.format_version != 1
        || record.version != "2.6.23"
        || record.source_sha256 != SOURCE
        || record.patch_sha256 != PATCH
        || record.files.source != SOURCE
        || record.files.patch != PATCH
        || record.crypto_version.len() > 24
        || record.crypto_version.split('.').count() != 3
        || !record
            .crypto_version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        || !record
            .files
            .entries()
            .iter()
            .all(|(_, hash, _)| valid_digest(hash))
    {
        return Err(invalid("依赖材料版本、来源、补丁或摘要无效"));
    }
    Ok(record)
}

pub(crate) fn read_file(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    // 非阻塞打开避免恶意替换成管道时卡住管理员安装；只接受无硬链接的普通文件。
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return Err(invalid("依赖材料文件类型、链接数或大小无效"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("依赖材料读取超过上限"));
    }
    Ok(bytes)
}

impl BundleSnapshot {
    fn read(path: &Path) -> io::Result<Self> {
        let directory = fs::symlink_metadata(path)?;
        if !path.is_absolute() || !directory.is_dir() || directory.file_type().is_symlink() {
            return Err(invalid("依赖材料须为绝对路径的真实目录"));
        }
        let record = decode(&read_file(&path.join("bundle.json"), 16384)?)?;
        let mut files = Vec::new();
        let mut total = 0usize;
        for (name, expected, limit) in record.files.entries() {
            let bytes = read_file(&path.join(name), limit)?;
            total += bytes.len();
            if total > 128 * 1024 * 1024 || digest(&bytes) != expected {
                return Err(invalid("依赖材料摘要或总大小不符"));
            }
            if limit == 256 * 1024 && (bytes.is_empty() || std::str::from_utf8(&bytes).is_err()) {
                return Err(invalid("依赖声明及补丁必须为非空文本"));
            }
            if name.ends_with(".a") && !bytes.starts_with(b"!<arch>\n") {
                return Err(invalid("加密库构建输入不是静态归档"));
            }
            files.push((name.to_owned(), bytes));
        }
        let libraries = static_program_libraries(&files[0].1)?;
        Ok(Self {
            record,
            files,
            libraries,
        })
    }
    fn summary(&self) -> BundleSummary {
        BundleSummary {
            version: self.record.version.clone(),
            binary_sha256: self.record.files.openvpn.clone(),
            source_sha256: SOURCE.to_owned(),
            patch_sha256: PATCH.to_owned(),
            crypto_version: self.record.crypto_version.clone(),
            system_libraries: self.libraries.clone(),
            native_tunnel_validated: false,
        }
    }
}

pub(crate) fn static_program_libraries(bytes: &[u8]) -> io::Result<Vec<PathBuf>> {
    let libraries = launcher::macho_libraries(bytes, 2)?;
    if !libraries
        .iter()
        .all(|path| path.starts_with("/usr/lib") || path.starts_with("/System/Library"))
    {
        return Err(invalid("安装候选仍依赖非系统动态库"));
    }
    Ok(libraries)
}

pub fn inspect(path: &Path) -> io::Result<BundleSummary> {
    Ok(BundleSnapshot::read(path)?.summary())
}

pub(crate) struct PendingDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}
impl PendingDirectory {
    pub(crate) fn create(parent: &Path) -> io::Result<Self> {
        let path = parent.join(format!(".pending-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn cleanup(&self) -> io::Result<()> {
        let m = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !m.is_dir() || m.dev() != self.device || m.ino() != self.inode || m.uid() != self.uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "暂存目录身份已变化，拒绝删除",
            ));
        }
        fs::remove_dir_all(&self.path)
    }
}
impl Drop for PendingDirectory {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
pub(crate) fn write_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()
}
fn commit(parent: &Path, snapshot: &BundleSnapshot) -> io::Result<PathBuf> {
    let target = parent.join(format!("openvpn-2.6.23-{}", snapshot.record.files.openvpn));
    let guard = PendingDirectory::create(parent)?;
    let result = (|| -> io::Result<PathBuf> {
        fs::set_permissions(&guard.path, fs::Permissions::from_mode(0o700))?;
        for (name, bytes) in &snapshot.files {
            write_file(
                &guard.path.join(name),
                bytes,
                if name == "openvpn" { 0o700 } else { 0o600 },
            )?;
        }
        write_file(
            &guard.path.join("bundle.json"),
            &serde_json::to_vec_pretty(&snapshot.record)?,
            0o600,
        )?;
        let record = launcher::installation_record(
            target.join("openvpn"),
            snapshot.record.files.openvpn.clone(),
        )?;
        write_file(&guard.path.join("dependency.json"), &record, 0o600)?;
        File::open(&guard.path)?.sync_all()?;
        // 不覆盖已经存在的目录、文件或符号链接，包括并发安装和空目录。
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &guard.path,
            rustix::fs::CWD,
            &target,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        File::open(parent)?.sync_all()?;
        Ok(target.join("dependency.json"))
    })();
    match result {
        Err(error) => match guard.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(io::Error::new(
                error.kind(),
                format!("{error}；暂存清理失败：{cleanup}"),
            )),
        },
        success => success,
    }
}
fn prepare_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        launcher::root_chain(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    launcher::root_chain(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(invalid("依赖安装目录必须为管理员私有目录"));
    }
    Ok(())
}

/// 管理员显式选择自己审核的本地构建材料；摘要只验证一致性，不充当发布签名。
/// 所有输入先完成有界读取与核验，再创建受保护目录；不自动更新或激活服务。
pub fn install(bundle: &Path) -> io::Result<PathBuf> {
    if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "依赖安装需要管理员身份",
        ));
    }
    let snapshot = BundleSnapshot::read(bundle)?;
    let parent = Path::new(PARENT);
    prepare_parent(parent.parent().expect("固定项目目录"))?;
    prepare_parent(parent)?;
    commit(parent, &snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_user_cannot_install_or_read_install_input() {
        assert!(!nix::unistd::geteuid().is_root(), "此回归要求普通用户");
        assert_eq!(
            install(Path::new("/missing/bundle")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    fn fixture() -> BundleSnapshot {
        let hash = digest("本地事务测试材料".as_bytes());
        BundleSnapshot {
            record: BundleManifest {
                format_version: 1,
                version: "2.6.23".into(),
                source_sha256: SOURCE.into(),
                patch_sha256: PATCH.into(),
                crypto_version: "3.6.2".into(),
                files: FileDigests {
                    openvpn: hash.clone(),
                    source: SOURCE.into(),
                    patch: PATCH.into(),
                    copying: hash.clone(),
                    gpl: hash.clone(),
                    authors: hash.clone(),
                    crypto_license: hash.clone(),
                    ssl: hash.clone(),
                    crypto: hash,
                },
            },
            // 仅用于发布事务故障注入，不代表通过来源核验的程序。
            files: vec![("openvpn".into(), "本地事务测试材料".as_bytes().to_vec())],
            libraries: Vec::new(),
        }
    }

    fn assert_no_pending(parent: &Path) {
        assert!(!fs::read_dir(parent).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pending-")
        }));
    }

    #[test]
    fn dependency_record_rejects_wrong_pins_unknown_duplicate_and_invalid_hashes() {
        let record = fixture().record;
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(decode(&bytes).is_ok());
        for field in [
            "format_version",
            "version",
            "source_sha256",
            "patch_sha256",
            "crypto_version",
        ] {
            let mut value = serde_json::to_value(&record).unwrap();
            value[field] = serde_json::json!("不符合约定");
            assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for value in [
            "0".repeat(64),
            "A".repeat(64),
            "g".repeat(64),
            "f".repeat(63),
        ] {
            let mut record = record.clone();
            record.files.openvpn = value;
            assert!(decode(&serde_json::to_vec(&record).unwrap()).is_err());
        }
        let text = String::from_utf8(bytes).unwrap();
        assert!(decode(text.replacen("{", "{\"extra\":true,", 1).as_bytes()).is_err());
        assert!(
            decode(
                text.replacen("\"openvpn\":", "\"../openvpn\":", 1)
                    .as_bytes()
            )
            .is_err()
        );
        assert!(decode(text.replacen("\"openvpn\":", "\"openvpn\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"openvpn\":", 1).as_bytes()).is_err());
    }

    #[test]
    fn dependency_input_refuses_symlink_hardlink_fifo_and_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        fs::write(&file, b"12345").unwrap();
        assert_eq!(
            read_file(&file, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(read_file(&file, 5).unwrap(), b"12345");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_file(&link, 5).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&file, &link).unwrap();
        assert!(read_file(&file, 5).is_err());
        let fifo = directory.path().join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert_eq!(
            read_file(&fifo, 5).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn dependency_snapshot_rejects_changed_content_and_forged_source_archive() {
        let directory = tempfile::tempdir().unwrap();
        let mut snapshot = fixture();
        let bytes = b"wrong";
        fs::write(
            directory.path().join("bundle.json"),
            serde_json::to_vec(&snapshot.record).unwrap(),
        )
        .unwrap();
        fs::write(directory.path().join("openvpn"), bytes).unwrap();
        assert_eq!(
            BundleSnapshot::read(directory.path()).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        snapshot.record.files.openvpn = digest(bytes);
        fs::write(
            directory.path().join("bundle.json"),
            serde_json::to_vec(&snapshot.record).unwrap(),
        )
        .unwrap();
        fs::write(directory.path().join("openvpn-source.tar.gz"), bytes).unwrap();
        assert_eq!(
            BundleSnapshot::read(directory.path()).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!directory.path().join("dependency.json").exists());
    }

    fn loading_record(library: &str) -> Vec<u8> {
        let size = (24 + library.len() + 1 + 7) & !7;
        let mut data = vec![0u8; 32 + size];
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
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        data[56..56 + library.len()].copy_from_slice(library.as_bytes());
        data
    }

    #[test]
    fn dependency_candidate_requires_only_system_dynamic_libraries() {
        assert!(static_program_libraries(&loading_record("/usr/lib/libSystem.B.dylib")).is_ok());
        for path in [
            "/opt/homebrew/lib/libcrypto.dylib",
            "@rpath/libcrypto.dylib",
            "/usr/lib/../local/libcrypto.dylib",
        ] {
            assert!(static_program_libraries(&loading_record(path)).is_err());
        }
    }

    #[test]
    fn dependency_commit_preserves_existing_file_directory_and_symlink() {
        for kind in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let snapshot = fixture();
            let target = directory
                .path()
                .join(format!("openvpn-2.6.23-{}", snapshot.record.files.openvpn));
            match kind {
                0 => {
                    fs::create_dir(&target).unwrap();
                    fs::write(target.join("keep"), b"keep").unwrap();
                }
                1 => fs::write(&target, b"keep").unwrap(),
                _ => std::os::unix::fs::symlink("untouched", &target).unwrap(),
            }
            assert_eq!(
                commit(directory.path(), &snapshot).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_no_pending(directory.path());
            match kind {
                0 => assert_eq!(fs::read(target.join("keep")).unwrap(), b"keep"),
                1 => assert_eq!(fs::read(target).unwrap(), b"keep"),
                _ => assert_eq!(fs::read_link(target).unwrap(), PathBuf::from("untouched")),
            }
        }
    }

    #[test]
    fn dependency_concurrent_commit_has_one_winner_and_complete_record() {
        let directory = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let tasks = (0..2)
                .map(|_| {
                    let barrier = barrier.clone();
                    let parent = directory.path();
                    scope.spawn(move || {
                        barrier.wait();
                        commit(parent, &fixture())
                    })
                })
                .collect::<Vec<_>>();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let path = results.into_iter().find_map(Result::ok).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            value["binary_path"],
            serde_json::json!(path.parent().unwrap().join("openvpn"))
        );
        assert_eq!(value["binary_sha256"], fixture().record.files.openvpn);
        assert_eq!(value.as_object().unwrap().len(), 6);
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            path.parent()
                .unwrap()
                .join("openvpn")
                .metadata()
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        assert_no_pending(directory.path());
    }

    #[test]
    fn dependency_failed_write_removes_partial_stage_and_never_publishes() {
        let directory = tempfile::tempdir().unwrap();
        let mut snapshot = fixture();
        snapshot.files.push(snapshot.files[0].clone());
        assert_eq!(
            commit(directory.path(), &snapshot).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn dependency_cleanup_preserves_replaced_stage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pending");
        fs::create_dir(&path).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let guard = PendingDirectory {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        };
        fs::rename(&path, directory.path().join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"keep").unwrap();
        assert_eq!(
            guard.cleanup().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(guard);
        assert_eq!(fs::read(path.join("keep")).unwrap(), b"keep");
        assert!(directory.path().join("original").is_dir());
    }

    #[test]
    #[ignore = "需要显式提供已构建的独立静态依赖材料"]
    fn actual_static_dependency_bundle_matches_pins() {
        let path =
            PathBuf::from(std::env::var_os("VAP_TEST_DEPENDENCY_BUNDLE").expect("需要材料目录"));
        let summary = inspect(&path).unwrap();
        assert_eq!(summary.version, "2.6.23");
        assert!(!summary.native_tunnel_validated);
        assert_eq!(summary.system_libraries.len(), 2);
    }
}
