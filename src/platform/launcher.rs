//! 独立串行启动桥接；只能在创建运行时及其它线程前调用。
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::custody::{UtunCustody, receive};
use crate::{domain::Endpoint, openvpn::validate_regenerated};

pub(crate) const SOURCE: &str = "4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96";
pub(crate) const PATCH: &str = "cdf11425bb5806f87eb6fb5ee289adba86e7de3c08bbe550a777785d05b986fa";

pub struct TunnelLaunch {
    pub interface_notifications: bool,
    pub dependency_manifest: PathBuf,
    pub profile: PathBuf,
    pub management: PathBuf,
    pub endpoint: Endpoint,
    pub authorization: Uuid,
    pub interface_index: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DependencyManifest {
    format_version: u32,
    version: String,
    source_sha256: String,
    patch_sha256: String,
    binary_path: PathBuf,
    binary_sha256: String,
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn normal_path(path: &Path) -> io::Result<()> {
    if path
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| byte.is_ascii_control())
        || !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(denied("启动路径必须为无跳转分量的绝对路径"));
    }
    Ok(())
}

pub(crate) fn root_chain(path: &Path) -> io::Result<()> {
    normal_path(path)?;
    for component in path.ancestors() {
        let metadata = std::fs::symlink_metadata(component)?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.file_type().is_symlink()
            || (component != path && !metadata.is_dir())
        {
            return Err(denied("启动路径及祖先须由管理员所有且不可被普通用户修改"));
        }
    }
    // 模式位不能表达苹果扩展访问控制；保守拒绝存在任何额外访问控制项的路径。
    let ancestors = path.ancestors().collect::<Vec<_>>();
    let output = super::spawn::guarded(|| {
        Command::new("/bin/ls")
            .arg("-lde")
            .args(&ancestors)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .output()
    })?;
    if !output.status.success() || !no_acl(&output.stdout, ancestors.len()) {
        return Err(denied("启动路径包含扩展访问控制或权限清单不完整"));
    }
    Ok(())
}

fn no_acl(output: &[u8], count: usize) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };
    if output.len() > 65536 || output.lines().count() != count {
        return false;
    }
    output.lines().all(|line| {
        let Some(mode) = line.split_ascii_whitespace().next() else {
            return false;
        };
        let bytes = mode.as_bytes();
        (bytes.len() == 10 || (bytes.len() == 11 && bytes[10] == b'@'))
            && matches!(bytes[0], b'-' | b'd' | b's')
            && bytes[1..10].iter().all(|byte| b"rwxstST-".contains(byte))
    })
}

pub(crate) fn root_file(path: &Path, maximum: u64, private: bool) -> io::Result<File> {
    root_chain(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o6022 != 0
        || metadata.len() > maximum
        || (private && metadata.mode() & 0o777 != 0o600)
    {
        return Err(denied("启动文件类型、所有者、权限或大小不符"));
    }
    Ok(file)
}

fn read_bounded(file: File, maximum: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    file.take(maximum + 1).read_to_end(&mut data)?;
    if data.len() as u64 > maximum {
        return Err(denied("启动文件超过上限"));
    }
    Ok(data)
}

fn manifest(data: &[u8]) -> io::Result<DependencyManifest> {
    let record: DependencyManifest =
        serde_json::from_slice(data).map_err(|_| denied("受控依赖安装记录无效"))?;
    if record.format_version != 1
        || record.version != "2.6.23"
        || record.source_sha256 != SOURCE
        || record.patch_sha256 != PATCH
        || record.binary_sha256.len() != 64
        || !record
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || record.binary_sha256.bytes().all(|byte| byte == b'0')
    {
        return Err(denied("受控依赖版本或来源摘要不符"));
    }
    normal_path(&record.binary_path)?;
    Ok(record)
}

fn verify_digest(path: &Path, expected: &str) -> io::Result<()> {
    let mut file = root_file(path, 64 * 1024 * 1024, false)?;
    let mut digest = Sha256::new();
    io::copy(&mut file.by_ref().take(64 * 1024 * 1024 + 1), &mut digest)?;
    if format!("{:x}", digest.finalize()) != expected {
        return Err(denied("受控隧道程序摘要不符"));
    }
    if file.metadata()?.mode() & 0o111 == 0 {
        return Err(denied("受控隧道程序不可执行"));
    }
    Ok(())
}

pub(crate) fn macho_libraries(data: &[u8], file_type: u32) -> io::Result<Vec<PathBuf>> {
    fn word(data: &[u8], offset: usize) -> io::Result<u32> {
        let bytes = data
            .get(
                offset
                    ..offset
                        .checked_add(4)
                        .ok_or_else(|| denied("加载偏移溢出"))?,
            )
            .ok_or_else(|| denied("加载记录截断"))?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("已核对四字节长度"),
        ))
    }
    if data.len() < 32
        || data.len() > 64 * 1024 * 1024
        || word(data, 0)? != 0xfeedfacf
        || word(data, 4)? != 0x0100000c
        || word(data, 12)? != file_type
    {
        return Err(denied("只接受目标架构的单架构六十四位加载文件"));
    }
    let count = word(data, 16)? as usize;
    let end = 32usize
        .checked_add(word(data, 20)? as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| denied("加载命令总长度无效"))?;
    if count == 0 || count > 4096 {
        return Err(denied("加载命令数量无效"));
    }
    let mut cursor = 32usize;
    let mut libraries = Vec::new();
    for _ in 0..count {
        if cursor.checked_add(8).is_none_or(|offset| offset > end) {
            return Err(denied("加载命令标题截断"));
        }
        let kind = word(data, cursor)?;
        let size = word(data, cursor + 4)? as usize;
        let next = cursor
            .checked_add(size)
            .filter(|next| *next <= end)
            .ok_or_else(|| denied("加载命令越界"))?;
        if size < 8 || !size.is_multiple_of(8) {
            return Err(denied("加载命令长度或对齐无效"));
        }
        match kind {
            0x8000001c | 0x27 | 0x6 | 0x7 | 0x9 => {
                return Err(denied("不接受动态加载搜索路径、嵌入环境或旧式库加载"));
            }
            0xc | 0x80000018 | 0x8000001f | 0x20 | 0x80000023 | 0xe => {
                let minimum = if kind == 0xe { 12 } else { 24 };
                if size < minimum {
                    return Err(denied("动态库加载命令截断"));
                }
                let offset = word(data, cursor + 8)? as usize;
                if offset < minimum || offset >= size {
                    return Err(denied("动态库名称偏移无效"));
                }
                let name = &data[cursor + offset..next];
                let zero = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| denied("动态库名称没有终止符"))?;
                let name =
                    std::str::from_utf8(&name[..zero]).map_err(|_| denied("动态库名称编码无效"))?;
                let path = PathBuf::from(name);
                normal_path(&path)?;
                if kind == 0xe {
                    if path != Path::new("/usr/lib/dyld") {
                        return Err(denied("系统动态加载器路径不符"));
                    }
                } else {
                    libraries.push(path);
                }
            }
            // 已核对的非库加载命令只跳过其有界内容；未知格式须重新审查。
            0x2 | 0xb | 0xd | 0x19 | 0x1a | 0x1b | 0x1d | 0x1e | 0x22 | 0x80000022 | 0x24
            | 0x26 | 0x80000028 | 0x29 | 0x2a | 0x2b | 0x2d | 0x2e | 0x31 | 0x32 | 0x80000033
            | 0x80000034 | 0x36 | 0x37 | 0x38 | 0x39 => {}
            _ => return Err(denied("动态加载命令尚未核验")),
        }
        cursor = next;
    }
    if cursor != end || (file_type == 2 && libraries.is_empty()) {
        return Err(denied("加载命令总量或依赖不完整"));
    }
    Ok(libraries)
}

pub(crate) fn installation_record(
    binary_path: PathBuf,
    binary_sha256: String,
) -> io::Result<Vec<u8>> {
    let record = DependencyManifest {
        format_version: 1,
        version: "2.6.23".to_owned(),
        source_sha256: SOURCE.to_owned(),
        patch_sha256: PATCH.to_owned(),
        binary_path,
        binary_sha256,
    };
    let bytes = serde_json::to_vec_pretty(&record)?;
    manifest(&bytes)?;
    Ok(bytes)
}

fn verify_libraries(program: &Path) -> io::Result<()> {
    let mut pending = vec![(program.to_owned(), 2)];
    let mut checked = BTreeSet::new();
    while let Some((path, file_type)) = pending.pop() {
        if !checked.insert(path.clone()) {
            continue;
        }
        if checked.len() > 32 {
            return Err(denied("动态库依赖数量超限"));
        }
        let data = read_bounded(root_file(&path, 64 * 1024 * 1024, false)?, 64 * 1024 * 1024)?;
        for library in macho_libraries(&data, file_type)? {
            // 系统动态库缓存可能没有磁盘实体；其余依赖递归核验。
            if library.starts_with("/usr/lib") || library.starts_with("/System/Library") {
                continue;
            }
            pending.push((library, 6));
        }
    }
    Ok(())
}

fn management_path(path: &Path) -> io::Result<()> {
    root_chain(path)?;
    let parent = path.parent().ok_or_else(|| denied("管理目录缺失"))?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.mode() & 0o777 != 0o600
        || std::fs::symlink_metadata(parent)?.mode() & 0o777 != 0o700
    {
        return Err(denied("管理通道须位于管理员私有目录并使用私有套接字"));
    }
    Ok(())
}

/// 成功时替换当前进程，进程号保持不变；任一错误必须终止独立启动进程。
pub fn execute(request: TunnelLaunch) -> io::Error {
    let outcome: io::Result<()> = (|| {
        if !nix::unistd::geteuid().is_root() || !nix::unistd::getuid().is_root() {
            return Err(denied("隧道启动桥接需要管理员身份"));
        }
        if request.authorization.is_nil() || request.interface_index == 0 {
            return Err(denied("隧道启动身份无效"));
        }
        let record = verified_dependency(&request.dependency_manifest)?;
        let profile = Zeroizing::new(read_bounded(
            root_file(&request.profile, 256 * 1024, true)?,
            256 * 1024,
        )?);
        let text = std::str::from_utf8(&profile).map_err(|_| denied("本地隧道配置编码无效"))?;
        let sanitized = validate_regenerated(text, &request.endpoint)
            .map_err(|_| denied("本地隧道配置不符合授权端点及白名单"))?;
        management_path(&request.management)?;
        let channel =
            std::os::unix::net::UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
        let descriptor = receive(
            &channel,
            request.authorization,
            request.interface_index,
            Duration::from_secs(3),
        )?;
        let custody = UtunCustody::verify(descriptor, request.interface_index)?;
        drop(channel);
        let (descriptor, _) = custody.into_descriptor();
        let mut command = Command::new(record.binary_path);
        command
            .arg("--config")
            .arg(&request.profile)
            .arg("--management")
            .arg(&request.management)
            .arg("unix")
            .args([
                "--management-client",
                "--management-hold",
                "--management-client-user",
                "root",
                "--ifconfig-noexec",
                "--auth-retry",
                "none",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("DYLD_FALLBACK_LIBRARY_PATH", "/usr/lib")
            .env("DYLD_FALLBACK_FRAMEWORK_PATH", "/System/Library/Frameworks")
            // 固定加密库的编译默认配置目录可能位于普通用户可写的构建前缀。
            .env("OPENSSL_CONF", "/dev/null")
            .env(
                "OPENSSL_ENGINES",
                request.management.parent().expect("已核对管理目录"),
            )
            .env(
                "OPENSSL_MODULES",
                request.management.parent().expect("已核对管理目录"),
            )
            .current_dir(request.management.parent().expect("已核对管理目录"))
            .stdin(Stdio::null());
        interface_notifications(&mut command, request.interface_notifications);
        // 配置材料不保留到执行替换；只有控制句柄在最后一个串行步骤开放继承。
        drop(sanitized);
        drop(profile);
        Err(exec_inheriting(&mut command, descriptor))
    })();
    outcome.expect_err("成功执行替换不会返回")
}

fn verified_dependency(path: &Path) -> io::Result<DependencyManifest> {
    let record = manifest(&read_bounded(root_file(path, 32768, false)?, 32768)?)?;
    verify_digest(&record.binary_path, &record.binary_sha256)?;
    verify_libraries(&record.binary_path)?;
    Ok(record)
}
pub(crate) fn preflight_dependency(path: &Path) -> io::Result<()> {
    verified_dependency(path).map(|_| ())
}

fn interface_notifications(command: &mut Command, enabled: bool) {
    if enabled {
        command.arg("--management-up-down");
    }
}

fn exec_inheriting(command: &mut Command, descriptor: OwnedFd) -> io::Error {
    let fd = descriptor.as_raw_fd();
    if fd < 3 {
        return denied("隧道借用句柄不得占用标准描述符");
    }
    command.arg("--dev-node").arg(format!("utun-fd:{fd}"));
    let outcome: io::Result<()> = (|| {
        let original = FdFlag::from_bits_truncate(fcntl(&descriptor, FcntlArg::F_GETFD)?);
        fcntl(
            &descriptor,
            FcntlArg::F_SETFD(original & !FdFlag::FD_CLOEXEC),
        )?;
        let error = command.exec();
        // 失败不重试；先恢复继承标志，再由 OwnedFd 关闭本次句柄。
        let _ = fcntl(&descriptor, FcntlArg::F_SETFD(original));
        Err(error)
    })();
    outcome.expect_err("成功执行替换不会返回")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interface_notifications_are_only_enabled_by_explicit_mode() {
        for enabled in [false, true] {
            let mut command = Command::new("/固定程序");
            interface_notifications(&mut command, enabled);
            let args = command.get_args().collect::<Vec<_>>();
            assert_eq!(
                args,
                if enabled {
                    vec![std::ffi::OsStr::new("--management-up-down")]
                } else {
                    Vec::new()
                }
            );
        }
    }

    use std::io::Write;

    #[test]
    fn extended_permissions_are_not_mistaken_for_mode_only_protection() {
        assert!(no_acl(
            b"drwxr-xr-x@ 1 root wheel 0 /usr\n-rwxr-xr-x 1 root wheel 1 /usr/bin/true\n",
            2
        ));
        assert!(!no_acl(
            b"drwxr-xr-x+ 1 root wheel 0 /secure\n 0: user:test allow write\n",
            1
        ));
        assert!(!no_acl(
            b"drwxr-xr-x@ 1 root wheel 0 /secure\n 0: user:test allow write\n",
            1
        ));
        assert!(!no_acl(b"", 1));
        assert!(!no_acl(b"malformed\n", 1));
    }

    #[test]
    fn manifest_pins_version_source_patch_and_digest() {
        let valid = serde_json::json!({"format_version":1,"version":"2.6.23",
            "source_sha256":SOURCE,"patch_sha256":PATCH,"binary_path":"/usr/bin/true",
            "binary_sha256":"12".repeat(32)});
        assert!(manifest(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (key, value) in [
            ("version", "2.6.24"),
            ("source_sha256", "bad"),
            ("patch_sha256", "bad"),
            ("binary_sha256", &"00".repeat(32)),
            ("binary_sha256", &"AB".repeat(32)),
            ("binary_path", "relative"),
            ("binary_path", "/usr/../bin/true"),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value.into();
            assert!(manifest(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut invalid = valid;
        invalid["extra"] = true.into();
        assert!(manifest(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }

    fn image(command: u32, path: &str) -> Vec<u8> {
        let size = (24 + path.len() + 1).next_multiple_of(8);
        let mut data = Vec::new();
        for value in [
            0xfeedfacfu32,
            0x0100000c,
            0,
            2,
            1,
            size as u32,
            0,
            0,
            command,
            size as u32,
            24,
            0,
            0,
            0,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(path.as_bytes());
        data.resize(32 + size, 0);
        data
    }

    #[test]
    fn macho_paths_are_read_without_executing_development_tools() {
        for command in [0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023] {
            let paths = macho_libraries(&image(command, "/usr/lib/libSystem.B.dylib"), 2).unwrap();
            assert_eq!(paths, vec![PathBuf::from("/usr/lib/libSystem.B.dylib")]);
        }
        for path in [
            "@rpath/libcrypto.dylib",
            "/usr/lib/../user/lib.dylib",
            "relative",
        ] {
            assert!(macho_libraries(&image(0xc, path), 2).is_err());
        }
        for command in [0x8000001c, 0x27, 0xe] {
            assert!(macho_libraries(&image(command, "/user/redirect"), 2).is_err());
        }
    }

    #[test]
    fn malformed_macho_records_are_bounded_and_refused() {
        let valid = image(0xc, "/usr/lib/libSystem.B.dylib");
        for length in 0..valid.len() {
            assert!(macho_libraries(&valid[..length], 2).is_err());
        }
        for (offset, value) in [
            (0, 0),
            (4, 7),
            (12, 6),
            (16, 5000),
            (20, u32::MAX),
            (36, 0),
            (36, 9),
            (36, u32::MAX),
            (40, 0),
            (40, u32::MAX),
        ] {
            let mut data = valid.clone();
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(macho_libraries(&data, 2).is_err());
        }
        let mut data = valid;
        data[56..].fill(b'x');
        assert!(macho_libraries(&data, 2).is_err());
    }

    #[test]
    fn program_integrity_and_root_path_ownership_are_checked() {
        let program = Path::new("/usr/bin/true");
        let digest = format!("{:x}", Sha256::digest(std::fs::read(program).unwrap()));
        verify_digest(program, &digest).unwrap();
        // 系统程序为多架构文件；正式依赖只接受目标单架构构建。
        assert!(verify_libraries(program).is_err());
        assert!(verify_digest(program, &"00".repeat(32)).is_err());
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"test").unwrap();
        assert!(root_file(&file, 100, false).is_err());
        assert!(normal_path(Path::new("/path/../file")).is_err());
        assert!(normal_path(Path::new("/path/line\nfile")).is_err());
    }

    #[test]
    fn failed_exec_releases_the_inheritable_descriptor() {
        const MARKER: &str = "VAP_LAUNCHER_FAILURE_TEST_CHILD";
        if std::env::var_os(MARKER).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::launcher::tests::failed_exec_releases_the_inheritable_descriptor",
                ])
                .env(MARKER, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // 执行替换失败也可能改变信号处理状态，必须留在专属子进程中退出。
        let (owner, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let error = exec_inheriting(&mut Command::new("/missing/never-execute"), owner.into());
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn exec_replaces_same_process_and_preserves_only_authorized_descriptor() {
        const MARKER: &str = "VAP_LAUNCHER_TEST_CHILD";
        if std::env::var_os(MARKER).is_some() {
            let descriptor = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
            let mut command = Command::new("/usr/bin/python3");
            command
                .args([
                    "-c",
                    r#"import json,os,socket,stat,sys
fd=int(sys.argv[-1].split(':')[1])
channel=socket.socket(fileno=fd)
channel.settimeout(3)
data=channel.recv(4)
assert data==b'ping'
assert 'VAP_TEST_SECRET' not in os.environ
sockets=[]
for number in range(3,1024):
    try: metadata=os.fstat(number)
    except OSError: continue
    if stat.S_ISSOCK(metadata.st_mode): sockets.append(number)
assert sockets==[fd], sockets
print(json.dumps({'pid':os.getpid(),'received':data.decode()}))"#,
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .stdin(Stdio::null());
            panic!(
                "执行替换失败：{}",
                exec_inheriting(&mut command, descriptor)
            );
        }
        let (child_input, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::launcher::tests::exec_replaces_same_process_and_preserves_only_authorized_descriptor", "--nocapture"])
            .env(MARKER, "1").env("VAP_TEST_SECRET", "must-not-survive")
            .stdin(Stdio::from(OwnedFd::from(child_input))).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        let pid = child.id();
        peer.write_all(b"ping").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let record = stdout
            .lines()
            .find(|line| line.starts_with("{\"pid\""))
            .unwrap();
        let record: serde_json::Value = serde_json::from_str(record).unwrap();
        assert_eq!(record["pid"], pid);
        assert_eq!(record["received"], "ping");
    }

    #[test]
    #[ignore = "需明确提供固定受控隧道程序；仅核对加载格式，不执行程序"]
    fn actual_pinned_openvpn_loading_records_are_supported() {
        let path = std::env::var_os("VAP_TEST_OPENVPN").expect("须明确指定受控程序");
        let data = std::fs::read(path).unwrap();
        assert!(!macho_libraries(&data, 2).unwrap().is_empty());
    }
}
