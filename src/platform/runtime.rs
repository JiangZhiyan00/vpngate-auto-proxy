//! 私有代际目录的归属事务；丢弃对象不删除可能仍被消费者使用的材料。
use super::supervisor::WorkerCredentials;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    kind: NodeKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NodeKind {
    Directory,
    File,
    Socket,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceIntent {
    format_version: u32,
    generation_id: Uuid,
    phase: InterfacePhase,
    interface_name: Option<String>,
    interface_index: Option<u32>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceAssociation {
    format_version: u32,
    instance_id: Uuid,
    generation_id: Uuid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InterfacePhase {
    Creating,
    Identified,
}
impl InterfaceIntent {
    fn validate(&self, generation_id: Uuid) -> io::Result<()> {
        let denied = || io::Error::new(io::ErrorKind::InvalidData, "接口分配记录无效");
        if self.format_version != 1
            || self.generation_id != generation_id
            || match self.phase {
                InterfacePhase::Creating => {
                    self.interface_name.is_some() || self.interface_index.is_some()
                }
                InterfacePhase::Identified => {
                    let Some(name) = self.interface_name.as_deref() else {
                        return Err(denied());
                    };
                    let Some(index) = self.interface_index else {
                        return Err(denied());
                    };
                    index == 0
                        || name.len() > 15
                        || !name.strip_prefix("utun").is_some_and(|digits| {
                            !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_digit())
                        })
                }
            }
        {
            return Err(denied());
        }
        Ok(())
    }
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipManifest {
    format_version: u32,
    generation_id: Uuid,
    creator_pid: u32,
    consumers_may_exist: bool,
    nodes: Vec<Node>,
}
impl Node {
    fn read(path: PathBuf) -> io::Result<Self> {
        Self::from_metadata(path.clone(), &fs::symlink_metadata(path)?)
    }
    fn from_metadata(path: PathBuf, m: &fs::Metadata) -> io::Result<Self> {
        if m.file_type().is_symlink() || !(m.is_file() || m.is_dir() || m.file_type().is_socket()) {
            return Err(io::Error::other("代际节点类型无效"));
        }
        Ok(Self {
            path,
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            kind: if m.is_dir() {
                NodeKind::Directory
            } else if m.is_file() {
                NodeKind::File
            } else {
                NodeKind::Socket
            },
        })
    }
    fn check(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
            Ok(m) => self.check_metadata(&m),
        }
    }
    fn check_existing(&self) -> io::Result<()> {
        self.check_metadata(&fs::symlink_metadata(&self.path)?)
    }
    fn check_metadata(&self, m: &fs::Metadata) -> io::Result<()> {
        if m.dev() == self.device
            && m.ino() == self.inode
            && m.uid() == self.uid
            && m.gid() == self.gid
            && !m.file_type().is_symlink()
            && match self.kind {
                NodeKind::Directory => m.is_dir(),
                NodeKind::File => m.is_file(),
                NodeKind::Socket => m.file_type().is_socket(),
            }
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "代际节点归属已改变，拒绝回收",
            ))
        }
    }
}
pub(crate) struct GenerationRuntime {
    root: PathBuf,
    generation_id: Uuid,
    nodes: Vec<Node>,
    consumer_receipt: Option<super::lease::LeaseReceipt>,
    consumer_owner: Option<std::sync::Weak<super::lease::ConsumerLease>>,
    interface_intent: Option<InterfaceIntent>,
    instance_id: Option<Uuid>,
}
impl GenerationRuntime {
    /// 候选根目录没有公开锚点，只用于拒绝未知残留；结果不授权删除。
    pub(crate) fn audit_candidate(
        root: &Path,
        instance_id: Uuid,
        owner_uid: u32,
    ) -> io::Result<super::lease::LeaseReceipt> {
        let denied = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "候选代际与公开实例关联不符",
            )
        };
        if instance_id.is_nil() {
            return Err(denied());
        }
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(denied)?;
        let generation_id = name
            .strip_prefix("g-")
            .filter(|id| id.len() == 32)
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(denied)?;
        let metadata = fs::symlink_metadata(root)?;
        let receipt = Self::audit_recorded_nodes(
            root,
            generation_id,
            metadata.dev(),
            metadata.ino(),
            owner_uid,
        )?;
        let path = root.join("instance.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)?;
        let metadata = file.metadata()?;
        let named = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.uid() != owner_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 4096
            || metadata.dev() != named.dev()
            || metadata.ino() != named.ino()
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(denied());
        }
        let record: InstanceAssociation = serde_json::from_slice(&bytes)?;
        if record.format_version != 1
            || record.instance_id != instance_id
            || record.generation_id != generation_id
        {
            return Err(denied());
        }
        Ok(receipt)
    }
    /// 只读核对遗留代际的落盘归属。成功仍不授权删除：接口、路由和宿主基线尚无持久证据。
    pub(crate) fn audit_recorded_nodes(
        root: &Path,
        generation_id: Uuid,
        device: u64,
        inode: u64,
        owner_uid: u32,
    ) -> io::Result<super::lease::LeaseReceipt> {
        let denied = || io::Error::new(io::ErrorKind::PermissionDenied, "遗留代际归属证据不完整");
        if generation_id.is_nil()
            || !root.is_absolute()
            || root.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || root.file_name().and_then(|name| name.to_str())
                != Some(format!("g-{}", generation_id.simple()).as_str())
        {
            return Err(denied());
        }
        let root_metadata = fs::symlink_metadata(root)?;
        if !root_metadata.is_dir()
            || root_metadata.file_type().is_symlink()
            || root_metadata.dev() != device
            || root_metadata.ino() != inode
            || root_metadata.uid() != owner_uid
            || root_metadata.mode() & 0o7777 != 0o711
        {
            return Err(denied());
        }
        let manifest_path = root.join("ownership.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&manifest_path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != owner_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 65536
            || metadata.dev() != fs::symlink_metadata(&manifest_path)?.dev()
            || metadata.ino() != fs::symlink_metadata(&manifest_path)?.ino()
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(denied());
        }
        let record: OwnershipManifest = serde_json::from_slice(&bytes)?;
        if record.format_version != 3
            || record.generation_id != generation_id
            || !record.consumers_may_exist
            || record.nodes.len() < 6
            || record.nodes.len() > 16
        {
            return Err(denied());
        }
        let mut listed = HashSet::new();
        for node in &record.nodes {
            if !listed.insert(node.path.clone())
                || node.path != *root
                    && node.path.parent() != Some(root)
                    && node.path.parent() != Some(root.join("t").as_path())
                    && node.path.parent() != Some(root.join("w").as_path())
            {
                return Err(denied());
            }
            node.check_existing()?;
            let metadata = fs::symlink_metadata(&node.path)?;
            let expected_mode = if node.path == root {
                0o711
            } else if node.path == root.join("t") {
                0o700
            } else if node.path == root.join("w") {
                0o750
            } else {
                0o600
            };
            if metadata.mode() & 0o7777 != expected_mode
                || node.kind != NodeKind::Directory && metadata.nlink() != 1
            {
                return Err(denied());
            }
            if node.kind == NodeKind::Socket {
                let parent = node.path.parent().ok_or_else(denied)?;
                let prefix = if parent == root.join("t") {
                    "t-"
                } else if parent == root.join("w") {
                    "w-"
                } else {
                    return Err(denied());
                };
                let name = node
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(denied)?;
                let id = name
                    .strip_prefix(prefix)
                    .and_then(|name| name.strip_suffix(".sock"))
                    .ok_or_else(denied)?;
                if id.len() != 32 || Uuid::parse_str(id).is_err() {
                    return Err(denied());
                }
            } else if node.path != root
                && node.path != root.join("t")
                && node.path != root.join("w")
                && node.path != root.join("t/profile.ovpn")
                && node.path != root.join("consumers.lock")
                && node.path != root.join("consumers.json")
                && node.path != root.join("interface-intent.json")
                && node.path != root.join("instance.json")
                && node.path != root.join("w/identity-check")
            {
                return Err(denied());
            }
        }
        if !listed.contains(root)
            || !listed.contains(&root.join("t"))
            || !listed.contains(&root.join("w"))
            || !listed.contains(&root.join("t/profile.ovpn"))
            || !listed.contains(&root.join("consumers.lock"))
            || !listed.contains(&root.join("consumers.json"))
        {
            return Err(denied());
        }
        let required = [
            (root.to_owned(), NodeKind::Directory),
            (root.join("t"), NodeKind::Directory),
            (root.join("w"), NodeKind::Directory),
            (root.join("t/profile.ovpn"), NodeKind::File),
            (root.join("consumers.lock"), NodeKind::File),
            (root.join("consumers.json"), NodeKind::File),
        ];
        for (path, kind) in required {
            if !record
                .nodes
                .iter()
                .any(|node| node.path == path && node.kind == kind)
            {
                return Err(denied());
            }
        }
        if let Some(node) = record
            .nodes
            .iter()
            .find(|node| node.path == root.join("instance.json"))
        {
            if node.kind != NodeKind::File {
                return Err(denied());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&node.path)?;
            let metadata = file.metadata()?;
            node.check_metadata(&metadata)?;
            if metadata.len() == 0 || metadata.len() > 4096 {
                return Err(denied());
            }
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            if bytes.len() > 4096 {
                return Err(denied());
            }
            let association: InstanceAssociation = serde_json::from_slice(&bytes)?;
            if association.format_version != 1
                || association.instance_id.is_nil()
                || association.generation_id != generation_id
            {
                return Err(denied());
            }
        }
        if listed.contains(&root.join("interface-intent.json"))
            && !listed.contains(&root.join("instance.json"))
        {
            return Err(denied());
        }
        if let Some(intent_node) = record
            .nodes
            .iter()
            .find(|node| node.path == root.join("interface-intent.json"))
        {
            if intent_node.kind != NodeKind::File {
                return Err(denied());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(&intent_node.path)?;
            let metadata = file.metadata()?;
            intent_node.check_metadata(&metadata)?;
            if metadata.len() == 0 || metadata.len() > 4096 {
                return Err(denied());
            }
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            if bytes.len() > 4096 {
                return Err(denied());
            }
            let intent: InterfaceIntent = serde_json::from_slice(&bytes)?;
            intent.validate(generation_id)?;
        }
        let lock_node = record
            .nodes
            .iter()
            .find(|node| node.path == root.join("consumers.lock"))
            .ok_or_else(denied)?;
        let receipt_path = root.join("consumers.json");
        let receipt_node = record
            .nodes
            .iter()
            .find(|node| node.path == receipt_path)
            .ok_or_else(denied)?;
        let receipt_file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&receipt_path)?;
        let receipt_meta = receipt_file.metadata()?;
        receipt_node.check_metadata(&receipt_meta)?;
        if receipt_meta.nlink() != 1
            || receipt_meta.mode() & 0o7777 != 0o600
            || receipt_meta.len() == 0
            || receipt_meta.len() > 4096
        {
            return Err(denied());
        }
        let mut receipt_bytes = Vec::new();
        receipt_file.take(4097).read_to_end(&mut receipt_bytes)?;
        if receipt_bytes.len() > 4096 {
            return Err(denied());
        }
        let receipt: super::lease::LeaseReceipt = serde_json::from_slice(&receipt_bytes)?;
        if !receipt.matches_recorded_lock(
            &lock_node.path,
            lock_node.device,
            lock_node.inode,
            lock_node.uid,
            lock_node.gid,
        ) {
            return Err(denied());
        }
        for directory in [root.to_owned(), root.join("t"), root.join("w")] {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path();
                if path != manifest_path && !listed.contains(&path) {
                    return Err(denied());
                }
            }
        }
        Ok(receipt)
    }
    #[cfg(test)]
    pub(crate) fn test_prepare() -> (tempfile::TempDir, Self) {
        let parent = tempfile::Builder::new()
            .prefix("vr-")
            .tempdir_in("/private/tmp")
            .unwrap();
        let credentials = WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        };
        let runtime = Self::prepare_with(
            parent.path(),
            Uuid::new_v4(),
            b"private",
            credentials,
            |_, _, _| Ok(()),
        )
        .unwrap();
        (parent, runtime)
    }
    pub(crate) fn prepare(
        parent: &Path,
        profile: &[u8],
        credentials: WorkerCredentials,
    ) -> io::Result<Self> {
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "准备代际目录需要管理员身份",
            ));
        }
        credentials.validate_account()?;
        super::launcher::root_chain(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || ![0o711, 0o755].contains(&(metadata.mode() & 0o777)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "代际父目录须受管理员保护并允许消费者搜索",
            ));
        }
        Self::prepare_with(
            parent,
            Uuid::new_v4(),
            profile,
            credentials,
            |path, uid, gid| std::os::unix::fs::chown(path, Some(uid), Some(gid)),
        )
    }
    pub(crate) fn tunnel(&self) -> PathBuf {
        self.root.join("t")
    }
    pub(crate) fn worker(&self) -> PathBuf {
        self.root.join("w")
    }
    pub(crate) fn profile(&self) -> PathBuf {
        self.tunnel().join("profile.ovpn")
    }
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn identity(&self) -> (Uuid, u64, u64) {
        let root = self.nodes.first().expect("代际根节点已登记");
        (self.generation_id, root.device, root.inode)
    }
    /// 先登记锁文件和私有凭据，再允许派生消费者；它们保留到其余材料清理之后。
    pub(crate) fn consumer_lease(
        &mut self,
    ) -> io::Result<std::sync::Arc<super::lease::ConsumerLease>> {
        let path = self.root.join("consumers.lock");
        let lease = super::lease::ConsumerLease::create(&path)?;
        self.nodes.insert(1, Node::read(path)?);
        self.write(
            self.root.join("consumers.json"),
            &serde_json::to_vec(&lease.receipt())?,
        )?;
        let receipt = self.nodes.pop().expect("消费者锁凭据已登记");
        self.nodes.insert(2, receipt);
        self.persist_manifest()?;
        self.consumer_receipt = Some(lease.receipt());
        let lease = std::sync::Arc::new(lease);
        self.consumer_owner = Some(std::sync::Arc::downgrade(&lease));
        Ok(lease)
    }
    /// 候选代际在接口创建前绑定公开实例；单独的文件仍不授权恢复删除。
    pub(crate) fn bind_instance(&mut self, instance_id: Uuid) -> io::Result<()> {
        if instance_id.is_nil()
            || self.instance_id.is_some()
            || self.consumer_receipt.is_none()
            || self.interface_intent.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "候选实例关联前置状态无效",
            ));
        }
        let record = InstanceAssociation {
            format_version: 1,
            instance_id,
            generation_id: self.generation_id,
        };
        self.write(
            self.root.join("instance.json"),
            &serde_json::to_vec(&record)?,
        )?;
        File::open(&self.root)?.sync_all()?;
        self.persist_manifest()?;
        self.instance_id = Some(instance_id);
        Ok(())
    }
    /// 在可能创建接口前持久记录不可逆边界；崩溃在创建与身份落盘之间只能保留待审计状态。
    pub(crate) fn begin_interface_creation(&mut self) -> io::Result<()> {
        if self.interface_intent.is_some()
            || self.consumer_receipt.is_none()
            || self.instance_id.is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "接口分配前置状态无效",
            ));
        }
        let intent = InterfaceIntent {
            format_version: 1,
            generation_id: self.generation_id,
            phase: InterfacePhase::Creating,
            interface_name: None,
            interface_index: None,
        };
        self.write(
            self.root.join("interface-intent.json"),
            &serde_json::to_vec(&intent)?,
        )?;
        File::open(&self.root)?.sync_all()?;
        self.persist_manifest()?;
        self.interface_intent = Some(intent);
        Ok(())
    }
    /// 只接受本次已核验控制句柄的名称与索引；落盘失败不得继续交付隧道或业务。
    pub(crate) fn record_interface(
        &mut self,
        custody: &super::custody::UtunCustody,
    ) -> io::Result<()> {
        custody.revalidate()?;
        self.record_interface_identity(custody.interface_name(), custody.interface_index())
    }
    fn record_interface_identity(&mut self, name: &str, index: u32) -> io::Result<()> {
        let previous = self
            .interface_intent
            .as_ref()
            .filter(|record| record.phase == InterfacePhase::Creating)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "接口分配记录未准备"))?;
        self.verify_interface_intent(previous)?;
        let next = InterfaceIntent {
            format_version: 1,
            generation_id: self.generation_id,
            phase: InterfacePhase::Identified,
            interface_name: Some(name.to_owned()),
            interface_index: Some(index),
        };
        next.validate(self.generation_id)?;
        let path = self.root.join("interface-intent.json");
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)?;
        self.intent_node()?.check_metadata(&file.metadata()?)?;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&serde_json::to_vec(&next)?)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        self.verify_interface_intent(&next)?;
        self.interface_intent = Some(next);
        Ok(())
    }
    fn intent_node(&self) -> io::Result<&Node> {
        self.nodes
            .iter()
            .find(|node| node.path == self.root.join("interface-intent.json"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "接口分配记录未登记"))
    }
    fn verify_interface_intent(&self, expected: &InterfaceIntent) -> io::Result<()> {
        let path = self.root.join("interface-intent.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)?;
        let node = self.intent_node()?;
        let metadata = file.metadata()?;
        node.check_metadata(&metadata)?;
        if metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 4096
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "接口分配记录节点无效",
            ));
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        let actual: InterfaceIntent = serde_json::from_slice(&bytes)?;
        actual.validate(self.generation_id)?;
        if &actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "接口分配记录内容已改变",
            ));
        }
        Ok(())
    }
    /// 仅接受本代际命名空间中的实际 Unix 套接字，登记落盘后才能发布就绪材料。
    pub(crate) fn register_socket(&mut self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("代际端点没有父目录"))?;
        let prefix = if parent == self.tunnel() {
            "t-"
        } else if parent == self.worker() {
            "w-"
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "端点不在本代际目录",
            ));
        };
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("端点名称无效"))?;
        let id = name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(".sock"))
            .ok_or_else(|| io::Error::other("端点名称不属于本代际"))?;
        if id.len() != 32
            || Uuid::parse_str(id).is_err()
            || self.nodes.iter().any(|n| n.path == path)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "端点名称或登记状态无效",
            ));
        }
        let directory = self
            .nodes
            .iter()
            .find(|node| node.path == parent && node.kind == NodeKind::Directory)
            .ok_or_else(|| io::Error::other("端点父目录未登记"))?;
        directory.check_existing()?;
        let node = Node::read(path.to_owned())?;
        let metadata = fs::symlink_metadata(path)?;
        if node.kind != NodeKind::Socket
            || metadata.uid() != directory.uid
            || metadata.gid() != directory.gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "端点类型、归属或权限无效",
            ));
        }
        self.nodes.push(node);
        File::open(parent)?.sync_all()?;
        self.persist_manifest()
    }
    fn prepare_with(
        parent: &Path,
        id: Uuid,
        profile: &[u8],
        credentials: WorkerCredentials,
        mut owner: impl FnMut(&Path, u32, u32) -> io::Result<()>,
    ) -> io::Result<Self> {
        let root = parent.join(format!("g-{}", id.simple()));
        for directory in [root.join("t"), root.join("w")] {
            nix::sys::socket::UnixAddr::new(
                &directory.join(format!("w-{}.sock", Uuid::nil().simple())),
            )?;
        }
        let mut runtime = Self {
            root,
            generation_id: id,
            nodes: Vec::new(),
            consumer_receipt: None,
            consumer_owner: None,
            interface_intent: None,
            instance_id: None,
        };
        let result = (|| {
            runtime.directory(runtime.root.clone(), 0o711)?;
            runtime.directory(runtime.tunnel(), 0o700)?;
            runtime.directory(runtime.worker(), 0o750)?;
            owner(&runtime.worker(), credentials.uid, credentials.gid)?;
            *runtime.nodes.last_mut().expect("工作目录已登记") = Node::read(runtime.worker())?;
            runtime.write(runtime.profile(), profile)?;
            let record = OwnershipManifest {
                format_version: 3,
                generation_id: id,
                creator_pid: std::process::id(),
                consumers_may_exist: true,
                nodes: runtime.nodes.clone(),
            };
            runtime.write(
                runtime.root.join("ownership.json"),
                &serde_json::to_vec_pretty(&record)?,
            )?;
            let manifest = runtime.nodes.pop().expect("清单节点已登记");
            runtime.nodes.insert(1, manifest);
            File::open(runtime.tunnel())?.sync_all()?;
            File::open(&runtime.root)?.sync_all()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(runtime),
            Err(error) => match runtime.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}；代际准备回收：{cleanup}；材料目录：{}",
                        runtime.root.display()
                    ),
                )),
            },
        }
    }
    fn directory(&mut self, path: PathBuf, mode: u32) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        self.nodes.push(Node::read(path.clone())?);
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    fn write(&mut self, path: PathBuf, bytes: &[u8]) -> io::Result<()> {
        self.write_open(path, bytes).map(drop)
    }
    fn write_open(&mut self, path: PathBuf, bytes: &[u8]) -> io::Result<File> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)?;
        self.nodes
            .push(Node::from_metadata(path, &file.metadata()?)?);
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(file)
    }
    /// 清单写入失败时不得交付新消费者；截断中断留下无效清单，后续恢复必须拒绝。
    fn persist_manifest(&self) -> io::Result<()> {
        let path = self.root.join("ownership.json");
        let manifest_node = self
            .nodes
            .iter()
            .find(|node| node.path == path)
            .ok_or_else(|| io::Error::other("代际清单未登记"))?;
        manifest_node.check()?;
        let record = self.current_manifest();
        let bytes = serde_json::to_vec_pretty(&record)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.dev() != manifest_node.device
            || metadata.ino() != manifest_node.inode
            || metadata.uid() != manifest_node.uid
            || metadata.gid() != manifest_node.gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || bytes.len() > 65536
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "代际清单身份、权限或长度无效",
            ));
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        self.verify_persisted_manifest(&record)
    }
    fn current_manifest(&self) -> OwnershipManifest {
        let path = self.root.join("ownership.json");
        OwnershipManifest {
            format_version: 3,
            generation_id: self.generation_id,
            creator_pid: std::process::id(),
            consumers_may_exist: true,
            nodes: self
                .nodes
                .iter()
                .filter(|node| node.path != path)
                .cloned()
                .collect(),
        }
    }
    /// 重新打开并比较精确节点登记；这仅证明静态清单可读，不代表运行期资源已完整登记。
    fn verify_persisted_manifest(&self, expected: &OwnershipManifest) -> io::Result<()> {
        let path = self.root.join("ownership.json");
        let registered = self
            .nodes
            .iter()
            .find(|node| node.path == path)
            .ok_or_else(|| io::Error::other("代际清单未登记"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.dev() != registered.device
            || metadata.ino() != registered.inode
            || metadata.uid() != registered.uid
            || metadata.gid() != registered.gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 65536
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "持久代际清单节点无效",
            ));
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "持久代际清单超过长度上限",
            ));
        }
        let actual: OwnershipManifest = serde_json::from_slice(&bytes)?;
        if &actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "持久代际清单内容与已登记节点不一致",
            ));
        }
        for node in &actual.nodes {
            node.check_existing()?;
        }
        Ok(())
    }
    /// 部署验证使用的唯一可写文件；先登记节点，再变更归属，失败时保留回收责任。
    pub(crate) fn deployment_marker(&mut self, credentials: WorkerCredentials) -> io::Result<()> {
        self.deployment_marker_with(credentials, |_| Ok(()))
    }
    fn deployment_marker_with(
        &mut self,
        credentials: WorkerCredentials,
        after_create: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let path = self.worker().join("identity-check");
        let file = self.write_open(path.clone(), b"")?;
        after_create(&path)?;
        // 工作目录已交付普通账户；路径可能被替换，归属操作必须只作用于原描述符。
        rustix::fs::fchown(
            &file,
            Some(rustix::fs::Uid::from_raw(credentials.uid)),
            Some(rustix::fs::Gid::from_raw(credentials.gid)),
        )?;
        let metadata = file.metadata()?;
        let node = Node::from_metadata(path.clone(), &metadata)?;
        *self.nodes.last_mut().expect("部署文件已登记") = node.clone();
        // 不能采用清理时允许文件缺失的规则；交付必须确认原节点仍在且只有一个链接。
        let current = Node::read(path)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || current.device != node.device
            || current.inode != node.inode
            || current.uid != credentials.uid
            || current.gid != credentials.gid
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "部署文件在交付前已被替换或链接",
            ));
        }
        file.sync_all()?;
        File::open(self.worker())?.sync_all()?;
        self.persist_manifest()
    }
    pub(crate) fn deployment_marker_matches(&self, expected: &[u8]) -> io::Result<bool> {
        let path = self.worker().join("identity-check");
        let node = self
            .nodes
            .iter()
            .find(|node| node.path == path)
            .ok_or_else(|| io::Error::other("部署验证文件未登记"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.dev() != node.device
            || m.ino() != node.inode
            || m.uid() != node.uid
            || m.gid() != node.gid
            || m.nlink() != 1
            || m.mode() & 0o777 != 0o600
        {
            return Err(io::Error::other("部署验证文件身份已改变"));
        }
        let mut bytes = Vec::new();
        file.take(expected.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes == expected)
    }
    /// 只可在尚未派生消费者或已经确认全部回收之后调用。
    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        for node in &self.nodes {
            node.check()?;
        }
        if let Some(owner) = self
            .consumer_owner
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            owner.close_owner()?;
        }
        let _quiescent = match &self.consumer_receipt {
            Some(receipt) => Some(
                receipt
                    .wait_quiescent(std::time::Duration::from_millis(100))?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::WouldBlock, "消费者锁仍被占用，保留代际材料")
                    })?,
            ),
            None => None,
        };
        while let Some(node) = self.nodes.last() {
            node.check()?;
            let result = if node.kind == NodeKind::Directory {
                fs::remove_dir(&node.path)
            } else {
                fs::remove_file(&node.path)
            };
            match result {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            self.nodes.pop();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credentials() -> WorkerCredentials {
        WorkerCredentials {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }
    #[test]
    fn legacy_audit_reads_exact_nodes_and_rejects_foreign_entry() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        let (id, dev, ino) = layout.identity();
        let root = layout.root().to_owned();
        let uid = nix::unistd::getuid().as_raw();
        GenerationRuntime::audit_recorded_nodes(&root, id, dev, ino, uid).unwrap();
        let foreign = root.join("w/unknown");
        fs::write(&foreign, b"keep").unwrap();
        assert!(GenerationRuntime::audit_recorded_nodes(&root, id, dev, ino, uid).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"keep");
        fs::remove_file(foreign).unwrap();
        assert!(GenerationRuntime::audit_recorded_nodes(&root, id, dev, ino + 1, uid).is_err());
        drop(lease);
        layout.cleanup().unwrap();
    }
    #[test]
    fn legacy_audit_rejects_mismatched_consumer_receipt_without_changes() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        let (id, dev, ino) = layout.identity();
        let root = layout.root().to_owned();
        let receipt = root.join("consumers.json");
        let original = fs::read(&receipt).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["inode"] = serde_json::json!(1);
        fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            GenerationRuntime::audit_recorded_nodes(
                &root,
                id,
                dev,
                ino,
                nix::unistd::getuid().as_raw()
            )
            .is_err()
        );
        assert!(root.join("consumers.lock").exists());
        fs::write(receipt, original).unwrap();
        drop(lease);
        layout.cleanup().unwrap();
    }
    #[test]
    fn legacy_audit_rejects_changed_directory_mode_and_profile_hardlink() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        let (id, dev, ino) = layout.identity();
        let root = layout.root().to_owned();
        let uid = nix::unistd::getuid().as_raw();
        fs::set_permissions(layout.worker(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(GenerationRuntime::audit_recorded_nodes(&root, id, dev, ino, uid).is_err());
        fs::set_permissions(layout.worker(), fs::Permissions::from_mode(0o750)).unwrap();
        let alias = layout.tunnel().join("profile-alias");
        fs::hard_link(layout.profile(), &alias).unwrap();
        assert!(GenerationRuntime::audit_recorded_nodes(&root, id, dev, ino, uid).is_err());
        assert!(alias.exists());
        fs::remove_file(alias).unwrap();
        drop(lease);
        layout.cleanup().unwrap();
    }
    #[test]
    fn interface_intent_is_durable_before_creation_and_identity_update() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        assert!(layout.record_interface_identity("utun7", 35).is_err());
        layout.bind_instance(Uuid::new_v4()).unwrap();
        layout.begin_interface_creation().unwrap();
        let path = layout.root().join("interface-intent.json");
        let creating: InterfaceIntent = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(creating.phase, InterfacePhase::Creating);
        assert_eq!(creating.generation_id, layout.generation_id);
        assert!(layout.begin_interface_creation().is_err());
        assert!(layout.record_interface_identity("en0", 35).is_err());
        layout.record_interface_identity("utun7", 35).unwrap();
        let identified: InterfaceIntent =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(identified.phase, InterfacePhase::Identified);
        assert_eq!(identified.interface_name.as_deref(), Some("utun7"));
        assert_eq!(identified.interface_index, Some(35));
        assert!(layout.record_interface_identity("utun8", 36).is_err());
        let (id, dev, ino) = layout.identity();
        GenerationRuntime::audit_recorded_nodes(
            layout.root(),
            id,
            dev,
            ino,
            nix::unistd::getuid().as_raw(),
        )
        .unwrap();
        drop(lease);
        layout.cleanup().unwrap();
    }
    #[test]
    fn changed_interface_intent_is_never_rewritten_or_adopted() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        layout.bind_instance(Uuid::new_v4()).unwrap();
        layout.begin_interface_creation().unwrap();
        let path = layout.root().join("interface-intent.json");
        fs::write(&path, b"broken").unwrap();
        assert!(layout.record_interface_identity("utun7", 35).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
        let (id, dev, ino) = layout.identity();
        assert!(
            GenerationRuntime::audit_recorded_nodes(
                layout.root(),
                id,
                dev,
                ino,
                nix::unistd::getuid().as_raw()
            )
            .is_err()
        );
        drop(lease);
        layout.cleanup().unwrap();
    }
    #[test]
    fn candidate_instance_association_is_durable_and_tampering_blocks_audit() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        let instance = Uuid::new_v4();
        layout.bind_instance(instance).unwrap();
        assert!(layout.bind_instance(Uuid::new_v4()).is_err());
        let path = layout.root().join("instance.json");
        let record: InstanceAssociation =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(record.instance_id, instance);
        let (id, dev, ino) = layout.identity();
        GenerationRuntime::audit_candidate(layout.root(), instance, nix::unistd::getuid().as_raw())
            .unwrap();
        assert!(
            GenerationRuntime::audit_candidate(
                layout.root(),
                Uuid::new_v4(),
                nix::unistd::getuid().as_raw()
            )
            .is_err()
        );
        GenerationRuntime::audit_recorded_nodes(
            layout.root(),
            id,
            dev,
            ino,
            nix::unistd::getuid().as_raw(),
        )
        .unwrap();
        fs::write(&path, b"{").unwrap();
        assert!(
            GenerationRuntime::audit_recorded_nodes(
                layout.root(),
                id,
                dev,
                ino,
                nix::unistd::getuid().as_raw()
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"{");
        drop(lease);
        layout.cleanup().unwrap();
    }
    fn parent() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("vr-")
            .tempdir_in("/private/tmp")
            .unwrap()
    }
    #[test]
    fn complete_layout_records_nodes_and_cleans_without_recursive_deletion() {
        let parent = parent();
        let mut layout = GenerationRuntime::prepare_with(
            parent.path(),
            Uuid::new_v4(),
            b"private",
            credentials(),
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(fs::metadata(layout.root()).unwrap().mode() & 0o777, 0o711);
        assert_eq!(fs::metadata(layout.tunnel()).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(layout.worker()).unwrap().mode() & 0o777, 0o750);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.root().join("ownership.json")).unwrap())
                .unwrap();
        assert!(value["consumers_may_exist"].as_bool().unwrap());
        layout.cleanup().unwrap();
        assert!(!layout.root().exists());
        layout.cleanup().unwrap();
    }
    #[test]
    fn consumer_receipt_is_private_and_cleanup_tracks_its_exact_nodes() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        let root = layout.root().to_path_buf();
        let lock = root.join("consumers.lock");
        let receipt = root.join("consumers.json");
        assert_eq!(fs::metadata(&lock).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&receipt).unwrap().mode() & 0o777, 0o600);
        let saved: super::super::lease::LeaseReceipt =
            serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
        assert!(saved.try_quiescent().unwrap().is_none());
        let consumer = lease.child_stdio().unwrap();
        assert!(layout.cleanup().is_err());
        assert!(layout.consumer_lease().is_err());
        assert!(lease.child_stdio().is_err());
        drop(lease);
        assert!(saved.try_quiescent().unwrap().is_none());
        drop(consumer);
        assert!(
            saved
                .wait_quiescent(std::time::Duration::from_millis(100))
                .unwrap()
                .is_some()
        );
        layout.cleanup().unwrap();
        assert!(!root.exists());
    }
    #[test]
    fn manifest_records_each_static_node_before_a_consumer_can_start() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let manifest_path = layout.root().join("ownership.json");
        let read = || -> OwnershipManifest {
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap()
        };
        let original = read();
        assert_eq!(original.format_version, 3);
        assert_eq!(original.generation_id, layout.generation_id);
        assert_eq!(original.nodes.len(), 4);
        assert!(original.nodes.iter().all(|node| node.check().is_ok()));
        let lease = layout.consumer_lease().unwrap();
        let with_lease = read();
        assert_eq!(with_lease.nodes.len(), 6);
        assert!(
            with_lease
                .nodes
                .iter()
                .any(|node| node.path == layout.root().join("consumers.lock"))
        );
        assert!(
            with_lease
                .nodes
                .iter()
                .any(|node| node.path == layout.root().join("consumers.json"))
        );
        layout.deployment_marker(credentials()).unwrap();
        let with_marker = read();
        assert_eq!(with_marker.nodes.len(), 7);
        assert!(with_marker.nodes.iter().all(|node| node.check().is_ok()));
        assert!(
            with_marker
                .nodes
                .iter()
                .any(|node| node.path == layout.worker().join("identity-check"))
        );
        drop(lease);
        layout.cleanup().unwrap();
    }
    #[test]
    fn replaced_manifest_is_not_rewritten_or_adopted_when_adding_a_lease() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let path = layout.root().join("ownership.json");
        let saved = layout.root().join("saved-manifest");
        fs::rename(&path, &saved).unwrap();
        fs::write(&path, b"outside").unwrap();
        assert!(layout.consumer_lease().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"outside");
        assert!(layout.root().join("consumers.lock").exists());
        assert!(layout.root().join("consumers.json").exists());
        assert!(layout.cleanup().is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(saved, path).unwrap();
        layout.cleanup().unwrap();
    }
    #[test]
    fn persisted_manifest_verification_rejects_truncation_and_missing_owned_nodes() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let path = layout.root().join("ownership.json");
        let expected = layout.current_manifest();
        fs::write(&path, b"{").unwrap();
        assert!(layout.verify_persisted_manifest(&expected).is_err());
        layout.persist_manifest().unwrap();
        let saved = layout.tunnel().join("saved-profile");
        fs::rename(layout.profile(), &saved).unwrap();
        assert!(layout.verify_persisted_manifest(&expected).is_err());
        fs::rename(saved, layout.profile()).unwrap();
        layout.verify_persisted_manifest(&expected).unwrap();
        layout.cleanup().unwrap();
    }
    #[test]
    fn owned_runtime_sockets_are_recorded_before_publication_and_removed_exactly() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let tunnel = layout
            .tunnel()
            .join(format!("t-{}.sock", Uuid::new_v4().simple()));
        let worker = layout
            .worker()
            .join(format!("w-{}.sock", Uuid::new_v4().simple()));
        let _tunnel_listener = std::os::unix::net::UnixListener::bind(&tunnel).unwrap();
        let _worker_listener = std::os::unix::net::UnixListener::bind(&worker).unwrap();
        fs::set_permissions(&tunnel, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o600)).unwrap();
        layout.register_socket(&tunnel).unwrap();
        layout.register_socket(&worker).unwrap();
        let manifest: OwnershipManifest =
            serde_json::from_slice(&fs::read(layout.root().join("ownership.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.format_version, 3);
        assert_eq!(manifest.nodes.len(), 6);
        assert!(
            manifest
                .nodes
                .iter()
                .any(|node| node.path == tunnel && node.kind == NodeKind::Socket)
        );
        assert!(
            manifest
                .nodes
                .iter()
                .any(|node| node.path == worker && node.kind == NodeKind::Socket)
        );
        assert!(layout.register_socket(&worker).is_err());
        layout.cleanup().unwrap();
        assert!(!tunnel.exists());
        assert!(!worker.exists());
    }
    #[test]
    fn foreign_or_replaced_socket_is_never_registered_or_deleted() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let path = layout
            .tunnel()
            .join(format!("t-{}.sock", Uuid::new_v4().simple()));
        let outside = tempfile::tempdir().unwrap();
        let foreign = outside.path().join("t-foreign.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&foreign).unwrap();
        assert!(layout.register_socket(&foreign).is_err());
        std::os::unix::fs::symlink(&foreign, &path).unwrap();
        assert!(layout.register_socket(&path).is_err());
        fs::remove_file(&path).unwrap();
        let _owned = std::os::unix::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        layout.register_socket(&path).unwrap();
        let saved = layout.tunnel().join("saved.sock");
        fs::rename(&path, &saved).unwrap();
        let _replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(layout.cleanup().is_err());
        assert!(path.exists());
        assert!(foreign.exists());
        fs::remove_file(&path).unwrap();
        fs::rename(saved, &path).unwrap();
        layout.cleanup().unwrap();
    }
    #[test]
    fn unknown_content_keeps_consumer_receipt_for_recovery() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        let lease = layout.consumer_lease().unwrap();
        let root = layout.root().to_path_buf();
        let extra = layout.worker().join("unowned");
        fs::write(&extra, b"keep").unwrap();
        drop(lease);
        assert!(layout.cleanup().is_err());
        assert!(root.join("consumers.lock").exists());
        assert!(root.join("consumers.json").exists());
        assert!(root.join("ownership.json").exists());
        fs::remove_file(extra).unwrap();
        layout.cleanup().unwrap();
    }
    #[test]
    fn failed_owner_change_rolls_back_only_new_nodes() {
        let parent = parent();
        assert!(
            GenerationRuntime::prepare_with(
                parent.path(),
                Uuid::new_v4(),
                b"private",
                credentials(),
                |_, _, _| Err(io::Error::other("受控归属失败"))
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    #[test]
    fn unknown_worker_content_preserves_manifest_and_is_never_deleted() {
        let parent = parent();
        let mut layout = GenerationRuntime::prepare_with(
            parent.path(),
            Uuid::new_v4(),
            b"private",
            credentials(),
            |_, _, _| Ok(()),
        )
        .unwrap();
        let unowned = layout.worker().join("unowned");
        fs::write(&unowned, b"keep").unwrap();
        assert!(layout.cleanup().is_err());
        assert_eq!(fs::read(&unowned).unwrap(), b"keep");
        assert!(layout.root().join("ownership.json").exists());
        fs::remove_file(unowned).unwrap();
        layout.cleanup().unwrap();
    }
    #[test]
    fn replaced_node_and_existing_generation_are_not_adopted() {
        let parent = parent();
        let id = Uuid::new_v4();
        let mut layout = GenerationRuntime::prepare_with(
            parent.path(),
            id,
            b"private",
            credentials(),
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert!(
            GenerationRuntime::prepare_with(
                parent.path(),
                id,
                b"other",
                credentials(),
                |_, _, _| Ok(())
            )
            .is_err()
        );
        assert_eq!(fs::read(layout.profile()).unwrap(), b"private");
        let saved = layout.profile().with_extension("saved");
        fs::rename(layout.profile(), &saved).unwrap();
        std::os::unix::fs::symlink(&saved, layout.profile()).unwrap();
        assert_eq!(
            layout.cleanup().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(layout.root().join("ownership.json").exists());
        fs::remove_file(layout.profile()).unwrap();
        fs::rename(saved, layout.profile()).unwrap();
        layout.cleanup().unwrap();
    }
    #[test]
    fn marker_path_replacements_never_become_owned_nodes() {
        for symlink in [false, true] {
            let (_parent, mut layout) = GenerationRuntime::test_prepare();
            let outside = tempfile::NamedTempFile::new().unwrap();
            fs::write(outside.path(), b"outside").unwrap();
            fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o640)).unwrap();
            let before = fs::metadata(outside.path()).unwrap();
            let marker = layout.worker().join("identity-check");
            let saved = layout.worker().join("saved-marker");
            assert!(
                layout
                    .deployment_marker_with(credentials(), |path| {
                        fs::rename(path, &saved)?;
                        if symlink {
                            std::os::unix::fs::symlink(outside.path(), path)?;
                        } else {
                            fs::write(path, b"replacement")?;
                            fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
                        }
                        Ok(())
                    })
                    .is_err()
            );
            let recorded = layout.nodes.last().unwrap();
            assert_eq!(recorded.inode, fs::metadata(&saved).unwrap().ino());
            assert!(layout.cleanup().is_err());
            assert!(layout.root().join("ownership.json").exists());
            let after = fs::metadata(outside.path()).unwrap();
            assert_eq!(
                (before.ino(), before.uid(), before.gid(), before.mode()),
                (after.ino(), after.uid(), after.gid(), after.mode())
            );
            assert_eq!(fs::read(outside.path()).unwrap(), b"outside");
            if !symlink {
                assert_eq!(fs::read(&marker).unwrap(), b"replacement");
                assert_eq!(fs::metadata(&marker).unwrap().mode() & 0o777, 0o644);
            }
            fs::remove_file(&marker).unwrap();
            fs::rename(saved, marker).unwrap();
            layout.cleanup().unwrap();
        }
    }
    #[test]
    fn marker_missing_or_multiply_linked_is_not_delivered() {
        for missing in [false, true] {
            let (_parent, mut layout) = GenerationRuntime::test_prepare();
            let marker = layout.worker().join("identity-check");
            let saved = layout.worker().join("saved-marker");
            assert!(
                layout
                    .deployment_marker_with(credentials(), |path| {
                        if missing {
                            fs::rename(path, &saved)
                        } else {
                            fs::hard_link(path, &saved)
                        }
                    })
                    .is_err()
            );
            if missing {
                fs::rename(&saved, &marker).unwrap();
            } else {
                fs::remove_file(saved).unwrap();
            }
            layout.cleanup().unwrap();
        }
    }
    #[test]
    fn marker_descriptor_handoff_preserves_identity_and_exact_cleanup() {
        let (_parent, mut layout) = GenerationRuntime::test_prepare();
        layout.deployment_marker(credentials()).unwrap();
        let marker = layout.worker().join("identity-check");
        let node = layout.nodes.last().unwrap();
        let metadata = fs::metadata(&marker).unwrap();
        assert_eq!(
            (node.inode, node.uid, node.gid),
            (metadata.ino(), credentials().uid, credentials().gid)
        );
        assert_eq!(metadata.mode() & 0o777, 0o600);
        fs::write(marker, b"verified").unwrap();
        assert!(layout.deployment_marker_matches(b"verified").unwrap());
        layout.cleanup().unwrap();
    }
    #[test]
    fn long_socket_paths_are_rejected_before_creating_materials() {
        let parent = parent();
        let deep = parent.path().join("a".repeat(100));
        fs::create_dir(&deep).unwrap();
        assert!(
            GenerationRuntime::prepare_with(
                &deep,
                Uuid::new_v4(),
                b"private",
                credentials(),
                |_, _, _| Ok(())
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(deep).unwrap().count(), 0);
    }
}
