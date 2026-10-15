//! 只管理本次持有接口的作用域默认路由；不改宿主默认出口。
use super::management::InterfaceMaterial;
use std::io;

mod wire;

/// 必须先回收全部消费者，再显式移除路由；丢弃不执行网络写入。
pub struct ScopedRoute {
    material: InterfaceMaterial,
    control: wire::Control,
    installed: Option<wire::Record>,
}

trait Backend {
    fn check(&mut self, admitting: bool) -> io::Result<()>;
    fn lookup(&mut self) -> io::Result<Option<wire::Record>>;
    fn add(&mut self) -> io::Result<()>;
    fn delete(&mut self) -> io::Result<()>;
    fn valid(&self, record: &wire::Record) -> bool;
}

fn install(backend: &mut impl Backend) -> io::Result<wire::Record> {
    backend.check(true)?;
    if backend.lookup()?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "所属接口已有作用域默认路由，拒绝接管",
        ));
    }
    backend.check(true)?;
    backend.add()?;
    let outcome = (|| {
        backend.check(true)?;
        let record = backend
            .lookup()?
            .filter(|r| backend.valid(r))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "新增作用域路由复核不符"))?;
        backend.check(true)?;
        Ok(record)
    })();
    match outcome {
        Ok(record) => Ok(record),
        Err(error) => {
            // 只有已确认新增成功且仍符合本次固定请求的路由，才承担精确回滚。
            let cleanup = (|| {
                backend.check(false)?;
                match backend.lookup()? {
                    Some(record) if backend.valid(&record) => remove(backend, &record),
                    None => Ok(()),
                    Some(_) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "新增路由已变化，拒绝回滚未知资源",
                    )),
                }
            })();
            match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}；路由回滚：{cleanup}"),
                )),
            }
        }
    }
}
fn remove(backend: &mut impl Backend, owned: &wire::Record) -> io::Result<()> {
    backend.check(false)?;
    match backend.lookup()? {
        None => return Ok(()),
        Some(actual) if &actual == owned => {}
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "作用域路由归属已变化，拒绝删除",
            ));
        }
    }
    backend.check(false)?;
    backend.delete()?;
    if backend.lookup()?.is_some() {
        return Err(io::Error::other("作用域默认路由删除后仍存在"));
    }
    Ok(())
}

impl ScopedRoute {
    pub fn install(material: &InterfaceMaterial) -> io::Result<Self> {
        let result = (|| {
            if !nix::unistd::Uid::effective().is_root() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "配置作用域路由需要管理员身份",
                ));
            }
            // 复制件与真实控制句柄核验在任何路由写入之前完成。
            let material = material.duplicate_checked()?;
            u16::try_from(material.custody().interface_index()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "路由接口索引超出系统字段范围")
            })?;
            let mut route = Self {
                material,
                control: wire::Control::new()?,
                installed: None,
            };
            static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _serial = SERIAL
                .lock()
                .map_err(|_| io::Error::other("作用域路由串行锁已失效"))?;
            route.installed = Some(install(&mut route)?);
            Ok(route)
        })();
        if result.is_err() {
            material.revoke();
        }
        result
    }
    /// 调用方须先停止并等待本代际全部业务及隧道消费者。
    /// 已撤销令牌仍允许回收，但真实句柄身份与路由快照必须继续吻合。
    pub fn retire(&mut self) -> io::Result<()> {
        if let Some(owned) = self.installed.clone() {
            remove(self, &owned)?;
            self.installed = None;
        }
        Ok(())
    }
}
impl Backend for ScopedRoute {
    fn check(&mut self, admitting: bool) -> io::Result<()> {
        self.material.custody().revalidate()?;
        if admitting {
            if self.material.is_revoked() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "路由所属代际已经撤销",
                ));
            }
            super::address::verify_configured(&self.material)?;
        }
        Ok(())
    }
    fn lookup(&mut self) -> io::Result<Option<wire::Record>> {
        self.control
            .lookup(self.material.custody().interface_index() as u16)
    }
    fn add(&mut self) -> io::Result<()> {
        self.control.add(
            self.material.custody().interface_index() as u16,
            self.material.assignment().interface_name(),
        )
    }
    fn delete(&mut self) -> io::Result<()> {
        self.control.delete(
            self.material.custody().interface_index() as u16,
            self.material.assignment().interface_name(),
        )
    }
    fn valid(&self, record: &wire::Record) -> bool {
        record.is_direct(
            self.material.custody().interface_index() as u16,
            self.material.assignment().interface_name(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        route: Option<wire::Record>,
        checks: usize,
        cancel_at: Option<usize>,
        adds: usize,
        deletes: usize,
    }
    fn record() -> wire::Record {
        wire::Record::test_direct(42, "utun41")
    }
    impl Backend for Fake {
        fn check(&mut self, admitting: bool) -> io::Result<()> {
            self.checks += 1;
            if admitting && self.cancel_at == Some(self.checks) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "受控撤销"));
            }
            Ok(())
        }
        fn lookup(&mut self) -> io::Result<Option<wire::Record>> {
            Ok(self.route.clone())
        }
        fn add(&mut self) -> io::Result<()> {
            self.adds += 1;
            self.route = Some(record());
            Ok(())
        }
        fn delete(&mut self) -> io::Result<()> {
            self.deletes += 1;
            self.route = None;
            Ok(())
        }
        fn valid(&self, record: &wire::Record) -> bool {
            record.is_direct(42, "utun41")
        }
    }
    fn empty() -> Fake {
        Fake {
            route: None,
            checks: 0,
            cancel_at: None,
            adds: 0,
            deletes: 0,
        }
    }
    #[test]
    fn new_scoped_default_is_verified_and_removed_only_when_owned() {
        let mut backend = empty();
        let owned = install(&mut backend).unwrap();
        assert_eq!(backend.adds, 1);
        assert_eq!(owned, record());
        remove(&mut backend, &owned).unwrap();
        assert_eq!(backend.deletes, 1);
        assert!(backend.route.is_none());
        remove(&mut backend, &owned).unwrap();
        assert_eq!(backend.deletes, 1);
    }
    #[test]
    fn preexisting_or_replaced_route_is_never_deleted() {
        let mut backend = empty();
        backend.route = Some(record());
        assert_eq!(
            install(&mut backend).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(backend.adds, 0);
        let owned = record();
        backend.route = Some(wire::Record::test_direct(42, "utun99"));
        assert!(remove(&mut backend, &owned).is_err());
        assert_eq!(backend.deletes, 0);
    }
    #[test]
    fn cancellation_never_publishes_route_and_rolls_back_successful_add() {
        for boundary in 1..=4 {
            let mut backend = empty();
            backend.cancel_at = Some(boundary);
            assert!(install(&mut backend).is_err());
            assert!(backend.route.is_none());
            assert_eq!(backend.adds, backend.deletes);
        }
    }

    #[test]
    fn ordinary_user_is_rejected_before_route_channel_or_material_adoption() {
        use crate::platform::{custody::UtunCustody, management};
        use std::{io::Read, os::unix::net::UnixStream};
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let (owner, mut peer) = UnixStream::pair().unwrap();
        let material = management::test_material(
            UtunCustody::test_unverified_resource(owner.into()),
            tokio_util::sync::CancellationToken::new(),
        );
        let result = ScopedRoute::install(&material);
        assert_eq!(
            result.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(material.is_revoked());
        drop(material);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn unconfirmed_add_and_failed_rollback_preserve_responsibility_and_errors() {
        struct Failing {
            inner: Fake,
            ambiguous_add: bool,
        }
        impl Backend for Failing {
            fn check(&mut self, admitting: bool) -> io::Result<()> {
                self.inner.check(admitting)
            }
            fn lookup(&mut self) -> io::Result<Option<wire::Record>> {
                self.inner.lookup()
            }
            fn valid(&self, r: &wire::Record) -> bool {
                self.inner.valid(r)
            }
            fn add(&mut self) -> io::Result<()> {
                self.inner.add()?;
                if self.ambiguous_add {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "新增回复未确认"))
                } else {
                    Ok(())
                }
            }
            fn delete(&mut self) -> io::Result<()> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "受控删除失败",
                ))
            }
        }
        let mut backend = Failing {
            inner: empty(),
            ambiguous_add: true,
        };
        assert_eq!(
            install(&mut backend).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(backend.inner.route.is_some());
        assert_eq!(backend.inner.deletes, 0);
        let mut backend = Failing {
            inner: empty(),
            ambiguous_add: false,
        };
        backend.inner.cancel_at = Some(3);
        let error = install(&mut backend).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(error.to_string().contains("路由回滚"));
        assert!(backend.inner.route.is_some());
    }
}
