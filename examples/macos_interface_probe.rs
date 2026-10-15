//! 显式管理员接口生命周期诊断；不配置地址、路由或启动加密隧道。
#[cfg(target_os = "macos")]
fn main() {
    let report = native::exercise();
    let passed = report["status"] == "passed";
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("诊断记录可序列化")
    );
    if !passed {
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("接口诊断仅支持苹果系统");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
mod native {
    use nix::net::if_::{if_nameindex, if_nametoindex};
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        io, thread,
        time::{Duration, Instant},
    };
    use vpngate_auto_proxy::platform::{custody::UtunCustody, interface};

    fn inventory() -> io::Result<BTreeMap<String, u32>> {
        if_nameindex()?
            .iter()
            .map(|item| {
                let name = item
                    .name()
                    .to_str()
                    .map_err(|_| io::Error::other("接口名称编码无效"))?;
                Ok((name.to_owned(), item.index()))
            })
            .collect()
    }

    fn wait(mut condition: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if condition()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "接口生命周期确认超时",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn exercise() -> Value {
        let mut report = json!({
            "case": "owned-interface-creation",
            "status": "failed",
            "native_interface_validated": false,
            "native_tunnel_validated": false,
            "full_macos_backend_validated": false,
            "checks": {},
            "interfaces": [],
            "cleanup_errors": [],
            "scope": "仅本项目控制连接创建、并存身份核对、逐一释放及接口清单恢复；不配置地址、路由或启动隧道"
        });
        // 在读取清单和任何创建操作之前拒绝普通用户。
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            report["error"] = json!("接口原生诊断需要管理员身份");
            return report;
        }
        let before = match inventory() {
            Ok(before) => before,
            Err(error) => {
                report["error"] = json!(error.to_string());
                return report;
            }
        };
        let mut owned: Vec<UtunCustody> = Vec::new();
        let mut identities = Vec::new();
        let outcome = (|| -> io::Result<()> {
            for _ in 0..2 {
                let custody = interface::create()?;
                custody.revalidate()?;
                let name = custody.interface_name().to_owned();
                let index = if_nametoindex(name.as_str())?;
                owned.push(custody);
                identities.push((name, index));
            }
            report["interfaces"] = json!(
                identities
                    .iter()
                    .map(|(name, index)| json!({"name": name, "index": index}))
                    .collect::<Vec<_>>()
            );
            if identities[0].0 == identities[1].0 || identities[0].1 == identities[1].1 {
                return Err(io::Error::other("并存接口身份不独立"));
            }
            report["checks"]["distinct_live_identities"] = json!(true);
            drop(owned.remove(0));
            wait(|| Ok(!inventory()?.contains_key(&identities[0].0)))?;
            report["checks"]["first_removed_after_release"] = json!(true);
            owned[0].revalidate()?;
            report["checks"]["second_survived_first_release"] = json!(true);
            owned.clear();
            wait(|| Ok(inventory()? == before))?;
            report["checks"]["baseline_restored"] = json!(true);
            Ok(())
        })();
        // 出错也只释放本次句柄，禁止按名称销毁未知接口。
        owned.clear();
        let cleanup = wait(|| Ok(inventory()? == before));
        if let Err(error) = &cleanup {
            report["cleanup_errors"] = json!([error.to_string()]);
        }
        match outcome {
            Ok(()) if cleanup.is_ok() => {
                report["status"] = json!("passed");
                report["native_interface_validated"] = json!(true);
            }
            Err(error) => report["error"] = json!(error.to_string()),
            _ => report["error"] = json!("接口清理未确认"),
        }
        report
    }
}
