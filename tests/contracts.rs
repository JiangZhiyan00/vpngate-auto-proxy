//! 契约测试入口；随对应任务增加显式模块注册。
#[path = "contracts/cli.rs"]
mod cli;
#[path = "contracts/config.rs"]
mod config;
#[cfg(target_os = "macos")]
#[path = "contracts/custody.rs"]
mod custody;
#[path = "contracts/domain.rs"]
mod domain;
#[path = "contracts/failover.rs"]
mod failover;
#[path = "contracts/generation.rs"]
mod generation;
#[path = "contracts/netd.rs"]
mod netd;
#[path = "contracts/platform.rs"]
mod platform;
#[path = "contracts/probe.rs"]
mod probe;
#[path = "contracts/scheduler.rs"]
mod scheduler;
#[path = "contracts/socks.rs"]
mod socks;
#[path = "contracts/storage.rs"]
mod storage;
#[path = "integration/support.rs"]
mod support;
