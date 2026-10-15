//! Linux 受控集成测试入口；随对应任务增加显式模块注册。
#[path = "integration/candidates.rs"]
mod candidates;
#[path = "integration/capacity.rs"]
mod capacity;
#[path = "integration/failover.rs"]
mod failover;
#[path = "integration/lifecycle.rs"]
mod lifecycle;
#[path = "integration/network_foundation.rs"]
mod network_foundation;
#[path = "integration/startup.rs"]
mod startup;
#[path = "integration/support.rs"]
mod support;
#[path = "integration/tunnels.rs"]
mod tunnels;
