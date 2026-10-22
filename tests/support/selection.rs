//! 无网络节点构造；身份与配置固定，时间由调用者提供。
pub fn source(count: usize) -> vpngate_auto_proxy::domain::SourceSnapshot {
    crate::storage::snapshot(count)
}
