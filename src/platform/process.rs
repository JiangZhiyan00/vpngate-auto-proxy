//! 本次直属子进程是否已明确回收；逻辑成功和进程回收是两种独立事实。
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone)]
pub(crate) struct Receipt {
    reaped: Arc<AtomicBool>,
    lease: Option<Arc<super::lease::ConsumerLease>>,
}
impl Default for Receipt {
    fn default() -> Self {
        Self {
            reaped: Arc::new(AtomicBool::new(true)),
            lease: None,
        }
    }
}

impl Receipt {
    pub(crate) fn with_lease(mut self, lease: Option<Arc<super::lease::ConsumerLease>>) -> Self {
        self.lease = lease;
        self
    }
    pub(crate) fn child_stderr(&self) -> std::io::Result<std::process::Stdio> {
        match &self.lease {
            Some(lease) => lease.child_stdio(),
            None => Ok(std::process::Stdio::null()),
        }
    }
    pub(crate) fn spawned(&self) {
        self.reaped.store(false, Ordering::Release);
    }
    pub(crate) fn observe(&self, child: &mut tokio::process::Child) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            self.reaped.store(true, Ordering::Release);
        }
    }
    pub(crate) fn reaped(&self) -> bool {
        self.reaped.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn receipt_requires_observing_actual_direct_child_reaping() {
        let receipt = Receipt::default();
        assert!(receipt.reaped());
        let mut child = crate::platform::spawn::guarded(|| {
            tokio::process::Command::new("/usr/bin/python3")
                .args(["-c", "import time; time.sleep(60)"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
        })
        .unwrap();
        receipt.spawned();
        receipt.observe(&mut child);
        assert!(!receipt.reaped());
        child.start_kill().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!receipt.reaped());
        receipt.observe(&mut child);
        assert!(receipt.reaped());
    }
}
