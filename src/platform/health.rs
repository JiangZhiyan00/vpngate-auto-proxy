//! 活动代际的独立健康调度；仅使用正式低权限检测，不累积重叠轮次。
use super::{exit_probe::ExitProbeSettings, lifecycle::MacExitSession};
use crate::{domain::WorkerId, probe::ProbeReport};
use std::{future::Future, io, time::Duration};
use tokio::{sync::watch, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
pub struct MacHealthSettings {
    pub interval: Duration,
    pub exit: ExitProbeSettings,
}
impl MacHealthSettings {
    pub(super) fn validate(&self) -> io::Result<()> {
        self.exit.validate()?;
        if self.interval <= self.exit.budget || Instant::now().checked_add(self.interval).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "健康间隔须大于检测预算且可表示",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacHealthResult {
    pub worker_id: WorkerId,
    pub generation: Uuid,
    pub sequence: u64,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub report: Option<ProbeReport>,
    pub error: Option<String>,
}
trait Checker: Send + 'static {
    fn check(
        &mut self,
        settings: ExitProbeSettings,
        stop: CancellationToken,
    ) -> impl Future<Output = io::Result<ProbeReport>> + Send;
}
impl Checker for MacExitSession {
    async fn check(
        &mut self,
        settings: ExitProbeSettings,
        stop: CancellationToken,
    ) -> io::Result<ProbeReport> {
        MacExitSession::check(self, settings, stop).await
    }
}
pub(super) struct MacHealthMonitor {
    stop: CancellationToken,
    revoked: CancellationToken,
    result: watch::Receiver<Option<MacHealthResult>>,
    task: Option<JoinHandle<io::Result<()>>>,
    completion: Option<Result<(), String>>,
}
impl MacHealthMonitor {
    pub(super) fn start(
        session: MacExitSession,
        worker: WorkerId,
        settings: MacHealthSettings,
    ) -> io::Result<Self> {
        let generation = session.generation();
        let revoked = session.cancellation();
        Self::launch(session, worker, generation, revoked, settings)
    }
    fn launch<C: Checker>(
        checker: C,
        worker: WorkerId,
        generation: Uuid,
        revoked: CancellationToken,
        settings: MacHealthSettings,
    ) -> io::Result<Self> {
        settings.validate()?;
        if revoked.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "健康调度所属代际已撤销",
            ));
        }
        let stop = CancellationToken::new();
        let (sender, result) = watch::channel(None);
        let cancellation = stop.clone();
        let failure = revoked.clone().drop_guard();
        let generation_stop = revoked.clone();
        let task = tokio::spawn(async move {
            let _failure = failure;
            run(
                checker,
                worker,
                generation,
                settings,
                cancellation,
                generation_stop,
                sender,
            )
            .await
        });
        Ok(Self {
            stop,
            revoked,
            result,
            task: Some(task),
            completion: None,
        })
    }
    pub(super) fn subscribe(&self) -> watch::Receiver<Option<MacHealthResult>> {
        self.result.clone()
    }
    pub(super) fn cancel(&self) {
        self.stop.cancel();
        self.revoked.cancel();
    }
    pub(super) async fn shutdown(&mut self) -> io::Result<()> {
        self.cancel();
        if let Some(task) = self.task.as_mut() {
            self.completion = Some(match task.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("健康调度任务异常，所属代际已撤销".into()),
            });
            self.task.take();
        }
        match &self.completion {
            Some(Err(error)) => Err(io::Error::other(error.clone())),
            _ => Ok(()),
        }
    }
}
impl Drop for MacHealthMonitor {
    fn drop(&mut self) {
        self.cancel();
        // 不中止仍在等待直属检测回收的任务；外层运行时须保持存活。
    }
}
async fn run<C: Checker>(
    mut checker: C,
    worker: WorkerId,
    generation: Uuid,
    settings: MacHealthSettings,
    stop: CancellationToken,
    revoked: CancellationToken,
    sender: watch::Sender<Option<MacHealthResult>>,
) -> io::Result<()> {
    let mut sequence = 0_u64;
    let mut next = Instant::now()
        .checked_add(settings.interval)
        .ok_or_else(|| io::Error::other("健康截止无法表示"))?;
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Ok(()),
            _ = revoked.cancelled() => return Ok(()),
            _ = tokio::time::sleep_until(next) => {},
        }
        let started_at = chrono::Utc::now();
        // 不丢弃执行中的检查未来；取消由正式检测监督处理并确认子进程回收。
        let result = checker.check(settings.exit.clone(), stop.clone()).await;
        if stop.is_cancelled() {
            return Ok(());
        }
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("健康轮次序号耗尽"))?;
        let success = result.as_ref().is_ok_and(|report| report.success);
        if success && revoked.is_cancelled() {
            return Ok(());
        }
        let (report, error) = match result {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        };
        // 失败先撤销所属代际，随后才通知结果订阅者。
        if !success {
            revoked.cancel();
        }
        sender.send_replace(Some(MacHealthResult {
            worker_id: worker,
            generation,
            sequence,
            started_at,
            finished_at: chrono::Utc::now(),
            report,
            error,
        }));
        if !success {
            return Err(io::Error::other("活动出口健康检测失败，代际已撤销"));
        }
        let now = Instant::now();
        let scheduled = next
            .checked_add(settings.interval)
            .ok_or_else(|| io::Error::other("健康截止无法表示"))?;
        // 已错过的调度丢弃，不在长检测或回收后突发补跑。
        next = if scheduled <= now {
            now.checked_add(settings.interval)
                .ok_or_else(|| io::Error::other("健康截止无法表示"))?
        } else {
            scheduled
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Fake<F>(F);
    impl<F, R> Checker for Fake<F>
    where
        F: FnMut(CancellationToken) -> R + Send + 'static,
        R: Future<Output = io::Result<ProbeReport>> + Send,
    {
        async fn check(
            &mut self,
            _: ExitProbeSettings,
            stop: CancellationToken,
        ) -> io::Result<ProbeReport> {
            (self.0)(stop).await
        }
    }
    fn settings() -> MacHealthSettings {
        MacHealthSettings {
            interval: Duration::from_secs(10),
            exit: ExitProbeSettings {
                urls: vec![url::Url::parse("https://example.com/").unwrap()],
                max_attempts: 1,
                budget: Duration::from_secs(5),
            },
        }
    }
    fn report(success: bool) -> ProbeReport {
        ProbeReport {
            success,
            attempts: 1,
            status: success.then_some(204),
            failure: (!success).then_some(crate::probe::ProbeFailure::Transport),
            elapsed: Duration::from_millis(1),
        }
    }
    async fn advance(seconds: u64) {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::task::yield_now().await;
    }
    fn monitor<C: Checker>(checker: C, revoked: CancellationToken) -> MacHealthMonitor {
        MacHealthMonitor::launch(
            checker,
            WorkerId::default(),
            Uuid::new_v4(),
            revoked,
            settings(),
        )
        .unwrap()
    }
    #[tokio::test(start_paused = true)]
    async fn checks_start_on_interval_and_carry_generation_identity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let revoked = CancellationToken::new();
        let mut monitor = monitor(
            Fake(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                async { Ok(report(true)) }
            }),
            revoked.clone(),
        );
        let worker = WorkerId::default();
        // 使用单独已知身份启动第二个监视器，证明结果与其所属代际绑定。
        let generation = Uuid::new_v4();
        let mut identified = MacHealthMonitor::launch(
            Fake(|_| async { Ok(report(true)) }),
            worker,
            generation,
            CancellationToken::new(),
            settings(),
        )
        .unwrap();
        advance(9).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        advance(1).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let value = identified.subscribe().borrow().clone().unwrap();
        assert_eq!(value.worker_id, worker);
        assert_eq!(value.generation, generation);
        assert_eq!(value.sequence, 1);
        assert!(value.report.unwrap().success);
        advance(10).await;
        assert_eq!(monitor.subscribe().borrow().as_ref().unwrap().sequence, 2);
        assert!(!revoked.is_cancelled());
        monitor.shutdown().await.unwrap();
        identified.shutdown().await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn first_failed_round_revokes_before_result_and_never_retries() {
        for operational_error in [false, true] {
            let revoked = CancellationToken::new();
            let mut monitor = monitor(
                Fake(move |_| async move {
                    if operational_error {
                        Err(io::Error::other("受控检测监督错误"))
                    } else {
                        Ok(report(false))
                    }
                }),
                revoked.clone(),
            );
            advance(10).await;
            assert!(revoked.is_cancelled());
            let value = monitor.subscribe().borrow().clone().unwrap();
            assert_eq!(value.sequence, 1);
            assert_eq!(value.error.is_some(), operational_error);
            advance(100).await;
            assert_eq!(monitor.subscribe().borrow().as_ref().unwrap().sequence, 1);
            for _ in 0..2 {
                assert!(monitor.shutdown().await.is_err());
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn long_check_does_not_overlap_or_burst_to_catch_up() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (allow, gate) = tokio::sync::oneshot::channel();
        let mut gate = Some(gate);
        let mut monitor = monitor(
            Fake(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                let gate = gate.take();
                async move {
                    if let Some(gate) = gate {
                        gate.await.unwrap();
                    }
                    Ok(report(true))
                }
            }),
            CancellationToken::new(),
        );
        advance(10).await;
        advance(35).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        allow.send(()).unwrap();
        tokio::task::yield_now().await;
        advance(9).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        advance(1).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        monitor.shutdown().await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn cancelled_shutdown_keeps_check_and_resumes_retirement() {
        let (entered, mut started) = tokio::sync::mpsc::channel(1);
        let (allow, gate) = tokio::sync::oneshot::channel();
        let mut gate = Some(gate);
        let mut monitor = monitor(
            Fake(move |stop: CancellationToken| {
                let gate = gate.take().unwrap();
                let entered = entered.clone();
                async move {
                    entered.send(()).await.unwrap();
                    stop.cancelled().await;
                    gate.await.unwrap();
                    Ok(report(true))
                }
            }),
            CancellationToken::new(),
        );
        advance(10).await;
        started.recv().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), monitor.shutdown())
                .await
                .is_err()
        );
        assert!(monitor.task.is_some());
        assert!(monitor.subscribe().borrow().is_none());
        allow.send(()).unwrap();
        monitor.shutdown().await.unwrap();
        assert!(monitor.subscribe().borrow().is_none());
    }
    #[tokio::test(start_paused = true)]
    async fn drop_revokes_synchronously_and_keeps_retirement_running() {
        let revoked = CancellationToken::new();
        let (entered, mut started) = tokio::sync::mpsc::channel(1);
        let (finished, done) = tokio::sync::oneshot::channel();
        let mut finished = Some(finished);
        let monitor = monitor(
            Fake(move |stop: CancellationToken| {
                let finished = finished.take().unwrap();
                let entered = entered.clone();
                async move {
                    entered.send(()).await.unwrap();
                    stop.cancelled().await;
                    finished.send(()).unwrap();
                    Ok(report(true))
                }
            }),
            revoked.clone(),
        );
        advance(10).await;
        started.recv().await.unwrap();
        drop(monitor);
        assert!(revoked.is_cancelled());
        done.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn panic_revokes_and_retains_failed_completion() {
        let revoked = CancellationToken::new();
        let mut monitor = monitor(
            Fake(|_| async {
                panic!("受控健康任务异常");
                #[allow(unreachable_code)]
                Ok(report(true))
            }),
            revoked.clone(),
        );
        advance(10).await;
        assert!(revoked.is_cancelled());
        assert!(monitor.shutdown().await.is_err());
        assert!(monitor.shutdown().await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn revoked_generation_never_publishes_late_success() {
        let revoked = CancellationToken::new();
        let token = revoked.clone();
        let mut monitor = monitor(
            Fake(move |_| {
                token.cancel();
                async { Ok(report(true)) }
            }),
            revoked,
        );
        advance(10).await;
        assert!(monitor.subscribe().borrow().is_none());
        monitor.shutdown().await.unwrap();
    }
    #[test]
    fn invalid_intervals_and_probe_settings_are_rejected() {
        for interval in [Duration::ZERO, Duration::from_secs(5), Duration::MAX] {
            let mut settings = settings();
            settings.interval = interval;
            assert!(settings.validate().is_err());
        }
        let mut settings = settings();
        settings.exit.max_attempts = 0;
        assert!(settings.validate().is_err());
    }
}
