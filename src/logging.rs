//! 显式日志策略；输出拥塞只损失诊断，不能阻塞业务或资源回收。
use crate::{config::AppConfig, domain::*};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::VecDeque,
    io::Write,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tokio::time::Instant;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}
impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = LogLevel;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("log_level 必须为 error、warn、info 或 debug")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<LogLevel, E> {
                match value {
                    "error" => Ok(LogLevel::Error),
                    "warn" => Ok(LogLevel::Warn),
                    "info" => Ok(LogLevel::Info),
                    "debug" => Ok(LogLevel::Debug),
                    _ => Err(E::custom("log_level 必须为 error、warn、info 或 debug")),
                }
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}
#[derive(Debug, Clone, Copy)]
pub struct LogPolicy {
    pub level: LogLevel,
    pub summary_interval: Duration,
}
impl LogPolicy {
    pub fn new(level: LogLevel, seconds: u64) -> Self {
        Self {
            level,
            summary_interval: Duration::from_secs(seconds),
        }
    }
    pub fn allows(self, severity: LogLevel) -> bool {
        severity <= self.level
    }
}
impl From<&AppConfig> for LogPolicy {
    fn from(config: &AppConfig) -> Self {
        Self::new(config.log_level, config.log_summary_interval_seconds)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenScope {
    #[default]
    ProcessLocal,
    ContainerInternal,
}

#[derive(Serialize)]
pub struct StartupConfig<'a> {
    listen_address: std::net::Ipv4Addr,
    port: u16,
    protocol: &'static str,
    listen_scope: ListenScope,
    countries: Vec<String>,
    timezone: &'static str,
    max_connections: usize,
    log_level: LogLevel,
    log_summary_interval_seconds: u64,
    data_dir: &'a std::path::Path,
    runtime_dir: &'a std::path::Path,
    authentication_enabled: bool,
}
#[derive(Serialize)]
pub struct StartupSummary<'a> {
    #[serde(flatten)]
    event: Event,
    instance_id: uuid::Uuid,
    ready: bool,
    config: StartupConfig<'a>,
}
impl<'a> StartupSummary<'a> {
    pub fn new(
        config: &'a AppConfig,
        instance_id: uuid::Uuid,
        actual: std::net::SocketAddr,
    ) -> Option<Self> {
        let std::net::SocketAddr::V4(actual) = actual else {
            return None;
        };
        if instance_id.is_nil()
            || !config.data_dir.is_absolute()
            || !config.runtime_dir.is_absolute()
        {
            return None;
        }
        let event = event(
            config,
            EventKind::StartupSummary,
            ServiceState::Waiting,
            None,
            None,
            Some("服务已开始监听，等待已验证出口"),
            Duration::ZERO,
        )?;
        Some(Self {
            event,
            instance_id,
            ready: false,
            config: StartupConfig {
                listen_address: *actual.ip(),
                port: actual.port(),
                protocol: "socks5",
                listen_scope: config.listen_scope,
                countries: config
                    .countries
                    .iter()
                    .map(|value| value.to_ascii_uppercase())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                timezone: config.timezone.name(),
                max_connections: config.max_connections,
                log_level: config.log_level,
                log_summary_interval_seconds: config.log_summary_interval_seconds,
                data_dir: &config.data_dir,
                runtime_dir: &config.runtime_dir,
                authentication_enabled: config.credentials_file.is_some(),
            },
        })
    }
}

macro_rules! kinds {
    ($($variant:ident => ($name:literal, $level:ident)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum EventKind { $(#[serde(rename = $name)] $variant),+ }
        impl EventKind {
            pub const fn name(self) -> &'static str { match self { $(Self::$variant => $name),+ } }
            pub const fn level(self) -> LogLevel { match self { $(Self::$variant => LogLevel::$level),+ } }
        }
    }
}
kinds! {
    StartupSummary => ("startup_summary", Info),
    Stopped => ("stopped", Info),
    SourceChanged => ("source_changed", Info),
    StateChanged => ("state_changed", Info),
    ActivePromoted => ("active_promoted", Info),
    SourceFailed => ("source_failed", Warn),
    ActiveCheckFailed => ("active_check_failed", Warn),
    ActiveBlocked => ("active_blocked", Warn),
    CacheWriteFailed => ("cache_write_failed", Warn),
    DiagnosticsWriteFailed => ("diagnostics_write_failed", Warn),
    RuntimeFailed => ("runtime_failed", Error),
    SelectionAssessed => ("selection_assessed", Debug),
    SelectionDispatched => ("selection_dispatched", Debug),
    SelectionSkipped => ("selection_skipped", Debug),
    SourceFetch => ("source_fetch", Debug),
    SourceUpdated => ("source_updated", Debug),
    CacheLoaded => ("cache_loaded", Debug),
    CacheIgnored => ("cache_ignored", Debug),
    DiagnosticsIgnored => ("diagnostics_ignored", Debug),
    PendingStarted => ("pending_started", Debug),
    CandidateStarted => ("candidate_started", Debug),
    TunnelConnected => ("tunnel_connected", Debug),
    CandidateResult => ("candidate_result", Debug),
    RoundStarted => ("round_started", Debug),
    RoundFinished => ("round_finished", Debug),
    ActiveCheckSucceeded => ("active_check_succeeded", Debug),
    RuntimeSummary => ("runtime_summary", Debug),
}

/// 白名单安全原因；不直接转发未知错误、远端文字或完整配置。
pub fn safe_reason(kind: EventKind, value: Option<&str>) -> Option<String> {
    let reason = value?;
    const SAFE: &[&str] = &[
        "来源缓存不存在、无效或已过期",
        "诊断缓存不存在或无效，不影响来源恢复",
        "来源缓存写入失败",
        "诊断写入失败，不改变可用性",
        "诊断缓存写入失败，不改变可用性",
        "来源获取或解析失败，保留原快照与时间",
        "结构性隧道故障",
        "活动隧道结构检查失败",
        "出口检测总时限耗尽",
        "出口检测证书校验失败",
        "出口检测响应失败",
        "出口检测连接失败",
        "出口检测全部失败",
        "当前无已验证出口，等待节点",
        "history_capacity_exceeded：节点历史容量不足，停止新派发并回收资源",
        "服务已开始监听，等待已验证出口",
    ];
    if SAFE.contains(&reason) {
        return Some(reason.into());
    }
    if matches!(
        kind,
        EventKind::ActiveCheckFailed | EventKind::ActiveCheckSucceeded
    ) && let Ok(mut check) = serde_json::from_str::<crate::service::ActiveCheckSummary>(reason)
    {
        check.failure = check.failure.as_deref().map(|value| {
            if SAFE.contains(&value) {
                value.into()
            } else {
                "出口检测失败".into()
            }
        });
        return serde_json::to_string(&check).ok();
    }
    Some(
        match kind {
            EventKind::SourceChanged | EventKind::SourceUpdated => "来源有效状态已更新",
            EventKind::ActiveBlocked => "活动出口已阻断，等待重新验证",
            EventKind::RuntimeFailed => "实例操作失败，请核对安全检查阶段",
            _ => "详细原因不在公开诊断白名单中",
        }
        .into(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn event(
    config: &AppConfig,
    kind: EventKind,
    state: ServiceState,
    node: Option<NodeId>,
    worker: Option<WorkerId>,
    reason: Option<&str>,
    elapsed: Duration,
) -> Option<Event> {
    if !LogPolicy::from(config).allows(kind.level()) {
        return None;
    }
    Some(Event {
        timestamp: chrono::Utc::now()
            .with_timezone(&config.timezone)
            .fixed_offset(),
        level: kind.level(),
        event_type: kind.name().into(),
        node_id: node,
        worker_id: worker,
        state,
        reason: safe_reason(kind, reason),
        elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
    })
}

pub struct SummaryClock {
    interval: Duration,
    next: Instant,
}
impl SummaryClock {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            next: Instant::now(),
        }
    }
    pub fn due(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + self.interval;
        true
    }
}

struct Line {
    text: String,
    kind: EventKind,
    selected: LogLevel,
    timestamp: String,
}
struct Sink {
    ordinary: Arc<Mutex<VecDeque<Line>>>,
    startup: mpsc::SyncSender<Line>,
    startup_used: AtomicBool,
    losses: Arc<[AtomicU64; 4]>,
    pending: Arc<AtomicUsize>,
}
fn lost(losses: &[AtomicU64; 4], level: LogLevel) {
    let counter = &losses[level as usize];
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
impl Sink {
    fn new() -> Self {
        let ordinary = Arc::new(Mutex::new(VecDeque::<Line>::with_capacity(63)));
        let losses = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
        let pending = Arc::new(AtomicUsize::new(0));
        let (startup, receiver) = mpsc::sync_channel::<Line>(1);
        let queue = ordinary.clone();
        let counts = losses.clone();
        let outstanding = pending.clone();
        // 独立线程只持有日志目标，不持有实例控制、隧道或资源租约。
        // 标准错误不可写甚至永久阻塞时，业务线程仍可退休，进程不等待此线程。
        let _ = std::thread::Builder::new().name("vap-log".into()).spawn(move || {
            let mut last_overflow = None::<std::time::Instant>;
            loop {
                let next = receiver
                    .try_recv()
                    .ok()
                    .or_else(|| queue.lock().ok()?.pop_front());
                let Some(line) = next else {
                    std::thread::park_timeout(Duration::from_millis(10));
                    continue;
                };
                let mut stderr = std::io::stderr().lock();
                let success = writeln!(stderr, "{}", line.text).is_ok();
                outstanding.fetch_sub(1, Ordering::Release);
                if !success {
                    lost(&counts, line.kind.level());
                    continue;
                }
                let now = std::time::Instant::now();
                if last_overflow.is_some_and(|at| now.duration_since(at) < Duration::from_secs(60))
                {
                    continue;
                }
                let snapshot: [u64; 4] =
                    std::array::from_fn(|i| counts[i].swap(0, Ordering::Relaxed));
                if let Some(highest) = snapshot.iter().position(|count| *count != 0) {
                    let level = [
                        LogLevel::Error,
                        LogLevel::Warn,
                        LogLevel::Info,
                        LogLevel::Debug,
                    ][highest];
                    if level <= line.selected {
                        let report = serde_json::json!({"timestamp":line.timestamp,"event_type":"diagnostics_overflow",
                            "level":level,"node_id":null,"worker_id":null,"state":"waiting","reason":"诊断交付发生损失",
                            "elapsed_ms":0,"loss_counts":snapshot});
                        if writeln!(stderr, "{report}").is_err() {
                            for (i, value) in snapshot.iter().enumerate() {
                                let _ = counts[i].fetch_update(
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                    |old| Some(old.saturating_add(*value)),
                                );
                            }
                        }
                    }
                    last_overflow = Some(now);
                }
            }
        });
        Self {
            ordinary,
            startup,
            startup_used: AtomicBool::new(false),
            losses,
            pending,
        }
    }
    fn submit(&self, line: Line) {
        if line.kind == EventKind::StartupSummary {
            if self.startup_used.swap(true, Ordering::Relaxed) {
                return;
            }
            self.pending.fetch_add(1, Ordering::Release);
            if self.startup.try_send(line).is_err() {
                self.pending.fetch_sub(1, Ordering::Release);
            }
            return;
        }
        let Ok(mut queue) = self.ordinary.try_lock() else {
            lost(&self.losses, line.kind.level());
            return;
        };
        if queue.len() == 63 {
            let level = line.kind.level();
            let replace = [
                LogLevel::Debug,
                LogLevel::Info,
                LogLevel::Warn,
                LogLevel::Error,
            ]
            .iter()
            .filter(|candidate| **candidate >= level)
            .find_map(|candidate| {
                queue.iter().position(|old| {
                    old.kind.level() == *candidate
                        && (level != LogLevel::Info
                            || *candidate != LogLevel::Info
                            || old.kind == line.kind)
                })
            });
            let Some(index) = replace.filter(|_| level != LogLevel::Debug) else {
                lost(&self.losses, level);
                return;
            };
            if let Some(old) = queue.remove(index) {
                lost(&self.losses, old.kind.level());
            }
            self.pending.fetch_sub(1, Ordering::Release);
        }
        self.pending.fetch_add(1, Ordering::Release);
        queue.push_back(line);
    }
}
static SINK: OnceLock<Sink> = OnceLock::new();

pub fn write<T: Serialize>(config: &AppConfig, kind: EventKind, value: &T) {
    if !LogPolicy::from(config).allows(kind.level()) {
        return;
    }
    let Ok(text) = serde_json::to_string(value) else {
        return;
    };
    if text.len() > 1024 * 1024 {
        return;
    }
    let line = Line {
        text,
        kind,
        selected: config.log_level,
        timestamp: chrono::Utc::now()
            .with_timezone(&config.timezone)
            .to_rfc3339(),
    };
    SINK.get_or_init(Sink::new).submit(line);
}
/// 有限结束排空；调用方须从已有停止总预算中提供剩余时间。
pub async fn flush(budget: Duration) {
    let Some(sink) = SINK.get() else {
        return;
    };
    let end = Instant::now() + budget.min(Duration::from_secs(1));
    while sink.pending.load(Ordering::Acquire) != 0 && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// 固定类型的单节点选择说明；不包含配置正文或自由远端文本。
pub struct SelectionDiagnostic {
    pub event_type: EventKind,
    pub level: LogLevel,
    pub timestamp: chrono::DateTime<chrono::FixedOffset>,
    pub state: ServiceState,
    pub policy_version: u32,
    pub weights: [u64; 5],
    pub selection: crate::scheduler::SelectionRecord,
}
impl serde::Serialize for SelectionDiagnostic {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // 时间统一服从配置时区；仅转换固定类型结构的已知时间路径。
        let mut selection =
            serde_json::to_value(&self.selection).map_err(serde::ser::Error::custom)?;
        selection["reason_text"] =
            serde_json::Value::String(self.selection.reason.description().into());
        selection["earliest_eligible_at"] =
            serde_json::to_value(self.selection.cooldown_at).map_err(serde::ser::Error::custom)?;
        let fields = ["score", "speed_bps", "ping_ms", "sessions", "uptime_ms"];
        selection["assessment"]["unknown_metrics"] = serde_json::json!(
            self.selection
                .assessment
                .metrics
                .values()
                .iter()
                .zip(fields)
                .filter_map(|(value, name)| value.is_none().then_some(name))
                .collect::<Vec<_>>()
        );
        for path in [
            "/recent_success_at",
            "/cooldown_at",
            "/earliest_eligible_at",
            "/assessment/source_fetched_at",
            "/assessment/last_attempt_at",
        ] {
            if let Some(value) = selection.pointer_mut(path)
                && let Some(raw) = value.as_str()
            {
                let time =
                    chrono::DateTime::parse_from_rfc3339(raw).map_err(serde::ser::Error::custom)?;
                *value = serde_json::Value::String(
                    time.with_timezone(self.timestamp.offset()).to_rfc3339(),
                );
            }
        }
        #[derive(Serialize)]
        struct Encoded<'a> {
            event_type: EventKind,
            level: LogLevel,
            timestamp: chrono::DateTime<chrono::FixedOffset>,
            state: ServiceState,
            node_id: &'a NodeId,
            worker_id: Option<uuid::Uuid>,
            policy_version: u32,
            weights: [u64; 5],
            selection: serde_json::Value,
        }
        Encoded {
            event_type: self.event_type,
            level: self.level,
            timestamp: self.timestamp,
            state: self.state,
            node_id: &self.selection.assessment.node_id,
            worker_id: None,
            policy_version: self.policy_version,
            weights: self.weights,
            selection,
        }
        .serialize(serializer)
    }
}
struct SelectionBatch {
    records: Vec<crate::scheduler::SelectionRecord>,
    timezone: chrono_tz::Tz,
    state: ServiceState,
}
struct SelectionSink {
    sender: mpsc::SyncSender<SelectionBatch>,
}
impl SelectionSink {
    fn new(mut submit: impl FnMut(Line) + Send + 'static) -> Self {
        // 一批待编码、一批编码中；不持有协调器或任何工作槽租约。
        let (sender, receiver) = mpsc::sync_channel::<SelectionBatch>(1);
        let _ = std::thread::Builder::new()
            .name("vap-selection-log".into())
            .spawn(move || {
                while let Ok(batch) = receiver.recv() {
                    for selection in batch.records {
                        let kind = match selection.kind {
                            crate::scheduler::SelectionKind::Assessed => {
                                EventKind::SelectionAssessed
                            }
                            crate::scheduler::SelectionKind::Dispatched => {
                                EventKind::SelectionDispatched
                            }
                            crate::scheduler::SelectionKind::Skipped => EventKind::SelectionSkipped,
                        };
                        let event = SelectionDiagnostic {
                            event_type: kind,
                            level: LogLevel::Debug,
                            timestamp: chrono::Utc::now()
                                .with_timezone(&batch.timezone)
                                .fixed_offset(),
                            state: batch.state,
                            policy_version: 1,
                            weights: crate::quality::WEIGHTS,
                            selection,
                        };
                        if let Ok(text) = serde_json::to_string(&event)
                            && text.len() <= 1_048_576
                        {
                            submit(Line {
                                text,
                                kind,
                                selected: LogLevel::Debug,
                                timestamp: event.timestamp.to_rfc3339(),
                            });
                        }
                    }
                }
            });
        Self { sender }
    }
    fn submit(&self, batch: SelectionBatch) {
        if let Err(error) = self.sender.try_send(batch) {
            let count = match error {
                mpsc::TrySendError::Full(batch) | mpsc::TrySendError::Disconnected(batch) => {
                    batch.records.len() as u64
                }
            };
            if let Some(sink) = SINK.get() {
                let _ = sink.losses[LogLevel::Debug as usize].fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |old| Some(old.saturating_add(count)),
                );
            }
        }
    }
}
static SELECTION_SINK: OnceLock<SelectionSink> = OnceLock::new();
pub fn selection_events(
    config: &AppConfig,
    scheduler: &mut crate::scheduler::Scheduler,
    state: ServiceState,
) {
    let records = scheduler.take_diagnostics();
    if records.is_empty() || !LogPolicy::from(config).allows(LogLevel::Debug) {
        return;
    }
    let sink = SINK.get_or_init(Sink::new);
    SELECTION_SINK
        .get_or_init(|| SelectionSink::new(move |line| sink.submit(line)))
        .submit(SelectionBatch {
            records,
            timezone: config.timezone,
            state,
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn typed_maximum_selection_batch_does_not_wait_for_blocked_output() {
        use crate::scheduler::{Catalog, RoundPurpose, Scheduler};
        let wall = chrono::Utc::now();
        let mut catalog = Catalog::default();
        for index in 0..20_000_u32 {
            let endpoint = Endpoint {
                ip: std::net::Ipv4Addr::from(0x0b000001 + index),
                port: 1194,
                transport: Transport::Tcp,
            };
            let node = VpnNode {
                id: NodeId::from_endpoint(&endpoint),
                endpoint,
                source_hostname: String::new(),
                country: "JP".into(),
                profile: "敏感配置标记".into(),
                profile_digest: "a".repeat(64),
                quality: Default::default(),
                source_fetched_at: wall,
                present: true,
                last_attempt_at: None,
            };
            catalog.nodes.insert(node.id.clone(), node);
        }
        let mut scheduler = Scheduler::new(20, 2);
        scheduler.configure(900, true);
        scheduler
            .begin_at(&catalog, None, RoundPurpose::Initial, wall, Instant::now())
            .unwrap();
        let records = scheduler.take_diagnostics();
        assert_eq!(records.len(), 20_000);
        let (encoded_tx, encoded_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let mut blocked = false;
        let sink = SelectionSink::new(move |line| {
            if !blocked {
                assert!(line.text.len() < 1_048_576);
                assert!(!line.text.contains("敏感配置标记"));
                encoded_tx.send(()).unwrap();
                let _ = release_rx.recv();
                blocked = true;
            }
        });
        let batch = || SelectionBatch {
            records: records.clone(),
            timezone: chrono_tz::Asia::Shanghai,
            state: ServiceState::Validating,
        };
        sink.submit(batch());
        encoded_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        sink.submit(batch());
        sink.submit(batch()); // 队列已满，必须直接丢弃，不能等待输出。
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::task::yield_now().await;
            let node = scheduler.next(&mut catalog, wall).unwrap();
            let attempt = scheduler.attempt_id(&node).unwrap();
            let (active, _) = tokio::sync::watch::channel(Some(node.id.clone()));
            active.send_replace(None); // 故障撤销独立于编码及输出。
            scheduler.cancel_queued();
            scheduler.complete(
                &node,
                attempt,
                crate::scheduler::AttemptDisposition::Cancelled,
                wall,
                Instant::now(),
            );
            assert!(active.borrow().is_none());
            assert_eq!(scheduler.running(), 0);
            assert!(!scheduler.is_running());
        })
        .await
        .unwrap();
        release_tx.send(()).unwrap();
    }
    fn silent_sink() -> (Sink, mpsc::Receiver<Line>) {
        let (startup, receiver) = mpsc::sync_channel(1);
        (
            Sink {
                ordinary: Arc::new(Mutex::new(VecDeque::new())),
                startup,
                startup_used: AtomicBool::new(false),
                losses: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
                pending: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
        )
    }
    fn line(kind: EventKind) -> Line {
        Line {
            text: "安全事件".into(),
            kind,
            selected: LogLevel::Debug,
            timestamp: "安全时间".into(),
        }
    }
    #[test]
    fn saturated_output_keeps_startup_and_severity_priority_without_waiting() {
        let (sink, receiver) = silent_sink();
        for _ in 0..63 {
            sink.submit(line(EventKind::CandidateStarted));
        }
        sink.submit(line(EventKind::CandidateStarted));
        sink.submit(line(EventKind::ActivePromoted));
        sink.submit(line(EventKind::SourceFailed));
        sink.submit(line(EventKind::RuntimeFailed));
        sink.submit(line(EventKind::StartupSummary));
        sink.submit(line(EventKind::StartupSummary));
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
        let queue = sink.ordinary.lock().unwrap();
        assert_eq!(queue.len(), 63);
        for level in [LogLevel::Info, LogLevel::Warn, LogLevel::Error] {
            assert!(queue.iter().any(|value| value.kind.level() == level));
        }
        assert_eq!(
            sink.losses[LogLevel::Debug as usize].load(Ordering::Relaxed),
            4
        );
    }
    #[test]
    fn selection_congestion_is_bounded_and_does_not_hide_activity_failure() {
        let (sink, _receiver) = silent_sink();
        for _ in 0..20_000 {
            sink.submit(line(EventKind::SelectionAssessed));
            sink.submit(line(EventKind::SelectionDispatched));
        }
        sink.submit(line(EventKind::ActiveBlocked));
        sink.submit(line(EventKind::RuntimeFailed));
        let queue = sink.ordinary.lock().unwrap();
        assert_eq!(queue.len(), 63);
        assert!(
            queue
                .iter()
                .any(|line| line.kind == EventKind::ActiveBlocked)
        );
        assert!(
            queue
                .iter()
                .any(|line| line.kind == EventKind::RuntimeFailed)
        );
        assert!(sink.losses[LogLevel::Debug as usize].load(Ordering::Relaxed) > 39_000);
    }
    #[test]
    fn all_errors_cannot_be_overwritten_by_warning_and_counters_saturate() {
        let (sink, _receiver) = silent_sink();
        for _ in 0..63 {
            sink.submit(line(EventKind::RuntimeFailed));
        }
        sink.submit(line(EventKind::SourceFailed));
        assert!(
            sink.ordinary
                .lock()
                .unwrap()
                .iter()
                .all(|line| line.kind.level() == LogLevel::Error)
        );
        sink.submit(line(EventKind::RuntimeFailed));
        assert_eq!(sink.ordinary.lock().unwrap().len(), 63);
        sink.losses[0].store(u64::MAX, Ordering::Relaxed);
        lost(&sink.losses, LogLevel::Error);
        assert_eq!(sink.losses[0].load(Ordering::Relaxed), u64::MAX);
    }
}
