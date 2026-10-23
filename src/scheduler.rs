//! 有界去重轮次；队列固定配置版本，历史诊断不参与当前可用性。
use crate::domain::*;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[derive(Default)]
pub struct Catalog {
    pub nodes: BTreeMap<NodeId, VpnNode>,
    pub checks: BTreeMap<(NodeId, Layer), CheckResult>,
}
impl Catalog {
    pub fn start_attempt(&mut self, node: &VpnNode, now: DateTime<Utc>) {
        self.checks.retain(|(id, _), _| id != &node.id);
        for layer in [Layer::Port, Layer::Tunnel, Layer::Exit] {
            let outcome = match (layer, node.endpoint.transport) {
                (Layer::Port, Transport::Udp) => Outcome::NotApplicable,
                (Layer::Port, Transport::Tcp) => Outcome::Running,
                _ => Outcome::NotTested,
            };
            self.record(CheckResult {
                node_id: node.id.clone(),
                profile_digest: node.profile_digest.clone(),
                layer,
                outcome,
                started_at: now,
                finished_at: now,
                elapsed_ms: 0,
                attempts: 0,
                status: None,
                expires_at: None,
                failure_reason: None,
            });
        }
    }
    pub fn merge(&mut self, snapshot: &SourceSnapshot, active: Option<&NodeId>) {
        for node in self.nodes.values_mut() {
            node.present = false;
        }
        for node in &snapshot.nodes {
            let mut node = node.clone();
            if let Some(old) = self.nodes.get(&node.id) {
                if old.profile_digest == node.profile_digest {
                    node.last_attempt_at = old.last_attempt_at;
                } else {
                    self.checks.retain(|(id, _), _| id != &node.id);
                }
            }
            self.nodes.insert(node.id.clone(), node);
        }
        self.nodes.retain(|id, n| n.present || active == Some(id));
        self.checks
            .retain(|(id, _), _| self.nodes.get(id).is_some_and(|node| node.present));
    }
    pub fn record(&mut self, result: CheckResult) {
        if self
            .nodes
            .get(&result.node_id)
            .is_some_and(|n| n.profile_digest == result.profile_digest)
        {
            self.checks
                .insert((result.node_id.clone(), result.layer), result);
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeKey(pub NodeId, pub String);
impl NodeKey {
    pub fn of(node: &VpnNode) -> Self {
        Self(node.id.clone(), node.profile_digest.clone())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundPurpose {
    Initial,
    Recovery,
    Background,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptDisposition {
    Succeeded,
    Failed,
    Cancelled,
    Invalidated,
}
#[derive(Debug, Default)]
pub struct NodeRuntime {
    pub consecutive_failures: u32,
    pub cooldown_until: Option<tokio::time::Instant>,
    pub cooldown_at: Option<DateTime<Utc>>,
    pub attempted: bool,
    pub last_attempt_at: Option<DateTime<Utc>>,
}
impl NodeRuntime {
    fn cooling(&self, now: tokio::time::Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until > now)
    }
}
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    QualityQuota,
    ExplorationQuota,
    RecentSuccess,
    Cooldown,
    AlreadyAttempted,
    NotPresent,
    ProfileChanged,
    ActiveNode,
    SourceExpired,
    RoundBackoff,
    Cancelled,
    HistoryCapacityExceeded,
}
impl SelectionReason {
    pub fn description(&self) -> &'static str {
        match self {
            Self::QualityQuota => "按综合质量名额派发",
            Self::ExplorationQuota => "按最久未尝试的探索名额派发",
            Self::RecentSuccess => "优先重新验证本次运行的有效近期成功节点",
            Self::Cooldown => "节点配置仍在失败冷却期",
            Self::AlreadyAttempted => "节点配置已在本次遍历尝试",
            Self::NotPresent => "节点已离开有效来源",
            Self::ProfileChanged => "节点配置已变化，原轮次身份失效",
            Self::ActiveNode => "健康活动出口不参与候选检测",
            Self::SourceExpired => "来源已过期，停止新派发",
            Self::RoundBackoff => "完整失败轮次仍在退避期",
            Self::Cancelled => "任务已取消，不计节点失败",
            Self::HistoryCapacityExceeded => "节点历史容量不足，停止新派发并回收资源",
        }
    }
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelectionRecord {
    pub round_id: u64,
    pub search_id: Option<u64>,
    pub traversal_id: Option<u64>,
    pub purpose: RoundPurpose,
    pub assessment: crate::quality::NodeAssessment,
    pub recent_success_at: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
    pub cooldown_at: Option<DateTime<Utc>>,
    pub attempted: bool,
    pub reason: SelectionReason,
    pub kind: SelectionKind,
}
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionKind {
    Assessed,
    Dispatched,
    Skipped,
}
#[derive(Clone)]
struct Queued {
    key: NodeKey,
    assessment: crate::quality::NodeAssessment,
    success: Option<DateTime<Utc>>,
    refresh: bool,
    reason: SelectionReason,
}
pub const MAX_RUNTIME_IDENTITIES: usize = 40_000;
pub struct Scheduler {
    #[cfg(all(test, target_os = "macos"))]
    capacity_for_test: Option<usize>,
    batch: usize,
    concurrency: usize,
    queue: VecDeque<Queued>,
    running: BTreeMap<NodeId, NodeKey>,
    attempt_ids: BTreeMap<NodeId, uuid::Uuid>,
    active_key: Option<NodeKey>,
    history: BTreeMap<NodeKey, NodeRuntime>,
    purpose: RoundPurpose,
    search_open: bool,
    search_id: u64,
    traversal_id: u64,
    round_id: u64,
    dispatched: usize,
    interval_seconds: u64,
    single_exploration: bool,
    background_plan: bool,
    quality_remaining: usize,
    exploration_remaining: usize,
    diagnostics_enabled: bool,
    diagnostics: Vec<SelectionRecord>,
    pub selected: usize,
    pub completed: usize,
}
impl Scheduler {
    pub fn new(batch: usize, concurrency: usize) -> Self {
        Self {
            #[cfg(all(test, target_os = "macos"))]
            capacity_for_test: None,
            batch,
            concurrency,
            queue: VecDeque::new(),
            running: BTreeMap::new(),
            attempt_ids: BTreeMap::new(),
            active_key: None,
            history: BTreeMap::new(),
            purpose: RoundPurpose::Initial,
            search_open: false,
            search_id: 0,
            traversal_id: 0,
            round_id: 0,
            dispatched: 0,
            interval_seconds: 900,
            single_exploration: false,
            background_plan: false,
            quality_remaining: 0,
            exploration_remaining: 0,
            diagnostics_enabled: false,
            diagnostics: Vec::new(),
            selected: 0,
            completed: 0,
        }
    }
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn limit_capacity_for_test(&mut self, capacity: usize) {
        self.capacity_for_test = Some(capacity);
    }
    pub fn configure(&mut self, interval_seconds: u64, diagnostics: bool) {
        self.interval_seconds = interval_seconds;
        self.diagnostics_enabled = diagnostics;
    }
    pub fn runtime(&self, node: &VpnNode) -> Option<&NodeRuntime> {
        self.history.get(&NodeKey::of(node))
    }
    pub fn history_len(&self) -> usize {
        self.history.len()
    }
    pub fn sync(&mut self, catalog: &Catalog, now: tokio::time::Instant) -> anyhow::Result<()> {
        let mut current: BTreeSet<_> = catalog.nodes.values().map(NodeKey::of).collect();
        // 健康活动隧道可能仍持有来源已更换的旧配置；它也属于当前身份并集。
        current.extend(self.active_key.iter().cloned());
        self.history.retain(|key, state| {
            current.contains(key)
                || state.attempted
                || state.cooling(now)
                || self.running.values().any(|value| value == key)
        });
        let additions = current
            .iter()
            .filter(|key| !self.history.contains_key(*key))
            .count();
        #[cfg(all(test, target_os = "macos"))]
        let capacity = self.capacity_for_test.unwrap_or(MAX_RUNTIME_IDENTITIES);
        #[cfg(not(all(test, target_os = "macos")))]
        let capacity = MAX_RUNTIME_IDENTITIES;
        anyhow::ensure!(
            self.history.len().saturating_add(additions) <= capacity,
            "history_capacity_exceeded：节点历史容量不足，停止新派发并回收资源"
        );
        for key in current {
            self.history.entry(key).or_default();
        }
        Ok(())
    }
    pub fn start_recovery(&mut self) {
        self.search_open = true;
        self.search_id = self.search_id.saturating_add(1);
        self.traversal_id = 1;
        self.purpose = RoundPurpose::Recovery;
        for state in self.history.values_mut() {
            state.attempted = false;
        }
    }
    pub(crate) fn continue_with_active(&mut self, node: &VpnNode) {
        self.active_key = Some(NodeKey::of(node));
        self.purpose = RoundPurpose::Background;
        self.search_open = false;
        for state in self.history.values_mut() {
            state.attempted = false;
        }
    }
    pub fn active_failure(
        &mut self,
        node: &VpnNode,
        wall: DateTime<Utc>,
        now: tokio::time::Instant,
    ) {
        self.active_key = None;
        // 活动引用撤销方只通知一次；不从逐层检查重复累计失败。
        if let Some(state) = self.history.get_mut(&NodeKey::of(node)) {
            Self::fail(state, wall, now);
        }
        self.start_recovery();
    }
    fn fail(state: &mut NodeRuntime, wall: DateTime<Utc>, now: tokio::time::Instant) {
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let delay = 30_u64
            .saturating_mul(1_u64 << state.consecutive_failures.saturating_sub(1).min(4))
            .min(300);
        state.cooldown_until = Some(now + std::time::Duration::from_secs(delay));
        state.cooldown_at = wall.checked_add_signed(chrono::Duration::seconds(delay as i64));
    }
    pub fn attempt_id(&self, node: &VpnNode) -> Option<uuid::Uuid> {
        (self.running.get(&node.id) == Some(&NodeKey::of(node)))
            .then(|| self.attempt_ids.get(&node.id).copied())
            .flatten()
    }
    pub fn complete(
        &mut self,
        node: &VpnNode,
        attempt_id: uuid::Uuid,
        outcome: AttemptDisposition,
        wall: DateTime<Utc>,
        now: tokio::time::Instant,
    ) {
        let key = NodeKey::of(node);
        if self.running.get(&node.id) != Some(&key)
            || self.attempt_ids.get(&node.id) != Some(&attempt_id)
        {
            return;
        }
        self.running.remove(&node.id);
        self.attempt_ids.remove(&node.id);
        self.completed += 1;
        if let Some(state) = self.history.get_mut(&key) {
            match outcome {
                AttemptDisposition::Succeeded => {
                    state.consecutive_failures = 0;
                    state.cooldown_until = None;
                    state.cooldown_at = None;
                    state.attempted = self.search_open;
                }
                AttemptDisposition::Failed => {
                    Self::fail(state, wall, now);
                    state.attempted = self.search_open;
                }
                AttemptDisposition::Cancelled | AttemptDisposition::Invalidated => {}
            }
        }
        self.trim_finished();
    }
    // 旧契约辅助入口：只完成派发，不制造成功或失败的质量结论。
    pub fn finish(&mut self, id: &NodeId) {
        if let Some(key) = self.running.remove(id) {
            self.attempt_ids.remove(id);
            self.completed += 1;
            if let Some(state) = self.history.get_mut(&key) {
                state.attempted = self.search_open;
            }
        }
        self.trim_finished();
    }
    pub fn cancel_queued(&mut self) {
        self.cancel_queued_with_reason(SelectionReason::Cancelled);
    }
    pub fn cancel_queued_with_reason(&mut self, reason: SelectionReason) {
        let remaining = self.selected.saturating_sub(self.dispatched);
        for mut queued in self.queue.drain(..).take(remaining).collect::<Vec<_>>() {
            queued.reason = reason.clone();
            self.diagnose(&queued, SelectionKind::Skipped);
        }
        self.selected = self.dispatched;
    }
    pub fn begin(&mut self, catalog: &Catalog, active: Option<&NodeId>) -> bool {
        self.begin_at(
            catalog,
            active,
            if active.is_some() {
                RoundPurpose::Background
            } else {
                RoundPurpose::Initial
            },
            Utc::now(),
            tokio::time::Instant::now(),
        )
        .unwrap_or(false)
    }
    pub fn begin_recovery(&mut self, catalog: &Catalog, now: DateTime<Utc>) -> bool {
        self.begin_at(
            catalog,
            None,
            RoundPurpose::Recovery,
            now,
            tokio::time::Instant::now(),
        )
        .unwrap_or(false)
    }
    pub fn begin_at(
        &mut self,
        catalog: &Catalog,
        active: Option<&NodeId>,
        purpose: RoundPurpose,
        wall: DateTime<Utc>,
        now: tokio::time::Instant,
    ) -> anyhow::Result<bool> {
        if self.is_running() {
            return Ok(false);
        }
        if purpose != RoundPurpose::Background
            && (!self.search_open
                || (purpose == RoundPurpose::Recovery && self.purpose != RoundPurpose::Recovery))
        {
            self.start_recovery();
            self.purpose = purpose;
        }
        self.sync(catalog, now)?;
        if self.search_open
            && catalog.nodes.values().filter(|n| n.present).all(|n| {
                self.history
                    .get(&NodeKey::of(n))
                    .is_some_and(|s| s.attempted)
            })
        {
            self.traversal_id = self.traversal_id.saturating_add(1);
            for state in self.history.values_mut() {
                state.attempted = false;
            }
            self.sync(catalog, now)?;
        }
        self.purpose = purpose;
        self.round_id = self.round_id.saturating_add(1);
        self.dispatched = 0;
        self.completed = 0;
        self.queue.clear();
        self.diagnostics.clear();
        let nodes: Vec<_> = catalog.nodes.values().filter(|n| n.present).collect();
        let assessments = crate::quality::assess(&nodes);
        let horizon = wall
            .checked_add_signed(chrono::Duration::seconds(
                self.interval_seconds.min(i64::MAX as u64) as i64,
            ))
            .unwrap_or(wall);
        let mut candidates = Vec::new();
        for node in nodes {
            let key = NodeKey::of(node);
            let state = &self.history[&key];
            let mut assessment = assessments[&node.id].clone();
            if state.last_attempt_at.is_some() {
                assessment.last_attempt_at = state.last_attempt_at;
            }
            let check = catalog
                .checks
                .get(&(node.id.clone(), Layer::Exit))
                .filter(|check| check.is_usable_for(node, wall));
            let reason = if active == Some(&node.id) {
                SelectionReason::ActiveNode
            } else if state.cooling(now) {
                SelectionReason::Cooldown
            } else if self.search_open && state.attempted {
                SelectionReason::AlreadyAttempted
            } else {
                SelectionReason::QualityQuota
            };
            let eligible = matches!(reason, SelectionReason::QualityQuota);
            let queued = Queued {
                key,
                assessment,
                success: check.map(|c| c.finished_at),
                refresh: check.is_none_or(|c| c.expires_at.is_some_and(|at| at <= horizon)),
                reason,
            };
            self.diagnose(
                &queued,
                if eligible {
                    SelectionKind::Assessed
                } else {
                    SelectionKind::Skipped
                },
            );
            if eligible {
                candidates.push(queued);
            }
        }
        self.selected = self.batch.min(candidates.len());
        self.background_plan = purpose == RoundPurpose::Background;
        self.quality_remaining = 0;
        self.exploration_remaining = 0;
        if purpose == RoundPurpose::Background && self.selected > 0 {
            let explore = if self.selected == 1 {
                usize::from(self.single_exploration)
            } else {
                self.selected.div_ceil(5)
            };
            if self.selected == 1 {
                self.single_exploration = !self.single_exploration;
            }
            candidates.sort_by(|a, b| {
                a.assessment
                    .last_attempt_at
                    .cmp(&b.assessment.last_attempt_at)
                    .then_with(|| a.key.0.cmp(&b.key.0))
            });
            let mut explorers: Vec<_> = candidates.drain(..explore).collect();
            for node in &mut explorers {
                node.reason = SelectionReason::ExplorationQuota;
            }
            candidates.sort_by(|a, b| {
                b.refresh
                    .cmp(&a.refresh)
                    .then_with(|| a.assessment.compare(&b.assessment))
            });
            let quality_count = self.selected - explore;
            self.quality_remaining = quality_count;
            self.exploration_remaining = explore;
            let backup = candidates.split_off(quality_count.min(candidates.len()));
            candidates.extend(explorers);
            candidates.extend(backup);
        } else {
            candidates.sort_by(|a, b| {
                let success = if purpose == RoundPurpose::Recovery {
                    b.success.cmp(&a.success)
                } else {
                    std::cmp::Ordering::Equal
                };
                success.then_with(|| a.assessment.compare(&b.assessment))
            });
            if purpose == RoundPurpose::Recovery {
                for node in &mut candidates {
                    if node.success.is_some() {
                        node.reason = SelectionReason::RecentSuccess;
                    }
                }
            }
        }
        self.queue = candidates.into();
        Ok(true)
    }
    pub fn next(&mut self, catalog: &mut Catalog, wall: DateTime<Utc>) -> Option<VpnNode> {
        if self.running.len() >= self.concurrency
            || (self.purpose == RoundPurpose::Recovery && !self.running.is_empty())
        {
            return None;
        }
        let now = tokio::time::Instant::now();
        while self.dispatched < self.selected {
            if self.background_plan
                && self.quality_remaining > 0
                && !self
                    .queue
                    .iter()
                    .any(|node| matches!(node.reason, SelectionReason::QualityQuota))
            {
                self.quality_remaining = 0;
                self.selected = self.dispatched + self.exploration_remaining.min(self.queue.len());
            }
            // 补位保持预留名额及质量先行；不重算指标或引入新快照身份。
            let index = if self.background_plan && self.quality_remaining > 0 {
                self.queue
                    .iter()
                    .position(|node| matches!(node.reason, SelectionReason::QualityQuota))
                    .unwrap_or(0)
            } else if self.background_plan && self.exploration_remaining > 0 {
                self.queue
                    .iter()
                    .position(|node| matches!(node.reason, SelectionReason::ExplorationQuota))
                    .unwrap_or_else(|| {
                        self.queue
                            .iter()
                            .enumerate()
                            .min_by(|(_, a), (_, b)| {
                                a.assessment
                                    .last_attempt_at
                                    .cmp(&b.assessment.last_attempt_at)
                                    .then_with(|| a.key.0.cmp(&b.key.0))
                            })
                            .map_or(0, |(index, _)| index)
                    })
            } else {
                0
            };
            let Some(mut queued) = self.queue.remove(index) else {
                self.selected = self.dispatched;
                return None;
            };
            let reason = match catalog.nodes.get(&queued.key.0) {
                None => Some(SelectionReason::NotPresent),
                Some(node) if !node.present => Some(SelectionReason::NotPresent),
                Some(node) if node.profile_digest != queued.key.1 => {
                    Some(SelectionReason::ProfileChanged)
                }
                _ => self.history.get(&queued.key).and_then(|state| {
                    if state.cooling(now) {
                        Some(SelectionReason::Cooldown)
                    } else if self.search_open && state.attempted {
                        Some(SelectionReason::AlreadyAttempted)
                    } else {
                        None
                    }
                }),
            };
            if let Some(reason) = reason {
                queued.reason = reason;
                self.diagnose(&queued, SelectionKind::Skipped);
                continue;
            }
            let node = catalog.nodes.get_mut(&queued.key.0)?;
            node.last_attempt_at = Some(wall);
            if let Some(state) = self.history.get_mut(&queued.key) {
                state.last_attempt_at = Some(wall);
            }
            if self.background_plan {
                if self.quality_remaining > 0 {
                    self.quality_remaining -= 1;
                    queued.reason = SelectionReason::QualityQuota;
                } else {
                    self.exploration_remaining = self.exploration_remaining.saturating_sub(1);
                    queued.reason = SelectionReason::ExplorationQuota;
                }
            }
            self.running.insert(node.id.clone(), queued.key.clone());
            self.attempt_ids
                .insert(node.id.clone(), uuid::Uuid::new_v4());
            self.dispatched += 1;
            self.diagnose(&queued, SelectionKind::Dispatched);
            return Some(node.clone());
        }
        self.trim_finished();
        None
    }
    fn trim_finished(&mut self) {
        if self.dispatched >= self.selected {
            self.queue.clear();
        }
    }
    pub fn is_running(&self) -> bool {
        !self.running.is_empty() || (self.dispatched < self.selected && !self.queue.is_empty())
    }
    pub fn running(&self) -> usize {
        self.running.len()
    }
    pub fn earliest_ready(
        &self,
        catalog: &Catalog,
        now: tokio::time::Instant,
    ) -> Option<tokio::time::Instant> {
        catalog
            .nodes
            .values()
            .filter(|n| n.present)
            .filter_map(|node| self.history.get(&NodeKey::of(node)))
            .filter(|state| !self.search_open || !state.attempted)
            .filter_map(|state| state.cooldown_until)
            .filter(|at| *at > now)
            .min()
    }
    fn diagnose(&mut self, node: &Queued, kind: SelectionKind) {
        if !self.diagnostics_enabled {
            return;
        }
        let state = self.history.get(&node.key);
        // 一轮每个候选评定一次，派发或从队列跳过一次；无逐时钟重复。
        self.diagnostics.push(SelectionRecord {
            round_id: self.round_id,
            search_id: self.search_open.then_some(self.search_id),
            traversal_id: self.search_open.then_some(self.traversal_id),
            purpose: self.purpose,
            assessment: node.assessment.clone(),
            recent_success_at: node.success,
            consecutive_failures: state.map_or(0, |s| s.consecutive_failures),
            cooldown_at: state.and_then(|s| s.cooldown_at),
            attempted: state.is_some_and(|s| s.attempted),
            reason: node.reason.clone(),
            kind,
        });
    }
    pub fn take_diagnostics(&mut self) -> Vec<SelectionRecord> {
        std::mem::take(&mut self.diagnostics)
    }
}
pub struct Backoff {
    initial: u64,
    maximum: u64,
    next: u64,
}
impl Backoff {
    pub fn new(initial: u64, maximum: u64) -> Self {
        Self {
            initial,
            maximum,
            next: initial,
        }
    }
    pub fn next_delay(&mut self) -> u64 {
        let value = self.next;
        self.next = self.next.saturating_mul(2).min(self.maximum);
        value
    }
    pub fn reset(&mut self) {
        self.next = self.initial;
    }
}
