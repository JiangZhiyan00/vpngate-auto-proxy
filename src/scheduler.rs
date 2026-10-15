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
        self.checks.retain(|(id, _), _| self.nodes.contains_key(id));
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
pub struct Scheduler {
    batch: usize,
    concurrency: usize,
    queue: VecDeque<(NodeId, String)>,
    running: BTreeSet<NodeId>,
    in_round: bool,
    recovery: bool,
    pub selected: usize,
    pub completed: usize,
}
impl Scheduler {
    pub fn begin_recovery(&mut self, catalog: &Catalog, now: DateTime<Utc>) -> bool {
        self.begin_ordered(catalog, None, Some(now))
    }
    pub fn cancel_queued(&mut self) {
        self.completed += self.queue.len();
        self.queue.clear();
        self.in_round = !self.running.is_empty();
    }
    /// 苹果协调方已成功提升活动出口后，原轮剩余预算可按候选并发继续，不重排或扩大配额。
    #[cfg(target_os = "macos")]
    pub(crate) fn continue_with_active(&mut self) {
        self.recovery = false;
    }
    pub fn new(batch: usize, concurrency: usize) -> Self {
        Self {
            batch,
            concurrency,
            queue: VecDeque::new(),
            running: BTreeSet::new(),
            in_round: false,
            recovery: false,
            selected: 0,
            completed: 0,
        }
    }
    pub fn begin(&mut self, catalog: &Catalog, active: Option<&NodeId>) -> bool {
        self.begin_ordered(catalog, active, None)
    }
    fn begin_ordered(
        &mut self,
        catalog: &Catalog,
        active: Option<&NodeId>,
        recovery: Option<DateTime<Utc>>,
    ) -> bool {
        if self.is_running() {
            return false;
        }
        let mut nodes: Vec<_> = catalog
            .nodes
            .values()
            .filter(|n| n.present && active != Some(&n.id))
            .collect();
        nodes.sort_by(|a, b| {
            if let Some(now) = recovery {
                let successful_at = |node: &VpnNode| {
                    catalog
                        .checks
                        .get(&(node.id.clone(), Layer::Exit))
                        .filter(|result| result.is_usable_for(node, now))
                        .map(|result| result.finished_at)
                };
                let priority = successful_at(b).cmp(&successful_at(a));
                if !priority.is_eq() {
                    return priority;
                }
                if successful_at(a).is_some() {
                    return a.id.cmp(&b.id);
                }
            }
            a.last_attempt_at
                .cmp(&b.last_attempt_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        self.queue = nodes
            .into_iter()
            .take(self.batch)
            .map(|n| (n.id.clone(), n.profile_digest.clone()))
            .collect();
        self.selected = self.queue.len();
        self.completed = 0;
        self.recovery = recovery.is_some();
        self.in_round = !self.queue.is_empty();
        true
    }
    pub fn next(&mut self, catalog: &mut Catalog, now: DateTime<Utc>) -> Option<VpnNode> {
        // 恢复逐个验证，避免较低优先级节点抢先成功并提升。
        if self.running.len() >= self.concurrency || (self.recovery && !self.running.is_empty()) {
            return None;
        }
        while let Some((id, digest)) = self.queue.pop_front() {
            if let Some(node) = catalog
                .nodes
                .get_mut(&id)
                .filter(|n| n.present && n.profile_digest == digest)
            {
                node.last_attempt_at = Some(now);
                self.running.insert(id);
                return Some(node.clone());
            }
            self.completed += 1;
        }
        self.in_round = !self.running.is_empty();
        None
    }
    pub fn finish(&mut self, id: &NodeId) {
        if self.running.remove(id) {
            self.completed += 1;
        }
        self.in_round = !self.queue.is_empty() || !self.running.is_empty();
    }
    pub fn is_running(&self) -> bool {
        self.in_round
    }
    pub fn running(&self) -> usize {
        self.running.len()
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
