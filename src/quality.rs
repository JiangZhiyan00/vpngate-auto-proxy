//! 固定精度来源评分；不推断隧道或出口可用性。
use crate::domain::{NodeId, SourceQualityMetrics, VpnNode};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{cmp::Ordering, collections::BTreeMap};

pub const WEIGHTS: [u64; 5] = [30, 35, 15, 10, 10];
pub const FULL_SCORE: u64 = 100_000_000;
pub const UPTIME_CAP_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Serialize)]
pub struct NodeAssessment {
    pub node_id: NodeId,
    pub profile_digest: String,
    pub source_fetched_at: DateTime<Utc>,
    pub metrics: SourceQualityMetrics,
    pub score_micros: [u64; 5],
    pub total_score_micros: u64,
    pub valid_count: u8,
    pub last_attempt_at: Option<DateTime<Utc>>,
}
impl NodeAssessment {
    pub fn compare(&self, other: &Self) -> Ordering {
        other
            .total_score_micros
            .cmp(&self.total_score_micros)
            .then_with(|| other.valid_count.cmp(&self.valid_count))
            .then_with(|| self.last_attempt_at.cmp(&other.last_attempt_at))
            .then_with(|| self.node_id.cmp(&other.node_id))
    }
}
fn rounded(numerator: u128, denominator: u128) -> u64 {
    ((numerator + denominator / 2) / denominator) as u64
}
pub fn assess(nodes: &[&VpnNode]) -> BTreeMap<NodeId, NodeAssessment> {
    let mut output: Vec<_> = nodes
        .iter()
        .map(|node| NodeAssessment {
            node_id: node.id.clone(),
            profile_digest: node.profile_digest.clone(),
            source_fetched_at: node.source_fetched_at,
            metrics: node.quality,
            score_micros: [40_000_000; 5],
            total_score_micros: 0,
            valid_count: node.quality.values().iter().filter(|v| v.is_some()).count() as u8,
            last_attempt_at: node.last_attempt_at,
        })
        .collect();
    for field in 0..4 {
        let mut values: Vec<_> = nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| node.quality.values()[field].map(|value| (index, value)))
            .collect();
        values.sort_by(|a, b| {
            if field < 2 {
                b.1.cmp(&a.1)
            } else {
                a.1.cmp(&b.1)
            }
        });
        let length = values.len();
        let mut start = 0;
        while start < length {
            let mut end = start;
            while end + 1 < length && values[end + 1].1 == values[start].1 {
                end += 1;
            }
            let score = if length == 1 || (start == 0 && end + 1 == length) {
                50_000_000
            } else {
                rounded(
                    u128::from(FULL_SCORE) * (2 * (length - 1) - start - end) as u128,
                    (2 * (length - 1)) as u128,
                )
            };
            for (index, _) in &values[start..=end] {
                output[*index].score_micros[field] = score;
            }
            start = end + 1;
        }
    }
    for (node, result) in nodes.iter().zip(&mut output) {
        if let Some(uptime) = node.quality.uptime_ms {
            result.score_micros[4] = rounded(
                u128::from(uptime.min(UPTIME_CAP_MS)) * u128::from(FULL_SCORE),
                u128::from(UPTIME_CAP_MS),
            );
        }
        result.total_score_micros = rounded(
            result
                .score_micros
                .iter()
                .zip(WEIGHTS)
                .map(|(score, weight)| u128::from(*score) * u128::from(weight))
                .sum(),
            100,
        );
    }
    output
        .into_iter()
        .map(|value| (value.node_id.clone(), value))
        .collect()
}
