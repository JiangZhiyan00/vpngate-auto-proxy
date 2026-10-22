use super::storage::{check, snapshot};
use chrono::{Duration as TimeDelta, Utc};
use std::collections::BTreeSet;
use vpngate_auto_proxy::{domain::*, scheduler::*};
#[test]
fn forty_five_nodes_rotate_fairly_with_batch_and_concurrency_limits() {
    let source = snapshot(45);
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(20, 2);
    let mut seen = BTreeSet::new();
    for round in 0..3 {
        assert!(scheduler.begin(&catalog, None));
        assert!(!scheduler.begin(&catalog, None));
        let mut selected = Vec::new();
        loop {
            let first = scheduler
                .next(&mut catalog, Utc::now() + TimeDelta::seconds(round))
                .unwrap();
            let second = scheduler.next(&mut catalog, Utc::now() + TimeDelta::seconds(round));
            assert!(
                scheduler.next(&mut catalog, Utc::now()).is_none(),
                "并发不得超过二"
            );
            selected.push(first.id.clone());
            scheduler.finish(&first.id);
            if let Some(second) = second {
                assert_ne!(first.id, second.id);
                selected.push(second.id.clone());
                scheduler.finish(&second.id);
            }
            if !scheduler.is_running() {
                break;
            }
        }
        assert_eq!(selected.len(), if round < 2 { 20 } else { 5 });
        assert_eq!(
            selected.iter().collect::<BTreeSet<_>>().len(),
            selected.len()
        );
        seen.extend(selected);
    }
    assert_eq!(seen.len(), 45);
}
#[test]
fn active_nodes_are_excluded_and_stable_id_breaks_ties() {
    let source = snapshot(4);
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let active = catalog.nodes.keys().next().unwrap().clone();
    // 最久未尝试的首个候选已预留给探索，质量名额先派发。
    let expected = catalog.nodes.keys().nth(2).unwrap().clone();
    let mut scheduler = Scheduler::new(20, 2);
    assert!(scheduler.begin(&catalog, Some(&active)));
    assert_eq!(
        scheduler.next(&mut catalog, Utc::now()).unwrap().id,
        expected
    );
}
#[test]
fn refresh_changes_invalidate_checks_and_queued_versions_but_keep_removed_active() {
    let mut source = snapshot(3);
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let node = source.nodes[0].clone();
    catalog.record(check(&node, Layer::Exit));
    let mut scheduler = Scheduler::new(20, 2);
    assert!(scheduler.begin(&catalog, None));
    source.nodes[0].profile_digest = "0".repeat(64);
    catalog.merge(&source, None);
    assert!(!catalog.checks.contains_key(&(node.id.clone(), Layer::Exit)));
    let mut seen = Vec::new();
    while let Some(node) = scheduler.next(&mut catalog, Utc::now()) {
        seen.push(node.id.clone());
        scheduler.finish(&node.id);
    }
    assert!(
        !seen.contains(&node.id),
        "本轮排队的旧配置须取消，不能悄悄换成新版本"
    );
    catalog.merge(&snapshot(0), Some(&node.id));
    assert_eq!(catalog.nodes.len(), 1);
    assert!(!catalog.nodes[&node.id].present);
    catalog.record(check(&node, Layer::Exit));
    assert!(catalog.checks.is_empty(), "旧配置完成结果不得重新生效");
    catalog.merge(&snapshot(0), None);
    assert!(catalog.nodes.is_empty());
}
#[test]
fn diagnostics_never_restore_runtime_availability_and_expiry_is_dynamic() {
    let source = snapshot(1);
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    assert!(catalog.checks.is_empty());
    let result = check(&source.nodes[0], Layer::Exit);
    assert_eq!(
        result.current_outcome(result.expires_at.unwrap()),
        Outcome::Expired
    );
    catalog.record(check(&source.nodes[0], Layer::Port));
    assert!(
        !catalog
            .checks
            .values()
            .any(|r| r.is_usable_for(&source.nodes[0], Utc::now()))
    );
}
#[test]
fn fresh_attempt_clears_old_exit_and_summaries_do_not_infer_higher_layers() {
    use std::time::Duration;
    use vpngate_auto_proxy::service::{candidate_summary, source_summary};
    let source = snapshot(1);
    let node = &source.nodes[0];
    let now = Utc::now();
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    catalog.record(check(node, Layer::Exit));
    let scheduler = Scheduler::new(20, 2);
    assert_eq!(
        candidate_summary(&catalog, &scheduler, now, now).available,
        1
    );
    catalog.start_attempt(node, now);
    catalog.record(check(node, Layer::Port));
    assert_eq!(
        catalog.checks[&(node.id.clone(), Layer::Exit)].outcome,
        Outcome::NotTested
    );
    assert_eq!(
        candidate_summary(&catalog, &scheduler, now, now).available,
        0
    );
    let mut exit = check(node, Layer::Exit);
    exit.expires_at = Some(now);
    catalog.record(exit);
    assert_eq!(candidate_summary(&catalog, &scheduler, now, now).expired, 1);
    let summary = source_summary(
        Some(now - TimeDelta::seconds(5)),
        now,
        Duration::from_secs(10),
        Some("刷新失败"),
    );
    assert_eq!(summary.age_seconds, Some(5));
    assert!(!summary.expired);
    assert!(summary.last_error.is_some());
    assert!(
        source_summary(
            Some(now + TimeDelta::seconds(5)),
            now,
            Duration::from_secs(10),
            None
        )
        .expired
    );
}

#[tokio::test(start_paused = true)]
async fn ranked_search_visits_twenty_first_and_preserves_reappearing_identity() {
    let mut source = super::selection_support::source(21);
    for (index, node) in source.nodes.iter_mut().enumerate() {
        node.quality.score = Some((100 - index) as u64);
    }
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(20, 2);
    let wall = Utc::now();
    let mono = tokio::time::Instant::now();
    scheduler
        .begin_at(&catalog, None, RoundPurpose::Initial, wall, mono)
        .unwrap();
    let mut tried = BTreeSet::new();
    while let Some(node) = scheduler.next(&mut catalog, wall) {
        tried.insert(node.id.clone());
        scheduler.complete(
            &node,
            scheduler.attempt_id(&node).unwrap_or_default(),
            AttemptDisposition::Failed,
            wall,
            mono,
        );
    }
    assert_eq!(tried.len(), 20);
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Initial,
            wall + TimeDelta::seconds(60),
            tokio::time::Instant::now(),
        )
        .unwrap();
    let remaining = scheduler.next(&mut catalog, wall).unwrap();
    assert!(!tried.contains(&remaining.id));
    scheduler.complete(
        &remaining,
        scheduler.attempt_id(&remaining).unwrap_or_default(),
        AttemptDisposition::Cancelled,
        wall,
        tokio::time::Instant::now(),
    );
    let failed = source.nodes[0].clone();
    source.nodes.retain(|n| n.id != failed.id);
    catalog.merge(&source, None);
    scheduler
        .sync(&catalog, tokio::time::Instant::now())
        .unwrap();
    source.nodes.push(failed.clone());
    catalog.merge(&source, None);
    scheduler
        .sync(&catalog, tokio::time::Instant::now())
        .unwrap();
    assert!(scheduler.runtime(&failed).unwrap().attempted);
}

#[tokio::test(start_paused = true)]
async fn cooldown_is_monotonic_cancel_safe_and_survives_source_absence() {
    let source = super::selection_support::source(1);
    let node = source.nodes[0].clone();
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(20, 2);
    let wall = Utc::now();
    let start = tokio::time::Instant::now();
    scheduler
        .begin_at(&catalog, None, RoundPurpose::Initial, wall, start)
        .unwrap();
    scheduler.next(&mut catalog, wall).unwrap();
    scheduler.complete(
        &node,
        scheduler.attempt_id(&node).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        start,
    );
    scheduler.complete(
        &node,
        scheduler.attempt_id(&node).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        start,
    );
    assert_eq!(scheduler.runtime(&node).unwrap().consecutive_failures, 1);
    catalog.merge(&super::selection_support::source(0), None);
    scheduler.sync(&catalog, start).unwrap();
    catalog.merge(&source, None);
    scheduler.sync(&catalog, start).unwrap();
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Initial,
            wall + TimeDelta::days(100),
            start,
        )
        .unwrap();
    assert!(scheduler.next(&mut catalog, wall).is_none());
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Initial,
            wall,
            tokio::time::Instant::now(),
        )
        .unwrap();
    scheduler.next(&mut catalog, wall).unwrap();
    scheduler.complete(
        &node,
        scheduler.attempt_id(&node).unwrap_or_default(),
        AttemptDisposition::Succeeded,
        wall,
        tokio::time::Instant::now(),
    );
    assert_eq!(scheduler.runtime(&node).unwrap().consecutive_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn runtime_capacity_preserves_protected_history_and_reclaims_after_traversal() {
    let source = super::selection_support::source(40_001);
    let mut catalog = Catalog::default();
    let mut scheduler = Scheduler::new(20_000, 2);
    let wall = Utc::now();
    let now = tokio::time::Instant::now();
    for part in 0..2 {
        let mut batch = source.clone();
        batch.nodes = source.nodes[part * 20_000..(part + 1) * 20_000].to_vec();
        catalog.merge(&batch, None);
        scheduler
            .begin_at(&catalog, None, RoundPurpose::Initial, wall, now)
            .unwrap();
        while let Some(node) = scheduler.next(&mut catalog, wall) {
            scheduler.complete(
                &node,
                scheduler.attempt_id(&node).unwrap_or_default(),
                AttemptDisposition::Failed,
                wall,
                now,
            );
        }
    }
    assert_eq!(scheduler.history_len(), 40_000);
    scheduler.sync(&catalog, now).unwrap();
    assert_eq!(scheduler.history_len(), 40_000);
    let mut extra = source.clone();
    extra.nodes = vec![source.nodes[40_000].clone()];
    catalog.merge(&extra, None);
    let error = scheduler.sync(&catalog, now).unwrap_err();
    assert!(error.to_string().starts_with("history_capacity_exceeded"));
    assert_eq!(scheduler.history_len(), 40_000);
    assert!(scheduler.runtime(&source.nodes[0]).unwrap().attempted);
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    let mut last = source.clone();
    last.nodes = source.nodes[20_000..40_000].to_vec();
    catalog.merge(&last, None);
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Initial,
            wall,
            tokio::time::Instant::now(),
        )
        .unwrap();
    assert_eq!(scheduler.history_len(), 20_000);
    scheduler.cancel_queued();
    catalog.merge(&extra, None);
    scheduler
        .sync(&catalog, tokio::time::Instant::now())
        .unwrap();
    assert_eq!(scheduler.history_len(), 1);
}

#[tokio::test(start_paused = true)]
async fn background_reserves_exploration_and_freezes_refresh_horizon() {
    let mut source = super::selection_support::source(25);
    for (i, node) in source.nodes.iter_mut().enumerate() {
        node.quality.score = Some(i as u64);
    }
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let now = Utc::now();
    let mono = tokio::time::Instant::now();
    let active = NodeId::from_endpoint(&Endpoint {
        ip: "11.53.0.3".parse().unwrap(),
        port: 1,
        transport: Transport::Tcp,
    });
    let mut scheduler = Scheduler::new(20, 2);
    scheduler.configure(900, true);
    let mut covered = BTreeSet::new();
    for round in 0..7 {
        scheduler
            .begin_at(
                &catalog,
                Some(&active),
                RoundPurpose::Background,
                now + TimeDelta::seconds(round),
                mono,
            )
            .unwrap();
        let mut explorers = 0;
        while let Some(node) = scheduler.next(&mut catalog, now + TimeDelta::seconds(round)) {
            covered.insert(node.id.clone());
            scheduler.complete(
                &node,
                scheduler.attempt_id(&node).unwrap_or_default(),
                AttemptDisposition::Succeeded,
                now,
                mono,
            );
        }
        for event in scheduler.take_diagnostics() {
            if matches!(event.kind, SelectionKind::Dispatched)
                && matches!(event.reason, SelectionReason::ExplorationQuota)
            {
                explorers += 1;
            }
        }
        assert_eq!(explorers, 4);
    }
    assert_eq!(covered.len(), 25);

    let mut source = super::selection_support::source(3);
    for (node, score) in source.nodes.iter_mut().zip([50, 1, 100]) {
        node.quality.score = Some(score);
    }
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    for (node, expiry) in source.nodes.iter().zip([2000, 900, 901]) {
        let mut check = super::storage::check(node, Layer::Exit);
        check.finished_at = now;
        check.expires_at = Some(now + TimeDelta::seconds(expiry));
        catalog.record(check);
    }
    // 单名额首轮只取质量，900秒到期的低分节点先于901秒到期的高分节点。
    let mut scheduler = Scheduler::new(1, 2);
    scheduler.configure(900, true);
    scheduler
        .begin_at(&catalog, Some(&active), RoundPurpose::Background, now, mono)
        .unwrap();
    let first = scheduler
        .next(&mut catalog, now + TimeDelta::seconds(30))
        .unwrap();
    assert_eq!(first.id, source.nodes[1].id);
    scheduler.complete(
        &first,
        scheduler.attempt_id(&first).unwrap_or_default(),
        AttemptDisposition::Succeeded,
        now,
        mono,
    );
    scheduler
        .begin_at(&catalog, Some(&active), RoundPurpose::Background, now, mono)
        .unwrap();
    let explored = scheduler.next(&mut catalog, now).unwrap();
    scheduler.complete(
        &explored,
        scheduler.attempt_id(&explored).unwrap_or_default(),
        AttemptDisposition::Succeeded,
        now,
        mono,
    );
    assert!(scheduler.take_diagnostics().iter().any(|v| matches!(
        v.kind,
        SelectionKind::Dispatched
    ) && matches!(
        v.reason,
        SelectionReason::ExplorationQuota
    )));
}

#[tokio::test(start_paused = true)]
async fn cooldown_growth_and_invalidated_results_are_not_duplicate_failures() {
    let source = super::selection_support::source(1);
    let node = &source.nodes[0];
    let wall = Utc::now();
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(1, 1);
    for expected in [30, 60, 120, 240, 300, 300] {
        let now = tokio::time::Instant::now();
        scheduler
            .begin_at(&catalog, None, RoundPurpose::Recovery, wall, now)
            .unwrap();
        scheduler.next(&mut catalog, wall).unwrap();
        scheduler.complete(
            node,
            scheduler.attempt_id(node).unwrap_or_default(),
            AttemptDisposition::Failed,
            wall,
            now,
        );
        assert_eq!(
            scheduler.runtime(node).unwrap().cooldown_until.unwrap() - now,
            std::time::Duration::from_secs(expected)
        );
        tokio::time::advance(std::time::Duration::from_secs(expected)).await;
    }
    let count = scheduler.runtime(node).unwrap().consecutive_failures;
    let now = tokio::time::Instant::now();
    scheduler
        .begin_at(&catalog, None, RoundPurpose::Recovery, wall, now)
        .unwrap();
    scheduler.next(&mut catalog, wall).unwrap();
    scheduler.complete(
        node,
        scheduler.attempt_id(node).unwrap_or_default(),
        AttemptDisposition::Invalidated,
        wall,
        now,
    );
    assert_eq!(scheduler.runtime(node).unwrap().consecutive_failures, count);
    assert!(!scheduler.runtime(node).unwrap().attempted);
}

#[tokio::test(start_paused = true)]
async fn frozen_round_keeps_scores_and_replaces_invalidated_entries_without_using_quota() {
    let mut source = super::selection_support::source(3);
    for (node, score) in source.nodes.iter_mut().zip([100, 90, 80]) {
        node.quality.score = Some(score);
    }
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let wall = Utc::now();
    let mono = tokio::time::Instant::now();
    let mut scheduler = Scheduler::new(2, 1);
    scheduler.configure(900, true);
    scheduler
        .begin_at(&catalog, None, RoundPurpose::Initial, wall, mono)
        .unwrap();
    source.nodes[0].profile_digest = "f".repeat(64);
    source.nodes[1].quality.score = Some(1);
    source.nodes[2].quality.score = Some(999);
    catalog.merge(&source, None);
    scheduler.sync(&catalog, mono).unwrap();
    let second = scheduler.next(&mut catalog, wall).unwrap();
    assert_eq!(
        second.id, source.nodes[1].id,
        "指标更新不能重排本轮冻结队列"
    );
    assert!(
        scheduler.next(&mut catalog, wall).is_none(),
        "并发为一时必须等待在途回收"
    );
    scheduler.complete(
        &second,
        scheduler.attempt_id(&second).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        mono,
    );
    let third = scheduler.next(&mut catalog, wall).unwrap();
    assert_eq!(third.id, source.nodes[2].id);
    scheduler.complete(
        &third,
        scheduler.attempt_id(&third).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        mono,
    );
    assert_eq!((scheduler.selected, scheduler.completed), (2, 2));
    assert!(!scheduler.is_running());
    let records = scheduler.take_diagnostics();
    assert!(
        records
            .iter()
            .any(|e| matches!(e.reason, SelectionReason::ProfileChanged))
    );
    assert!(
        records
            .iter()
            .any(|e| matches!(e.kind, SelectionKind::Dispatched)
                && e.assessment.metrics.score == Some(90))
    );
}

#[test]
fn background_invalid_quality_entry_uses_quality_backup_before_reserved_exploration() {
    let mut source = super::selection_support::source(6);
    let wall = Utc::now();
    for (index, node) in source.nodes.iter_mut().enumerate() {
        node.quality.score = Some((100 - index) as u64);
        node.last_attempt_at = if index == 5 { None } else { Some(wall) };
    }
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(5, 1);
    scheduler.configure(900, true);
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Background,
            wall,
            tokio::time::Instant::now(),
        )
        .unwrap();
    catalog.nodes.get_mut(&source.nodes[0].id).unwrap().present = false;
    let mut actual = Vec::new();
    while let Some(node) = scheduler.next(&mut catalog, wall) {
        actual.push(node.id.clone());
        scheduler.complete(
            &node,
            scheduler.attempt_id(&node).unwrap_or_default(),
            AttemptDisposition::Succeeded,
            wall,
            tokio::time::Instant::now(),
        );
    }
    assert_eq!(
        actual,
        source.nodes[1..]
            .iter()
            .map(|n| n.id.clone())
            .collect::<Vec<_>>()
    );
    let dispatched: Vec<_> = scheduler
        .take_diagnostics()
        .into_iter()
        .filter(|e| matches!(e.kind, SelectionKind::Dispatched))
        .collect();
    assert!(
        dispatched[..4]
            .iter()
            .all(|e| matches!(e.reason, SelectionReason::QualityQuota))
    );
    assert!(matches!(
        dispatched[4].reason,
        SelectionReason::ExplorationQuota
    ));
}

#[test]
fn one_slot_background_alternates_only_nonempty_rounds_and_covers_low_scores() {
    let mut input = super::selection_support::source(3);
    for (index, node) in input.nodes.iter_mut().enumerate() {
        node.quality.score = Some((100 - index) as u64);
    }
    let mut catalog = Catalog::default();
    catalog.merge(&input, None);
    let mut scheduler = Scheduler::new(1, 2);
    scheduler.configure(900, true);
    let wall = Utc::now();
    let mut covered = BTreeSet::new();
    for round in 0..6 {
        scheduler
            .begin_at(
                &Catalog::default(),
                None,
                RoundPurpose::Background,
                wall,
                tokio::time::Instant::now(),
            )
            .unwrap();
        assert_eq!(scheduler.selected, 0);
        scheduler
            .begin_at(
                &catalog,
                None,
                RoundPurpose::Background,
                wall,
                tokio::time::Instant::now(),
            )
            .unwrap();
        let node = scheduler
            .next(&mut catalog, wall + TimeDelta::seconds(round))
            .unwrap();
        covered.insert(node.id.clone());
        scheduler.complete(
            &node,
            scheduler.attempt_id(&node).unwrap_or_default(),
            AttemptDisposition::Succeeded,
            wall,
            tokio::time::Instant::now(),
        );
        let dispatched = scheduler
            .take_diagnostics()
            .into_iter()
            .find(|e| matches!(e.kind, SelectionKind::Dispatched))
            .unwrap();
        assert_eq!(
            matches!(dispatched.reason, SelectionReason::ExplorationQuota),
            round % 2 == 1
        );
    }
    assert_eq!(covered.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn late_completion_cannot_settle_a_new_attempt_of_the_same_profile() {
    use vpngate_auto_proxy::scheduler::{AttemptDisposition, RoundPurpose};
    let source = super::selection_support::source(1);
    let wall = Utc::now();
    let now = tokio::time::Instant::now();
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(1, 1);
    for first_outcome in [AttemptDisposition::Cancelled, AttemptDisposition::Succeeded] {
        scheduler
            .begin_at(&catalog, None, RoundPurpose::Recovery, wall, now)
            .unwrap();
        let node = scheduler.next(&mut catalog, wall).unwrap();
        let old = scheduler.attempt_id(&node).unwrap();
        scheduler.complete(&node, old, first_outcome, wall, now);
        scheduler
            .begin_at(&catalog, None, RoundPurpose::Recovery, wall, now)
            .unwrap();
        scheduler.next(&mut catalog, wall).unwrap();
        let current = scheduler.attempt_id(&node).unwrap();
        assert_ne!(old, current);
        scheduler.complete(&node, old, AttemptDisposition::Failed, wall, now);
        assert_eq!(scheduler.running(), 1);
        assert_eq!(scheduler.completed, 0);
        assert_eq!(scheduler.runtime(&node).unwrap().consecutive_failures, 0);
        assert!(!scheduler.runtime(&node).unwrap().attempted);
        scheduler.complete(&node, current, AttemptDisposition::Succeeded, wall, now);
        assert_eq!(scheduler.running(), 0);
        assert_eq!(scheduler.completed, 1);
    }
}
