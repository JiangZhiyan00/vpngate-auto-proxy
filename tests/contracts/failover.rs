use super::storage::{check, snapshot};
use chrono::{Duration as Delta, Utc};
use vpngate_auto_proxy::{domain::*, scheduler::*};

#[test]
fn recovery_prefers_fresh_exit_success_and_rejects_expired_changed_or_removed_nodes() {
    let source = snapshot(6);
    let now = Utc::now();
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let ids: Vec<_> = catalog.nodes.keys().cloned().collect();
    for (index, id) in ids.iter().enumerate().skip(1) {
        let mut result = check(&catalog.nodes[id], Layer::Exit);
        result.finished_at = now - Delta::seconds(10 - index as i64);
        result.expires_at = Some(now + Delta::seconds(60));
        if index == 3 {
            result.expires_at = Some(now);
        }
        if index == 4 {
            result.profile_digest = "0".repeat(64);
        }
        catalog.record(result);
    }
    catalog.nodes.get_mut(&ids[5]).unwrap().present = false;
    let mut scheduler = Scheduler::new(2, 2);
    assert!(scheduler.begin_recovery(&catalog, now));
    let first = scheduler.next(&mut catalog, now).unwrap();
    assert_eq!(first.id, ids[2]);
    assert!(scheduler.next(&mut catalog, now).is_none());
    scheduler.finish(&first.id);
    let second = scheduler.next(&mut catalog, now).unwrap();
    assert_eq!(second.id, ids[1]);
    scheduler.finish(&second.id);
    assert!(!scheduler.is_running());
    assert_eq!(scheduler.selected, 2);
}

#[test]
fn recovery_cancels_queued_work_but_waits_for_running_workers_to_release_slots() {
    let mut catalog = Catalog::default();
    catalog.merge(&snapshot(5), None);
    let mut scheduler = Scheduler::new(3, 1);
    scheduler.begin(&catalog, None);
    let running = scheduler.next(&mut catalog, Utc::now()).unwrap();
    scheduler.cancel_queued();
    assert!(!scheduler.begin_recovery(&catalog, Utc::now()));
    assert!(scheduler.next(&mut catalog, Utc::now()).is_none());
    scheduler.finish(&running.id);
    assert!(scheduler.begin_recovery(&catalog, Utc::now()));
    assert_eq!(scheduler.selected, 3);
}

#[test]
fn independent_recovery_backoff_caps_resets_and_does_not_overflow() {
    let mut nodes = Backoff::new(30, 300);
    let mut source = Backoff::new(30, 300);
    assert_eq!(
        (0..7).map(|_| nodes.next_delay()).collect::<Vec<_>>(),
        vec![30, 60, 120, 240, 300, 300, 300]
    );
    assert_eq!(source.next_delay(), 30);
    nodes.reset();
    assert_eq!(nodes.next_delay(), 30);
    assert_eq!(source.next_delay(), 60);
    let mut large = Backoff::new(u64::MAX / 2 + 1, u64::MAX);
    assert_eq!(large.next_delay(), u64::MAX / 2 + 1);
    assert_eq!(large.next_delay(), u64::MAX);
}

#[test]
fn identical_fresh_source_refresh_preserves_recovery_backoff_but_new_inputs_reopen_it() {
    let source = snapshot(3);
    let mut catalog = Catalog::default();
    assert!(vpngate_auto_proxy::service::source_adds_usable_nodes(
        &catalog, &source, true
    ));
    catalog.merge(&source, None);
    assert!(!vpngate_auto_proxy::service::source_adds_usable_nodes(
        &catalog, &source, true
    ));
    assert!(vpngate_auto_proxy::service::source_adds_usable_nodes(
        &catalog, &source, false
    ));
    let mut changed = source.clone();
    changed.nodes[0].profile_digest = "0".repeat(64);
    assert!(vpngate_auto_proxy::service::source_adds_usable_nodes(
        &catalog, &changed, true
    ));
    catalog.nodes.get_mut(&source.nodes[0].id).unwrap().present = false;
    assert!(vpngate_auto_proxy::service::source_adds_usable_nodes(
        &catalog, &source, true
    ));
    let mut empty = source.clone();
    empty.nodes.clear();
    assert!(!vpngate_auto_proxy::service::source_adds_usable_nodes(
        &catalog, &empty, false
    ));
}

#[tokio::test(start_paused = true)]
async fn recovery_cooldown_identity_history_and_new_search_are_independent() {
    let wall = Utc::now();
    let mono = tokio::time::Instant::now();
    let source = snapshot(3);
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(1, 2);
    scheduler
        .begin_at(&catalog, None, RoundPurpose::Recovery, wall, mono)
        .unwrap();
    let failed = scheduler.next(&mut catalog, wall).unwrap();
    scheduler.complete(
        &failed,
        scheduler.attempt_id(&failed).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        mono,
    );
    scheduler.complete(
        &failed,
        scheduler.attempt_id(&failed).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        mono,
    );
    assert_eq!(scheduler.runtime(&failed).unwrap().consecutive_failures, 1);
    let mut reduced = source.clone();
    reduced.nodes.retain(|n| n.id != failed.id);
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    catalog.merge(&reduced, None);
    scheduler
        .sync(&catalog, tokio::time::Instant::now())
        .unwrap();
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    catalog.merge(&source, None);
    scheduler
        .sync(&catalog, tokio::time::Instant::now())
        .unwrap();
    assert!(scheduler.runtime(&failed).unwrap().attempted);
    assert_eq!(
        scheduler.runtime(&failed).unwrap().cooldown_until,
        Some(mono + std::time::Duration::from_secs(30))
    );
    scheduler.start_recovery();
    assert!(!scheduler.runtime(&failed).unwrap().attempted);
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Recovery,
            wall + Delta::seconds(10),
            tokio::time::Instant::now(),
        )
        .unwrap();
    let next = scheduler
        .next(&mut catalog, wall + Delta::seconds(10))
        .unwrap();
    assert_ne!(next.id, failed.id, "新故障寻找不能清除节点冷却");
    scheduler.complete(
        &next,
        scheduler.attempt_id(&next).unwrap_or_default(),
        AttemptDisposition::Cancelled,
        wall,
        tokio::time::Instant::now(),
    );
    assert_eq!(scheduler.runtime(&next).unwrap().consecutive_failures, 0);
    assert!(!scheduler.runtime(&next).unwrap().attempted);
}

#[test]
fn removed_active_identity_does_not_restore_stale_success_on_reappearance() {
    let source = snapshot(1);
    let node = &source.nodes[0];
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    catalog.record(check(node, Layer::Exit));
    let mut empty = source.clone();
    empty.nodes.clear();
    catalog.merge(&empty, Some(&node.id));
    assert!(catalog.checks.is_empty());
    catalog.merge(&source, Some(&node.id));
    assert!(catalog.checks.is_empty());
}

#[tokio::test(start_paused = true)]
async fn switching_back_to_old_profile_keeps_its_own_cooldown_and_traversal() {
    let wall = Utc::now();
    let start = tokio::time::Instant::now();
    let source = snapshot(2);
    let original = source.nodes[0].clone();
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(1, 1);
    catalog.nodes.get_mut(&original.id).unwrap().quality.score = Some(100);
    scheduler
        .begin_at(&catalog, None, RoundPurpose::Recovery, wall, start)
        .unwrap();
    let failed = scheduler.next(&mut catalog, wall).unwrap();
    assert_eq!(failed.id, original.id);
    scheduler.complete(
        &failed,
        scheduler.attempt_id(&failed).unwrap_or_default(),
        AttemptDisposition::Failed,
        wall,
        start,
    );
    let mut changed = source.clone();
    changed.nodes[0].profile_digest = "f".repeat(64);
    catalog.merge(&changed, None);
    scheduler.sync(&catalog, start).unwrap();
    assert!(!scheduler.runtime(&changed.nodes[0]).unwrap().attempted);
    assert_eq!(
        scheduler.runtime(&original).unwrap().consecutive_failures,
        1
    );
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    catalog.merge(&source, None);
    scheduler
        .sync(&catalog, tokio::time::Instant::now())
        .unwrap();
    assert!(scheduler.runtime(&original).unwrap().attempted);
    assert_eq!(
        scheduler.runtime(&original).unwrap().cooldown_until,
        Some(start + std::time::Duration::from_secs(30))
    );
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Recovery,
            wall,
            tokio::time::Instant::now(),
        )
        .unwrap();
    let other = scheduler.next(&mut catalog, wall).unwrap();
    assert_ne!(other.id, original.id);
}
