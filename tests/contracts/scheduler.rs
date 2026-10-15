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
        assert_eq!(selected.len(), 20);
        assert_eq!(selected.iter().collect::<BTreeSet<_>>().len(), 20);
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
    let expected = catalog.nodes.keys().nth(1).unwrap().clone();
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
