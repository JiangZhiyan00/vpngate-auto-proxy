use super::selection_support::source;
use vpngate_auto_proxy::{domain::SourceQualityMetrics, quality};

#[test]
fn exact_weighted_example_and_missing_scores() {
    let mut source = source(3);
    let raw = [
        (300, 200_000_000, 10, 30, 86_400_000),
        (200, 300_000_000, 20, 20, 43_200_000),
        (100, 100_000_000, 30, 10, 0),
    ];
    for (node, (score, speed, ping, sessions, uptime)) in source.nodes.iter_mut().zip(raw) {
        node.quality = SourceQualityMetrics {
            score: Some(score),
            speed_bps: Some(speed),
            ping_ms: Some(ping),
            sessions: Some(sessions),
            uptime_ms: Some(uptime),
        };
    }
    let assessed = quality::assess(&source.nodes.iter().collect::<Vec<_>>());
    for (node, expected) in source
        .nodes
        .iter()
        .zip([72_500_000, 67_500_000, 10_000_000])
    {
        assert_eq!(assessed[&node.id].total_score_micros, expected);
    }
    for node in &mut source.nodes {
        node.quality = Default::default();
    }
    let assessed = quality::assess(&source.nodes.iter().collect::<Vec<_>>());
    assert!(
        assessed
            .values()
            .all(|v| v.total_score_micros == 40_000_000 && v.valid_count == 0)
    );
}

#[test]
fn singleton_ties_extremes_and_metric_parsing() {
    let mut source = source(3);
    for node in &mut source.nodes {
        node.quality = SourceQualityMetrics {
            score: Some(u64::MAX),
            speed_bps: Some(1),
            ping_ms: Some(1),
            sessions: Some(0),
            uptime_ms: Some(u64::MAX),
        };
    }
    let assessed = quality::assess(&source.nodes.iter().collect::<Vec<_>>());
    assert!(
        assessed
            .values()
            .all(|v| v.total_score_micros == 55_000_000)
    );
    assert_eq!(
        quality::assess(&[&source.nodes[0]])[&source.nodes[0].id].total_score_micros,
        55_000_000
    );
    for (node, score) in source.nodes.iter_mut().zip([100, 100, 1]) {
        node.quality = SourceQualityMetrics {
            score: Some(score),
            ..Default::default()
        };
    }
    let partial = quality::assess(&source.nodes.iter().collect::<Vec<_>>());
    for (node, expected) in source.nodes.iter().zip([75_000_000, 75_000_000, 0]) {
        assert_eq!(partial[&node.id].score_micros[0], expected);
    }
    source.nodes[1].quality.score = None;
    source.nodes[2].quality.score = None;
    let single_valid = quality::assess(&source.nodes.iter().collect::<Vec<_>>());
    assert_eq!(
        single_valid[&source.nodes[0].id].score_micros[0],
        50_000_000
    );
    assert_eq!(
        single_valid[&source.nodes[1].id].score_micros[0],
        40_000_000
    );
    for value in ["", "-1", "+1", "1.0", "x", "18446744073709551616"] {
        assert_eq!(SourceQualityMetrics::parse(value, false), None);
    }
    assert_eq!(SourceQualityMetrics::parse(" 0 ", false), Some(0));
    assert_eq!(SourceQualityMetrics::parse("0", true), None);
    assert_eq!(
        SourceQualityMetrics::parse("18446744073709551615", false),
        Some(u64::MAX)
    );
}

#[test]
#[ignore = "收口时显式运行两万节点发布模式性能观察"]
fn selection_performance_observation() {
    use chrono::{Duration as Delta, TimeZone, Utc};
    use vpngate_auto_proxy::{
        domain::Layer,
        scheduler::{Catalog, RoundPurpose, Scheduler},
    };
    let wall = Utc.with_ymd_and_hms(2026, 10, 22, 0, 0, 0).unwrap();
    let mono = tokio::time::Instant::now();
    for group in ["有差异", "并列", "缺失"] {
        let mut input = source(20_000);
        input.fetched_at = wall;
        for (i, node) in input.nodes.iter_mut().enumerate() {
            node.source_fetched_at = wall;
            let i = i as u64;
            node.quality = if group == "并列" {
                SourceQualityMetrics {
                    score: Some(100),
                    speed_bps: Some(100_000_000),
                    ping_ms: Some(20),
                    sessions: Some(10),
                    uptime_ms: Some(86_400_000),
                }
            } else {
                SourceQualityMetrics {
                    score: Some(i + 1),
                    speed_bps: Some((i + 1) * 10_000),
                    ping_ms: Some(1 + i % 250),
                    sessions: Some(i % 200),
                    uptime_ms: Some((i % 48) * 3_600_000),
                }
            };
            if group == "缺失" {
                match i % 5 {
                    0 => node.quality.score = None,
                    1 => node.quality.speed_bps = None,
                    2 => node.quality.ping_ms = None,
                    3 => node.quality.sessions = None,
                    _ => node.quality.uptime_ms = None,
                }
            }
        }
        let summary = blake3::hash(&serde_json::to_vec(&input).unwrap())
            .to_hex()
            .to_string();
        for purpose in [
            RoundPurpose::Initial,
            RoundPurpose::Recovery,
            RoundPurpose::Background,
        ] {
            let mut catalog = Catalog::default();
            catalog.merge(&input, None);
            if purpose == RoundPurpose::Recovery {
                for node in input.nodes.iter().step_by(3) {
                    let mut result = super::storage::check(node, Layer::Exit);
                    result.started_at = wall - Delta::seconds(60);
                    result.finished_at = result.started_at;
                    result.expires_at = Some(wall + Delta::seconds(900));
                    catalog.record(result);
                }
            }
            // 后台活动节点在候选总体之外，不从两万节点中减去一个。
            let outside_id = vpngate_auto_proxy::domain::NodeId::from_endpoint(
                &vpngate_auto_proxy::domain::Endpoint {
                    ip: "11.53.0.3".parse().unwrap(),
                    port: 1194,
                    transport: vpngate_auto_proxy::domain::Transport::Tcp,
                },
            );
            let active = (purpose == RoundPurpose::Background).then_some(&outside_id);
            let mut samples = Vec::new();
            for sample in 0..35 {
                // 构造与重置在计时外，只保留当次冻结计划。
                let mut scheduler = Scheduler::new(20, 2);
                scheduler.configure(900, false);
                scheduler.sync(&catalog, mono).unwrap();
                let start = std::time::Instant::now();
                assert!(
                    scheduler
                        .begin_at(&catalog, active, purpose, wall, mono)
                        .unwrap()
                );
                let elapsed = start.elapsed().as_nanos() as u64;
                assert_eq!(scheduler.selected, 20);
                if sample >= 5 {
                    samples.push(elapsed);
                }
            }
            let mut sorted = samples.clone();
            sorted.sort_unstable();
            eprintln!(
                "{}",
                serde_json::json!({"数据组":group,"用途":purpose,"输入摘要":summary,"节点数":20_000,"预热":5,"纳秒样本":samples,"中位数纳秒":(sorted[14] as f64+sorted[15] as f64)/2.0,"第九十五百分位纳秒":sorted[28],"最大纳秒":sorted[29],"超过一秒观察":sorted[29]>1_000_000_000})
            );
        }
    }
}

#[test]
fn bounded_typed_selection_diagnostics_are_debug_only_and_do_not_leak_profiles() {
    use chrono::Utc;
    use vpngate_auto_proxy::{
        domain::ServiceState,
        logging::{EventKind, LogLevel, LogPolicy, SelectionDiagnostic},
        scheduler::{Catalog, RoundPurpose, Scheduler},
    };
    let mut source = source(20_000);
    for node in &mut source.nodes {
        node.profile.push_str("敏感配置标记禁止输出");
    }
    let mut catalog = Catalog::default();
    catalog.merge(&source, None);
    let mut scheduler = Scheduler::new(20, 2);
    scheduler.configure(900, true);
    scheduler
        .begin_at(
            &catalog,
            None,
            RoundPurpose::Initial,
            Utc::now(),
            tokio::time::Instant::now(),
        )
        .unwrap();
    let first = scheduler.next(&mut catalog, Utc::now()).unwrap();
    assert!(scheduler.next(&mut catalog, Utc::now()).is_some());
    for _ in 0..100 {
        assert!(scheduler.next(&mut catalog, Utc::now()).is_none());
    }
    let records = scheduler.take_diagnostics();
    assert_eq!(records.len(), 20_002, "控制循环不得重复生成相同原因");
    assert!(scheduler.take_diagnostics().is_empty());
    assert_eq!(scheduler.running(), 2);
    let config = vpngate_auto_proxy::config::AppConfig::default();
    for kind in [
        EventKind::SelectionAssessed,
        EventKind::SelectionDispatched,
        EventKind::SelectionSkipped,
    ] {
        assert_eq!(kind.level(), LogLevel::Debug);
        assert!(!LogPolicy::new(LogLevel::Info, 60).allows(kind.level()));
    }
    let record = records
        .into_iter()
        .find(|r| r.assessment.node_id == first.id)
        .unwrap();
    let event = SelectionDiagnostic {
        event_type: EventKind::SelectionAssessed,
        level: LogLevel::Debug,
        timestamp: Utc::now().with_timezone(&config.timezone).fixed_offset(),
        state: ServiceState::Starting,
        policy_version: 1,
        weights: quality::WEIGHTS,
        selection: record,
    };
    let value = serde_json::to_value(&event).unwrap();
    let text = serde_json::to_string(&value).unwrap();
    assert!(!text.contains("敏感配置标记禁止输出"));
    assert!(text.len() < 1_048_576);
    assert_eq!(value["weights"], serde_json::json!([30, 35, 15, 10, 10]));
    assert_eq!(value["selection"]["reason_text"], "按综合质量名额派发");
    assert_eq!(
        value["selection"]["assessment"]["unknown_metrics"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert!(value["selection"].get("earliest_eligible_at").is_some());
    assert_eq!(
        value["node_id"],
        value["selection"]["assessment"]["node_id"]
    );
    assert!(
        value["selection"]["assessment"]["source_fetched_at"]
            .as_str()
            .unwrap()
            .ends_with("+08:00")
    );
}

#[test]
fn tied_quality_uses_valid_count_oldest_attempt_then_stable_id() {
    use chrono::{Duration as Delta, Utc};
    let input = source(3);
    let assessments = quality::assess(&input.nodes.iter().collect::<Vec<_>>());
    let mut a = assessments[&input.nodes[0].id].clone();
    let mut b = assessments[&input.nodes[1].id].clone();
    a.valid_count = 3;
    b.valid_count = 2;
    assert!(a.compare(&b).is_lt());
    b.valid_count = 3;
    a.last_attempt_at = None;
    b.last_attempt_at = Some(Utc::now());
    assert!(a.compare(&b).is_lt());
    a.last_attempt_at = b.last_attempt_at.map(|t| t - Delta::seconds(1));
    assert!(a.compare(&b).is_lt());
    a.last_attempt_at = b.last_attempt_at;
    assert_eq!(a.compare(&b), a.node_id.cmp(&b.node_id));
    assert_eq!(
        serde_json::to_value(quality::assess(&input.nodes.iter().collect::<Vec<_>>())).unwrap(),
        serde_json::to_value(assessments).unwrap()
    );
}
