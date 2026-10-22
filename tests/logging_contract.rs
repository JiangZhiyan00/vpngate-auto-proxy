//! 日志策略独立契约，不启动隧道或修改网络。
use std::time::Duration;
use vpngate_auto_proxy::{
    config::AppConfig,
    domain::ServiceState,
    logging::{EventKind, LogLevel, LogPolicy, SummaryClock, event},
};

#[test]
fn four_levels_filter_the_same_sequence() {
    let levels = [
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
    ];
    for (index, selected) in levels.iter().enumerate() {
        let policy = LogPolicy::new(*selected, 60);
        for (severity, candidate) in levels.iter().enumerate() {
            assert_eq!(policy.allows(*candidate), severity <= index);
        }
    }
    assert_eq!(EventKind::RuntimeSummary.level(), LogLevel::Debug);
    assert_eq!(EventKind::CandidateStarted.level(), LogLevel::Debug);
    for kind in [
        EventKind::SelectionAssessed,
        EventKind::SelectionDispatched,
        EventKind::SelectionSkipped,
    ] {
        assert_eq!(kind.level(), LogLevel::Debug);
        assert!(!LogPolicy::new(LogLevel::Info, 60).allows(kind.level()));
    }
    assert_eq!(EventKind::SourceFailed.level(), LogLevel::Warn);
    assert_eq!(EventKind::ActivePromoted.level(), LogLevel::Info);
    assert_eq!(EventKind::RuntimeFailed.level(), LogLevel::Error);
}

#[tokio::test(start_paused = true)]
async fn summary_clock_never_catches_up_or_uses_wall_time() {
    for seconds in [1, 60, 300] {
        let mut clock = SummaryClock::new(Duration::from_secs(seconds));
        let first = tokio::time::Instant::now();
        assert!(clock.due(first));
        assert!(!clock.due(first));
        tokio::time::advance(Duration::from_secs(seconds - 1)).await;
        assert!(!clock.due(tokio::time::Instant::now()));
        tokio::time::advance(Duration::from_secs(1 + seconds * 5)).await;
        assert!(clock.due(tokio::time::Instant::now()));
        assert!(!clock.due(tokio::time::Instant::now()));
    }
}

#[test]
fn all_levels_protect_raw_reasons_and_keep_event_fields() {
    for level in [
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
    ] {
        let config = AppConfig {
            log_level: level,
            ..Default::default()
        };
        let rendered = event(&config, EventKind::RuntimeFailed, ServiceState::Stopped,
                             None, None, Some("令牌秘密 https://user:secret@example.invalid/?token=秘密 -----BEGIN PRIVATE KEY-----"), Duration::ZERO).unwrap();
        let text = serde_json::to_string(&rendered).unwrap();
        for secret in ["令牌秘密", "user:secret", "PRIVATE KEY", "example.invalid"] {
            assert!(!text.contains(secret));
        }
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        for key in [
            "timestamp",
            "event_type",
            "level",
            "node_id",
            "worker_id",
            "state",
            "reason",
            "elapsed_ms",
        ] {
            assert!(value.get(key).is_some(), "{key}");
        }
    }
}

#[tokio::test]
async fn startup_summary_uses_the_listener_and_only_safe_effective_fields() {
    use vpngate_auto_proxy::{
        logging::{ListenScope, StartupSummary},
        socks,
    };
    let mut config = AppConfig {
        listen: "127.0.0.1:1080".parse().unwrap(),
        countries: vec!["sg".into(), "JP".into(), "jp".into()],
        timezone: chrono_tz::Asia::Tokyo,
        max_connections: 20,
        credentials_file: Some("/private/secret-marker".into()),
        ..Default::default()
    };
    config.listen_scope = ListenScope::ContainerInternal;
    let listener = socks::bind_gateway("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let actual = listener.local_addr().unwrap();
    let summary = StartupSummary::new(&config, uuid::Uuid::new_v4(), actual).unwrap();
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(value["config"]["port"], actual.port());
    assert_eq!(value["config"]["listen_address"], "127.0.0.1");
    assert_eq!(value["config"]["listen_scope"], "container_internal");
    assert_eq!(
        value["config"]["countries"],
        serde_json::json!(["JP", "SG"])
    );
    assert_eq!(value["config"]["authentication_enabled"], true);
    assert_eq!(value["ready"], false);
    assert_eq!(value["state"], "waiting");
    assert!(!value.to_string().contains("secret-marker"));
    for forbidden in [
        "credentials_file",
        "username",
        "password",
        "source_url",
        "host_port",
        "public_ip",
    ] {
        assert!(value["config"].get(forbidden).is_none());
    }
    assert!(socks::bind_gateway(actual, None).await.is_err());
    for level in [LogLevel::Warn, LogLevel::Error] {
        config.log_level = level;
        assert!(StartupSummary::new(&config, uuid::Uuid::new_v4(), actual).is_none());
    }
}
