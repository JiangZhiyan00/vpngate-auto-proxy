use chrono::{Offset, TimeZone, Utc};
use vpngate_auto_proxy::config::AppConfig;

#[test]
fn defaults_keep_all_regions_and_shanghai() {
    let config: AppConfig = serde_json::from_str("{}").unwrap();
    assert!(config.accepts_country("JP"));
    assert!(config.accepts_country("SG"));
    assert!(config.accepts_country(""));
    assert_eq!(config.timezone.name(), "Asia/Shanghai");
}

#[test]
fn regions_are_case_insensitive_and_do_not_fall_back() {
    let config: AppConfig = serde_json::from_str(r#"{"countries":["JP","sg"]}"#).unwrap();
    config.validate().unwrap();
    assert!(config.accepts_country("jp"));
    assert!(config.accepts_country("SG"));
    assert!(!config.accepts_country("US"));
    assert!(!config.accepts_country(""));
    for value in ["Japan", "", "J1", " JP", "日本"] {
        let mut invalid = config.clone();
        invalid.countries = vec![value.into()];
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn named_timezone_observes_daylight_saving_without_changing_instant() {
    for (zone, winter, summer) in [
        ("Asia/Tokyo", 9, 9),
        ("Asia/Singapore", 8, 8),
        ("America/New_York", -5, -4),
        ("Australia/Sydney", 11, 10),
    ] {
        let config: AppConfig =
            serde_json::from_value(serde_json::json!({"timezone":zone})).unwrap();
        for (month, hours) in [(1, winter), (7, summer)] {
            let utc = Utc.with_ymd_and_hms(2026, month, 15, 12, 0, 0).unwrap();
            let shown = utc.with_timezone(&config.timezone);
            assert_eq!(shown.offset().fix().local_minus_utc(), hours * 3600);
            assert_eq!(shown.with_timezone(&Utc), utc);
        }
    }
    assert!(serde_json::from_str::<AppConfig>(r#"{"timezone":"Asia/Typo"}"#).is_err());
}
