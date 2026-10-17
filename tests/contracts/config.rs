use std::os::unix::fs::PermissionsExt;
use vpngate_auto_proxy::config::{AppConfig, Credentials, MacOsConfig};

#[test]
fn default_and_cross_field_constraints() {
    let mut config = AppConfig::default();
    assert!(config.validate().is_ok());
    assert_eq!(
        config.allow_legacy_vpngate_crypto,
        cfg!(target_os = "linux")
    );
    assert_eq!(config.exit_check_max_attempts, 3);
    assert_eq!(config.health_interval_seconds, 60);
    assert_eq!(config.health_timeout_seconds, 5);
    for maximum in [1, 5] {
        config.exit_check_max_attempts = maximum;
        assert!(config.validate().is_ok());
    }
    config.health_timeout_seconds = config.health_interval_seconds;
    assert!(config.validate().is_err());
    config.health_timeout_seconds = 5;
    config.candidate_concurrency = 255;
    assert!(config.validate().is_err());
}
#[test]
fn legacy_crypto_supports_explicit_strict_mode_and_linux_backend() {
    let omitted: AppConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(
        omitted.allow_legacy_vpngate_crypto,
        cfg!(target_os = "linux")
    );
    let strict: AppConfig =
        serde_json::from_str(r#"{"allow_legacy_vpngate_crypto":false}"#).unwrap();
    assert!(!strict.allow_legacy_vpngate_crypto);
    let mut config: AppConfig =
        serde_json::from_str(r#"{"allow_legacy_vpngate_crypto":true}"#).unwrap();
    assert!(config.allow_legacy_vpngate_crypto);
    assert!(config.validate().is_ok());
    assert!(
        serde_json::from_str::<AppConfig>(r#"{"allow_legacy_vpngate_crypto":"true"}"#).is_err()
    );
    config.macos = Some(MacOsConfig {
        dependency_manifest: "/tmp/dependency.json".into(),
        runtime_parent: "/tmp/generations".into(),
        worker_uid: 501,
        worker_gid: 20,
    });
    assert!(config.validate().is_err());
}
#[test]
fn rejects_unknown_fields_empty_urls_and_exposed_listener() {
    assert!(serde_json::from_str::<AppConfig>(r#"{"unsupported":true}"#).is_err());
    let mut config = AppConfig {
        exit_check_urls: vec![],
        ..AppConfig::default()
    };
    assert!(config.validate().is_err());
    config = AppConfig {
        listen: "0.0.0.0:1080".parse().unwrap(),
        ..AppConfig::default()
    };
    assert!(config.validate().is_err());
    config.credentials_file = Some("credentials.json".into());
    assert!(config.validate().is_ok());
    config.source_timeout_seconds = u64::MAX;
    assert!(config.validate().is_err());
}
#[test]
fn credentials_require_private_file_and_utf8_byte_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret.json");
    std::fs::write(&path, r#"{"username":"用户","password":"secret"}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Credentials::load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Credentials::load(&path).is_ok());
    std::fs::write(
        &path,
        serde_json::json!({"username":"名".repeat(86),"password":"secret"}).to_string(),
    )
    .unwrap();
    assert!(Credentials::load(&path).is_err());
}
#[test]
fn resolves_relative_paths_from_configuration_directory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(&path, r#"{"runtime_dir":"run","data_dir":"data"}"#).unwrap();
    let (config, _) = AppConfig::load(&path).unwrap();
    assert_eq!(config.runtime_dir, directory.path().join("run"));
    assert_eq!(config.data_dir, directory.path().join("data"));
}

#[test]
fn macos_paths_resolve_but_privileged_load_does_not_read_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
          "runtime_dir":"run",
          "data_dir":"data",
          "credentials_file":"missing-secret.json",
          "allow_legacy_vpngate_crypto":false,
          "macos":{
            "dependency_manifest":"dependency.json",
            "runtime_parent":"generations",
            "worker_uid":501,
            "worker_gid":20
          }
        }"#,
    )
    .unwrap();
    let config = AppConfig::load_config(&path).unwrap();
    let macos = config.macos.unwrap();
    assert_eq!(
        macos.dependency_manifest,
        directory.path().join("dependency.json")
    );
    assert_eq!(macos.runtime_parent, directory.path().join("generations"));
    assert!(AppConfig::load(&path).is_err());
}

#[test]
fn macos_deployment_requires_non_root_identity_and_normal_absolute_paths() {
    let valid = MacOsConfig {
        dependency_manifest: "/private/var/vap/dependency.json".into(),
        runtime_parent: "/private/var/vap/generations".into(),
        worker_uid: 501,
        worker_gid: 20,
    };
    let mut config = AppConfig {
        macos: Some(valid.clone()),
        allow_legacy_vpngate_crypto: false,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
    config.macos.as_mut().unwrap().worker_uid = 0;
    assert!(config.validate().is_err());
    config.macos = Some(MacOsConfig {
        runtime_parent: "/private/var/vap/../other".into(),
        ..valid
    });
    assert!(config.validate().is_err());
}

#[test]
fn accepts_owner_read_only_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret.json");
    std::fs::write(&path, r#"{"username":"用户名","password":"密码"}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(Credentials::load(&path).is_ok());
}

#[test]
fn validates_every_numeric_and_url_boundary() {
    let defaults = serde_json::to_value(AppConfig::default()).unwrap();
    for (field, value) in defaults.as_object().unwrap() {
        if value.is_number() {
            for invalid in [
                serde_json::json!(-1),
                serde_json::json!(1.5),
                serde_json::json!("1"),
            ] {
                let mut document = defaults.clone();
                document[field] = invalid;
                assert!(
                    serde_json::from_value::<AppConfig>(document).is_err(),
                    "{field}"
                );
            }
            if field != "candidate_retries" {
                let mut document = defaults.clone();
                document[field] = serde_json::json!(0);
                let config: AppConfig = serde_json::from_value(document).unwrap();
                assert!(config.validate().is_err(), "{field}");
            }
        }
    }
    for address in [
        "ftp://example.com/",
        "https://user:secret@example.com/",
        "http://user@example.com/",
    ] {
        let config = AppConfig {
            source_url: url::Url::parse(address).unwrap(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
        let config = AppConfig {
            exit_check_urls: vec![url::Url::parse(address).unwrap()],
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }
    let config = AppConfig {
        retry_initial_seconds: 301,
        ..AppConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn rejects_partial_empty_or_oversized_credentials_without_echoing_values() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret.json");
    for value in [
        serde_json::json!({"username":"保密用户名"}),
        serde_json::json!({"username":"保密用户名","password":""}),
        serde_json::json!({"username":"","password":"保密密码"}),
        serde_json::json!({"username":"保密用户名","password":"密".repeat(86)}),
    ] {
        std::fs::write(&path, value.to_string()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = Credentials::load(&path).err().expect("应拒绝非法凭据");
        assert!(!format!("{error:#}").contains("保密"));
    }
    std::fs::write(
        &path,
        serde_json::json!({"username":"a".repeat(255),"password":"b".repeat(255)}).to_string(),
    )
    .unwrap();
    assert!(Credentials::load(&path).is_ok());
}

#[test]
fn log_defaults_and_exact_file_boundaries() {
    use vpngate_auto_proxy::logging::LogLevel;
    let old: AppConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(old.log_level, LogLevel::Info);
    assert_eq!(old.log_summary_interval_seconds, 60);
    for level in ["error", "warn", "info", "debug"] {
        let config: AppConfig =
            serde_json::from_value(serde_json::json!({"log_level":level})).unwrap();
        assert!(config.validate().is_ok());
    }
    for value in [
        serde_json::json!(null),
        serde_json::json!("INFO"),
        serde_json::json!("trace"),
        serde_json::json!("off"),
        serde_json::json!(true),
    ] {
        assert!(
            serde_json::from_value::<AppConfig>(serde_json::json!({"log_level":value})).is_err()
        );
    }
    for value in [
        serde_json::json!(null),
        serde_json::json!(true),
        serde_json::json!(1.5),
        serde_json::json!(-1),
    ] {
        assert!(
            serde_json::from_value::<AppConfig>(
                serde_json::json!({"log_summary_interval_seconds":value})
            )
            .is_err()
        );
    }
    for interval in [0, 1, 86400, 86401] {
        let config = AppConfig {
            log_summary_interval_seconds: interval,
            ..Default::default()
        };
        assert_eq!(config.validate().is_ok(), (1..=86400).contains(&interval));
    }
}
