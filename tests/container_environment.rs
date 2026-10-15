use std::process::Command;
use vpngate_auto_proxy::config::AppConfig;

fn convert(values: &[(&str, &str)]) -> anyhow::Result<AppConfig> {
    AppConfig::container_from_environment(|name| {
        Ok(values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).into()))
    })
}

#[test]
fn container_defaults_keep_fixed_paths_and_no_secret_content() {
    let config = convert(&[]).unwrap();
    assert_eq!(config.listen.to_string(), "0.0.0.0:1080");
    assert_eq!(config.data_dir.to_str(), Some("/var/lib/vap"));
    assert_eq!(config.runtime_dir.to_str(), Some("/run/vap"));
    assert_eq!(
        config.credentials_file.unwrap().to_str(),
        Some("/run/secrets/proxy_credentials")
    );
    assert!(config.countries.is_empty());
    assert_eq!(config.timezone.name(), "Asia/Shanghai");
}

#[test]
fn environment_values_are_typed_and_use_existing_validation() {
    let config = convert(&[
        ("VAP_COUNTRIES", "JP, sg"),
        ("VAP_TIMEZONE", "Asia/Tokyo"),
        ("VAP_MAX_CONNECTIONS", "25"),
        ("VAP_CANDIDATE_CONCURRENCY", "1"),
        ("VAP_SOURCE_URL", "https://example.com/nodes"),
        (
            "VAP_EXIT_CHECK_URLS",
            "https://example.com/a, https://example.com/b",
        ),
        ("VAP_ALLOW_LEGACY_VPNGATE_CRYPTO", "false"),
    ])
    .unwrap();
    assert_eq!(config.countries, ["JP", "sg"]);
    assert_eq!(config.timezone.name(), "Asia/Tokyo");
    assert_eq!(config.max_connections, 25);
    assert_eq!(config.candidate_concurrency, 1);
    assert_eq!(config.exit_check_urls.len(), 2);
}

#[test]
fn empty_values_keep_defaults_and_unrelated_variables_cannot_override_paths() {
    let config = convert(&[
        ("VAP_COUNTRIES", ""),
        ("VAP_TIMEZONE", ""),
        ("VAP_MAX_CONNECTIONS", ""),
        ("VAP_LISTEN", "127.0.0.1:7"),
        ("VAP_DATA_DIR", "/tmp/other"),
        ("HTTP_PROXY", "http://invalid/"),
        ("VAP_PASSWORD", "do-not-copy"),
    ])
    .unwrap();
    assert_eq!(config.max_connections, 50);
    assert_eq!(config.listen.to_string(), "0.0.0.0:1080");
    let value = serde_json::to_string(&config).unwrap();
    assert!(!value.contains("do-not-copy"));
    assert!(!value.contains("/tmp/other"));
}

#[test]
fn malformed_environment_fails_before_any_network_start() {
    for (key, value) in [
        ("VAP_COUNTRIES", "JP,,SG"),
        ("VAP_COUNTRIES", "Japan"),
        ("VAP_TIMEZONE", "Moon/Base"),
        ("VAP_MAX_CONNECTIONS", "0"),
        ("VAP_MAX_CONNECTIONS", "-1"),
        ("VAP_MAX_CONNECTIONS", "1.2"),
        ("VAP_MAX_CONNECTIONS", "18446744073709551616"),
        ("VAP_ALLOW_LEGACY_VPNGATE_CRYPTO", "yes"),
        ("VAP_SOURCE_URL", "https://user:password@example.com/"),
        ("VAP_EXIT_CHECK_URLS", "https://example.com/,"),
    ] {
        assert!(convert(&[(key, value)]).is_err(), "{key}");
    }
}

#[test]
fn real_config_command_validates_without_starting_a_service() {
    let result = Command::new(env!("CARGO_BIN_EXE_vpngate-auto-proxy"))
        .env_clear()
        .env("VAP_COUNTRIES", "JP,SG")
        .args(["container-config"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: AppConfig = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value.countries, ["JP", "SG"]);
    let result = Command::new(env!("CARGO_BIN_EXE_vpngate-auto-proxy"))
        .env_clear()
        .env("VAP_TIMEZONE", "Moon/Base")
        .args(["container-config"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}
