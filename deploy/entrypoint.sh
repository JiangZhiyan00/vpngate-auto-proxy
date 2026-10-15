#!/bin/sh
set -eu
if [ "$#" = 0 ]; then
    case "${VAP_CONFIG_MODE:-file}" in
        environment)
            umask 077
            config_file=$(mktemp /tmp/vap-container-config.XXXXXX)
            if ! /usr/local/bin/vpngate-auto-proxy container-config > "$config_file"; then
                rm -f "$config_file"
                exit 2
            fi
            set -- run --config "$config_file"
            ;;
        file) set -- run --config "${VAP_CONFIG_PATH:-/etc/vap/config.json}" ;;
        *) echo "容器配置模式必须为 file 或 environment" >&2; exit 2 ;;
    esac
fi
exec /usr/local/bin/vpngate-auto-proxy "$@"
