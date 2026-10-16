FROM rust:1.90.0-alpine3.22 AS builder
ARG TARGETARCH
RUN apk add --no-cache build-base pkgconf openssl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN --mount=type=cache,id=vap-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=vap-target-${TARGETARCH},target=/build/target,sharing=locked \
    cargo build --locked --release && cp target/release/vap /build/vap

FROM alpine:3.22
RUN apk add --no-cache openvpn iproute2 nftables util-linux tini ca-certificates libssl3 libcrypto3 libgcc \
    && mkdir -p /etc/vap /var/lib/vap /run/vap \
    && chmod 0700 /var/lib/vap \
    && chmod 0750 /run/vap
COPY --from=builder /build/vap /usr/local/bin/vap
COPY deploy/entrypoint.sh /usr/local/bin/vap-entrypoint
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/vpngate-auto-proxy/
COPY docs/third-party/rust/ /usr/share/licenses/vpngate-auto-proxy/rust/
COPY docs/third-party/nested/ /usr/share/licenses/vpngate-auto-proxy/nested/
COPY docs/third-party/runtime/ /usr/share/licenses/vpngate-auto-proxy/runtime/
RUN chmod 0755 /usr/local/bin/vap-entrypoint
ENV VAP_CONFIG_PATH=/etc/vap/config.json VAP_RUNTIME_DIR=/run/vap
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD vap status --runtime-dir "$VAP_RUNTIME_DIR" --json >/dev/null || exit 1
ENTRYPOINT ["/sbin/tini", "-g", "--", "/usr/local/bin/vap-entrypoint"]
