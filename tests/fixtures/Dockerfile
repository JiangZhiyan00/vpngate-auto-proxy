FROM rust:1.90.0-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables openvpn util-linux openssl libssl-dev pkg-config python3 tcpdump curl && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
