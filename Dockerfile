# Two very different uses of the same image:
#   - evaluation: try the console with the built-in demo data, no capture, bridge networking
#   - a real collector: needs host networking and NET_RAW/NET_ADMIN (see docker-compose.yml,
#     docs/docker.md, and WINDOWS.md-style honesty: the capture path here is unverified — see below)
#
# Multi-stage: the builder needs libpcap's headers to link against; the runtime image only needs
# the shared library, not the whole Rust toolchain.
#
# cargo-chef splits "compile the dependencies" from "compile this crate's own code" into separate
# layers, cached separately: a one-line change to src/ no longer invalidates and recompiles the
# ~150-crate dependency tree from scratch (found the hard way, rebuilding this image several times
# over while fixing two real, unrelated bugs it also caught -- see below and docker-compose.yml).
FROM rust:1-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin denis

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /data --shell /usr/sbin/nologin denis
COPY --from=builder /build/target/release/denis /usr/local/bin/denis
COPY packaging/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
VOLUME /data
WORKDIR /data
# Non-root by default (safe for the "demo" service, which needs no capability at all -- see
# docker-compose.yml). Tried a Linux file capability here first (`setcap cap_net_raw,cap_net_admin
# =eip`, the same thing packaging/denis.service grants a dedicated user on a bare-metal install)
# so the "denis" (capture) service could stay non-root too, but that genuinely does not work in a
# container: a file capability can only grant what the container's own capability bounding set
# already has, and Docker's default bounding set excludes both -- confirmed by actually running it
# (`docker run --rm --entrypoint sh denis:local -c '.../denis --version'` failed with "Operation
# not permitted", *even for --version*, once the file capability was set but nothing granted the
# container the matching capabilities). So: the "denis" service instead overrides to `user: root`
# in docker-compose.yml, with `cap_add: [NET_ADMIN]` (`NET_RAW` is already in Docker's own default
# root capability set) -- see that file for why dropping every other default capability too, while
# tempting, is not as simple as it looks here.
USER denis
EXPOSE 8080
# --no-tls by default: most Docker deployments put a reverse proxy in front anyway, and a
# container-generated self-signed certificate is usually more friction than it is worth here.
# Unset it (`-e DENIS_NO_TLS=`) to get the same built-in HTTPS a real Linux install has.
ENV DENIS_NO_TLS=true
ENV DENIS_LISTEN=0.0.0.0:8080
# /api/health needs no session (see src/web/mod.rs::is_public) -- a real liveness check, not just
# "the process exists". http vs https follows DENIS_NO_TLS so this still works if that is unset.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD sh -c 'scheme=http; [ -z "$DENIS_NO_TLS" ] && scheme=https; curl -fsk "$scheme://127.0.0.1:${DENIS_LISTEN##*:}/api/health"'
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run"]
