# rtpflux container image.
#
#   docker build -t rtpflux .
#   docker run --rm --network host \
#       -v "$PWD/config/docker.toml:/etc/rtpflux/rtpflux.toml:ro" rtpflux
#
# Media relays need the host network: every call opens ports from the
# configured range, and the addresses in the SDP must be the host's own.
# See compose.yaml and docs/getting-started.md.

# --- build ----------------------------------------------------------------
# The toolchain pinned in rust-toolchain.toml.
FROM docker.io/library/rust:1.100.0-slim-trixie AS build

# Use the image's toolchain as is (rust-toolchain.toml would also ask for
# rustfmt and clippy, which the build does not need).
ENV RUSTUP_TOOLCHAIN=1.100.0 \
    CARGO_TERM_COLOR=never

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY config config
# With MP3 recordings (LAME) and S3 recording storage (rustls over ring),
# built by the C compiler the image already has for linking.
RUN cargo build --release --locked -p rtpflux --features mp3,s3 \
 && install -D -m 755 target/release/rtpflux /out/rtpflux

# --- run ------------------------------------------------------------------
FROM docker.io/library/debian:trixie-slim

LABEL org.opencontainers.image.title="rtpflux" \
      org.opencontainers.image.description="A fast RTP media relay for SIP, controlled over the ng protocol" \
      org.opencontainers.image.source="https://github.com/RustedBytes/rtpflux" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# An unprivileged user, and the directories it writes: the state file and
# recordings (mount volumes here to keep them).
RUN useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin rtpflux \
 && install -d -o rtpflux -g rtpflux -m 750 /var/lib/rtpflux /var/spool/rtpflux \
 && install -d -m 755 /etc/rtpflux

COPY --from=build /out/rtpflux /usr/bin/rtpflux
# The documented example; replace it with your own configuration.
COPY config/rtpflux.toml /etc/rtpflux/rtpflux.example.toml

USER rtpflux
# SIGTERM ends the relay cleanly (with a state file, calls are saved).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/rtpflux"]
CMD ["--config", "/etc/rtpflux/rtpflux.toml"]
