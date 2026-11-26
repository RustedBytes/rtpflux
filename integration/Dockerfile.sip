# Kamailio and SIPp from Debian's own packages, for the integration bench.
FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends kamailio sip-tester ca-certificates \
 && rm -rf /var/lib/apt/lists/*
