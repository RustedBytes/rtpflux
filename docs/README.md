# rtpflux documentation

rtpflux is a media relay for SIP calls. Start with the page that matches
what you want to do.

## I want to run it

1. [Getting started](getting-started.md): build, configure, run, and
   follow a call through the relay.
2. [Configuration](configuration.md): every setting, with examples.
3. [Control protocol](control-protocol.md): connect Kamailio or OpenSIPS,
   and the commands and options they can send.
4. [Integration](integration.md): tested Kamailio, OpenSIPS, ferrosip and
   FreeSWITCH configurations.
5. [Operations](operations.md): metrics, logs, restarts and the systemd
   service.
6. [Web UI](webui.md): a read-only website with live traffic, calls,
   statistics and logs.

## I want to know what it can do

- [Media handling](media.md): NAT traversal, SRTP, WebRTC (ICE, DTLS,
  BUNDLE), re-INVITEs and hold.
- [Call features](call-features.md): DTMF detection, blocking, recording,
  announcements, transcoding and call-quality statistics.
- [XDP fast path](xdp.md): forwarding calls inside the network driver.
- [Benchmarks](benchmarks.md): how fast it is, and how that is measured.

## I want to work on the code

- [Architecture](architecture.md): threads, the path of a packet and the
  crates.
- [Testing](testing.md): the test suites, browser tests and kernel tests.
- [Conformance](conformance.md): checking rtpflux against an independent
  reference model.
- [AGENTS.md](https://github.com/RustedBytes/rtpflux/blob/main/AGENTS.md): the rules every change follows.

## Terms

The [Glossary](glossary.md) explains SIP, SDP, RTP, SRTP, ICE, BUNDLE and
the other terms used throughout, in plain English.
