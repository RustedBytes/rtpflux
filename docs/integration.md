# Integration with SIP servers

rtpflux speaks rtpengine's ng protocol, so a SIP proxy that drives
rtpengine drives rtpflux the same way. This page has complete, tested
configurations for Kamailio, OpenSIPS and ferrosip, the FreeSWITCH side of a
proxy + rtpflux + FreeSWITCH setup, and the test bench that checks them
with real calls.
For the ng options themselves, see [Control protocol](control-protocol.md).

## Kamailio

[`contrib/kamailio/kamailio.cfg`](https://github.com/RustedBytes/rtpflux/blob/main/contrib/kamailio/kamailio.cfg) is a
complete configuration: Kamailio as the edge proxy in front of a PBX, with
rtpflux relaying every call's media through Kamailio's `rtpengine` module.

```text
phones ──SIP──▶ Kamailio ──SIP──▶ PBX (FreeSWITCH, Asterisk, …)
   │               │ ng (UDP 2223)            │
   └────RTP────▶ rtpflux ◀───────RTP──────────┘
```

What it does:

- Every INVITE goes to the PBX. Kamailio adds a `Record-Route`, so
  re-INVITEs and BYE come back through it.
- `rtpengine_manage()` rewrites each SDP with rtpflux's address and ports:
  the offer in the INVITE (or a late offer's answer in the ACK), the
  answer in the provisional or final reply.
- BYE, CANCEL and failed calls delete the call in rtpflux, which frees
  its ports at once.
- The `rtpengine` module pings rtpflux at start
  ("rtpengine instance … found, support for it enabled" in Kamailio's log)
  and retries an unanswered command three times; rtpflux answers a
  retransmitted command from its reply cache, so a retry never creates a
  second call.

It is set up from the environment (Kamailio 5.6 or later):

| Variable | Default | Meaning |
|---|---|---|
| `KAMAILIO_LISTEN` | `udp:0.0.0.0:5060` | Where Kamailio listens |
| `KAMAILIO_ADVERTISE` | none | The address to put in `Via` and `Record-Route` when listening on 0.0.0.0 or behind NAT |
| `PBX_URI` | `sip:127.0.0.1:5080` | Where calls go |
| `RTPFLUX_NG` | `udp:127.0.0.1:2223` | rtpflux's `[control] listen` |
| `RTPFLUX_FLAGS` | `trust-address replace-origin` | The flags of every offer and answer |

For example, rtpflux on the same host and FreeSWITCH's external profile
on another:

```sh
PBX_URI=sip:10.0.0.20:5080 RTPFLUX_NG=udp:127.0.0.1:2223 \
    kamailio -DD -E -f contrib/kamailio/kamailio.cfg
```

On the rtpflux side, `[control] listen` must be reachable from Kamailio,
and `[[interface]] address` (or `advertise`) must be an address both the
phones and the PBX can send RTP to.

**Flags.** `trust-address` uses the addresses in the SDP as they are;
leave it out when phones are behind NAT and their SDP addresses are
private, and rtpflux uses the address the SIP message came from (Kamailio
sends it) and learns the real one from the media. Other useful flags:
`ICE=remove` towards SIP phones, `RTP/AVP` to offer plain RTP to the PBX
when callers are browsers, `direction=external direction=internal` with
two interfaces. See [Control protocol](control-protocol.md#options).

## OpenSIPS

[`contrib/opensips/opensips.cfg`](https://github.com/RustedBytes/rtpflux/blob/main/contrib/opensips/opensips.cfg) is the
same edge proxy for OpenSIPS 3.4 or later, with its `rtpengine` module:
every INVITE goes to the PBX through a `Record-Route`,
`rtpengine_manage()` rewrites each SDP with rtpflux's address and
ports, and BYE, CANCEL and failed calls delete the call in rtpflux.

Set where it listens (`socket`) and rtpflux's ng address
(`rtpengine_sock`) in the file. At run time it reads `PBX_URI` (default
`sip:127.0.0.1:5080`) and `RTPFLUX_FLAGS` (default `trust-address
replace-origin`) from the environment. `mpath` is the module directory of
Debian and Ubuntu packages and of the official `opensips/opensips`
images; adjust it elsewhere.

```sh
PBX_URI=sip:10.0.0.20:5080 opensips -F -f contrib/opensips/opensips.cfg
```

The flags are the same as Kamailio's. For SIPREC recording, OpenSIPS's
`siprec` module drives rtpflux's subscriptions; see
[Control protocol](control-protocol.md#subscribe-request-subscribe-answer-and-unsubscribe).

## ferrosip

[ferrosip](https://github.com/RustedBytes/ferrosip)'s `media` module is
Kamailio's `rtpengine` module: the same ng commands and flag syntax.
[`contrib/ferrosip/`](https://github.com/RustedBytes/rtpflux/tree/main/contrib/ferrosip/) is the same setup as the
Kamailio one, in ferrosip's own configuration (`ferrosip.toml` and the
routing in `routes/main.fsr`):

- Every INVITE goes to the PBX, record-routed; its offer goes through
  `media.offer()`, the answer in a 180–299 reply through `media.answer()`.
- BYE and CANCEL, and a call that fails or times out, `media.delete()` it
  in rtpflux. A re-INVITE's offer (or a late answer in the ACK) goes
  through `media.manage()`.

It is set up from the environment, with the same names as the Kamailio
configuration:

| Variable | Default | Meaning |
|---|---|---|
| `SIP_ADDR` | `127.0.0.1` | Where ferrosip listens (UDP 5060) |
| `PBX_URI` | `sip:127.0.0.1:5080` | Where calls go |
| `RTPFLUX_NG` | `udp:127.0.0.1:2223` | rtpflux's `[control] listen` |
| `RTPFLUX_FLAGS` | `trust-address replace-origin` | The flags of every offer and answer |

```sh
SIP_ADDR=10.0.0.10 PBX_URI=sip:10.0.0.20:5080 \
    ferrosip --config contrib/ferrosip/ferrosip.toml
ferrosip check --config contrib/ferrosip/ferrosip.toml   # validate it
```

## FreeSWITCH

FreeSWITCH does not drive a media relay itself: it sits behind Kamailio
as the PBX, and Kamailio has rtpflux relay the media between the phones
and FreeSWITCH (the diagram above). FreeSWITCH then only ever sees
rtpflux's address and ports in the SDP, and sends its RTP there.

[`contrib/freeswitch/`](https://github.com/RustedBytes/rtpflux/tree/main/contrib/freeswitch/) has two drop-in files for
a standard FreeSWITCH configuration:

- `sip_profiles/rtpflux.xml`: a SIP profile on port 5080 for calls from
  the proxy. Calls from the addresses in the ACL list `rtpflux_proxies`
  are taken without digest authentication (Kamailio authenticates its
  users); anything else is challenged. Add the list to
  `autoload_configs/acl.conf.xml`:

  ```xml
  <list name="rtpflux_proxies" default="deny">
    <node type="allow" cidr="10.0.0.10/32"/>   <!-- Kamailio -->
  </list>
  ```

  No NAT settings are needed on this profile: rtpflux already learns
  where each phone's media really comes from.
- `dialplan/rtpflux.xml`: the `from-proxy` context, with two test numbers
  (`echo` sends back what it hears, `tone` plays 440 Hz) and a commented
  transfer to your `default` context.

The profile prefers G.722, then PCMA, PCMU and Opus; G.722 needs
`mod_spandsp` loaded (it is in a standard FreeSWITCH build).

Point Kamailio at the profile with `PBX_URI=sip:<freeswitch>:5080`.

## The test bench

[`integration/`](https://github.com/RustedBytes/rtpflux/tree/main/integration/) runs real calls through these
configurations in Docker:

```text
uac .13    ──SIP──▶ kamailio      .11 ──SIP──▶ uas (SIPp)        .12
uac .13    ──SIP──▶ kamailio-fs   .15 ──SIP──▶ freeswitch:5080   .14
uac .13    ──SIP──▶ ferrosip      .17 ──SIP──▶ uas (SIPp)        .12
uac .13    ──SIP──▶ kamailio-g722 .18 ──SIP──▶ freeswitch:5080   .14
uac .13    ──SIP──▶ opensips      .19 ──SIP──▶ uas (SIPp)        .12
zrtp-a .21 ──SIP──▶ kamailio-zrtp .16 ──SIP──▶ zrtp-b (linphone) .22
  │                    │ ng                     │
  └──────RTP──▶ rtpflux 172.30.89.10 ◀──RTP─────┘
```

- **rtpflux** is built from the repository's `Dockerfile`.
- **Kamailio** and **SIPp** come from Debian's packages. Both Kamailio
  instances run `contrib/kamailio/kamailio.cfg` unchanged; they differ
  only in `PBX_URI`.
- **OpenSIPS** (3.6) is the official image `opensips/opensips`, pinned by
  digest. It runs `contrib/opensips/opensips.cfg` with only its listen
  socket and rtpflux's ng address set to the bench's (`sed` at start), and
  `PBX_URI` pointing at the SIPp callee. The caller calls through it as
  through Kamailio.
- **FreeSWITCH** (1.11) is the community image `safarov/freeswitch`,
  pinned by digest. It runs a minimal `freeswitch.xml` that includes
  `contrib/freeswitch/`'s profile and dialplan unchanged.
- The caller (SIPp) offers G.711 A-law and plays 7 seconds of audio (236
  RTP packets). It calls twice: through the first Kamailio to a SIPp
  callee that echoes every packet, then through the second to
  FreeSWITCH's `echo`.
- **ferrosip** is built from its repository at the commit in
  `integration/ferrosip.ref`, and runs `contrib/ferrosip/` unchanged.
  The repository is private: `run.sh` clones it over SSH (or uses a
  checkout in `integration/ferrosip-src`; CI makes one with the
  `FERROSIP_TOKEN` secret, a read-only token). Without access, the
  ferrosip call is skipped (`REQUIRE_FERROSIP=1` makes that a failure).
  The caller calls through it to the SIPp callee.
- **Transcoding**: a fourth Kamailio adds `codec-transcode-G722
  codec-mask-PCMA` to its flags, so FreeSWITCH is offered G.722 only while
  the caller speaks PCMA. The call connects only if FreeSWITCH takes
  rtpflux's G.722, and the echo comes back only if each side decodes the
  other's (FreeSWITCH's G.722 is SpanDSP's); the caller is answered with
  its own PCMA.
- **ZRTP**: two `linphonec` (Debian's `linphone-cli`, with bzrtp) with
  ZRTP mandatory call each other through the third Kamailio. Their keys
  are agreed end to end, through rtpflux (see
  [Media handling](media.md#zrtp-end-to-end-keys)).

```sh
integration/run.sh          # build, run one call, check, tear down
KEEP=1 integration/run.sh   # leave the bench running
RUST_LOG=debug integration/run.sh   # rtpflux logs at debug (ng warnings included)
```

It passes when, for each call:

1. the call completes (INVITE, 200, ACK, BYE, 200 through the proxy);
2. the parties got rtpflux's address in the SDP, not each other's (the
   caller's and the SIPp callee's SDP are checked; a FreeSWITCH that got
   the caller's address would send its echo around rtpflux, which the next
   check catches);
3. rtpflux forwarded the audio both ways (472 packets, 236 each way;
   95% is required, as FreeSWITCH's echo starts a few frames late);
4. rtpflux answered every ng command without an error;
5. the call is gone from rtpflux after the BYE;

and when, for the ZRTP call, both phones reach ZRTP's secure state with
the **same** short authentication string (they could not if the relay had
interfered with the key agreement) and rtpflux relayed their ZRTP packets.

The bench found one real bug on its first run: the two Kamailio
instances, identical containers, sent the same ng cookies, and rtpflux
answered the second one's `offer` from its reply cache. Replies are now
cached per sender.

The SIP messages each party saw, and every container's log, are left in
`integration/out/`. It needs Docker with Compose (v2, or v1's
`docker-compose`). CI runs it on every push.
