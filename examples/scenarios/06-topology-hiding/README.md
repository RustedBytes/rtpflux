# 06: topology hiding between networks

**The case.** One relay joins a public network, where it is behind a
1:1 NAT, to a private core. Each side must see only the relay's address
on its own network.

## Setting it up

```toml
[[interface]]
name = "external"
address = "10.0.0.5"          # bound locally
advertise = "198.51.100.1"    # written into SDP (the NAT's public address)

[[interface]]
name = "internal"
address = "172.16.0.5"
```

```text
rtpengine_offer("direction=external direction=internal replace-origin");
```

## What `run.py` checks

- **SDP rewriting:** each side gets its own interface's address in
  `c=`, `o=` (with `replace-origin`) and `a=rtcp`. The advertised
  address faces the outside, and no core address reaches it.
- **Media:** packets leave from the interface the side was given, and an
  outside port is not open on the internal interface.
- **Directions:** unknown interface names, one name, and no names.
- **IPv6:** an IPv4 caller with an IPv6 callee, and an IPv6 caller on an
  IPv4-only direction.

## Caveats

- Free-form attributes (`a=tool:…`) pass through unchanged: the relay
  cannot know what they mean. Remove them in the proxy, or have the relay
  do it with `sdp-attr` (`remove`, per session or media kind).
