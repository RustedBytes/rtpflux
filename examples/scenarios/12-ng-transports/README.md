# 12: ng over TCP, HTTP and WebSocket

**The case.** Proxies that do not use UDP: Kamailio's
`rtpengine_sock "ws://host:port"` (WebSocket), HTTP-based controllers,
and TCP for large messages.

## Setting it up

```toml
[control]
listen = ["127.0.0.1:2223"]        # UDP
listen_tcp = ["127.0.0.1:2223"]    # messages back to back
listen_http = ["127.0.0.1:2225"]   # POST /ng, /ng-plain, GET /ping, WebSocket
```

## What `run.py` checks

- **TCP:**
  - 200 pipelined requests are answered in order.
  - A request arriving in 7-byte pieces is handled.
  - A retransmission on the same connection gets the cached reply.
  - 100 concurrent connections are all answered.
  - Each kind of bad stream closes only its own connection: no space in
    the first 256 bytes, an empty cookie, a leading zero, a repeated key,
    nesting deeper than 32, or more than 64 KB.
- **HTTP:** `POST /ng` (cookie and bencode), and `/ng-plain` with
  bencode or JSON, including a JSON `query`. Broken JSON gets 400, an
  unknown path 404, and `GET /ping` works.
- **WebSocket:**
  - The handshake confirms the `ng.rtpengine.com` subprotocol.
  - Replies are binary frames with the cookie; an offer works over it.
  - A fragmented message is reassembled, and a ping gets a pong.
  - `ng-plain.rtpengine.com` works with JSON and with bencode.
  - An unknown subprotocol is refused.
- **RFC 6455 failures**, each closed with 1002: an unmasked frame, a
  reserved bit, a reserved opcode, a fragmented control frame, a
  non-minimal length, or a continuation with no message in progress. A
  message over 64 KB is refused too.
- **One table:** calls made over TCP, HTTP and WebSocket all appear in
  the same call table.
