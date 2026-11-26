# rtpflux-ng

The `ng` control protocol, as spoken by the `rtpengine` modules of Kamailio
and OpenSIPS: a cookie, a space, and a bencoded dictionary in one UDP
datagram.

## Why it is a crate of its own

Every `ng` message comes from the network, so this is the first code that
untrusted input reaches. A crate of its own lets that code follow the
strictest rules and be tested and fuzzed on its own:

- **`no_std`, no `alloc`, no I/O.** Parsing never allocates and cannot
  touch a socket.
- **Zero-copy.** A parsed `Message` and its `bencode::Value`s borrow from
  the datagram; nothing is copied to inspect a command.
- **Bounded.** Nesting is limited (`bencode::MAX_DEPTH`) and so is the
  number of keys in a dictionary (`MAX_KEYS`), so a hostile message cannot
  exhaust the stack or the CPU.
- **Panic-free.** Unchecked indexing and arithmetic are denied by Clippy
  outside tests.

## What is inside

| Item | What it does |
|---|---|
| `parse_message` | Splits a datagram into its cookie and its decoded dictionary |
| `write_reply` | Writes a reply (cookie and bencoded dictionary) into a caller's buffer |
| `bencode::decode`, `Value`, `Dict`, `List` | The bencode decoder and its borrowed values |
| `bencode::item_len` | The length of one bencoded item, used to split messages on a TCP stream |
| `bencode::Encoder` | Writes bencode into a caller-provided `&mut [u8]` |

What the commands mean (`offer`, `answer`, `delete`, …) is decided by the
daemon's `control` module; this crate only reads and writes the wire
format.

## Used by

The daemon (`rtpflux`), the load generator (`rtpflux-bench`), and the
daemon's tests.

## Testing

```sh
cargo test -p rtpflux-ng
cargo test -p rtpflux --test robustness   # fuzzes the parser with hostile input
```
