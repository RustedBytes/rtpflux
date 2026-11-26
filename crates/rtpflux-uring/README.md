# rtpflux-uring

Receiving UDP with `io_uring` for the media workers: one multishot
receive per socket, with buffers the kernel picks from a provided-buffer
ring. This is the default `runtime.receive = "io_uring"`.

## Why it is a crate of its own

Each media worker reads datagrams from thousands of sockets. With `epoll`
and `recvmmsg`, that costs system calls per ready socket. With `io_uring`,
one request per socket keeps receiving, and the completions of every
socket arrive on one queue, without a system call per socket or per
datagram. The benchmark below measures the difference.

The kernel and the program share memory here (the rings and the
buffers), which needs `unsafe` code. This crate keeps it small and in one
place:

- **`unsafe` only in the `ring` module**, each block with a `// SAFETY:`
  comment. The provided buffers and their ring are allocated once and
  never freed, since the kernel may use them until the ring is torn down.
  A received buffer is read only through a slice made for it, while it is
  out of the ring. Everything above `ring` is safe code.
- The daemon gets a safe `Receiver` and stays free of `unsafe`.

## How it is used

A `Receiver` is armed on sockets (`Receiver::arm`, each with a token),
waited on (`Receiver::wait`, or its file descriptor in an epoll set), and
drained (`Receiver::complete`). Each datagram comes with its token,
source and payload, and its buffer then goes back to the ring. A socket
whose multishot request ends (the buffers ran out, say) is armed again.
`Receiver::disarm` stops one, and anything it still completes is
dropped.

It needs Linux 6.0 or later. Where `io_uring` is refused (Docker's default
seccomp profile, for example) the daemon falls back to `recvmmsg` and
says so in its log.

## Benchmark

`benches/recv.rs` compares this crate with `epoll` + `recvmmsg` on many
sockets at RTP's packet size and rate, measuring the receiving thread's
CPU time per datagram:

```sh
cargo bench -p rtpflux-uring      # on an otherwise idle machine
```

## Testing

```sh
cargo test -p rtpflux-uring
```

## Used by

The daemon's media workers (`rtpflux`). See `[runtime] receive` in
[Configuration](../../docs/configuration.md).
