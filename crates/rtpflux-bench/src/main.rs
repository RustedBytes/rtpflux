//! The `rtpflux-bench` command: see the library documentation.

// No `unsafe` here, and no way to allow it (AGENTS.md §5).
#![forbid(unsafe_code)]
use clap::Parser;
use nix::sys::resource::{Resource, getrlimit, setrlimit};

fn main() -> std::io::Result<()> {
    let args = rtpflux_bench::Args::parse();
    // Two endpoint sockets per call: raise the open-file limit to its hard
    // limit (the default soft limit of 1024 caps the client at ~500 calls).
    if let Ok((_, hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
        let _ = setrlimit(Resource::RLIMIT_NOFILE, hard, hard);
    }
    rtpflux_bench::run(&args, &mut std::io::stdout().lock())
}
