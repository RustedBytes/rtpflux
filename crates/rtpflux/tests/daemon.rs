//! The daemon as `main` runs it: the command line's preflight, then the
//! relay, its ng server and metrics started, used and stopped.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::daemon::{Cli, Daemon, Preflight, preflight};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

fn temp_dir(name: &str) -> std::path::PathBuf {
    logging::init();
    let d = std::env::temp_dir().join(format!("rtpflux-daemon-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run_preflight(args: &[&str]) -> (Preflight, String, String) {
    let cli = Cli::try_parse_from(args).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let p = preflight(&cli, &mut out, &mut err);
    (
        p,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn preflight_prints_checks_and_reports() {
    let (p, out, _) = run_preflight(&["rtpflux", "--print-example-config"]);
    assert!(matches!(p, Preflight::Done));
    assert!(out.contains("[[interface]]"), "{out}");

    let dir = temp_dir("preflight");
    let good = dir.join("good.toml");
    std::fs::write(
        &good,
        "[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n",
    )
    .unwrap();
    let good = good.to_str().unwrap();
    let (p, out, _) = run_preflight(&["rtpflux", "-c", good, "--check"]);
    assert!(matches!(p, Preflight::Done));
    assert!(out.ends_with("configuration is valid\n"), "{out}");
    let (p, _, _) = run_preflight(&["rtpflux", "-c", good]);
    assert!(matches!(p, Preflight::Run(c) if c.interfaces.len() == 1));

    // Warnings are printed, but the configuration is still valid.
    let warned = dir.join("warned.toml");
    std::fs::write(
        &warned,
        "[control]\nlisten = [\"0.0.0.0:2223\"]\n[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n",
    )
    .unwrap();
    let (p, out, err) = run_preflight(&["rtpflux", "-c", warned.to_str().unwrap(), "--check"]);
    assert!(matches!(p, Preflight::Done));
    assert!(out.ends_with("configuration is valid\n"), "{out}");
    assert!(
        err.contains("warning: control.listen: 0.0.0.0:2223 is reachable"),
        "{err}"
    );

    let missing = dir.join("missing.toml");
    let (p, _, err) = run_preflight(&["rtpflux", "-c", missing.to_str().unwrap()]);
    assert!(matches!(p, Preflight::Failed));
    assert!(err.starts_with("rtpflux: "), "{err}");

    let bad = dir.join("bad.toml");
    std::fs::write(
        &bad,
        "[[interface]]\nname = \"lo\"\naddress = \"0.0.0.0\"\n",
    )
    .unwrap();
    let (p, _, err) = run_preflight(&["rtpflux", "-c", bad.to_str().unwrap(), "--check"]);
    assert!(matches!(p, Preflight::Failed));
    assert!(err.contains("concrete address"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One ng request (already bencoded) and its reply.
fn ng(to: std::net::SocketAddr, request: &[u8]) -> String {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.send_to(request, to).unwrap();
    let mut buf = vec![0u8; 65_535];
    let n = s.recv(&mut buf).expect("ng reply");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[test]
fn starts_serves_and_stops_saving_its_calls() {
    let dir = temp_dir("run");
    let state = dir.join("state.json");
    let recordings = dir.join("recordings");
    let config = Config::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 52000
        max = 52063
        [sessions]
        max = 8
        state_file = "{}"
        [runtime]
        workers = 1
        [metrics]
        listen = ["127.0.0.1:0"]
        [recording]
        dir = "{}"
        "#,
        state.display(),
        recordings.display()
    ))
    .unwrap();
    let daemon = Daemon::start(&config).unwrap();
    assert!(recordings.is_dir(), "the recording directory is created");
    let control = daemon.control_addrs()[0];
    assert_ne!(control.port(), 0);
    assert_eq!(ng(control, b"1 d7:command4:pinge"), "1 d6:result4:ponge");
    let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";
    let offer = format!(
        "2 d7:call-id4:keep7:command5:offer8:from-tag1:f3:sdp{}:{sdp}e",
        sdp.len()
    );
    assert!(ng(control, offer.as_bytes()).contains("6:result2:ok"));

    let mut http = TcpStream::connect(daemon.metrics_addrs()[0]).unwrap();
    write!(http, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut page = String::new();
    http.read_to_string(&mut page).unwrap();
    assert!(
        page.contains("rtpflux_ng_requests_total{command=\"offer\"} 1"),
        "{page}"
    );
    assert!(page.contains("rtpflux_sessions 1"), "{page}");

    daemon.stop();
    let saved = std::fs::read_to_string(&state).unwrap();
    assert!(saved.contains(&rtpflux::state::hex(b"keep")), "{saved}");

    // A second daemon on the same state file restores the call.
    let daemon = Daemon::start(&config).unwrap();
    let list = ng(daemon.control_addrs()[0], b"3 d7:command4:liste");
    assert!(list.contains("4:keep"), "{list}");
    daemon.stop();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_taken_address_fails_to_start() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = Config::from_toml(&format!(
        "[control]\nlisten = [\"{}\"]\n[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n\
         [ports]\nmin = 52100\nmax = 52163\n[sessions]\nmax = 8\n[runtime]\nworkers = 1\n",
        taken.local_addr().unwrap()
    ))
    .unwrap();
    let e = Daemon::start(&config).unwrap_err();
    assert!(
        matches!(e, rtpflux::daemon::StartError::Listen { what: "ng", .. }),
        "{e}"
    );
    assert!(e.to_string().starts_with("ng: cannot listen on"), "{e}");
}

/// The `rtpflux` binary itself.
fn binary() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_rtpflux"))
}

#[test]
fn the_binary_checks_runs_and_stops_on_sigterm() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let out = binary().arg("--print-example-config").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("[[interface]]"));

    let dir = temp_dir("binary");
    let config = dir.join("rtpflux.toml");
    // A fixed ng port: the binary reports no bound address back.
    let ng_addr = "127.0.0.1:52290";
    std::fs::write(
        &config,
        format!(
            "[control]\nlisten = [\"{ng_addr}\"]\n[[interface]]\nname = \"lo\"\naddress = \"127.0.0.1\"\n\
             [ports]\nmin = 52300\nmax = 52363\n[sessions]\nmax = 8\n[runtime]\nworkers = 1\n[log]\nformat = \"compact\"\n"
        ),
    )
    .unwrap();
    let out = binary()
        .arg("--check")
        .arg("-c")
        .arg(&config)
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = binary()
        .args(["-c", "/nonexistent/rtpflux.toml"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("rtpflux: "));

    let mut child = binary()
        .arg("-c")
        .arg(&config)
        .args(["--log-level", "debug"])
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let to: std::net::SocketAddr = ng_addr.parse().unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 256];
    let mut pong = None;
    for _ in 0..50 {
        s.send_to(b"p d7:command4:pinge", to).unwrap();
        if let Ok(n) = s.recv(&mut buf) {
            pong = Some(buf[..n].to_vec());
            break;
        }
    }
    assert_eq!(pong.as_deref(), Some(&b"p d6:result4:ponge"[..]));
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    assert!(child.wait().unwrap().success(), "a clean exit on SIGTERM");

    // Starting fails cleanly when the ng address is taken.
    let taken = UdpSocket::bind(ng_addr).unwrap();
    let out = binary().arg("-c").arg(&config).output().unwrap();
    assert!(!out.status.success());
    drop(taken);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_binary_hashes_a_web_ui_password() {
    use std::process::Stdio;
    let mut child = binary()
        .arg("--webui-hash")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"secret\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let hash = String::from_utf8(out.stdout).unwrap();
    let c = rtpflux::webui::auth::Credentials::new("admin", hash.trim()).unwrap();
    // "admin:secret"
    assert!(c.check(Some("Basic YWRtaW46c2VjcmV0")));
}
