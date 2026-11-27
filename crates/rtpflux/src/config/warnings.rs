//! Settings that are valid but probably not what was meant: exposed
//! listeners, values that are ignored or silently adjusted. They never stop
//! the daemon; it logs them at start-up and `--check` prints them.

use super::{Config, Ports, Recording, Sessions, Xdp};
use crate::recording::store::{S3Config, Storage};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// A setting that works, but likely not as intended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// An `ng` listener (`key`) reachable from outside a private network;
    /// the protocol has no authentication.
    ControlExposed { key: &'static str, addr: SocketAddr },
    /// The web UI on a non-loopback address: Basic auth without TLS.
    WebUiExposed(SocketAddr),
    /// `control.native_listen` not on loopback: plain TCP, tokens in clear.
    NativeExposed(SocketAddr),
    /// An interface (named) advertising another address family than it
    /// binds.
    AdvertiseFamily(String),
    /// `ports.min` below 1024: privileged, well-known ports.
    PrivilegedPorts(u16),
    /// More workers than port pairs allow (two each); `used` start.
    WorkersClamped { workers: usize, used: usize },
    /// Redis without a password; the state holds SRTP keys.
    RedisNoPassword,
    /// Redis on another host: the state crosses the network in clear text.
    RedisRemote,
    /// A setting that has no effect, and why.
    Ignored {
        key: &'static str,
        because: &'static str,
    },
    /// A relative path (the key), resolved against the working directory.
    RelativePath(&'static str),
    /// A file-name template that gives many recordings the same name.
    FileNamesRepeat,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::ControlExposed { key, addr } => write!(
                f,
                "{key}: {addr} is reachable beyond loopback and private networks, and ng has no authentication"
            ),
            Warning::NativeExposed(addr) => write!(
                f,
                "control.native_listen: {addr} is not loopback; tokens and SDP travel without TLS unless a proxy adds it"
            ),
            Warning::WebUiExposed(addr) => write!(
                f,
                "webui.listen: {addr} is not loopback; the login travels without TLS unless a reverse proxy adds it"
            ),
            Warning::AdvertiseFamily(n) => write!(
                f,
                "interface '{n}': advertise and address are of different IP families"
            ),
            Warning::PrivilegedPorts(min) => write!(
                f,
                "ports.min = {min}: the range includes well-known ports below 1024"
            ),
            Warning::WorkersClamped { workers, used } => write!(
                f,
                "runtime.workers = {workers}: the port range serves {used} (two port pairs per worker at least)"
            ),
            Warning::RedisNoPassword => f.write_str(
                "sessions.redis: no password, and the state holds SRTP keys",
            ),
            Warning::RedisRemote => f.write_str(
                "sessions.redis: not on this host; the state (with SRTP keys) crosses the network without TLS",
            ),
            Warning::Ignored { key, because } => write!(f, "{key}: ignored, {because}"),
            Warning::FileNamesRepeat => f.write_str(
                "recording.file_name: without {call_id} (or {timestamp}) and {section}, names repeat; \
                 later recordings of a name get -2, -3, …",
            ),
            Warning::RelativePath(key) => write!(
                f,
                "{key}: a relative path, resolved against the working directory"
            ),
        }
    }
}

impl Config {
    /// Settings that are valid but likely mistakes, in file order. Call it
    /// on a configuration that passed [`Config::validate`].
    #[must_use]
    pub fn warnings(&self) -> Vec<Warning> {
        let mut w = Vec::new();
        let ng = (self.control.listen.iter().map(|a| ("control.listen", a)))
            .chain(
                self.control
                    .listen_tcp
                    .iter()
                    .map(|a| ("control.listen_tcp", a)),
            )
            .chain(
                self.control
                    .listen_http
                    .iter()
                    .map(|a| ("control.listen_http", a)),
            );
        for (key, &addr) in ng {
            if !is_private(addr.ip()) {
                w.push(Warning::ControlExposed { key, addr });
            }
        }
        for &addr in &self.control.native_listen {
            if !addr.ip().is_loopback() {
                w.push(Warning::NativeExposed(addr));
            }
        }
        for i in &self.interfaces {
            if i.advertise
                .is_some_and(|a| a.is_ipv4() != i.address.is_ipv4())
            {
                w.push(Warning::AdvertiseFamily(i.name.clone()));
            }
        }
        ports_warnings(self.ports, self.runtime.workers, &mut w);
        sessions_warnings(&self.sessions, &mut w);
        xdp_warnings(&self.xdp, &mut w);
        if let Some(addr) = self.webui.listen {
            if !addr.ip().is_loopback() {
                w.push(Warning::WebUiExposed(addr));
            }
        } else if !self.webui.user.is_empty() || !self.webui.password_hash.is_empty() {
            w.push(Warning::Ignored {
                key: "webui.user / webui.password_hash",
                because: "webui.listen is not set (the web UI is off)",
            });
        }
        if self.ice.stun_server.is_some() && self.interfaces.iter().all(|i| i.advertise.is_some()) {
            w.push(Warning::Ignored {
                key: "ice.stun_server",
                because: "every interface has `advertise`, and STUN is asked only for the others",
            });
        }
        recording_warnings(&self.recording, &mut w);
        w
    }
}

fn ports_warnings(ports: Ports, workers: usize, w: &mut Vec<Warning>) {
    if ports.min < 1024 {
        w.push(Warning::PrivilegedPorts(ports.min));
    }
    // As the relay starts them: at least two pairs per worker.
    let used = workers.clamp(1, (ports.pairs() / 2).max(1));
    if workers > used {
        w.push(Warning::WorkersClamped { workers, used });
    }
}

fn sessions_warnings(s: &Sessions, w: &mut Vec<Warning>) {
    let defaults = Sessions::default();
    if s.state_file.as_deref().is_some_and(Path::is_relative) {
        w.push(Warning::RelativePath("sessions.state_file"));
    }
    // validate() has checked the URL; a broken one is not warned about.
    if let Ok(Some(t)) = s.redis_target() {
        if !t.has_password() {
            w.push(Warning::RedisNoPassword);
        }
        if !t.is_local() {
            w.push(Warning::RedisRemote);
        }
    } else if s.redis.is_none() && s.redis_key != defaults.redis_key {
        w.push(Warning::Ignored {
            key: "sessions.redis_key",
            because: "sessions.redis is not set",
        });
    }
}

fn xdp_warnings(x: &Xdp, w: &mut Vec<Warning>) {
    if x.enabled {
        if x.object.is_relative() {
            w.push(Warning::RelativePath("xdp.object"));
        }
    } else if !x.devices.is_empty() {
        w.push(Warning::Ignored {
            key: "xdp.devices",
            because: "xdp.enabled is false",
        });
    }
    if !x.af_xdp && x.af_xdp_frames != Xdp::default().af_xdp_frames {
        w.push(Warning::Ignored {
            key: "xdp.af_xdp_frames",
            because: "xdp.af_xdp is false",
        });
    }
}

fn recording_warnings(r: &Recording, w: &mut Vec<Warning>) {
    let defaults = Recording::default();
    if let Some(dir) = &r.dir {
        if dir.is_relative() {
            w.push(Warning::RelativePath("recording.dir"));
        }
    } else if r.settings() != defaults.settings() {
        w.push(Warning::Ignored {
            key: "recording (format, channels, sample_rate, bitrate, keep_pcap)",
            because: "recording.dir is not set, so `start recording` is refused",
        });
    }
    if r.dir.is_some()
        && (!(r.file_name.contains("{call_id}") || r.file_name.contains("{timestamp}"))
            || !r.file_name.contains("{section}"))
    {
        w.push(Warning::FileNamesRepeat);
    }
    if !r.format.lossy() && r.bitrate != defaults.bitrate {
        w.push(Warning::Ignored {
            key: "recording.bitrate",
            because: "only opus and mp3 have a bitrate",
        });
    }
    if r.keep_pcap && r.format == crate::recording::Format::Pcap {
        w.push(Warning::Ignored {
            key: "recording.keep_pcap",
            because: "with format = \"pcap\" the pcap is the recording",
        });
    }
    if r.storage == Storage::Local && r.s3 != S3Config::default() {
        w.push(Warning::Ignored {
            key: "recording.s3",
            because: "recording.storage is \"local\"",
        });
    }
}

/// Loopback, private (RFC 1918, RFC 4193) or link-local.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            let first = a.segments()[0];
            a.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "[[interface]]\nname = \"a\"\naddress = \"10.0.0.1\"\n";

    fn warnings(extra: &str) -> Vec<String> {
        Config::from_toml(&format!("{MINIMAL}{extra}"))
            .unwrap()
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn defaults_and_the_example_warn_about_nothing() {
        assert_eq!(warnings(""), Vec::<String>::new());
        let example = Config::from_toml(super::super::EXAMPLE).unwrap();
        assert_eq!(example.warnings(), Vec::new());
    }

    #[test]
    fn exposed_listeners() {
        let w = warnings(
            "[control]\nlisten = [\"0.0.0.0:2223\", \"192.168.1.1:2224\"]\nlisten_tcp = [\"[2001:db8::1]:2223\"]\nlisten_http = [\"[fd00::1]:8080\"]\n\
             [webui]\nlisten = \"10.0.0.1:8090\"\nuser = \"admin\"\npassword_hash = \"sha256:0a856b929ea8da34e01f762b:5ba04d919a1648780d4662a15ac148dddb008905a1f2688dca32550070666c81\"\n",
        );
        assert_eq!(w.len(), 3, "{w:#?}");
        assert!(w[0].starts_with("control.listen: 0.0.0.0:2223"), "{w:#?}");
        assert!(
            w[1].starts_with("control.listen_tcp: [2001:db8::1]"),
            "{w:#?}"
        );
        assert!(w[2].starts_with("webui.listen: 10.0.0.1:8090"), "{w:#?}");
    }

    #[test]
    fn ignored_settings() {
        let w = warnings(
            "[sessions]\nfinal_timeout = 7200\nredis_key = \"x\"\n\
             [xdp]\ndevices = [\"eth0\"]\naf_xdp_frames = 4096\n\
             [webui]\nuser = \"admin\"\n\
             [recording]\nformat = \"wav\"\nbitrate = 64\n[recording.s3]\nbucket = \"b\"\n",
        );
        for needle in [
            "sessions.redis_key: ignored",
            "xdp.devices: ignored",
            "xdp.af_xdp_frames: ignored",
            "webui.user / webui.password_hash: ignored",
            "recording (format",
            "recording.bitrate: ignored",
            "recording.s3: ignored",
        ] {
            assert!(w.iter().any(|x| x.starts_with(needle)), "{needle}: {w:#?}");
        }
        let w = warnings("[recording]\ndir = \"spool\"\nkeep_pcap = true\n");
        assert!(w.iter().any(|x| x.starts_with("recording.dir: a relative")));
        assert!(w.iter().any(|x| x.starts_with("recording.keep_pcap")));
    }

    #[test]
    fn redis_without_password_or_elsewhere() {
        let w = warnings("[sessions]\nredis = \"redis://10.0.0.9\"\n");
        assert_eq!(w.len(), 2, "{w:#?}");
        assert_eq!(
            warnings("[sessions]\nredis = \"redis://:pw@localhost\"\n"),
            [""; 0]
        );
        assert_eq!(
            warnings("[sessions]\nredis = \"redis://:pw@[::1]:6380\"\n"),
            [""; 0]
        );
    }

    #[test]
    fn interfaces_ports_and_workers() {
        let w = Config::from_toml(
            "[[interface]]\nname = \"a\"\naddress = \"10.0.0.1\"\nadvertise = \"2001:db8::1\"\n\
             [ice]\nstun_server = \"stun.example.net:3478\"\n\
             [ports]\nmin = 1000\nmax = 1039\n[sessions]\nmax = 10\n[runtime]\nworkers = 64\n",
        )
        .unwrap()
        .warnings();
        assert_eq!(
            w,
            vec![
                Warning::AdvertiseFamily("a".to_owned()),
                Warning::PrivilegedPorts(1000),
                Warning::WorkersClamped {
                    workers: 64,
                    used: 10
                },
                Warning::Ignored {
                    key: "ice.stun_server",
                    because: "every interface has `advertise`, and STUN is asked only for the others",
                },
            ]
        );
    }

    #[test]
    fn private_ranges() {
        for (ip, private) in [
            ("127.0.0.1", true),
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("192.168.0.1", true),
            ("169.254.1.1", true),
            ("0.0.0.0", false),
            ("203.0.113.1", false),
            ("::1", true),
            ("fd12::1", true),
            ("fe80::1", true),
            ("::", false),
            ("2001:db8::1", false),
        ] {
            assert_eq!(is_private(ip.parse().unwrap()), private, "{ip}");
        }
    }
}
