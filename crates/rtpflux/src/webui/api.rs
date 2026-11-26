//! The read-only JSON API under `/api/v1/`.
//!
//! Each path is answered from read-only state: the counters (the same as
//! `/metrics`), process and configuration facts, the control thread's
//! dialogs (asked over [`WebLink`]) and the log ring. Lists are filtered
//! (`q`), sorted (`sort=field` / `sort=-field`) and paged (`offset`,
//! `limit` ≤ 500) here. The dialog list is cached for a second, so several
//! open browsers cost the control thread one answer.

use super::logs;
use crate::control::{Unanswered, WebLink, WebQuery};
use crate::metrics::Sources;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_LIMIT: usize = 500;
const CACHE_TTL: Duration = Duration::from_secs(1);

/// Query arguments of a request.
pub type Query = HashMap<String, String>;

/// An API answer: HTTP status and JSON body.
pub type Answer = (u16, Value);

/// What the API reads.
pub struct Api {
    sources: Sources,
    control: WebLink,
    /// Configuration facts for the Overview page (fixed at start).
    config: Value,
    started: SystemTime,
    pub refresh_ms: u64,
    calls: Mutex<Option<(Instant, Value)>>,
    /// `[recording] dir`'s pcaps (the Recordings page).
    pub recordings: super::recordings::Recordings,
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Resident memory (KiB) and threads of this process, from
/// `/proc/self/status`.
fn process_status() -> (Option<u64>, Option<u64>) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return (None, None);
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse().ok())
    };
    (field("VmRSS:"), field("Threads:"))
}

fn unanswered(e: Unanswered) -> Answer {
    match e {
        Unanswered::Busy => (503, json!({ "error": "the control thread is busy" })),
        Unanswered::Timeout => (504, json!({ "error": "the control thread did not answer" })),
    }
}

impl Api {
    #[must_use]
    pub fn new(
        sources: Sources,
        control: WebLink,
        config: Value,
        refresh_ms: u64,
        recordings: super::recordings::Recordings,
    ) -> Self {
        Api {
            sources,
            control,
            config,
            started: SystemTime::now(),
            refresh_ms,
            calls: Mutex::new(None),
            recordings,
        }
    }

    /// `path` without the `/api/v1/` prefix.
    #[must_use]
    pub fn handle(&self, path: &str, q: &Query) -> Answer {
        match path {
            "meta" => (200, self.meta()),
            "stats" => (200, self.stats()),
            "info" => (200, self.info()),
            "calls" => match self.calls() {
                Ok(v) => (200, page(v, q)),
                Err(e) => unanswered(e),
            },
            "calls/detail" => self.call(q),
            "calls/parties" => self.parties(q),
            "logs" => logs_tail(q),
            "recordings" => self.recordings.handle("", q),
            "xdp" if self.xdp_enabled() => self.xdp(q),
            "uploads" if self.uploads_enabled() => {
                (200, page(Value::Array(self.sources.recording.uploads()), q))
            }
            "uploads/webhooks" if self.uploads_enabled() => (
                200,
                page(Value::Array(self.sources.recording.deliveries()), q),
            ),
            _ => match path.strip_prefix("recordings/") {
                Some(rest) => self.recordings.handle(rest, q),
                None => (404, json!({ "error": "no such API path" })),
            },
        }
    }

    fn meta(&self) -> Value {
        let mut sections = Map::new();
        sections.insert("overview".into(), json!(["info", "stats"]));
        sections.insert(
            "calls".into(),
            json!(["calls", "calls/detail", "calls/parties"]),
        );
        sections.insert("statistics".into(), json!(["stats"]));
        if logs::enabled() {
            sections.insert("logs".into(), json!(["logs"]));
        }
        if self.uploads_enabled() {
            sections.insert("uploads".into(), json!(["uploads", "uploads/webhooks"]));
        }
        if self.xdp_enabled() {
            sections.insert("xdp".into(), json!(["xdp"]));
        }
        if self.recordings.enabled() {
            sections.insert(
                "recordings".into(),
                json!([
                    "recordings",
                    "recordings/streams",
                    "recordings/packets",
                    "recordings/download"
                ]),
            );
        }
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "refresh_ms": self.refresh_ms,
            "sections": sections,
        })
    }

    /// Every counter and gauge, with its kind and help.
    fn stats(&self) -> Value {
        let rows: Vec<Value> = self
            .sources
            .samples()
            .into_iter()
            .map(|s| {
                json!({
                    "group": s.group,
                    "name": s.name,
                    "value": s.value,
                    "kind": if s.counter { "counter" } else { "gauge" },
                    "help": s.help,
                })
            })
            .collect();
        json!({ "ts_ms": unix_ms(SystemTime::now()), "rows": rows })
    }

    fn info(&self) -> Value {
        let (rss_kb, threads) = process_status();
        let mut v = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "started": unix_ms(self.started) / 1000,
            "uptime": self.started.elapsed().map_or(0, |d| d.as_secs()),
            "rss_kb": rss_kb,
            "threads": threads,
            // Each worker: how it receives (io_uring, or recvmmsg and why),
            // its calls and its counters. (`workers` is the configured
            // count.)
            "worker_stats": self
                .sources
                .workers
                .iter()
                .enumerate()
                .map(|(n, w)| {
                    let get = |a: &std::sync::atomic::AtomicU64| a.load(std::sync::atomic::Ordering::Relaxed);
                    json!({
                        "index": n + 1,
                        "receive": w.receive.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
                        "calls": get(&w.calls),
                        "offloaded_calls": get(&w.offloaded_calls),
                        "forwarded": get(&w.forwarded),
                        "kernel_packets": get(&w.kernel_packets),
                        "dropped": get(&w.dropped),
                        "send_errors": get(&w.send_errors),
                        "srtp_rejected": get(&w.srtp_rejected),
                    })
                })
                .collect::<Vec<_>>(),
            // Each interface's server-reflexive address, once learned.
            "srflx": self
                .sources
                .srflx
                .read()
                .map_or_else(
                    |_| Vec::new(),
                    |v| v.iter().map(|a| a.map(|a| a.to_string())).collect::<Vec<_>>(),
                ),
        });
        if let (Value::Object(o), Value::Object(c)) = (&mut v, &self.config) {
            o.extend(c.clone());
        }
        v
    }

    /// The dialog list, at most a second old. The cache stays locked while
    /// the control thread is asked: requests that come meanwhile wait for
    /// that one answer instead of each asking again.
    fn calls(&self) -> Result<Value, Unanswered> {
        let mut cache = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((t, v)) = cache.as_ref()
            && t.elapsed() < CACHE_TTL
        {
            return Ok(v.clone());
        }
        let v = self.control.ask(WebQuery::Calls)?;
        *cache = Some((Instant::now(), v.clone()));
        Ok(v)
    }

    fn call(&self, q: &Query) -> Answer {
        let (Some(call_id), Some(from_tag)) = (q.get("call_id"), q.get("from_tag")) else {
            return (400, json!({ "error": "call_id and from_tag are required" }));
        };
        match self.control.ask(|reply| WebQuery::Call {
            call_id: call_id.clone(),
            from_tag: from_tag.clone(),
            reply,
        }) {
            Ok(Value::Null) => (404, json!({ "error": "no such call" })),
            Ok(v) => (200, v),
            Err(e) => unanswered(e),
        }
    }
}

impl Api {
    /// The XDP fast path is on: its calls are listed.
    fn xdp_enabled(&self) -> bool {
        !self.config["xdp"].is_null()
    }

    /// `xdp`: the calls the XDP program relays, as of its last poll, each
    /// with its dialog and media section when the control thread answers.
    fn xdp(&self, q: &Query) -> Answer {
        let flows = self
            .sources
            .xdp_flows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let names = self
            .control
            .ask(WebQuery::RelayCalls)
            .unwrap_or(Value::Null);
        let dir = |d: &crate::relay::XdpDir| {
            json!({
                "from": d.from.to_string(),
                "to": d.to.to_string(),
                "device": d.device,
                "drops": d.drops,
                "events_up": d.events_up,
                "records": d.records,
                "packets": d.packets,
                "octets": d.octets,
            })
        };
        let rows: Vec<Value> = flows
            .iter()
            .map(|f| {
                let id = f.call.to_string();
                let n = &names[&id];
                json!({
                    "relay_call": f.call,
                    "worker": f.worker + 1,
                    "call_id": n["call_id"],
                    "from_tag": n["from_tag"],
                    "key": n["key"],
                    "section": n["section"],
                    "packets": f.dirs[0].packets + f.dirs[1].packets,
                    "octets": f.dirs[0].octets + f.dirs[1].octets,
                    "a": dir(&f.dirs[0]),
                    "b": dir(&f.dirs[1]),
                })
            })
            .collect();
        (200, page(Value::Array(rows), q))
    }

    /// Recordings go to S3: their uploads (and webhook deliveries) are
    /// listed.
    fn uploads_enabled(&self) -> bool {
        self.config["recording"]["storage"] == "s3"
    }

    /// `calls/parties?call_id=…`: a call's parties and what links them.
    fn parties(&self, q: &Query) -> Answer {
        let Some(call_id) = q.get("call_id") else {
            return (400, json!({ "error": "call_id is required" }));
        };
        match self.control.ask(|reply| WebQuery::Parties {
            call_id: call_id.clone(),
            reply,
        }) {
            Ok(Value::Null) => (404, json!({ "error": "no such call" })),
            Ok(v) => (200, v),
            Err(e) => unanswered(e),
        }
    }
}

/// `logs?after=<seq>`: the lines after it and the newest sequence number.
fn logs_tail(q: &Query) -> Answer {
    let after = q.get("after").and_then(|s| s.parse().ok()).unwrap_or(0);
    let Some((lines, newest)) = logs::tail(after, 1000) else {
        return (
            404,
            json!({ "error": "the log ring is off ([webui] log_buffer = 0)" }),
        );
    };
    let lines: Vec<Value> = lines
        .into_iter()
        .map(|l| json!({ "seq": l.seq, "ts_ms": l.ts_ms, "level": l.level, "text": l.text }))
        .collect();
    (200, json!({ "newest": newest, "lines": lines }))
}

/// Filter, sort and page an array; anything else passes through.
#[must_use]
pub fn page(v: Value, q: &Query) -> Value {
    let Value::Array(mut rows) = v else {
        return v;
    };
    if let Some(needle) = q
        .get("q")
        .map(|s| s.to_lowercase())
        .filter(|s| !s.is_empty())
    {
        rows.retain(|r| r.to_string().to_lowercase().contains(&needle));
    }
    if let Some(field) = q.get("sort").filter(|s| !s.is_empty()) {
        let (desc, field) = match field.strip_prefix('-') {
            Some(f) => (true, f),
            None => (false, field.as_str()),
        };
        // Rows without the field stay last in both directions.
        rows.sort_by(|a, b| match (a[field].is_null(), b[field].is_null()) {
            (false, false) => {
                let o = cmp_json(&a[field], &b[field]);
                if desc { o.reverse() } else { o }
            }
            (x, y) => x.cmp(&y),
        });
    }
    let total = rows.len();
    let offset = q
        .get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0usize)
        .min(total);
    let limit = q
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100usize)
        .clamp(1, MAX_LIMIT);
    let rows: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
    json!({ "total": total, "offset": offset, "limit": limit, "rows": rows })
}

/// Numbers by value, everything else by its text.
fn cmp_json(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering::Equal;
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            x.as_f64().partial_cmp(&y.as_f64()).unwrap_or(Equal)
        }
        (Value::String(x), Value::String(y)) => x.to_lowercase().cmp(&y.to_lowercase()),
        _ => a.to_string().cmp(&b.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(s: &str) -> Query {
        s.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap();
                (k.to_owned(), v.to_owned())
            })
            .collect()
    }

    #[test]
    fn paging() {
        let rows = json!([{"n": 3, "s": "c"}, {"n": 1, "s": "a"}, {"n": 2, "s": "b"}, {"s": "z"}]);
        let names = |p: &Value| -> String {
            p["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["s"].as_str().unwrap())
                .collect()
        };
        assert_eq!(names(&page(rows.clone(), &q("sort=n"))), "abcz");
        let p = page(rows.clone(), &q("sort=-n&limit=2"));
        assert_eq!((p["total"].as_u64(), names(&p)), (Some(4), "cb".to_owned()));
        assert_eq!(page(rows.clone(), &q("q=B"))["total"], 1);
        let p = page(rows, &q("offset=3&limit=100000"));
        assert_eq!(
            (p["rows"].as_array().unwrap().len(), p["limit"].as_u64()),
            (1, Some(MAX_LIMIT as u64))
        );
        assert_eq!(
            page(json!({"a": 1}), &Query::new()),
            json!({"a": 1}),
            "objects pass through"
        );
    }

    /// With S3 storage the uploads and webhook deliveries are listed (newest
    /// first, paged); without it the paths do not exist.
    #[test]
    fn uploads_and_webhook_deliveries() {
        use crate::recording::activity::{Activity, UploadedFile};
        use std::sync::Arc;
        let activity = Arc::new(Activity::default());
        let file = |name: &str, ok: bool| UploadedFile {
            name: name.to_owned(),
            key: ok.then(|| format!("calls/{name}")),
            size: 10,
            error: (!ok).then(|| "refused".to_owned()),
        };
        activity.upload("c1", "a", "rec", &[file("c1.wav", true)]);
        activity.upload(
            "c2",
            "a",
            "rec",
            &[file("c2.wav", true), file("c2.json", false)],
        );
        activity.delivery("d1", "c1", "delivered", Some(204), 1, None);
        activity.delivery("d2", "c2", "failed", None, 5, Some("timeout"));
        let api = |storage: &str| {
            Api::new(
                Sources {
                    workers: Vec::new(),
                    control: Arc::default(),
                    recording: Arc::clone(&activity),
                    srflx: crate::srflx::Shared::default(),
                    xdp_flows: crate::relay::XdpFlows::default(),
                },
                WebLink::unanswered(),
                json!({ "recording": { "storage": storage } }),
                1000,
                crate::webui::recordings::Recordings::new(None),
            )
        };
        let s3 = api("s3");
        assert!(s3.meta()["sections"]["uploads"].is_array());
        let (code, up) = s3.handle("uploads", &Query::new());
        assert_eq!((code, up["total"].as_u64()), (200, Some(2)));
        assert_eq!(up["rows"][0]["call_id"], "c2", "newest first");
        assert_eq!(up["rows"][0]["complete"], false);
        let (_, hooks) = s3.handle("uploads/webhooks", &q("q=failed"));
        assert_eq!(hooks["total"], 1);
        assert_eq!(hooks["rows"][0]["error"], "timeout");
        // The counters are in the statistics.
        let stats = s3.stats();
        let value = |name: &str| {
            stats["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["group"] == "recording" && r["name"] == name)
                .map(|r| r["value"].as_u64().unwrap())
        };
        assert_eq!(value("recording_uploads"), Some(2));
        assert_eq!(value("recording_upload_failures"), Some(1));
        assert_eq!(value("recording_webhooks_failed"), Some(1));
        // Local storage: no such paths.
        let local = api("local");
        assert!(local.meta()["sections"]["uploads"].is_null());
        assert_eq!(local.handle("uploads", &Query::new()).0, 404);
    }

    /// With XDP on, the offloaded calls are listed with both directions'
    /// counters (names come from the control thread; none answers here).
    #[test]
    fn xdp_calls_are_listed() {
        use crate::relay::{XdpDir, XdpFlow, XdpFlows};
        use std::sync::Arc;
        let flows = XdpFlows::default();
        let dir = |from: &str, to: &str, packets| XdpDir {
            from: from.parse().unwrap(),
            to: to.parse().unwrap(),
            device: "eth0".to_owned(),
            drops: false,
            events_up: true,
            records: false,
            packets,
            octets: packets * 160,
        };
        flows.lock().unwrap().push(XdpFlow {
            call: crate::relay::CallId::of(7),
            worker: 1,
            dirs: [
                dir("192.0.2.1:4000", "192.0.2.2:5000", 10),
                dir("192.0.2.2:5000", "192.0.2.1:4000", 12),
            ],
        });
        let api = |xdp: Value| {
            Api::new(
                Sources {
                    workers: Vec::new(),
                    control: Arc::default(),
                    recording: Arc::default(),
                    srflx: crate::srflx::Shared::default(),
                    xdp_flows: Arc::clone(&flows),
                },
                WebLink::unanswered(),
                json!({ "xdp": xdp }),
                1000,
                crate::webui::recordings::Recordings::new(None),
            )
        };
        let on = api(json!({ "devices": ["eth0"] }));
        assert!(on.meta()["sections"]["xdp"].is_array());
        let (code, v) = on.handle("xdp", &Query::new());
        assert_eq!(code, 200);
        let row = &v["rows"][0];
        assert_eq!(
            (&row["relay_call"], &row["worker"], &row["packets"]),
            (&json!(7), &json!(2), &json!(22))
        );
        assert_eq!(row["a"]["events_up"], true);
        assert!(row["call_id"].is_null(), "no control thread: no name");
        let off = api(Value::Null);
        assert!(off.meta()["sections"]["xdp"].is_null());
        assert_eq!(off.handle("xdp", &Query::new()).0, 404);
    }

    #[test]
    fn process_facts_are_read() {
        let (rss, threads) = process_status();
        assert!(rss.is_some_and(|k| k > 0) && threads.is_some_and(|t| t >= 1));
    }
}
