//! What a recording is called and what it carries: the file-name template
//! (`[recording] file_name`) and the user's metadata (`[recording.metadata]`
//! and `start recording`'s `metadata`), embedded in the audio file's tags
//! and its JSON.

use std::collections::BTreeMap;

/// The default file name: what rtpflux always called recordings.
pub const DEFAULT_FILE_NAME: &str = "{call_id}-{from_tag}-{section}";

/// The default file name of a conference mixer's recording.
pub const DEFAULT_MIXER_FILE_NAME: &str = "mixer-{mixer_id}-{recording_id}-{section}{track}";

/// The placeholders a file name may hold.
pub const PLACEHOLDERS: [&str; 10] = [
    "call_id",
    "from_tag",
    "to_tag",
    "section",
    "date",
    "time",
    "timestamp",
    "mixer_id",
    "recording_id",
    "track",
];

/// The most metadata entries a recording carries, and their sizes.
pub const MAX_ENTRIES: usize = 32;
pub const MAX_KEY: usize = 64;
pub const MAX_VALUE: usize = 1024;

/// What fills a file-name template.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'a> {
    pub call_id: &'a [u8],
    pub from_tag: &'a [u8],
    pub to_tag: Option<&'a [u8]>,
    /// From 1.
    pub section: usize,
    /// When the recording starts, seconds since the Unix epoch (UTC).
    pub unix_s: u64,
    /// A mixer recording's mixer (`-` otherwise).
    pub mixer_id: Option<u32>,
    /// The native API's recording id (`-` without one).
    pub recording_id: Option<&'a str>,
    /// A per-participant track's endpoint id (empty for the mix).
    pub track: &'a str,
}

/// Why a file-name template cannot be used.
#[must_use]
pub fn check_file_name(template: &str) -> Option<String> {
    if template.is_empty() || template.len() > 200 {
        return Some("must be 1 to 200 characters".to_owned());
    }
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let lit = &rest[..open];
        if let Some(c) = lit.chars().find(|&c| !literal_ok(c)) {
            return Some(format!(
                "'{c}' is not allowed (letters, digits, . - _ @ and placeholders)"
            ));
        }
        let Some(close) = rest[open..].find('}') else {
            return Some("a '{' without its '}'".to_owned());
        };
        let name = &rest[open + 1..open + close];
        if !PLACEHOLDERS.contains(&name) {
            return Some(format!(
                "unknown placeholder {{{name}}} (known: {})",
                PLACEHOLDERS.map(|p| format!("{{{p}}}")).join(", ")
            ));
        }
        rest = &rest[open + close + 1..];
    }
    if let Some(c) = rest.chars().find(|&c| !literal_ok(c)) {
        return Some(format!(
            "'{c}' is not allowed (letters, digits, . - _ @ and placeholders)"
        ));
    }
    if template.starts_with('.') {
        return Some("must not start with '.'".to_owned());
    }
    None
}

/// Text a template may hold besides placeholders: what [`super::name_part`]
/// keeps, so names stay plain file names (no paths).
fn literal_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || ".-_@".contains(c)
}

/// Subdirectories (`recording-path`) a recording can be in, at most.
pub const MAX_DEPTH: usize = 4;

/// Why a subdirectory of the recording directory (`recording-path`)
/// cannot be used: it must be relative, of at most [`MAX_DEPTH`]
/// `/`-separated names of letters, digits, `.`, `-`, `_` and `@`, none
/// starting with `.` (so never `..`).
#[must_use]
pub fn check_subdir(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    if path.is_empty() || parts.len() > MAX_DEPTH {
        return Some(format!("1 to {MAX_DEPTH} directory names"));
    }
    parts
        .iter()
        .find(|p| p.is_empty() || p.starts_with('.') || p.len() > 100 || !p.chars().all(literal_ok))
        .map(|p| format!("{p:?}: names of letters, digits, . - _ and @, not starting with '.'"))
}

/// Why a fixed file name (`recording-file`, `output-destination`) cannot
/// be used: as a template without placeholders. A known extension is
/// dropped first ([`strip_extension`]).
#[must_use]
pub fn check_fixed_name(name: &str) -> Option<String> {
    if name.contains(['{', '}']) {
        return Some("no placeholders in a fixed name".to_owned());
    }
    check_file_name(name)
}

/// `name` without a recording extension (`.pcap`, `.wav`, …), if it has
/// one.
#[must_use]
pub fn strip_extension(name: &str) -> &str {
    ["pcap", "wav", "flac", "opus", "ogg", "mp3", "json"]
        .iter()
        .find_map(|x| name.strip_suffix(x)?.strip_suffix('.'))
        .unwrap_or(name)
}

/// The regular files under `dir`, down to [`MAX_DEPTH`] subdirectories,
/// never through a symbolic link: their paths relative to `dir` (with
/// `/`), full paths and metadata.
#[must_use]
pub fn walk(dir: &std::path::Path) -> Vec<(String, std::path::PathBuf, std::fs::Metadata)> {
    let mut out = Vec::new();
    let mut todo = vec![(String::new(), dir.to_path_buf(), 0)];
    while let Some((rel, path, depth)) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for e in entries.flatten() {
            let (Ok(name), Ok(meta)) = (e.file_name().into_string(), e.path().symlink_metadata())
            else {
                continue;
            };
            let rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if meta.is_file() {
                out.push((rel, e.path(), meta));
            } else if meta.is_dir() && depth < MAX_DEPTH {
                todo.push((rel, e.path(), depth + 1));
            }
        }
    }
    out
}

/// The file name (without extension) `template` gives `f`; values are
/// made safe with [`super::name_part`]. The template was checked.
#[must_use]
pub fn render(template: &str, f: &Fields<'_>) -> String {
    let (date, time) = utc(f.unix_s);
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        let name = &rest[open + 1..open + close];
        match name {
            "call_id" => out.push_str(&super::name_part(f.call_id)),
            "from_tag" => out.push_str(&super::name_part(f.from_tag)),
            "to_tag" => out.push_str(&super::name_part(f.to_tag.unwrap_or(b"-"))),
            "section" => out.push_str(&f.section.to_string()),
            "date" => out.push_str(&date),
            "time" => out.push_str(&time),
            "timestamp" => out.push_str(&f.unix_s.to_string()),
            "mixer_id" => match f.mixer_id {
                Some(m) => out.push_str(&m.to_string()),
                None => out.push('-'),
            },
            "recording_id" => out.push_str(&super::name_part(
                f.recording_id.map_or(b"-".as_slice(), str::as_bytes),
            )),
            "track" => out.push_str(&super::name_part(f.track.as_bytes())),
            _ => {}
        }
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

/// `YYYY-MM-DD` and `HHMMSS` of a Unix time, in UTC (proleptic
/// Gregorian; days to civil date after Howard Hinnant's algorithm).
#[must_use]
pub fn utc(unix_s: u64) -> (String, String) {
    let days = i64::try_from(unix_s / 86_400).unwrap_or(0);
    let secs = unix_s % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        format!("{y:04}-{m:02}-{d:02}"),
        format!("{:02}{:02}{:02}", secs / 3600, secs / 60 % 60, secs % 60),
    )
}

/// Why a metadata entry cannot be used: keys of 1 to 64 letters, digits,
/// `_`, `-` or `.` (they become Vorbis comment and ID3 names), values of
/// at most 1024 octets without NUL.
#[must_use]
pub fn check_entry(key: &str, value: &str) -> Option<String> {
    if key.is_empty()
        || key.len() > MAX_KEY
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
    {
        return Some(format!(
            "key {key:?}: 1 to {MAX_KEY} letters, digits, '_', '-' or '.'"
        ));
    }
    if value.len() > MAX_VALUE || value.contains('\0') {
        return Some(format!(
            "{key}: a value of at most {MAX_VALUE} octets, without NUL"
        ));
    }
    None
}

/// Why a set of metadata cannot be used (too many, or an entry).
#[must_use]
pub fn check_metadata(m: &BTreeMap<String, String>) -> Option<String> {
    if m.len() > MAX_ENTRIES {
        return Some(format!("at most {MAX_ENTRIES} entries"));
    }
    m.iter().find_map(|(k, v)| check_entry(k, v))
}

/// The tags an audio file carries: who and what the recording is of, then
/// the user's metadata (which may override them by name).
#[must_use]
pub fn tags(meta: &super::Meta, started_ms: u64) -> Vec<(String, String)> {
    let (date, time) = utc(started_ms / 1000);
    let mut t: BTreeMap<String, String> = BTreeMap::new();
    t.insert(
        "TITLE".into(),
        match meta.mixer_id {
            Some(m) => format!("mixer {m} ({})", meta.section),
            None => format!("{} ({})", meta.call_id, meta.section),
        },
    );
    if let Some(m) = meta.mixer_id {
        t.insert("MIXER_ID".into(), m.to_string());
        t.insert("RECORDING_ID".into(), meta.from_tag.clone());
    }
    t.insert("CALL_ID".into(), meta.call_id.clone());
    t.insert("FROM_TAG".into(), meta.from_tag.clone());
    if let Some(to) = &meta.to_tag {
        t.insert("TO_TAG".into(), to.clone());
    }
    t.insert("SECTION".into(), meta.section.to_string());
    t.insert(
        "DATE".into(),
        format!("{date}T{}:{}:{}Z", &time[0..2], &time[2..4], &time[4..6]),
    );
    t.insert(
        "ENCODER".into(),
        concat!("rtpflux ", env!("CARGO_PKG_VERSION")).into(),
    );
    for (k, v) in &meta.metadata {
        t.insert(k.to_ascii_uppercase().replace(['-', '.'], "_"), v.clone());
    }
    t.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_are_checked_and_rendered() {
        assert_eq!(check_file_name(DEFAULT_FILE_NAME), None);
        assert_eq!(check_file_name("{date}_{time}-{call_id}-{section}"), None);
        for bad in [
            "",
            "{nope}",
            "a/b-{section}",
            "{call_id",
            "x y",
            "..{section}",
            ".hidden",
            "{call_id}\\x",
        ] {
            assert!(check_file_name(bad).is_some(), "{bad}");
        }
        let f = Fields {
            call_id: b"abc/../d@x",
            from_tag: b"f1",
            to_tag: None,
            section: 2,
            unix_s: 1_795_609_499, // 2026-11-25 12:24:59 UTC
            mixer_id: None,
            recording_id: None,
            track: "",
        };
        assert_eq!(render(DEFAULT_FILE_NAME, &f), "abc_.._d@x-f1-2");
        assert_eq!(
            render("{date}_{time}-{to_tag}-{section}", &f),
            "2026-11-25_122459---2"
        );
        assert_eq!(render("rec-{timestamp}", &f), "rec-1795609499");
        assert_eq!(render("{mixer_id}-{recording_id}{track}", &f), "---");
        let m = Fields {
            mixer_id: Some(7),
            recording_id: Some("rec-ab"),
            ..f
        };
        assert_eq!(render(DEFAULT_MIXER_FILE_NAME, &m), "mixer-7-rec-ab-2");
        assert_eq!(check_file_name(DEFAULT_MIXER_FILE_NAME), None);
    }

    #[test]
    fn subdirectories_and_fixed_names_are_checked() {
        for ok in ["agents", "2026/11/acme", "team-1/x_y@z", "a/"] {
            assert_eq!(check_subdir(ok), None, "{ok}");
        }
        for bad in [
            "",
            "/etc",
            "../x",
            "a/../b",
            "a/.b",
            "a//b",
            "a/b/c/d/e",
            "a b",
            "a\\b",
        ] {
            assert!(check_subdir(bad).is_some(), "{bad}");
        }
        assert_eq!(check_fixed_name("call-42"), None);
        assert!(check_fixed_name("call-{section}").is_some());
        assert!(check_fixed_name("a/b").is_some());
        assert_eq!(strip_extension("call.wav"), "call");
        assert_eq!(strip_extension("call.v2"), "call.v2");
        assert_eq!(strip_extension("x.pcap"), "x");
    }

    #[test]
    fn the_walk_stays_inside_and_skips_links() {
        let dir = std::env::temp_dir().join(format!("rtpflux-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b/c/d/e/f")).unwrap();
        for f in [
            "top.pcap",
            "a/one.pcap",
            "a/b/c/d/four.pcap",
            "a/b/c/d/e/five.pcap",
        ] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::os::unix::fs::symlink("/etc", dir.join("link")).unwrap();
        let mut got: Vec<String> = walk(&dir).into_iter().map(|(r, ..)| r).collect();
        got.sort();
        assert_eq!(got, ["a/b/c/d/four.pcap", "a/one.pcap", "top.pcap"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dates_are_civil() {
        for (t, d, h) in [
            (0, "1970-01-01", "000000"),
            (951_782_400, "2000-02-29", "000000"),
            (4_107_542_399, "2100-02-28", "235959"),
            (1_795_609_499, "2026-11-25", "122459"),
        ] {
            assert_eq!(utc(t), (d.to_owned(), h.to_owned()), "{t}");
        }
    }

    #[test]
    fn metadata_is_checked() {
        assert_eq!(check_entry("agent", "Alice Smith"), None);
        assert_eq!(check_entry("queue-id.2", ""), None);
        for (k, v) in [("", "x"), ("a b", "x"), ("k=v", "x"), ("k", "a\0b")] {
            assert!(check_entry(k, v).is_some(), "{k:?}");
        }
        assert!(check_entry(&"k".repeat(65), "x").is_some());
        assert!(check_entry("k", &"v".repeat(1025)).is_some());
        let many: BTreeMap<String, String> =
            (0..33).map(|i| (format!("k{i}"), String::new())).collect();
        assert!(check_metadata(&many).is_some());
    }
}
