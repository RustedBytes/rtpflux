//! The single-page app, embedded at build time from `webui/assets/` (built
//! by `npm run build` in `webui/ui/` and committed, so `cargo build` needs
//! no Node). JavaScript and CSS are embedded plain and gzip-compressed.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::OnceLock;

/// One file of the app.
#[derive(Debug)]
pub struct Asset {
    pub path: &'static str,
    pub ctype: &'static str,
    pub bytes: &'static [u8],
    /// The same, gzip-compressed (served when the client accepts it).
    pub gzipped: Option<&'static [u8]>,
    pub etag: String,
}

fn all() -> &'static [Asset] {
    static ALL: OnceLock<Vec<Asset>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mk = |path, ctype, bytes: &'static [u8], gzipped| {
            let d = Sha256::digest(bytes);
            let mut etag = String::from("\"");
            for b in &d[..12] {
                let _ = write!(etag, "{b:02x}");
            }
            etag.push('"');
            Asset {
                path,
                ctype,
                bytes,
                gzipped,
                etag,
            }
        };
        vec![
            mk(
                "/",
                "text/html; charset=utf-8",
                include_bytes!("../../webui/assets/index.html"),
                None,
            ),
            mk(
                "/app.js",
                "text/javascript; charset=utf-8",
                include_bytes!("../../webui/assets/app.js"),
                Some(include_bytes!("../../webui/assets/app.js.gz")),
            ),
            mk(
                "/app.css",
                "text/css; charset=utf-8",
                include_bytes!("../../webui/assets/app.css"),
                Some(include_bytes!("../../webui/assets/app.css.gz")),
            ),
            mk(
                "/favicon.svg",
                "image/svg+xml",
                include_bytes!("../../webui/assets/favicon.svg"),
                None,
            ),
        ]
    })
}

/// The asset served at `path`.
#[must_use]
pub fn find(path: &str) -> Option<&'static Asset> {
    let path = if path == "/index.html" { "/" } else { path };
    all().iter().find(|a| a.path == path)
}
