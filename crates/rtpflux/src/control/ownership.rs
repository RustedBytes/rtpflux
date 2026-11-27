//! Exclusive controller ownership (`[ha]`): fencing epochs issued by an
//! ownership authority.
//!
//! The authority (the controller cluster's, never a controller) grants an
//! **ownership group** (a call, say) to one controller at a time, each
//! grant with a higher **epoch**, and signs it:
//!
//! ```text
//! HMAC-SHA256(key, "rtpflux-ownership-v1\n<tenant>\n<group>\n<epoch>\n<owner>\n<lease_expires_unix_ms>")
//! ```
//!
//! The controller presents it (`ownership.claim`). The relay checks the
//! signature, refuses an epoch lower than the highest it accepted for the
//! group (an old controller cannot promote itself, nor replay an old
//! grant: its lease has expired), and keeps the claim on disk, synced,
//! before acknowledging it.
//!
//! Every mutation then proves the group, epoch and **owner token** it acts
//! under. The token is issued by the authority to the owner alone, and
//! does not change when the lease is renewed:
//!
//! ```text
//! HMAC-SHA256(key, "rtpflux-ownership-token-v1\n<tenant>\n<group>\n<epoch>\n<owner>")
//! ```
//!
//! A mutation is refused unless:
//! - its epoch is the group's current one;
//! - the group's lease is running;
//! - its token is the current owner's;
//! - every resource it touches belongs to a group it proves.
//!
//! Knowing (or guessing) an epoch is not enough.
//!
//! Signing lives with the authority; this module only verifies, keeps the
//! highest epoch per group, and records which group owns which resource.
//!
//! The authority issues epochs from one rising sequence per tenant (a
//! database sequence, say), whatever the group. That lets the relay forget
//! a group whose lease is over and that owns nothing: it keeps the
//! tenant's **floor** (the highest epoch it forgot) and refuses any grant
//! at or below it for a group it does not know. An old grant replayed
//! later is refused whatever its lease says.

use super::native::{Code, NativeError};
use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// What the authority signs.
#[must_use]
pub fn signed_text(tenant: &str, group: &str, epoch: u64, owner: &str, lease_ms: u64) -> String {
    format!("rtpflux-ownership-v1\n{tenant}\n{group}\n{epoch}\n{owner}\n{lease_ms}")
}

/// What the owner's token signs: the right to act on `group` at `epoch`.
#[must_use]
pub fn token_text(tenant: &str, group: &str, epoch: u64, owner: &str) -> String {
    format!("rtpflux-ownership-token-v1\n{tenant}\n{group}\n{epoch}\n{owner}")
}

/// The signature of `text` with `key`, in lower-case hex (what the
/// authority sends; the relay only verifies).
#[must_use]
pub fn sign(key: &[u8], text: &str) -> String {
    let Ok(mut mac) = <HmacSha256 as KeyInit>::new_from_slice(key) else {
        return String::new();
    };
    mac.update(text.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A group's current grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub epoch: u64,
    pub owner: String,
    pub lease_expires_unix_ms: u64,
    /// The authority key it was signed with (owner tokens are checked
    /// with it too).
    #[serde(default)]
    pub key_id: String,
}

/// What is kept on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    /// `<tenant>/<group>` → its grant.
    claims: BTreeMap<String, Claim>,
    /// Tenant → the highest epoch of a group forgotten.
    #[serde(default)]
    floors: BTreeMap<String, u64>,
}

/// A mutation's proof: the group and epoch it acts under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub group: String,
    pub epoch: u64,
    /// The owner token, hex.
    pub token: String,
}

/// The claims accepted, and the authority's keys.
pub struct Ownership {
    keys: BTreeMap<String, Vec<u8>>,
    path: PathBuf,
    claims: HashMap<(String, String), Claim>,
    floors: BTreeMap<String, u64>,
    /// When it last forgot grants.
    last_prune_ms: u64,
}

impl std::fmt::Debug for Ownership {
    // Never the keys.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ownership")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .field("path", &self.path)
            .field("claims", &self.claims.len())
            .finish_non_exhaustive()
    }
}

fn group_key(tenant: &str, group: &str) -> String {
    format!("{tenant}/{group}")
}

impl Ownership {
    /// The claims kept in `path` (none if it does not exist yet).
    ///
    /// # Errors
    ///
    /// A file that cannot be read or parsed: the relay must not start
    /// without knowing the epochs it accepted (that would let an old
    /// controller back in).
    pub fn open(path: &Path, keys: &BTreeMap<String, String>) -> std::io::Result<Self> {
        let saved: Saved = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved::default(),
            Err(e) => return Err(e),
        };
        let mut claims = HashMap::new();
        for (k, c) in saved.claims {
            let Some((t, g)) = k.split_once('/') else {
                continue;
            };
            claims.insert((t.to_owned(), g.to_owned()), c);
        }
        Ok(Ownership {
            keys: keys
                .iter()
                .map(|(id, k)| (id.clone(), k.as_bytes().to_vec()))
                .collect(),
            path: path.to_owned(),
            claims,
            floors: saved.floors,
            last_prune_ms: 0,
        })
    }

    /// Write `claims` and `floors` (in place of the current ones) and sync
    /// them.
    fn save(
        &self,
        claims: &HashMap<(String, String), Claim>,
        floors: &BTreeMap<String, u64>,
    ) -> std::io::Result<()> {
        let saved = Saved {
            claims: claims
                .iter()
                .map(|((t, g), c)| (group_key(t, g), c.clone()))
                .collect(),
            floors: floors.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&saved).map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    /// Whether `signature` (hex) is `text`'s with key `key_id`, compared
    /// in constant time.
    fn verify(&self, key_id: &str, text: &str, signature: &str) -> bool {
        let (Some(key), Some(sig)) = (self.keys.get(key_id), unhex(signature)) else {
            return false;
        };
        let Ok(mut mac) = <HmacSha256 as KeyInit>::new_from_slice(key) else {
            return false;
        };
        mac.update(text.as_bytes());
        mac.verify_slice(&sig).is_ok()
    }

    /// The group's current grant.
    #[must_use]
    pub fn claim(&self, tenant: &str, group: &str) -> Option<&Claim> {
        self.claims.get(&(tenant.to_owned(), group.to_owned()))
    }

    /// Accept the authority's grant (`ownership.claim`): its signature,
    /// a lease still running, and an epoch not below the group's. Kept on
    /// disk before it counts. Returns the epoch it replaces.
    ///
    /// # Errors
    ///
    /// `unauthorized` (an unknown key or a wrong signature), `fenced` (a
    /// lower epoch, or a lease already over), `conflict` (the same epoch
    /// for another owner), `unavailable` (not kept on disk: nothing
    /// changed).
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        tenant: &str,
        group: &str,
        claim: Claim,
        key_id: &str,
        signature: &str,
        now_ms: u64,
    ) -> Result<Option<u64>, NativeError> {
        let text = signed_text(
            tenant,
            group,
            claim.epoch,
            &claim.owner,
            claim.lease_expires_unix_ms,
        );
        if !self.verify(key_id, &text, signature) {
            return Err(NativeError::new(
                Code::Unauthorized,
                "ownership: bad signature",
            ));
        }
        let claim = Claim {
            key_id: key_id.to_owned(),
            ..claim
        };
        if claim.lease_expires_unix_ms <= now_ms {
            return Err(NativeError::new(
                Code::Fenced,
                "ownership: the lease is over",
            ));
        }
        let k = (tenant.to_owned(), group.to_owned());
        let previous = self.claims.get(&k).cloned();
        let next = match &previous {
            Some(c) if claim.epoch < c.epoch => {
                return Err(NativeError::new(
                    Code::Fenced,
                    format!(
                        "ownership: epoch {} is below the group's {}",
                        claim.epoch, c.epoch
                    ),
                ));
            }
            Some(c) if claim.epoch == c.epoch && claim.owner != c.owner => {
                return Err(NativeError::new(
                    Code::Conflict,
                    format!("ownership: epoch {} belongs to another owner", c.epoch),
                ));
            }
            // A renewal: the lease never shortens.
            Some(c) if claim.epoch == c.epoch => Claim {
                lease_expires_unix_ms: c.lease_expires_unix_ms.max(claim.lease_expires_unix_ms),
                ..claim
            },
            Some(_) => claim,
            None => {
                let floor = self.floors.get(tenant).copied().unwrap_or(0);
                if claim.epoch <= floor {
                    return Err(NativeError::new(
                        Code::Fenced,
                        format!(
                            "ownership: epoch {} is not above the tenant's {floor}",
                            claim.epoch
                        ),
                    ));
                }
                claim
            }
        };
        let mut all = self.claims.clone();
        all.insert(k.clone(), next.clone());
        self.save(&all, &self.floors).map_err(|e| {
            NativeError::new(
                Code::Unavailable,
                format!("ownership: not kept on disk: {e}"),
            )
        })?;
        self.claims.insert(k, next);
        Ok(previous.map(|c| c.epoch))
    }

    /// Whether `proof` is the group's current epoch, its lease running.
    ///
    /// # Errors
    ///
    /// `fenced`, saying why.
    pub fn check(&self, tenant: &str, proof: &Proof, now_ms: u64) -> Result<(), NativeError> {
        let Some(c) = self.claim(tenant, &proof.group) else {
            return Err(NativeError::new(
                Code::Fenced,
                format!("ownership: group {} is not claimed", proof.group),
            ));
        };
        if proof.epoch != c.epoch {
            return Err(NativeError::new(
                Code::Fenced,
                format!(
                    "ownership: group {}: epoch {} is not the current {}",
                    proof.group, proof.epoch, c.epoch
                ),
            ));
        }
        if c.lease_expires_unix_ms <= now_ms {
            return Err(NativeError::new(
                Code::Fenced,
                format!("ownership: group {}: the lease is over", proof.group),
            ));
        }
        let text = token_text(tenant, &proof.group, c.epoch, &c.owner);
        if !self.verify(&c.key_id, &text, &proof.token) {
            return Err(NativeError::new(
                Code::Fenced,
                format!("ownership: group {}: not the owner's token", proof.group),
            ));
        }
        Ok(())
    }

    /// Forget grants whose lease ended and whose group owns nothing
    /// (`owning`: the groups that do), raising the tenant's floor; at most
    /// every 10 s.
    pub fn prune(&mut self, now_ms: u64, owning: &std::collections::HashSet<&(String, String)>) {
        if now_ms.saturating_sub(self.last_prune_ms) < 10_000 {
            return;
        }
        self.last_prune_ms = now_ms;
        let owned = owning;
        let (keep, gone): (HashMap<_, _>, HashMap<_, _>) = self
            .claims
            .iter()
            .map(|(k, c)| (k.clone(), c.clone()))
            .partition(|(k, c)| c.lease_expires_unix_ms > now_ms || owned.contains(k));
        if gone.is_empty() {
            return;
        }
        let mut floors = self.floors.clone();
        for ((t, _), c) in &gone {
            let f = floors.entry(t.clone()).or_insert(0);
            *f = (*f).max(c.epoch);
        }
        if self.save(&keep, &floors).is_ok() {
            self.claims = keep;
            self.floors = floors;
        }
    }
}

/// The operations that make a resource the request's group then owns.
const OWNING: [&str; 3] = ["endpoint.create", "mixer.create", "stream.start"];

/// A group name: printable, no `/` (it separates tenant and group on disk).
fn valid_group(g: &str) -> bool {
    !g.is_empty() && g.len() <= 128 && g.bytes().all(|c| c.is_ascii_graphic() && c != b'/')
}

impl super::Control {
    /// Fence native mutations with the claims kept in `path`, signed with
    /// `keys` (`[ha]`).
    ///
    /// # Errors
    ///
    /// The claims file cannot be read or parsed.
    pub fn open_ownership(
        &mut self,
        path: &Path,
        keys: &BTreeMap<String, String>,
    ) -> std::io::Result<()> {
        self.native.ha = Some(Ownership::open(path, keys)?);
        Ok(())
    }

    /// The proofs a request carries: `ownership` and, for a resource of
    /// another group (a bridge across calls), `peer_ownership`.
    fn proofs(req: &super::native::Request<'_>) -> Result<Vec<Proof>, NativeError> {
        let mut out = Vec::new();
        for key in ["ownership", "peer_ownership"] {
            let Some(v) = req.body.get(key) else {
                continue;
            };
            let group = v.get("group").and_then(serde_json::Value::as_str);
            let epoch = v.get("epoch").and_then(serde_json::Value::as_u64);
            let token = v.get("token").and_then(serde_json::Value::as_str);
            let (Some(group), Some(epoch), Some(token)) = (group, epoch, token) else {
                return Err(NativeError::invalid(format!(
                    "{key}: {{group, epoch, token}}"
                )));
            };
            out.push(Proof {
                group: group.to_owned(),
                epoch,
                token: token.to_owned(),
            });
        }
        Ok(out)
    }

    /// The resources a request names.
    fn touched(req: &super::native::Request<'_>) -> Vec<String> {
        let mut ids: Vec<String> = ["endpoint_id", "peer_endpoint_id"]
            .iter()
            .filter_map(|k| req.str(k).map(str::to_owned))
            .collect();
        for k in ["mixer_id", "stream_id"] {
            if let Some(n) = req.body.get(k).and_then(serde_json::Value::as_u64) {
                ids.push(format!("{k}:{n}"));
            }
        }
        ids
    }

    fn resource_exists(&self, id: &str) -> bool {
        let num = |p: &str| id.strip_prefix(p).and_then(|n| n.parse::<u32>().ok());
        if let Some(n) = num("mixer_id:") {
            self.native.mixers.contains_key(&n)
        } else if let Some(n) = num("stream_id:") {
            self.native.streams.contains_key(&n)
        } else {
            self.native.endpoints.contains_key(id)
        }
    }

    /// Under `[ha]`: a mutation must prove the current epoch (lease
    /// running) of the group of every resource it touches. Checked on the
    /// control thread before anything runs, so it is atomic with the
    /// mutation.
    pub(super) fn fence(&self, req: &super::native::Request<'_>) -> Result<(), NativeError> {
        let Some(ha) = &self.native.ha else {
            return Ok(());
        };
        if !super::native::mutates(req.op) || req.op == "ownership.claim" {
            return Ok(());
        }
        let proofs = Self::proofs(req)?;
        if proofs.is_empty() {
            return Err(NativeError::new(
                Code::Fenced,
                "ownership: under [ha] a change needs `ownership`: {group, epoch, token}",
            ));
        }
        let now = crate::relay::media_events::unix_ms();
        for p in &proofs {
            ha.check(req.tenant, p, now)?;
        }
        for id in Self::touched(req) {
            match self.native.owned.get(&id) {
                Some((t, g)) if t == req.tenant && proofs.iter().any(|p| &p.group == g) => {}
                Some(_) => {
                    return Err(NativeError::new(
                        Code::Fenced,
                        format!("ownership: {id} belongs to a group this request does not prove"),
                    ));
                }
                // Made before [ha]: nobody may change it until it ends.
                None if self.resource_exists(&id) => {
                    return Err(NativeError::new(
                        Code::Fenced,
                        format!("ownership: {id} belongs to no group"),
                    ));
                }
                // Gone: the operation says so.
                None => {}
            }
        }
        Ok(())
    }

    /// After a successful creation under `[ha]`: what it made belongs to
    /// the request's group.
    pub(super) fn record_owned(
        &mut self,
        req: &super::native::Request<'_>,
        reply: &serde_json::Value,
    ) {
        if self.native.ha.is_none()
            || !OWNING.contains(&req.op)
            || reply.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
        {
            return;
        }
        let Some(group) = req
            .body
            .get("ownership")
            .and_then(|o| o.get("group"))
            .and_then(serde_json::Value::as_str)
        else {
            return;
        };
        let Some(result) = reply.get("result") else {
            return;
        };
        let made = match req.op {
            "endpoint.create" => result
                .get("endpoint_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            _ => super::native::resource_refs(result)
                .into_iter()
                .find(|r| r.contains(':')),
        };
        if let Some(id) = made {
            self.native
                .owned
                .entry(id)
                .or_insert_with(|| (req.tenant.to_owned(), group.to_owned()));
        }
    }

    /// `ownership.claim`: the authority's grant of a group, kept on disk
    /// before it counts. Every later mutation of the group's resources
    /// must name this epoch; the previous owner's are refused.
    ///
    /// Nothing the previous owner did can land after it: mutations are
    /// checked and sent to the media workers on this one thread, and each
    /// worker applies its commands in order, so whatever the new owner
    /// sends comes after. The reply says whether the workers confirmed
    /// the previous commands applied (`drained`).
    pub(super) fn native_claim(
        &mut self,
        req: &super::native::Request<'_>,
    ) -> Result<serde_json::Value, NativeError> {
        let group = req.need("group")?;
        if !valid_group(group) {
            return Err(NativeError::invalid(
                "group: printable, no '/', at most 128",
            ));
        }
        let epoch = req
            .u64("epoch")?
            .ok_or_else(|| NativeError::invalid("missing epoch"))?;
        let owner = req.need("owner")?;
        let lease = req
            .u64("lease_expires_unix_ms")?
            .ok_or_else(|| NativeError::invalid("missing lease_expires_unix_ms"))?;
        let key_id = req.need("key_id")?;
        let signature = req.need("signature")?;
        let now = crate::relay::media_events::unix_ms();
        let Some(ha) = self.native.ha.as_mut() else {
            return Err(NativeError::new(
                Code::Unsupported,
                "ownership: [ha] is not enabled",
            ));
        };
        let claim = Claim {
            epoch,
            owner: owner.to_owned(),
            lease_expires_unix_ms: lease,
            key_id: String::new(),
        };
        let previous = ha.accept(req.tenant, group, claim, key_id, signature, now)?;
        let drained = if previous.is_some_and(|p| p < epoch) {
            let calls: Vec<crate::relay::CallId> = self
                .native
                .owned
                .iter()
                .filter(|(_, (t, g))| t == req.tenant && g == group)
                .filter_map(|(id, _)| self.native.endpoints.get(id))
                .filter_map(|e| self.party_legs(e.session.as_bytes(), e.id.as_bytes()))
                .flatten()
                .flatten()
                .map(|((id, _), _)| id)
                .collect();
            self.relay
                .applied(&calls, std::time::Duration::from_secs(1))
        } else {
            true
        };
        log::info!(
            "native: ownership of {}/{group}: epoch {epoch}, owner {owner}",
            req.tenant
        );
        Ok(serde_json::json!({
            "group": group,
            "epoch": epoch,
            "owner": owner,
            "lease_expires_unix_ms": self.native.ha.as_ref().and_then(|h| h.claim(req.tenant, group)).map(|c| c.lease_expires_unix_ms),
            "previous_epoch": previous,
            "drained": drained,
        }))
    }

    /// Under `[ha]`: whether an `ng` command would change a call holding
    /// native endpoints (only their owner may, through the native API).
    pub(super) fn ng_protected(
        &self,
        command: &[u8],
        body: &rtpflux_ng::bencode::Dict<'_>,
    ) -> bool {
        if self.native.ha.is_none()
            || matches!(command, b"ping" | b"list" | b"query" | b"statistics")
        {
            return false;
        }
        [b"call-id".as_slice(), b"to-call-id"].iter().any(|k| {
            body.get_bytes(k).is_some_and(|call| {
                self.native
                    .endpoints
                    .values()
                    .any(|e| e.session.as_bytes() == call)
            })
        })
    }

    /// Forget what no longer exists, and grants that ended.
    pub(super) fn ownership_prune(&mut self) {
        if self.native.ha.is_none() {
            return;
        }
        let n = &mut self.native;
        let (endpoints, mixers, streams) = (&n.endpoints, &n.mixers, &n.streams);
        n.owned.retain(|id, _| {
            let num = |p: &str| id.strip_prefix(p).and_then(|x| x.parse::<u32>().ok());
            num("mixer_id:").map_or_else(
                || {
                    num("stream_id:")
                        .map_or_else(|| endpoints.contains_key(id), |s| streams.contains_key(&s))
                },
                |m| mixers.contains_key(&m),
            )
        });
        let owning: std::collections::HashSet<&(String, String)> = n.owned.values().collect();
        if let Some(ha) = n.ha.as_mut() {
            ha.prune(crate::relay::media_events::unix_ms(), &owning);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn own(dir: &Path) -> Ownership {
        let keys = BTreeMap::from([("k1".to_owned(), KEY.to_owned())]);
        Ownership::open(&dir.join("ha.json"), &keys).unwrap()
    }

    fn claim(epoch: u64, owner: &str, lease: u64) -> Claim {
        Claim {
            epoch,
            owner: owner.into(),
            lease_expires_unix_ms: lease,
            key_id: String::new(),
        }
    }

    fn grant(
        o: &mut Ownership,
        epoch: u64,
        owner: &str,
        lease: u64,
        now: u64,
    ) -> Result<Option<u64>, NativeError> {
        let sig = sign(KEY.as_bytes(), &signed_text("t", "g", epoch, owner, lease));
        o.accept("t", "g", claim(epoch, owner, lease), "k1", &sig, now)
    }

    #[test]
    fn epochs_only_rise_and_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("rtpflux-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut o = own(&dir);
        assert_eq!(grant(&mut o, 1, "a", 10_000, 0).unwrap(), None);
        assert_eq!(grant(&mut o, 2, "b", 10_000, 0).unwrap(), Some(1));
        // An old controller's grant again: refused.
        assert_eq!(
            grant(&mut o, 1, "a", 10_000, 0).unwrap_err().code,
            Code::Fenced
        );
        // The same epoch for another owner: the authority's mistake.
        assert_eq!(
            grant(&mut o, 2, "a", 10_000, 0).unwrap_err().code,
            Code::Conflict
        );
        // A renewal never shortens the lease.
        grant(&mut o, 2, "b", 5_000, 0).unwrap();
        assert_eq!(o.claim("t", "g").unwrap().lease_expires_unix_ms, 10_000);
        // A forged signature, an unknown key, a lease already over.
        let c = claim(3, "a", 10_000);
        assert_eq!(
            o.accept("t", "g", c.clone(), "k1", &"00".repeat(32), 0)
                .unwrap_err()
                .code,
            Code::Unauthorized
        );
        assert_eq!(
            o.accept("t", "g", c.clone(), "k9", "", 0).unwrap_err().code,
            Code::Unauthorized
        );
        assert_eq!(
            grant(&mut o, 3, "a", 10, 10).unwrap_err().code,
            Code::Fenced
        );
        // Signed for another tenant: refused here.
        let sig = sign(KEY.as_bytes(), &signed_text("other", "g", 3, "a", 10_000));
        assert_eq!(
            o.accept("t", "g", c, "k1", &sig, 0).unwrap_err().code,
            Code::Unauthorized
        );

        let token = |epoch, owner: &str| sign(KEY.as_bytes(), &token_text("t", "g", epoch, owner));
        let p = |epoch| Proof {
            group: "g".into(),
            epoch,
            token: token(epoch, "b"),
        };
        assert!(o.check("t", &p(2), 0).is_ok());
        assert_eq!(o.check("t", &p(1), 0).unwrap_err().code, Code::Fenced);
        // The epoch without the owner's token: refused.
        let guessed = Proof {
            group: "g".into(),
            epoch: 2,
            token: token(2, "a"),
        };
        assert_eq!(o.check("t", &guessed, 0).unwrap_err().code, Code::Fenced);
        assert_eq!(
            o.check("t", &p(2), 10_000).unwrap_err().code,
            Code::Fenced,
            "lease over"
        );
        assert_eq!(
            o.check("u", &p(2), 0).unwrap_err().code,
            Code::Fenced,
            "another tenant's"
        );

        // Restarted: the epoch is still 2.
        let mut o = own(&dir);
        assert_eq!(o.claim("t", "g").unwrap().epoch, 2);
        assert_eq!(
            grant(&mut o, 1, "a", 20_000, 0).unwrap_err().code,
            Code::Fenced
        );
        // Pruned once its lease is over and it owns nothing; an old grant
        // (with a lease still running) cannot bring it back.
        o.prune(20_000, &std::collections::HashSet::new());
        let mut o = own(&dir);
        assert!(o.claim("t", "g").is_none());
        assert_eq!(
            grant(&mut o, 2, "b", 90_000, 20_000).unwrap_err().code,
            Code::Fenced
        );
        assert_eq!(grant(&mut o, 3, "c", 90_000, 20_000).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("rtpflux-own-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ha.json"), "{").unwrap();
        let keys = BTreeMap::new();
        assert!(Ownership::open(&dir.join("ha.json"), &keys).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
