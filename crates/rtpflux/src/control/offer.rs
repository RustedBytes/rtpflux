//! `offer`: a new dialog, or a re-offer of an existing one (from either
//! party), and the relay calls of its media sections.

use super::opts::CodecNames;
use super::sdp_edits::{SdpEdits, VersionMode, Versions};
#[allow(clippy::wildcard_imports)]
use super::*;
use crate::reoffer::Action;

impl Control {
    /// The relay-facing description of one media section's sender.
    pub(super) fn side(interface: InterfaceId, m: &Media, o: &Opts, srtp: Srtp) -> Side {
        let addr = if o.trust_address {
            m.address
        } else {
            o.received_from.or(m.address)
        }
        .filter(|a| !a.is_unspecified());
        let rtp = addr.map(|a| SocketAddr::new(a, m.port));
        let rtcp = if m.rtcp_mux {
            rtp
        } else {
            addr.map(|a| SocketAddr::new(a, m.rtcp_port))
        };
        Side {
            interface,
            rtp,
            rtcp,
            learning: o.learning,
            strict_source: o.strict_source,
            handover: o.media_handover,
            unidirectional: o.unidirectional,
            srtp,
            rtcp_mux: false,
            ice: None,
            dtls: None,
            dtmf: m.telephone_event,
            transcode: None,
            // T.38 (`udptl`) and other non-RTP sections: relayed as they
            // are.
            opaque: m.transport == Transport::Other,
            dtmf_xcode: None,
            repack: None,
        }
    }

    /// Refuse sections whose peer address (as [`Control::side`] picks
    /// it) is of another IP family than `interface`: its sockets could
    /// neither send to nor hear from that peer. ICE sections are let
    /// through: their media goes to checked candidates, not to `c=`.
    /// The interfaces of an offer's two sides: those `direction` names;
    /// otherwise the offerer's is the first interface of its address
    /// family (the first interface when it has none), and the answerer's
    /// the same one, or with `address-family` the first one of that family
    /// (IPv4 and IPv6 bridged).
    fn offer_directions(
        &self,
        d: &Dict<'_>,
        media: &[Media],
        o: &Opts,
    ) -> Result<[InterfaceId; 2], Error> {
        let named = self.named_directions(d)?;
        let first_of = |ipv6: bool| {
            self.interfaces
                .iter()
                .position(|i| i.address.is_ipv6() == ipv6)
                .map(InterfaceId::new)
        };
        let offerer_ipv6 = media
            .iter()
            .filter(|m| m.port != 0 && !m.ice)
            .find_map(|m| {
                if o.trust_address {
                    m.address
                } else {
                    o.received_from.or(m.address)
                }
                .filter(|a| !a.is_unspecified())
            })
            .map(|a| a.is_ipv6());
        let a = named[0]
            .or_else(|| offerer_ipv6.and_then(first_of))
            .unwrap_or(InterfaceId::new(0));
        let b = match (named[1], o.address_family) {
            (Some(b), Some(v6)) if self.interfaces[b.get()].address.is_ipv6() != v6 => {
                return Err(Error::unsupported(format!(
                    "address-family {}: interface {} is not",
                    if v6 { "IP6" } else { "IP4" },
                    self.interfaces[b.get()].name
                )));
            }
            (Some(b), _) => b,
            (None, Some(v6)) if self.interfaces[a.get()].address.is_ipv6() == v6 => a,
            (None, Some(v6)) => first_of(v6).ok_or_else(|| {
                Error::unsupported(format!(
                    "address-family {}: no interface of that family",
                    if v6 { "IP6" } else { "IP4" }
                ))
            })?,
            (None, None) => a,
        };
        Ok([a, b])
    }

    pub(super) fn check_family(
        &self,
        interface: InterfaceId,
        media: &[Media],
        o: &Opts,
    ) -> Result<(), Error> {
        let local = &self.interfaces[interface.get()];
        for (i, m) in media.iter().enumerate() {
            if m.port == 0 || m.ice {
                continue;
            }
            let addr = if o.trust_address {
                m.address
            } else {
                o.received_from.or(m.address)
            };
            if let Some(a) = addr.filter(|a| !a.is_unspecified())
                && a.is_ipv6() != local.address.is_ipv6()
            {
                return Err(Error::Sdp(SdpError::Family {
                    section: i + 1,
                    interface: local.name.clone(),
                    ipv6: a.is_ipv6(),
                }));
            }
        }
        Ok(())
    }

    /// Whether the offer fits under `sessions.max`: a new dialog (`new`)
    /// needs room; a re-offer of one that exists always passes.
    fn admit(&self, new: bool) -> Result<(), Error> {
        if new && self.sessions.len() >= self.max_sessions {
            return Err(Error::Request(RequestError::TooManySessions(
                self.max_sessions,
            )));
        }
        Ok(())
    }

    pub(super) fn read(sdp: &[u8]) -> Result<([Media; MAX_MEDIA], usize), Error> {
        sdp::check_body(sdp).map_err(|e| Error::Sdp(SdpError::Read(e)))?;
        let mut media = [Media::EMPTY; MAX_MEDIA];
        let n = sdp::read_media(sdp, &mut media).map_err(|e| Error::Sdp(SdpError::Read(e)))?;
        Ok((media, n))
    }

    /// Rewrite `sdp` towards one side into `buf`; returns the length.
    pub(super) fn rewrite_into(
        buf: &mut [u8],
        interfaces: &[Interface],
        (sdp, toward): (&[u8], InterfaceId),
        (ports, bundle): (&[Relayed<'_>], &[&[u8]]),
        o: &Opts,
        session: sdp::SessionEdits<'_>,
    ) -> Result<usize, Error> {
        let interface = &interfaces[toward.get()];
        let address = match o.media_address {
            Some(a) if a.is_ipv6() != interface.address.is_ipv6() => {
                return Err(Error::unsupported(format!(
                    "media-address {a}: not of interface {}'s address family",
                    interface.name
                )));
            }
            Some(a) => a,
            None => interface.advertised(),
        };
        let plan = Plan {
            address,
            media: ports,
            replace_origin: o.replace_origin,
            bundle,
            session,
            keep_connection: ports.iter().any(|r| r.passthrough.is_some())
                && ports
                    .iter()
                    .all(|r| r.passthrough.is_some() || r.rtp_port == 0),
        };
        sdp::rewrite(sdp, &plan, buf).map_err(|e| Error::Sdp(SdpError::Rewrite(e)))
    }

    /// The SDP `sdp` (its sections `media`) rewritten towards interface
    /// `toward` for `relayed`, with the request's edits (`sdp-attr`,
    /// `replace`, …), `loop protect`'s mark and `SDES lifetime`; the `o=`
    /// version for `recipient` from `versions`; `offer`: an offer (where
    /// `generate-mid` applies). Its length in the SDP buffer.
    pub(super) fn render(
        &mut self,
        req: &Dict<'_>,
        (sdp, media, toward): (&[u8], &[Media], InterfaceId),
        (relayed, group_ids): (&[Relayed<'_>], &[&[u8]]),
        opt: &Opts,
        (versions, recipient, offer): (&mut Versions, Option<&[u8]>, bool),
    ) -> Result<usize, Error> {
        let mut edits = SdpEdits::of(req);
        if Self::loop_protect(req) {
            edits.add_session(&self.loop_attr);
        }
        // A copy that may refer to the edits.
        let mut relayed: Vec<Relayed<'_>> = relayed.to_vec();
        edits.apply(sdp, media, &mut relayed, offer);
        for r in &mut relayed {
            r.sdes_lifetime = opt.sdes.lifetime;
        }
        Self::rewrite_edited(
            &mut self.sdp_buf,
            &self.interfaces,
            (sdp, toward),
            (&relayed, group_ids),
            opt,
            (&edits, versions, recipient),
        )
    }

    /// [`Self::rewrite_into`] with the proxy's `edits`; when the relay
    /// sets the `o=` version (`sdp-version`), rendered with it fixed
    /// first, to see whether what `recipient` gets changed.
    pub(super) fn rewrite_edited(
        buf: &mut [u8],
        interfaces: &[Interface],
        (sdp, toward): (&[u8], InterfaceId),
        (ports, bundle): (&[Relayed<'_>], &[&[u8]]),
        o: &Opts,
        (edits, versions, recipient): (&SdpEdits<'_>, &mut Versions, Option<&[u8]>),
    ) -> Result<usize, Error> {
        let render = |buf: &mut [u8], version| {
            Self::rewrite_into(
                buf,
                interfaces,
                (sdp, toward),
                (ports, bundle),
                o,
                edits.session(version),
            )
        };
        if edits.version == VersionMode::Input {
            return render(buf, None);
        }
        let n = render(buf, Some((0, 0)))?;
        let d = sdp_edits::digest(&buf[..n]);
        let input = (
            sdp::origin_session(sdp).unwrap_or(0),
            sdp::origin_version(sdp).unwrap_or(0),
        );
        let v = sdp_edits::next_version(versions, recipient, edits.version, input, d);
        render(buf, v)
    }

    /// Whether a re-offer of `media` (`members`: its BUNDLE members) keeps
    /// `prev`'s calls. Without BUNDLE a section may be disabled, added or
    /// change its profile (only that section's call changes); with BUNDLE
    /// the media and profiles stay as they were, and while the bundled
    /// party answers, the offerer stays unbundled.
    pub(super) fn reusable(
        prev: &Session,
        dir: [InterfaceId; 2],
        media: &[Media],
        members: &[bool],
        bundled: bool,
        b_transport: impl Fn(&Media) -> Transport,
    ) -> bool {
        if prev.dir != dir {
            return false;
        }
        if !bundled {
            return media.len() >= prev.media.len();
        }
        prev.media.len() == media.len()
            && prev
                .media
                .iter()
                .zip(media)
                .zip(members)
                .all(|((st, m), &member)| match st {
                    Some(st) if st.b_bundled() => {
                        m.port != 0 && !member && st.b_transport == b_transport(m)
                    }
                    Some(st) => {
                        (m.port != 0 || member)
                            && st.b_transport == b_transport(m)
                            && st.a_bundled() == member
                    }
                    None => m.port == 0 && !member,
                })
    }

    /// What the reply's `warning` says of an offer that succeeded: SDES
    /// keys with a lifetime (RFC 4568 §6.1), which the relay does not count
    /// packets against, and a `codec: mask` that masked nothing (a mask
    /// applies only with a codec to transcode to).
    fn warn_offer(
        &mut self,
        sdp: &[u8],
        media: &[Media],
        opt: &Opts,
        states: &[Option<MediaState>],
    ) {
        if media.iter().any(|m| m.crypto.is_some()) && sdp_has_key_lifetime(sdp) {
            self.warnings.push(
                "a=crypto lifetime: not enforced (the key is used until a re-INVITE changes it)"
                    .to_owned(),
            );
        }
        if opt.codecs.mask.iter().any(Option::is_some)
            && states.iter().flatten().all(|st| st.codec.is_none())
        {
            self.warnings
                .push("codec mask: ignored, there is no codec to transcode to".to_owned());
        }
    }

    /// An offer's options (with their warnings), interfaces and media
    /// sections, checked against the offerer's interface.
    fn read_offer(&mut self, req: &Dict<'_>, sdp: &[u8]) -> Result<ReadOffer, Error> {
        let mut opt = opts(req)?;
        opt.strict_source |= self.strict_source;
        self.warnings.extend(super::opts::unknown_options(req));
        self.warnings.extend(super::opts::codec_warnings(req));
        let (mut media, count) = Self::read(sdp)?;
        // `ICE=force-relay|optional`: an offer whose sections all use ICE
        // is passed through (relayed as it is, nothing terminated, the
        // relay a relay candidate); without ICE, `force`.
        if matches!(opt.ice, IcePolicy::ForceRelay | IcePolicy::Optional) {
            let active = || media[..count].iter().filter(|m| m.port != 0);
            if active().count() > 0 && active().all(|m| m.ice) {
                opt.ice_passthrough = Some(if opt.ice == IcePolicy::ForceRelay {
                    super::opts::Passthrough::DropRelays
                } else {
                    super::opts::Passthrough::KeepRelays
                });
                for m in &mut media[..count] {
                    m.transport = Transport::Other;
                    m.ice = false;
                }
                // The endpoints' ICE passes; the relay runs none.
                opt.ice = IcePolicy::Remove;
            } else {
                opt.ice = IcePolicy::Force;
            }
        }
        // `SDES prefer`: a section offering both DTLS and SDES is SDES
        // (its DTLS refused).
        if opt.sdes.prefer {
            for m in media[..count]
                .iter_mut()
                .filter(|m| m.transport.is_dtls() && m.crypto.is_some())
            {
                m.transport = match m.transport {
                    Transport::UdpTlsSavpf => Transport::Savpf,
                    _ => Transport::Savp,
                };
            }
        }
        let dir = self.offer_directions(req, &media[..count], &opt)?;
        let opt = across(&opt, dir);
        self.check_family(dir[0], &media[..count], &opt)?;
        Ok((opt, dir, (media, count)))
    }

    pub(super) fn offer(&mut self, req: &Dict<'_>) -> Result<usize, Error> {
        let key = self.branch_of_offer(
            (
                required(req, "call-id")?.to_vec(),
                required(req, "from-tag")?.to_vec(),
            ),
            req,
        );
        let sdp = required(req, "sdp")?;
        if let Some(n) = self.looped(req, sdp) {
            return Ok(n);
        }
        // `OSRTP: accept-legacy`: the offerer's doubled streams, one each.
        let (offer_legacy, accept_legacy) = super::opts::legacy_flags(req);
        let folded = accept_legacy.then(|| super::legacy::fold_offer(sdp));
        let legacy_a = folded.as_ref().map_or_else(Vec::new, |(_, p)| p.clone());
        let sdp: &[u8] = folded.as_ref().map_or(sdp, |(s, _)| s);
        let (opt, dir, (media, count)) = self.read_offer(req, sdp)?;
        let selections = select_formats(sdp, &media[..count], &opt, &CodecNames::of(req))?;
        // Passed through, BUNDLE is the endpoints' own business.
        let (members, primary) = if opt.ice_passthrough.is_some() {
            (vec![false; count], None)
        } else {
            Self::bundle_members(sdp, &media[..count])
        };
        // The offerer's ICE per section.
        let peers: Vec<Option<IcePeer>> = (0..count).map(|i| ice::peer_of(sdp, i)).collect();
        let (mut states, prev_meta) = self.offer_media(
            (&key, req.get_bytes(b"to-tag")),
            (&media[..count], &peers),
            &opt,
            dir,
            (&members, primary),
        )?;
        for st in states.iter_mut().flatten() {
            st.passthrough = opt.ice_passthrough;
        }
        let fingerprint = self
            .relay
            // B's own hash is not known yet.
            .dtls_fingerprint_with(fingerprint_hash(&opt, &[]))
            .to_owned();
        let relayed = self.offered_to_b(&states, &selections, &fingerprint, dir[1]);
        let (created, to_tag, sdps, mut versions, prev_via, checkpoint) =
            prev_meta.unwrap_or_else(|| (unix_now(), None, Vec::new(), Vec::new(), None, None));
        // Offering to a bundled answerer: its group again.
        let group_ids = if states.iter().flatten().any(MediaState::b_bundled) {
            Self::answer_group_ids(&states, &vec![true; states.len()])
        } else {
            Vec::new()
        };
        let written = self.render(
            req,
            (sdp, &media[..count], dir[1]),
            (&relayed, &group_ids),
            &opt,
            (&mut versions, to_tag.as_deref(), true),
        );
        drop(group_ids);
        drop(relayed);
        // `OSRTP: offer-legacy`: each opportunistic stream offered twice.
        let (written, legacy_b) = match written {
            Ok(n) if offer_legacy => {
                let (doubled, pattern) = super::legacy::duplicate(&self.sdp_buf[..n]);
                (self.replace_sdp(&doubled), pattern)
            }
            w => (w, Vec::new()),
        };
        let session = Session {
            created,
            to_tag,
            dir,
            media: states,
            sdps,
            versions,
            legacy: [legacy_a, legacy_b],
            via_branch: req
                .get_bytes(b"via-branch")
                .map(<[u8]>::to_vec)
                .or(prev_via),
            checkpoint,
        };
        self.warn_offer(sdp, &media[..count], &opt, &session.media);
        if written.is_ok() {
            self.apply_echo(&session.media, opt.media_echo, true);
        }
        self.store_offer(&key, session, sdp);
        written
    }

    /// The sections of an offer for dialog `key` (its `media` and their
    /// ICE `peers`): a re-offer keeps the dialog's ports and keys where it
    /// can (RFC 3264 §8, `reusable`), anything else replaces the session;
    /// on failure the dialog is put back exactly as it was. With the
    /// dialog's earlier (created, to-tag, SDPs, versions, via-branch).
    fn offer_media(
        &mut self,
        (key, peer): (&SessionKey, Option<&[u8]>),
        (media, peers): (&[Media], &[Option<IcePeer>]),
        opt: &Opts,
        dir: [InterfaceId; 2],
        (members, primary): (&[bool], Option<usize>),
    ) -> Result<(Vec<Option<MediaState>>, Option<PrevMeta>), Error> {
        // The profile offered to B for each section: `transport-protocol`
        // converts between the RTP/SRTP profiles; anything else passes.
        let b_transport = |m: &Media| match (m.transport, opt.transport) {
            (Transport::Other, _) | (_, None) => m.transport,
            (_, Some(t)) => t,
        };
        // A re-offer keeps the dialog's ports and keys where it can
        // (RFC 3264 §8, `reusable`); anything else replaces the session.
        // On failure the dialog is put back exactly as it was (`original`).
        let (prev, original) = self.take_for_offer(key, peer);
        self.admit(prev.is_none())?;
        // `track-state`: the dialog as last agreed, kept until the answer
        // (offers before it share one); the calls it has are not ended.
        let checkpoint = match (&prev, &original) {
            (Some(p), _) if p.checkpoint.is_some() => p.checkpoint.clone(),
            (Some(_), Some((k, s))) if opt.track_state && s.to_tag.is_some() => Some(Box::new((
                k.clone(),
                Session {
                    checkpoint: None,
                    ..s.clone()
                },
            ))),
            _ => None,
        };
        self.keep_calls = checkpoint
            .iter()
            .flat_map(|c| c.1.media.iter().flatten().map(|st| st.ports.id))
            .collect();
        let prev_meta = prev.as_ref().map(|p| {
            (
                p.created,
                p.to_tag.clone(),
                p.sdps.clone(),
                p.versions.clone(),
                p.via_branch.clone(),
                checkpoint,
            )
        });
        let bundled = members.iter().any(|&m| m)
            || prev
                .as_ref()
                .is_some_and(|s| s.media.iter().flatten().any(|st| st.group.is_some()));
        let reuse = prev
            .as_ref()
            .is_some_and(|s| Self::reusable(s, dir, media, members, bundled, b_transport));
        let profiles: Vec<Transport> = media.iter().map(b_transport).collect();
        let done = match prev.as_ref() {
            Some(p) if reuse => self.reoffer(p, media, &profiles, opt, peers),
            Some(p) if p.media.iter().flatten().any(MediaState::b_bundled) => {
                Err(Error::Sdp(SdpError::BundledReoffer))
            }
            p => self.replace_media(p, dir, (media, peers), opt, b_transport, (members, primary)),
        };
        self.keep_calls.clear();
        match done {
            Ok(states) => Ok((states, prev_meta)),
            Err(e) => {
                if let Some((k, s)) = original {
                    self.sessions.insert(k, s);
                }
                Err(e)
            }
        }
    }

    /// The SDP written (in the SDP buffer) replaced by `sdp`: its length.
    pub(super) fn replace_sdp(&mut self, sdp: &[u8]) -> Result<usize, Error> {
        let out = self
            .sdp_buf
            .get_mut(..sdp.len())
            .ok_or(Error::Request(RequestError::TooLarge))?;
        out.copy_from_slice(sdp);
        Ok(sdp.len())
    }

    /// The offered dialog `key`, with the offerer's SDP.
    fn store_offer(&mut self, key: &SessionKey, mut session: Session, sdp: &[u8]) {
        session.remember(super::base_tag(&key.1), sdp);
        self.sessions.insert(key.clone(), session);
        self.update_holds(key);
    }

    /// What the offer's sections write for B (on interface `toward_b`),
    /// with each one's chosen formats (`selections`).
    fn offered_to_b<'a>(
        &self,
        states: &'a [Option<MediaState>],
        selections: &'a [Option<sdp::PayloadTypes>],
        fingerprint: &'a str,
        toward_b: InterfaceId,
    ) -> Vec<Relayed<'a>> {
        states
            .iter()
            .zip(selections)
            .map(|(st, select)| {
                st.as_ref().map_or(Relayed::ports(0, 0), |st| {
                    let shared = st
                        .group
                        .filter(|_| st.b_bundled())
                        .and_then(|g| states[g].as_ref())
                        .unwrap_or(st);
                    Relayed {
                        select: select.as_ref().map(sdp::PayloadTypes::as_slice),
                        ..st.towards_b(
                            fingerprint,
                            shared,
                            (
                                self.ice_trickles(shared.ports.id, shared.leg(Party::B)),
                                self.srflx_of(toward_b),
                            ),
                        )
                    }
                })
            })
            .collect()
    }

    /// The key an offer for dialog `key` goes under: its own branch's when
    /// it is another branch of a forked INVITE (an initial offer, no
    /// `to-tag`, whose `via-branch` differs from that of the dialog's offer
    /// while unanswered), so that each branch gets its own media.
    fn branch_of_offer(&self, key: SessionKey, req: &Dict<'_>) -> SessionKey {
        // In a dialog: the one with the party `to-tag` names.
        if let Some(peer) = req.get_bytes(b"to-tag") {
            return self.dialog_key(key, peer);
        }
        let Some(via) = req.get_bytes(b"via-branch") else {
            return key;
        };
        let own = super::branch_key(&key, via);
        let fork = self.sessions.contains_key(&own)
            || self.sessions.get(&key).is_some_and(|s| {
                s.to_tag.is_none() && s.via_branch.as_deref().is_some_and(|w| w != via)
            });
        if fork { own } else { key }
    }

    /// The dialog an offer for `key` re-offers, taken out of the table
    /// (from either party: see [`Control::take_reversed`]), and the session
    /// as it was with its key, to put back if the offer fails.
    fn take_for_offer(
        &mut self,
        key: &SessionKey,
        peer: Option<&[u8]>,
    ) -> (Option<Session>, Option<Stored>) {
        match self.sessions.remove(key) {
            Some(p) => (Some(p.clone()), Some((key.clone(), p))),
            None => match self.take_reversed(key, peer) {
                Some((flipped, original)) => (Some(flipped), Some(original)),
                None => (None, None),
            },
        }
    }

    /// The dialog `key` names from its answerer's side: a re-offer from
    /// the party that answered (its tag is the dialog's `to-tag`). The
    /// session is taken out with its roles swapped, to be stored under the
    /// new offerer's tag. A BUNDLE group stays with the party that offered
    /// it (the relay call's A leg), which is now the answerer.
    /// Also returns the session as it was, with its key, to put back if
    /// the re-offer fails.
    /// With several dialogs, the one with `peer` (the request's `to-tag`,
    /// or the other party of a pair key).
    pub(super) fn take_reversed(
        &mut self,
        key: &SessionKey,
        peer: Option<&[u8]>,
    ) -> Option<(Session, Stored)> {
        let peer = Self::peer_of(key).or(peer);
        let old = self.reversed_key(&key.0, super::base_tag(&key.1), peer)?;
        let original = self.sessions.remove(&old)?;
        let mut s = original.clone();
        s.dir.swap(0, 1);
        s.to_tag = Some(super::base_tag(&old.1).to_vec());
        for st in s.media.iter_mut().flatten() {
            st.flip();
        }
        log::info!(
            "call {}: re-offer from the answerer; roles swapped",
            String::from_utf8_lossy(&key.0)
        );
        Some((s, (old, original)))
    }

    /// A re-offer of `prev`'s media: new addresses and keys of side A,
    /// same ports and relay keys. A section disabled now (port 0) loses
    /// its call; one added, re-enabled, or offered to B with another
    /// profile (`profiles`) gets a new one. The calls of disabled or
    /// replaced sections end only once everything else succeeded.
    ///
    /// On any failure the dialog's relay calls are as before: new calls
    /// end, and the sides already changed get their previous side A back.
    pub(super) fn reoffer(
        &mut self,
        prev: &Session,
        media: &[Media],
        profiles: &[Transport],
        opt: &Opts,
        peers: &[Option<IcePeer>],
    ) -> Result<Vec<Option<MediaState>>, Error> {
        let mut created: Vec<MediaState> = Vec::new();
        let mut updated: Vec<MediaState> = Vec::new();
        let done = self
            .reoffer_sections(
                prev,
                (media, peers),
                profiles,
                opt,
                &mut created,
                &mut updated,
            )
            .and_then(|(states, ended)| {
                self.rebundle(&states)?;
                Ok((states, ended))
            });
        match done {
            Ok((states, ended)) => {
                // Those a checkpoint has stay until the answer.
                let ended: Vec<MediaState> = ended
                    .into_iter()
                    .filter(|o| !self.keep_calls.contains(&o.ports.id))
                    .collect();
                for old in ended {
                    self.extras.remove(&old.ports.id);
                    self.ice_forget(old.ports.id);
                    if let Err(e) = self.relay.delete_call(old.ports.id) {
                        log::warn!("re-offer: ending call {}: {e}", old.ports.id);
                    }
                }
                Ok(states)
            }
            Err(e) => {
                for c in created {
                    let id = c.ports.id;
                    Self::logged("undoing a failed re-offer", id, self.relay.delete_call(id));
                }
                for st in updated {
                    let id = st.ports.id;
                    Self::logged(
                        "undoing a failed re-offer",
                        id,
                        self.relay.update_side(id, st.leg(Party::A), &st.a_side),
                    );
                }
                Err(e)
            }
        }
    }

    /// [`Control::reoffer`]'s work: the new states and the calls to end
    /// once everything succeeded. Calls it creates go to `created`, the
    /// previous states of sections whose side A it changed to `updated`.
    fn reoffer_sections(
        &mut self,
        prev: &Session,
        (media, peers): (&[Media], &[Option<IcePeer>]),
        profiles: &[Transport],
        opt: &Opts,
        created: &mut Vec<MediaState>,
        updated: &mut Vec<MediaState>,
    ) -> Result<(Vec<Option<MediaState>>, Vec<MediaState>), Error> {
        let mut states = Vec::with_capacity(media.len());
        let mut ended: Vec<MediaState> = Vec::new();
        for (i, m) in media.iter().enumerate() {
            let st = prev.media.get(i).copied().flatten();
            let (act, ends) = crate::reoffer::action(
                st.map(|st| (st.a_bundled(), st.bundled_member(i), st.b_transport)),
                m.port,
                &profiles[i],
            );
            if let Some(old) = st.filter(|_| ends) {
                ended.push(old);
            }
            let st = match (act, st) {
                (Action::Keep, Some(st)) => st,
                (Action::KeepBundled, Some(st)) => {
                    // Side A of a bundled member is the group's: nothing of its own.
                    states.push(Some(st));
                    continue;
                }
                (Action::Disabled, _) | (Action::Keep | Action::KeepBundled, None) => {
                    states.push(None);
                    continue;
                }
                (Action::Create, _) => {
                    let profile = profiles[i];
                    let new = self
                        .create_media(
                            prev.dir,
                            (core::slice::from_ref(m), core::slice::from_ref(&peers[i])),
                            opt,
                            |_| profile,
                            (&[false], None),
                        )?
                        .pop()
                        .flatten();
                    created.extend(new);
                    states.push(new);
                    continue;
                }
            };
            let (mut a, b, a_tag, b_alt) =
                self.offer_srtp(m, st.b_transport, Some(&st), &opt.sdes)?;
            let osrtp = self.offer_osrtp(m, st.b_transport, Some(&st), (opt.osrtp.0, &mut a))?;
            let a_tag = osrtp.a.map_or(a_tag, |(c, _)| c.tag);
            // A's ICE: a restart (new ufrag and password) gets new
            // credentials from the relay.
            let restart = self.ice_offered(st.ports.id, st.leg(Party::A), peers[i].clone());
            let (ice_a, ice_b) = self.offer_ice(m, opt, Some(&st), restart, st.b_transport)?;
            let (a_dtls, b_dtls) =
                Self::offer_dtls(m, st.b_transport, Some(&st), (opt.dtls, opt.dtls_reverse))?;
            let a = if a_dtls.is_some() { DTLS_PENDING } else { a };
            let a_side = Side {
                rtcp_mux: st.mux || st.a_bundled(),
                ice: ice_a,
                dtls: a_dtls,
                // Transcoding goes on until the answer settles it again.
                transcode: st.a_side.transcode,
                repack: st.a_side.repack,
                ..Self::side(prev.dir[0], m, opt, a)
            };
            updated.push(st);
            self.relay
                .update_side(st.ports.id, st.leg(Party::A), &a_side)
                .map_err(Error::from)?;
            states.push(Some(MediaState {
                a_transport: m.transport,
                a_tag,
                a,
                b,
                b_alt,
                osrtp,
                a_side,
                a_mux: m.rtcp_mux,
                ice_a,
                ice_b,
                a_dtls,
                b_dtls,
                codec: media::codec_plan(m, opt.codecs),
                dtmf_plan: media::dtmf_plan(m, opt.codecs, opt.always_transcode),
                te_toward_a: None,
                mux_policy: opt.rtcp_mux,
                b_setup: offered_setup(opt.dtls),
                a_actpass: matches!(m.setup, None | Some(Setup::Actpass)),
                ptime: packet_times(m, opt),
                opus: [m.opus, st.opus[1]],
                amr: [m.amr, st.amr[1]],
                amr_wb: [m.amr_wb, st.amr_wb[1]],
                payload_types: if st.b_bundled() {
                    // The bundled answerer sends with the offer's types.
                    let mut types = st.payload_types;
                    for &pt in m.payload_types.as_slice() {
                        if !types.as_slice().contains(&pt) {
                            types.push(pt);
                        }
                    }
                    types
                } else {
                    st.payload_types
                },
                ..st
            }));
        }
        Ok((states, ended))
    }

    /// Sort the bundled answerer's media by the payload types it now sends
    /// (after a re-offer from the other party).
    pub(super) fn rebundle(&mut self, states: &[Option<MediaState>]) -> Result<(), Error> {
        let Some(p) = states
            .iter()
            .flatten()
            .find(|st| st.b_bundled())
            .and_then(|st| st.group)
            .and_then(|g| states[g])
        else {
            return Ok(());
        };
        let group: Vec<(CallId, Vec<Pt>)> = states
            .iter()
            .flatten()
            .filter(|st| st.group.is_some())
            .map(|st| (st.ports.id, st.payload_types.as_slice().to_vec()))
            .collect();
        self.relay
            .bundle(p.ports.id, &group)
            .map(|_| ())
            .map_err(Error::from)
    }

    /// One relay call per offered (non-rejected) media section; on failure
    /// the calls created so far are deleted.
    /// Which media sections of the offer are in its BUNDLE group (RFC 8843),
    /// and the one whose transport they share: the first tag of the group
    /// whose section has a port. Members use `rtcp-mux`; a group of fewer
    /// than two members is ignored. DTLS members share the first member's
    /// keys; SDES members keep their own (sorted before decryption).
    pub(super) fn bundle_members(sdp: &[u8], media: &[Media]) -> (Vec<bool>, Option<usize>) {
        let mut group = [None; MAX_MEDIA];
        let n = sdp::bundle_group(sdp, &mut group);
        let index_of = |mid: &Mid| media.iter().position(|m| m.mid.as_ref() == Some(mid));
        let mut members = vec![false; media.len()];
        for mid in group[..n].iter().flatten() {
            if let Some(i) = index_of(mid) {
                let m = &media[i];
                members[i] = m.rtcp_mux && (m.port != 0 || m.bundle_only);
            }
        }
        let primary = group[..n]
            .iter()
            .flatten()
            .filter_map(index_of)
            .find(|&i| members[i] && media[i].port != 0);
        if primary.is_none() || members.iter().filter(|&&b| b).count() < 2 {
            return (vec![false; media.len()], None);
        }
        (members, primary)
    }

    /// One relay call per offered (non-rejected) media section; on failure
    /// the calls created so far are deleted. Sections in the BUNDLE group
    /// share side A of the first member's call.
    /// New calls for the whole offer, replacing `prev`'s: made first, so
    /// that if they cannot be, the dialog keeps its media (RFC 3264 §8:
    /// the old session stays); `prev`'s end once they exist.
    fn replace_media(
        &mut self,
        prev: Option<&Session>,
        dir: [InterfaceId; 2],
        media: (&[Media], &[Option<IcePeer>]),
        opt: &Opts,
        b_transport: impl Fn(&Media) -> Transport,
        group: (&[bool], Option<usize>),
    ) -> Result<Vec<Option<MediaState>>, Error> {
        let states = self.create_media(dir, media, opt, b_transport, group)?;
        if let Err(e) = self.rebundle(&states) {
            self.end_media(&states);
            return Err(e);
        }
        if let Some(old) = prev {
            // Those a checkpoint has stay until the answer.
            let ending: Vec<Option<MediaState>> = old
                .media
                .iter()
                .map(|st| st.filter(|st| !self.keep_calls.contains(&st.ports.id)))
                .collect();
            self.end_media(&ending);
        }
        Ok(states)
    }

    pub(super) fn create_media(
        &mut self,
        dir: [InterfaceId; 2],
        (media, peers): (&[Media], &[Option<IcePeer>]),
        opt: &Opts,
        b_transport: impl Fn(&Media) -> Transport,
        (members, primary): (&[bool], Option<usize>),
    ) -> Result<Vec<Option<MediaState>>, Error> {
        let mut states: Vec<Option<MediaState>> = vec![None; media.len()];
        // The first member first: the others are created on its worker.
        let order = primary
            .into_iter()
            .chain((0..media.len()).filter(|&i| Some(i) != primary));
        for i in order {
            let m = &media[i];
            if m.port == 0 && !members[i] {
                continue;
            }
            let member = members[i] && Some(i) != primary;
            let shared = primary.and_then(|p| states[p].map(|st| (p, st.ports.id)));
            let created = self.create_section(
                dir,
                (m, peers.get(i).cloned().flatten()),
                opt,
                b_transport(m),
                members[i],
                // The first member was created first: a member always has it.
                shared.filter(|_| member).map(|(p, id)| (&media[p], id)),
            );
            match created {
                Ok(mut st) => {
                    st.group = members[i].then_some(primary.unwrap_or(i));
                    states[i] = Some(st);
                }
                Err(e) => {
                    self.end_session(&Session::bare(dir, states));
                    return Err(e);
                }
            }
        }
        if let Some(p) = primary.and_then(|p| states[p]) {
            let group: Vec<(CallId, Vec<Pt>)> = states
                .iter()
                .zip(media)
                .filter_map(|(st, m)| {
                    st.filter(|s| s.group.is_some())
                        .map(|s| (s.ports.id, m.payload_types.as_slice().to_vec()))
                })
                .collect();
            if !self.relay.bundle(p.ports.id, &group).map_err(Error::from)? {
                log::warn!("bundle: the group's calls are not on one worker");
            }
        }
        Ok(states)
    }

    /// The relay call of one media section. `bundled`: side A is in the
    /// BUNDLE group (it uses `rtcp-mux`); `shared`: the first member's
    /// media section and call, when this section's side A is that one's.
    pub(super) fn create_section(
        &mut self,
        dir: [InterfaceId; 2],
        (m, peer): (&Media, Option<IcePeer>),
        opt: &Opts,
        bt: Transport,
        bundled: bool,
        shared: Option<(&Media, CallId)>,
    ) -> Result<MediaState, Error> {
        let (mut a, b, a_tag, b_alt) = self.offer_srtp(m, bt, None, &opt.sdes)?;
        let osrtp = self.offer_osrtp(m, bt, None, (opt.osrtp.0, &mut a))?;
        let a_tag = osrtp.a.map_or(a_tag, |(c, _)| c.tag);
        let (ice_a, ice_b) = self.offer_ice(m, opt, None, false, bt)?;
        let (a_dtls, b_dtls) = Self::offer_dtls(m, bt, None, (opt.dtls, opt.dtls_reverse))?;
        let b = if b_dtls.is_some() { DTLS_PENDING } else { b };
        // A bundled member's side A is the first member's: its media arrive
        // on the shared port, with that one's ICE and DTLS; SDES keys are
        // the member's own.
        let (a, a_dtls, ice_a, a_side) = if let Some((pm, _)) = shared {
            let a = if m.transport.is_sdes() {
                a
            } else {
                Srtp::default()
            };
            let a_side = Side {
                rtcp_mux: true,
                // Sorted into this member by payload type: its own events.
                dtmf: m.telephone_event,
                ..Self::side(dir[0], pm, opt, a)
            };
            (a, None, None, a_side)
        } else {
            let a = if a_dtls.is_some() { DTLS_PENDING } else { a };
            let a_side = Side {
                ice: ice_a,
                dtls: a_dtls,
                rtcp_mux: bundled,
                ..Self::side(dir[0], m, opt, a)
            };
            (a, a_dtls, ice_a, a_side)
        };
        let b_side = Side {
            interface: dir[1],
            rtp: None,
            rtcp: None,
            learning: opt.learning,
            strict_source: opt.strict_source,
            handover: opt.media_handover,
            unidirectional: opt.unidirectional,
            srtp: b,
            // `rtcp-mux require`: B is taken to multiplex from the start.
            rtcp_mux: opt.rtcp_mux == MuxPolicy::Require,
            ice: ice_b,
            dtls: b_dtls,
            dtmf: None,
            transcode: None,
            opaque: m.transport == Transport::Other,
            dtmf_xcode: None,
            repack: None,
        };
        let ports = self
            .relay
            .create_call_near(a_side, b_side, shared.map(|(_, id)| id))
            .map_err(Error::from)?;
        // A's ICE, for the relay's agent towards it (a bundled member's is
        // the first member's).
        if shared.is_none() && ice_a.is_some() {
            // A new call: party A is leg A.
            self.ice_offered(ports.id, CallLeg::A, peer);
        }
        // Until its answer, the call ends after offer_timeout whatever its
        // media (and is not ended by the media timeout while it rings).
        Self::logged(
            "waiting for its answer",
            ports.id,
            self.relay
                .awaiting_answer(ports.id, Some(self.offer_timeout)),
        );
        Ok(MediaState {
            ports,
            a_transport: m.transport,
            a_tag,
            b_transport: bt,
            a,
            b,
            b_alt,
            osrtp,
            passthrough: None,
            a_side,
            a_mux: m.rtcp_mux,
            mux: false,
            b_mux: opt.rtcp_mux == MuxPolicy::Require,
            mux_policy: opt.rtcp_mux,
            b_setup: offered_setup(opt.dtls),
            a_actpass: matches!(m.setup, None | Some(Setup::Actpass)),
            ptime: packet_times(m, opt),
            ice_a,
            ice_b,
            a_dtls,
            b_dtls,
            b_side,
            payload_types: m.payload_types,
            mid: m.mid,
            group: None,
            flipped: false,
            codec: media::codec_plan(m, opt.codecs),
            a_formats: None,
            a_law: None,
            b_law: None,
            audio: [None, None],
            opus: [m.opus, None],
            amr: [m.amr, None],
            amr_wb: [m.amr_wb, None],
            dtmf_plan: media::dtmf_plan(m, opt.codecs, opt.always_transcode),
            te_toward_a: None,
        })
    }
}

/// The packet times the relay repacketises to towards A and towards B
/// for section `m`: `ptime` sets B's leg, and A keeps its own (its
/// `a=ptime`, else 20 ms) unless `ptime-reverse` sets it.
fn packet_times(m: &Media, opt: &Opts) -> [Option<u16>; 2] {
    let own = m
        .ptime
        .or(Some(20))
        .filter(|&ms| crate::relay::repack::Repacker::new(ms).is_some());
    let to_a = opt.ptime_reverse.or(opt.ptime.and(own));
    let to_b = opt.ptime.or(opt.ptime_reverse.and(own));
    if m.port == 0 || m.transport == Transport::Other {
        return [None; 2];
    }
    [to_a, to_b]
}

/// The hash of the relay's fingerprint: `DTLS-fingerprint`, else the
/// peer's own (its first DTLS section's), else SHA-256.
pub(super) fn fingerprint_hash(opt: &Opts, media: &[Media]) -> rtpflux_core::dtls::HashFn {
    opt.dtls_hash
        .or_else(|| {
            media
                .iter()
                .find_map(|m| m.fingerprints.iter().flatten().next().map(|f| f.hash))
        })
        .unwrap_or(rtpflux_core::dtls::HashFn::Sha256)
}

/// The `a=setup` the relay offers B under `DTLS`.
fn offered_setup(dtls: Option<DtlsOpt>) -> Setup {
    match dtls {
        Some(DtlsOpt::Passive) => Setup::Passive,
        Some(DtlsOpt::Active) => Setup::Active,
        None | Some(DtlsOpt::Off) => Setup::Actpass,
    }
}

/// The offerer's formats each section of `sdp` offers the answerer under
/// the `codec` options `strip`, `except` and `offer` (`None`: all of them,
/// in order). A section left with no codec (only telephone events or
/// comfort noise, and nothing to transcode to) is refused.
fn select_formats(
    sdp: &[u8],
    media: &[Media],
    opt: &Opts,
    names: &CodecNames<'_>,
) -> Result<Vec<Option<sdp::PayloadTypes>>, Error> {
    let filter = names.filter();
    if filter.is_empty() {
        return Ok(vec![None; media.len()]);
    }
    media
        .iter()
        .enumerate()
        .map(|(i, m)| {
            if m.payload_types.as_slice().is_empty() {
                // No RTP formats (T.38's `image` section).
                return Ok(None);
            }
            let kept = sdp::select_formats(sdp, i, m.payload_types.as_slice(), &filter);
            let audio = kept.as_slice().iter().any(|&pt| {
                !sdp::format_name(sdp, i, pt).is_some_and(|(name, _)| {
                    name.eq_ignore_ascii_case(b"telephone-event")
                        || name.eq_ignore_ascii_case(b"CN")
                })
            });
            if m.port != 0 && !audio && media::codec_plan(m, opt.codecs).is_none() {
                return Err(Error::Request(RequestError::NoCodecLeft(i + 1)));
            }
            Ok(Some(kept))
        })
        .collect()
}

/// What a dialog had before a re-offer: (created, to-tag, SDPs, `o=`
/// versions, via-branch).
type PrevMeta = (
    u64,
    Option<Vec<u8>>,
    Vec<(Vec<u8>, Vec<u8>)>,
    sdp_edits::Versions,
    Option<Vec<u8>>,
    Option<Box<Stored>>,
);

/// An offer as read: its options, interfaces, and media sections (and
/// how many).
type ReadOffer = (Opts, [InterfaceId; 2], ([Media; MAX_MEDIA], usize));

/// `opt` for a call on interfaces `dir`: one that bridges two interfaces
/// (networks) gets `o=` replaced too, so neither network sees the other's
/// addresses (topology hiding) even without `replace-origin`.
pub(super) fn across(opt: &Opts, dir: [InterfaceId; 2]) -> Opts {
    Opts {
        replace_origin: opt.replace_origin || dir[0] != dir[1],
        ..*opt
    }
}

/// Whether an `a=crypto` line of `sdp` gives its key a lifetime
/// (`inline:<key>|<lifetime>`, RFC 4568 §6.1).
fn sdp_has_key_lifetime(sdp: &[u8]) -> bool {
    sdp.split(|&b| b == b'\n').any(|l| {
        l.starts_with(b"a=crypto:")
            && l.windows(7)
                .position(|w| w == b"inline:")
                .is_some_and(|at| l[at..].contains(&b'|'))
    })
}

#[cfg(test)]
mod tests {
    use super::sdp_has_key_lifetime;

    #[test]
    fn key_lifetimes_are_seen() {
        let with =
            b"m=audio 1 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUJD|2^20\r\n";
        let without = b"m=audio 1 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUJD\r\n";
        assert!(sdp_has_key_lifetime(with));
        assert!(!sdp_has_key_lifetime(without));
        assert!(!sdp_has_key_lifetime(b"a=x:inline:a|b\r\n"));
    }
}
