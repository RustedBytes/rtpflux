//! `answer`: settle each section from the answerer's SDP.

#[allow(clippy::wildcard_imports)]
use super::*;

impl Control {
    /// The answer's BUNDLE group (RFC 5888 §9, RFC 8843 §7.3): the offered
    /// group without the refused sections, the first member's tag first;
    /// none if the first member was refused.
    pub(super) fn answer_group_ids<'a>(
        states: &'a [Option<MediaState>],
        answered: &[bool],
    ) -> Vec<&'a [u8]> {
        let first = states.iter().flatten().find_map(|st| st.group);
        let mut offered: Vec<&[u8]> = Vec::new();
        let mut refused: Vec<&[u8]> = Vec::new();
        let order = first
            .into_iter()
            .chain((0..states.len()).filter(|&i| Some(i) != first));
        for i in order {
            if let Some(st) = states[i].as_ref().filter(|s| s.group.is_some())
                && let Some(mid) = st.mid.as_ref()
            {
                offered.push(mid.as_bytes());
                if !answered[i] {
                    refused.push(mid.as_bytes());
                }
            }
        }
        let mut ids: Vec<&[u8]> = vec![&[]; offered.len()];
        let n = sdp::answer_group(&offered, &refused, &mut ids);
        ids.truncate(if first.is_some_and(|f| answered[f]) {
            n
        } else {
            0
        });
        ids
    }

    /// Settle section `i` (`st`) from B's answer `m`; B is on interface
    /// `toward_b`.
    pub(super) fn answer_section(
        &mut self,
        i: usize,
        m: &Media,
        st: &mut MediaState,
        toward_b: InterfaceId,
        opt: &Opts,
    ) -> Result<(), Error> {
        if st.b_bundled() && st.bundled_member(i) {
            // B's side of a bundled member is the group's: only the
            // codecs and A's `rtcp-mux` settle.
            let mux = st.settle_mux(m.rtcp_mux).0;
            st.b_mux = true;
            st.settle_codecs(m);
            if mux != st.mux {
                st.a_side.rtcp_mux = mux;
                self.relay
                    .update_side(st.ports.id, st.leg(Party::A), &st.a_side)
                    .map_err(Error::from)?;
            }
            st.mux = mux;
            return Ok(());
        }
        // DTLS offered and answered: keyed by the handshake; otherwise
        // SDES or plain from the answer.
        let b_dtls = if st.b_dtls.is_some() && m.transport.is_dtls() {
            Some(Self::answer_dtls(m, st.b_setup)?)
        } else {
            None
        };
        let b = if b_dtls.is_some() {
            DTLS_PENDING
        } else {
            Self::answer_srtp(m, st, opt.sdes.static_keys)?
        };
        // A's opportunistic SRTP: taken when B took SRTP, or with `OSRTP:
        // accept` whatever B did (the relay converts).
        let a_srtp = match st.osrtp.a {
            Some((c, to_a)) if b.outbound.is_some() || opt.osrtp.1 => Srtp {
                inbound: Inbound::Key(c.key),
                outbound: Some(to_a),
            },
            Some(_) => Srtp::default(),
            None => st.a,
        };
        let (mux, b_mux) = st.settle_mux(m.rtcp_mux);
        let a_dtls = self.answer_role(st, opt.dtls);
        let xcode = st
            .settle_codecs(m)
            .map(|c| super::media::answered_amr(c, m));
        if st.ptime.iter().any(Option::is_some)
            && let Some(&pt) = m.payload_types.as_slice().first()
            && !crate::relay::repack::repacketises(pt)
            && m.opus != Some(pt)
        {
            self.warnings.push(format!(
                "ptime: payload type {pt} is relayed as it is (G.711, G.722, G.729 and Opus \
                 are repacketised)"
            ));
        }
        // The Opus payload type each direction carries after any
        // transcoding: B's towards A, A's towards B.
        let opus_of = |c: Option<(Pt, Codec)>| c.filter(|&(_, c)| c == Codec::Opus).map(|(p, _)| p);
        let (b_opus, a_opus) = match xcode {
            Some(c) => (opus_of(Some((c.a_pt, c.a))), opus_of(Some((c.b_pt, c.b)))),
            None => (st.opus[1], st.opus[0]),
        };
        let repack = |ms: Option<u16>, opus| ms.map(|ms| crate::relay::Repack { ms, opus });
        let (a_dtmf, b_dtmf) = st.settle_dtmf(m);
        let b_side = Side {
            rtcp_mux: b_mux || st.b_bundled(),
            // B's audio to A's packet time, A's to B's.
            repack: repack(st.ptime[0], b_opus),
            ice: st.ice_b,
            dtls: b_dtls,
            transcode: xcode.map(|c| c.transcodes().0),
            dtmf_xcode: b_dtmf,
            ..Self::side(toward_b, m, opt, b)
        };
        self.relay
            .update_side(st.ports.id, st.leg(Party::B), &b_side)
            .map_err(Error::from)?;
        let a_transcode = xcode.map(|c| c.transcodes().1);
        if (!st.a_bundled() && mux != st.mux)
            || a_transcode != st.a_side.transcode
            || a_dtmf != st.a_side.dtmf_xcode
            || a_dtls != st.a_dtls
            || st.a_side.repack != repack(st.ptime[1], a_opus)
            || a_srtp != st.a
        {
            st.a = a_srtp;
            st.a_side.srtp = a_srtp;
            st.a_side.repack = repack(st.ptime[1], a_opus);
            if !st.a_bundled() {
                st.a_side.rtcp_mux = mux;
            }
            st.a_dtls = a_dtls;
            st.a_side.dtls = a_dtls;
            st.a_side.transcode = a_transcode;
            st.a_side.dtmf_xcode = a_dtmf;
            self.relay
                .update_side(st.ports.id, st.leg(Party::A), &st.a_side)
                .map_err(Error::from)?;
        }
        st.b = b;
        st.b_alt = [None; super::keys::ALT_KEYS];
        st.osrtp = super::keys::Osrtp::default();
        st.b_side = b_side;
        st.b_dtls = b_dtls;
        st.mux = mux;
        st.b_mux = b_mux;
        Ok(())
    }

    /// The relay's DTLS towards A once answered: `DTLS=active|passive`
    /// sets its role when A offered `actpass` (A's choice stands
    /// otherwise, with a warning).
    fn answer_role(&mut self, st: &MediaState, dtls: Option<DtlsOpt>) -> Option<DtlsSide> {
        let mut a = st.a_dtls?;
        let role = match dtls {
            Some(DtlsOpt::Active) => DtlsRole::Client,
            Some(DtlsOpt::Passive) => DtlsRole::Server,
            None | Some(DtlsOpt::Off) => return Some(a),
        };
        if st.a_actpass {
            a.role = role;
        } else if a.role != role {
            self.warnings
                .push("DTLS: the offerer chose its role, the relay takes the other one".to_owned());
        }
        Some(a)
    }

    /// The sections an answer had changed get their sides back.
    fn undo_answer(&mut self, before: &[MediaState]) {
        for st in before {
            let id = st.ports.id;
            for (party, side) in [(Party::B, &st.b_side), (Party::A, &st.a_side)] {
                Self::logged(
                    "undoing a failed answer",
                    id,
                    self.relay.update_side(id, st.leg(party), side),
                );
            }
        }
    }

    /// Refuse an answer section that takes none of the formats it was
    /// offered (RFC 3264 §6.1): every one of its formats a static payload
    /// type (0-95, whose codec RFC 3551 fixes) that neither the offerer
    /// (`offerer`'s latest SDP) nor the relay's transcoding offered.
    /// Dynamic payload types may be renumbered in an answer, so a section
    /// with one passes.
    fn check_formats(session: &Session, offerer: &[u8], answer: &[Media]) -> Result<(), Error> {
        let Some((_, offer_sdp)) = session.sdps.iter().find(|(t, _)| t == offerer) else {
            return Ok(());
        };
        let mut offer = [Media::EMPTY; MAX_MEDIA];
        let Ok(n) = rtpflux_core::sdp::read_media(offer_sdp, &mut offer) else {
            return Ok(());
        };
        for (i, ((m, o), st)) in answer
            .iter()
            .zip(&offer[..n])
            .zip(&session.media)
            .enumerate()
        {
            if m.port == 0 || m.transport == Transport::Other {
                continue;
            }
            let added = st.as_ref().and_then(|st| st.codec).map(|c| c.b_pt);
            let offered = |pt: Pt| o.payload_types.as_slice().contains(&pt) || Some(pt) == added;
            let formats = m.payload_types.as_slice();
            if !formats.is_empty() && formats.iter().all(|&pt| pt.get() < 96 && !offered(pt)) {
                return Err(Error::Sdp(SdpError::FormatsNotOffered { section: i + 1 }));
            }
        }
        Ok(())
    }

    /// Check an answer of dialog `key` before anything changes: it has
    /// the offer's sections, takes offered formats, and its addresses fit
    /// the interface. Returns the dialog's interfaces and the options for
    /// it (a call across interfaces replaces `o=`).
    fn vet_answer(
        &self,
        key: &SessionKey,
        media: &[Media],
        opt: &Opts,
    ) -> Result<([InterfaceId; 2], Opts), Error> {
        let session = self.sessions.get(key).ok_or(Error::NoOffer)?;
        if session.media.len() != media.len() {
            return Err(Error::Sdp(SdpError::SectionCount {
                answer: media.len(),
                offer: session.media.len(),
            }));
        }
        let dir = session.dir;
        let mut opt = super::offer::across(opt, dir);
        opt.strict_source |= self.strict_source;
        Self::check_formats(session, super::base_tag(&key.1), media)?;
        self.check_family(dir[1], media, &opt)?;
        Ok((dir, opt))
    }

    pub(super) fn answer(&mut self, req: &Dict<'_>) -> Result<usize, Error> {
        let plain = (
            required(req, "call-id")?.to_vec(),
            required(req, "from-tag")?.to_vec(),
        );
        // The answer of a forked INVITE's branch: that branch's dialog; of
        // an offer between two parties of a call that are each in another
        // dialog, theirs ([`super::parties`]).
        let key = req
            .get_bytes(b"via-branch")
            .map(|via| super::branch_key(&plain, via))
            .into_iter()
            .chain(
                req.get_bytes(b"to-tag")
                    .map(|to| super::parties::pair_key(&plain, to)),
            )
            .find(|k| self.sessions.contains_key(k))
            .unwrap_or_else(|| plain.clone());
        let sdp = required(req, "sdp")?;
        if let Some(n) = self.looped(req, sdp) {
            return Ok(n);
        }
        // Legacy OSRTP: the answerer's answer to doubled streams, one
        // each; the answer to a doubled offer, doubled again (below).
        let (legacy, folded) = self.legacy_answer(&key, sdp)?;
        let sdp: &[u8] = folded.as_deref().unwrap_or(sdp);
        let opt = opts(req)?;
        self.warnings.extend(super::opts::unknown_options(req));
        let (mut media, count) = Self::read(sdp)?;
        self.passed_through(&key, &mut media[..count]);
        let peers: Vec<Option<IcePeer>> = (0..count).map(|i| ice::peer_of(sdp, i)).collect();
        let (dir, opt) = self.vet_answer(&key, &media[..count], &opt)?;
        let session = self.sessions.get(&key).ok_or(Error::NoOffer)?;
        let mut states = session.media.clone();
        let mut answered = vec![false; count];
        for (i, ((m, st), ok)) in media[..count]
            .iter()
            .zip(&mut states)
            .zip(&mut answered)
            .enumerate()
        {
            if let Some(st) = st.as_mut().filter(|_| m.port != 0) {
                if let Err(e) = self.answer_section(i, m, st, dir[1], &opt) {
                    // The dialog stays as it was: so do the relay calls of
                    // the sections settled so far (and this one).
                    if let Some(session) = self.sessions.get(&key) {
                        let before: Vec<MediaState> = session
                            .media
                            .iter()
                            .take(i + 1)
                            .flatten()
                            .copied()
                            .collect();
                        self.undo_answer(&before);
                    }
                    return Err(e);
                }
                *ok = true;
                self.ice_section_answered(i, st, peers[i].clone());
            }
        }
        let fingerprint = self
            .relay
            .dtls_fingerprint_with(super::offer::fingerprint_hash(&opt, &media[..count]))
            .to_owned();
        let group_ids = if states.iter().flatten().any(MediaState::a_bundled) {
            Self::answer_group_ids(&states, &answered)
        } else {
            Vec::new()
        };
        let mut versions = self
            .sessions
            .get(&key)
            .map_or_else(Vec::new, |s| s.versions.clone());
        let relayed = self.answered_to_a(&states, &answered, &fingerprint, dir[0]);
        let written = self.render(
            req,
            (sdp, &media[..count], dir[0]),
            (&relayed, &group_ids),
            &opt,
            (&mut versions, Some(super::base_tag(&key.1)), false),
        );
        drop(relayed);
        let written = match written {
            Ok(n) if legacy[0].iter().any(|&d| d) => {
                let doubled = super::legacy::unfold_answer(&self.sdp_buf[..n], &legacy[0]);
                self.replace_sdp(&doubled)
            }
            w => w,
        };
        if written.is_ok() {
            self.apply_echo(&states, opt.media_echo, false);
        }
        self.store_answer(&key, states, (req.get_bytes(b"to-tag"), sdp), versions);
        // (The native API's remote re-offer keeps it until its commit.)
        let keep = std::mem::take(&mut self.keep_checkpoint);
        if written.is_ok() && !keep {
            self.commit_checkpoint(&key);
        }
        // (A dialog under a pair key stays there.)
        if written.is_ok() && key != plain && super::parties::peer_of_key(&key.1).is_none() {
            self.promote(&plain, &key);
        }
        written
    }

    /// Branch `branch` of the forked dialog `plain` was answered: it
    /// becomes the dialog (later requests name no branch), and the dialog's
    /// first branch keeps its media under its own branch key, until the
    /// proxy deletes it.
    fn promote(&mut self, plain: &SessionKey, branch: &SessionKey) {
        let Some(answered) = self.sessions.remove(branch) else {
            return;
        };
        if let Some(first) = self.sessions.remove(plain) {
            let via = first.via_branch.clone().unwrap_or_default();
            self.sessions.insert(super::branch_key(plain, &via), first);
        }
        self.sessions.insert(plain.clone(), answered);
    }

    /// What the answer's sections write for A (on interface `toward_a`);
    /// the sections B refused get port 0.
    fn answered_to_a<'a>(
        &self,
        states: &'a [Option<MediaState>],
        answered: &[bool],
        fingerprint: &'a str,
        toward_a: InterfaceId,
    ) -> Vec<Relayed<'a>> {
        states
            .iter()
            .zip(answered)
            .map(|(st, &ok)| match st {
                Some(st) if ok => {
                    let shared = st
                        .group
                        .filter(|_| st.a_bundled())
                        .and_then(|g| states[g].as_ref())
                        .unwrap_or(st);
                    st.towards_a(
                        fingerprint,
                        shared,
                        (
                            self.ice_trickles(shared.ports.id, shared.leg(Party::A)),
                            self.srflx_of(toward_a),
                        ),
                    )
                }
                _ => Relayed::ports(0, 0),
            })
            .collect()
    }

    /// Legacy OSRTP of dialog `key`: which sections were folded and
    /// doubled ([`super::legacy`]), and the answer `sdp` folded back when
    /// the offer to the answerer was doubled.
    fn legacy_answer(
        &self,
        key: &SessionKey,
        sdp: &[u8],
    ) -> Result<(Legacy, Option<Vec<u8>>), Error> {
        let legacy = self
            .sessions
            .get(key)
            .map_or_else(Default::default, |s| s.legacy.clone());
        let folded = if legacy[1].iter().any(|&d| d) {
            Some(super::legacy::fold_answer(sdp, &legacy[1]).ok_or_else(|| {
                Error::unsupported(
                    "OSRTP offer-legacy: the answer does not match the doubled offer".to_owned(),
                )
            })?)
        } else {
            None
        };
        Ok((legacy, folded))
    }

    /// The answer's sections whose ICE is passed through: relayed as they
    /// are (nothing terminated).
    fn passed_through(&self, key: &SessionKey, media: &mut [Media]) {
        if let Some(s) = self.sessions.get(key) {
            for (m, st) in media.iter_mut().zip(&s.media) {
                if st.as_ref().is_some_and(|st| st.passthrough.is_some()) {
                    m.transport = Transport::Other;
                    m.ice = false;
                }
            }
        }
    }

    /// The answered dialog `key`: its sections, the answerer's tag and SDP,
    /// and the `o=` versions; the media timeout applies from now.
    fn store_answer(
        &mut self,
        key: &SessionKey,
        states: Vec<Option<MediaState>>,
        (to_tag, sdp): (Option<&[u8]>, &[u8]),
        mut versions: super::sdp_edits::Versions,
    ) {
        for st in states.iter().flatten() {
            let id = st.ports.id;
            Self::logged("answered", id, self.relay.awaiting_answer(id, None));
        }
        if let Some(session) = self.sessions.get_mut(key) {
            session.media = states;
            // Without a to-tag (the docs require one), keep the known one.
            if let Some(t) = to_tag {
                session.to_tag = Some(t.to_vec());
            }
            if let Some(t) = session.to_tag.clone() {
                session.remember(&t, sdp);
                super::sdp_edits::name_answerer(&mut versions, &t);
            }
            session.versions = versions;
        }
        self.update_holds(key);
    }
}

/// Legacy OSRTP's patterns of a dialog: which of the offerer's sections
/// were folded, which offered to the answerer doubled.
type Legacy = [Vec<bool>; 2];
