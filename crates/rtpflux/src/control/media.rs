//! One relayed media section of a dialog: its state, and the codec plan of
//! a transcoding offer.

#[allow(clippy::wildcard_imports)]
use super::*;

/// One relayed media section of a dialog.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // Independent per-section facts.
pub(super) struct MediaState {
    pub(super) ports: CallPorts,
    /// The offerer's (A's) profile, and the tag of its accepted key.
    pub(super) a_transport: Transport,
    pub(super) a_tag: u32,
    /// The profile offered to the answerer (B).
    pub(super) b_transport: Transport,
    /// SRTP of each side (the relay's keys are kept across re-offers).
    pub(super) a: Srtp,
    pub(super) b: Srtp,
    /// The relay's further SDES keys offered to B (other suites), until
    /// its answer takes one.
    pub(super) b_alt: super::keys::AltKeys,
    /// Opportunistic SRTP offered, until the answer.
    pub(super) osrtp: super::keys::Osrtp,
    /// ICE passed through (`ICE=force-relay`, `optional`).
    pub(super) passthrough: Option<super::opts::Passthrough>,
    /// Side A as the relay knows it (to update it when the answer
    /// settles `rtcp-mux`).
    pub(super) a_side: Side,
    /// A offered `rtcp-mux`.
    pub(super) a_mux: bool,
    /// RTCP is multiplexed towards A, and towards B (RFC 5761): by
    /// default both once B accepted what A offered; the `rtcp-mux` option
    /// (`policy`) can make them differ.
    pub(super) mux: bool,
    pub(super) b_mux: bool,
    /// The `rtcp-mux` option of the latest offer.
    pub(super) mux_policy: MuxPolicy,
    /// The `a=setup` offered to B (`actpass` unless `DTLS=passive` or
    /// `active`), which its answer must fit (RFC 4145 §4.1).
    pub(super) b_setup: Setup,
    /// A offered `actpass` (or no `a=setup`): the relay's role towards it
    /// is the relay's choice, so `DTLS=active|passive` at the answer can
    /// set it.
    pub(super) a_actpass: bool,
    /// The packet time (ms) the relay repacketises to towards A and
    /// towards B (`ptime`, `ptime-reverse`), from the latest offer.
    pub(super) ptime: [Option<u16>; 2],
    /// The relay's ICE-lite credentials towards A and towards B.
    pub(super) ice_a: Option<IceCreds>,
    pub(super) ice_b: Option<IceCreds>,
    /// DTLS-SRTP with A and with B.
    pub(super) a_dtls: Option<DtlsSide>,
    pub(super) b_dtls: Option<DtlsSide>,
    /// Side B as the relay knows it.
    pub(super) b_side: Side,
    /// The payload types the bundled endpoint sends (BUNDLE sorting).
    pub(super) payload_types: sdp::PayloadTypes,
    /// The offerer's `a=mid`.
    pub(super) mid: Option<Mid>,
    /// The original offerer (the relay call's A leg) is in a BUNDLE group
    /// whose transport is that of this media section index (itself for
    /// the first member). That is side A, or side B once `flipped`.
    pub(super) group: Option<usize>,
    /// Side A (the latest offerer) is the relay call's B leg: the
    /// answerer re-offered (RFC 3261 §14.1, either party may re-INVITE),
    /// so the dialog's roles were swapped.
    pub(super) flipped: bool,
    /// Transcoding offered to B for this section (until the answer).
    pub(super) codec: Option<CodecPlan>,
    /// The answer's format change towards A (transcoding chosen by B).
    pub(super) a_formats: Option<FormatEdit>,
    /// The G.711 law (payload type) A and B receive, once answered.
    pub(super) a_law: Option<Pt>,
    pub(super) b_law: Option<Pt>,
    /// The audio (payload type, codec) A and B receive, once answered, in
    /// a codec the relay converts (DTMF tones are made and found in it).
    pub(super) audio: [Option<(Pt, Codec)>; 2],
    /// The Opus payload types of A's offer and B's answer (recordings
    /// decode them).
    pub(super) opus: [Option<Pt>; 2],
    /// DTMF transcoding offered, and the answer's format change towards A
    /// it settled on.
    pub(super) dtmf_plan: Option<DtmfPlan>,
    pub(super) te_toward_a: Option<FormatEdit>,
    /// The same for AMR and AMR-WB (recordings decode them).
    pub(super) amr: [Option<Pt>; 2],
    pub(super) amr_wb: [Option<Pt>; 2],
}

/// A party of a dialog as its latest offer or answer sees it: `A`, the
/// latest offerer, or `B`, the answerer. Which relay call leg each is
/// turns on who offered last ([`MediaState::leg`]); the relay knows only
/// legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Party {
    A,
    B,
}

impl Party {
    /// `B` when `b` (as parties are written in the state file).
    pub(super) const fn of_b(b: bool) -> Party {
        if b { Party::B } else { Party::A }
    }

    pub(super) const fn is_b(self) -> bool {
        matches!(self, Party::B)
    }

    /// 0 for `A`, 1 for `B` (per-party arrays).
    pub(super) const fn index(self) -> usize {
        match self {
            Party::A => 0,
            Party::B => 1,
        }
    }

    pub(super) const fn other(self) -> Party {
        match self {
            Party::A => Party::B,
            Party::B => Party::A,
        }
    }
}

/// Transcoding offered for a section (`relay::codecs`).
pub(super) use crate::relay::codecs::CodecPlan;
use rtpflux_core::rtp::Pt;

/// The plan for a section `m` offered under `codecs`.
pub(super) fn codec_plan(m: &Media, codecs: CodecOpts) -> Option<CodecPlan> {
    // A dynamic codec the offer already names (a=rtpmap) is not added.
    if codecs.transcode.is_some_and(|b| m.dynamic_pt(b).is_some()) {
        return None;
    }
    let mut offer: Vec<(Pt, Option<Codec>)> = m
        .payload_types
        .as_slice()
        .iter()
        .map(|&pt| (pt, m.codec_of(pt)))
        .filter(|(_, c)| !c.is_some_and(|c| codecs.ignore.contains(&Some(c))))
        .collect();
    // `accept`: that codec first, so the relay transcodes from it.
    if let Some(a) = codecs.accept {
        offer.sort_by_key(|(_, c)| *c != Some(a));
    }
    let mask: Vec<Codec> = codecs.mask.iter().flatten().copied().collect();
    crate::relay::codecs::plan(&offer, codecs.transcode, &mask).map(|p| CodecPlan {
        opus_bitrate: codecs.opus_bitrate,
        // Towards A in A's AMR: a mode its `mode-set` takes; towards B: as
        // asked, checked against B's answer ([`answered_amr`]).
        amr_bitrate: [
            codecs
                .amr_bitrate_of(p.a)
                .filter(|&bps| amr_allows(m, p.a_pt, p.a, bps)),
            codecs.amr_bitrate_of(p.b),
        ],
        ..p
    })
}

/// Whether the AMR `mode-set` of `pt` in `m` takes the mode of `bps`.
fn amr_allows(m: &Media, pt: Pt, codec: Codec, bps: u32) -> bool {
    codec.amr_mode_of(bps).is_some_and(|mode| {
        m.amr_fmtp
            .iter()
            .flatten()
            .find(|f| f.pt == pt)
            .is_none_or(|f| f.allows(mode))
    })
}

/// The plan settled by B's answer `m`: an AMR bitrate towards B only if
/// B's `mode-set` takes it.
pub(super) fn answered_amr(plan: CodecPlan, m: &Media) -> CodecPlan {
    CodecPlan {
        amr_bitrate: [
            plan.amr_bitrate[0],
            plan.amr_bitrate[1].filter(|&bps| amr_allows(m, plan.b_pt, plan.b, bps)),
        ],
        ..plan
    }
}

/// `codec` options: a codec to offer B in addition (transcoded), and
/// codecs to withhold from B.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CodecOpts {
    pub(super) transcode: Option<Codec>,
    pub(super) mask: [Option<Codec>; 2],
    /// `codec: accept`: the offerer's codec the relay transcodes from (its
    /// first convertible one otherwise).
    pub(super) accept: Option<Codec>,
    /// `codec: ignore`: the offerer's codecs treated as never offered.
    pub(super) ignore: [Option<Codec>; 4],
    /// `opus/<rate>/<channels>/<bitrate>` in `transcode` or `set`: the
    /// relay's Opus encoder's bitrate.
    pub(super) opus_bitrate: Option<u32>,
    /// The same for AMR and AMR-WB: one of their modes' bitrates.
    pub(super) amr_bitrate: Option<u32>,
    pub(super) amr_wb_bitrate: Option<u32>,
    /// `transcode: telephone-event`: offer telephone events to B when A has
    /// none, and convert (DTMF transcoding).
    pub(super) telephone_event: bool,
}

impl CodecOpts {
    /// The bitrate asked for an AMR `codec`.
    pub(super) fn amr_bitrate_of(self, codec: Codec) -> Option<u32> {
        match codec {
            Codec::Amr => self.amr_bitrate,
            Codec::AmrWb => self.amr_wb_bitrate,
            _ => None,
        }
    }
}

/// DTMF transcoding offered for a section (`relay::xcode`).
pub(super) type DtmfPlan = crate::relay::xcode::Plan;

/// The plan for a section `m` offered under `codecs` and `always
/// transcode`.
pub(super) fn dtmf_plan(m: &Media, codecs: CodecOpts, always: bool) -> Option<DtmfPlan> {
    let audio: Vec<Pt> = m
        .payload_types
        .as_slice()
        .iter()
        .copied()
        .filter(|&pt| m.codec_of(pt).is_some_and(crate::codec::converts))
        .collect();
    crate::relay::xcode::plan(
        m.payload_types.as_slice(),
        &audio,
        m.telephone_event,
        codecs.telephone_event,
        always,
    )
}

/// SRTP of a side keyed by DTLS: nothing passes until the keys exist.
pub(super) const DTLS_PENDING: Srtp = Srtp {
    inbound: Inbound::Pending,
    outbound: None,
};

impl MediaState {
    /// The relay as a relay candidate of a section passed through.
    fn relay_candidate(&self) -> Option<sdp::RelayCandidate> {
        self.passthrough.map(|p| sdp::RelayCandidate {
            rtcp: !self.a_mux,
            drop_relay: p == super::opts::Passthrough::DropRelays,
        })
    }

    /// Whether the relay offers B `rtcp-mux`.
    pub(super) fn mux_offered_b(&self) -> bool {
        match self.mux_policy {
            MuxPolicy::Default | MuxPolicy::Accept => self.a_mux,
            MuxPolicy::Offer | MuxPolicy::Require => true,
            MuxPolicy::Demux | MuxPolicy::Reject => false,
        }
    }

    /// `rtcp-mux` towards A and towards B once B answered, `answered`
    /// being its `a=rtcp-mux` (RFC 5761 §5.1.1: only when offered and
    /// accepted, on each side).
    pub(super) fn settle_mux(&self, answered: bool) -> (bool, bool) {
        let b = self.mux_offered_b() && (answered || self.mux_policy == MuxPolicy::Require);
        let a = match self.mux_policy {
            MuxPolicy::Default | MuxPolicy::Offer | MuxPolicy::Require => self.a_mux && b,
            MuxPolicy::Demux | MuxPolicy::Accept => self.a_mux,
            MuxPolicy::Reject => false,
        };
        (a, b)
    }

    /// The relay call's leg of `party`: the same leg unless the answerer
    /// re-offered (`flipped`).
    pub(super) fn leg(&self, party: Party) -> CallLeg {
        CallLeg::of_b(party.is_b() != self.flipped)
    }

    /// A section restored from the state file on the relay call `ports`.
    pub(super) fn restored(
        ports: CallPorts,
        m: &state::SavedMedia,
        a_side: &Side,
        b_side: &Side,
    ) -> Self {
        let mut types = sdp::PayloadTypes::EMPTY;
        // Payload types as written in the state file: those above 127
        // (never written by the relay) are left out.
        for pt in m.payload_types.iter().copied().filter_map(Pt::new) {
            types.push(pt);
        }
        MediaState {
            ports,
            a_transport: Transport::parse(m.a_transport.as_bytes()),
            a_tag: m.a_tag,
            b_transport: Transport::parse(m.b_transport.as_bytes()),
            a: a_side.srtp,
            b: b_side.srtp,
            b_alt: [None; super::keys::ALT_KEYS],
            osrtp: super::keys::Osrtp::default(),
            passthrough: None,
            a_side: *a_side,
            a_mux: m.a_mux,
            mux: m.mux,
            b_mux: b_side.rtcp_mux,
            mux_policy: MuxPolicy::Default,
            b_setup: Setup::Actpass,
            a_actpass: true,
            ptime: [None; 2],
            ice_a: a_side.ice,
            ice_b: b_side.ice,
            a_dtls: a_side.dtls,
            b_dtls: b_side.dtls,
            b_side: *b_side,
            payload_types: types,
            mid: m.mid.as_deref().and_then(|t| Mid::new(t.as_bytes())),
            group: m.group,
            flipped: m.flipped,
            codec: None,
            a_formats: None,
            a_law: m.laws.0.and_then(Pt::new),
            b_law: m.laws.1.and_then(Pt::new),
            audio: [0, 1].map(|k| {
                m.audio[k].as_ref().and_then(|(pt, name)| {
                    Some((Pt::new(*pt)?, Codec::from_name(name.as_bytes())?))
                })
            }),
            opus: m.opus.map(|p| p.and_then(Pt::new)),
            amr: m.amr.map(|p| p.and_then(Pt::new)),
            amr_wb: m.amr_wb.map(|p| p.and_then(Pt::new)),
            dtmf_plan: None,
            te_toward_a: None,
        }
    }

    /// Swap the roles: the answerer becomes side A, the offerer side B.
    /// The relay's keys towards each endpoint stay; the new offerer's key
    /// and tag come with its offer.
    pub(super) fn flip(&mut self) {
        use core::mem::swap;
        swap(&mut self.ports.a, &mut self.ports.b);
        swap(&mut self.a_transport, &mut self.b_transport);
        swap(&mut self.a, &mut self.b);
        self.b_alt = [None; super::keys::ALT_KEYS];
        self.osrtp = super::keys::Osrtp::default();
        swap(&mut self.a_side, &mut self.b_side);
        swap(&mut self.ice_a, &mut self.ice_b);
        swap(&mut self.a_dtls, &mut self.b_dtls);
        self.codec = None;
        self.a_formats = None;
        self.dtmf_plan = None;
        self.te_toward_a = None;
        swap(&mut self.a_law, &mut self.b_law);
        self.audio.swap(0, 1);
        self.opus.swap(0, 1);
        self.amr.swap(0, 1);
        self.amr_wb.swap(0, 1);
        swap(&mut self.mux, &mut self.b_mux);
        self.a_mux = self.mux;
        self.mux_policy = MuxPolicy::Default;
        self.b_setup = Setup::Actpass;
        self.a_actpass = true;
        self.ptime = [None; 2];
        self.a_tag = 1;
        self.flipped = !self.flipped;
    }

    /// Settle the codecs from B's answer `m`: the law each side receives,
    /// and the answer's format change towards A. Returns the plan when B
    /// took the law only the relay offered (transcode both ways; A is
    /// answered with its own law).
    pub(super) fn settle_codecs(&mut self, m: &Media) -> Option<CodecPlan> {
        let first = m.payload_types.as_slice().first().copied();
        let (xcode, toward_a) = crate::relay::codecs::settle(self.codec, first);
        let b_law = first.filter(|&p| p == PT_PCMU || p == PT_PCMA);
        self.b_law = b_law;
        let b_audio =
            first.and_then(|pt| Some((pt, m.codec_of(pt).filter(|&c| crate::codec::converts(c))?)));
        self.audio = [
            match xcode {
                Some(c) => crate::codec::converts(c.a).then_some((c.a_pt, c.a)),
                None => b_audio,
            },
            b_audio,
        ];
        self.opus[1] = m.opus;
        self.amr[1] = m.amr;
        self.amr_wb[1] = m.amr_wb;
        // Only G.711 is a law (announcements are played in it).
        self.a_law = match xcode {
            Some(c) => c.a.static_pt().filter(|&p| p == PT_PCMU || p == PT_PCMA),
            None => b_law,
        };
        self.a_formats = toward_a;
        xcode
    }

    /// Settle DTMF transcoding from B's answer `m` (after the codecs): what
    /// A's and B's DTMF become, and the answer's format change towards A.
    pub(super) fn settle_dtmf(&mut self, m: &Media) -> (Option<DtmfXcode>, Option<DtmfXcode>) {
        use crate::relay::xcode::{Edit, settle};
        let x = settle(
            self.dtmf_plan,
            m.telephone_event,
            self.audio[0],
            self.audio[1],
        );
        self.te_toward_a = x.toward_a.map(|e| match e {
            Edit::Remove(pt) => FormatEdit::Remove(pt),
            Edit::Append(pt) => FormatEdit::Append(pt),
        });
        (x.a, x.b)
    }

    /// Side A is bundled (it offered BUNDLE).
    pub(super) fn a_bundled(&self) -> bool {
        self.group.is_some() && !self.flipped
    }

    /// Side B is bundled: it offered BUNDLE, then the other party
    /// re-offered.
    pub(super) fn b_bundled(&self) -> bool {
        self.group.is_some() && self.flipped
    }

    /// Whether this section's bundled side is another section's transport.
    pub(super) fn bundled_member(&self, index: usize) -> bool {
        self.group.is_some_and(|g| g != index)
    }

    /// Whether the relay changes this section's media rather than passing
    /// it through: SRTP keys of its own or DTLS on either side,
    /// transcoding offered or chosen, or a BUNDLE group to sort. The
    /// worker drops ZRTP for such a call, and the SDP loses `a=zrtp-hash`.
    pub(super) fn transforms(&self, shared: &MediaState) -> bool {
        !self.a.is_plain()
            || !self.b.is_plain()
            || shared.a_dtls.is_some()
            || shared.b_dtls.is_some()
            || self.codec.is_some()
            || self.a_formats.is_some()
            || self.group.is_some()
    }

    /// What the relay writes into the SDP for side B (the offer). `shared`
    /// is the section whose transport B uses: itself, or, when B is
    /// bundled, the first member of its group (as in [`Self::towards_a`]).
    pub(super) fn towards_b<'a>(
        &'a self,
        fingerprint: &'a str,
        shared: &'a MediaState,
        (trickle, srflx): (bool, Option<IpAddr>),
    ) -> Relayed<'a> {
        let bundled = self.b_bundled();
        Relayed {
            transport: (self.b_transport != Transport::Other).then_some(self.b_transport),
            // SDES, or opportunistic SRTP offered in a plain profile.
            crypto: self
                .b
                .outbound
                .or(self.osrtp.b)
                .map(|key| Crypto { tag: 1, key }),
            more_crypto: &self.b_alt,
            dtls: shared.b_dtls.map(|_| DtlsAttrs {
                setup: shared.b_setup,
                fingerprint,
            }),
            // B has not answered: offer an RTCP candidate as well.
            ice: shared.ice_b.as_ref().map(|c| IceAttrs {
                ufrag: &c.ufrag,
                pwd: &c.pwd,
                rtcp_candidate: !bundled && self.mux_policy != MuxPolicy::Require,
                candidates: self.ports.id == shared.ports.id,
                lite: c.lite,
                trickle: trickle && !c.lite,
                srflx,
            }),
            mid: if bundled {
                self.mid.as_ref().map(Mid::as_bytes)
            } else {
                None
            },
            // `rtcp-mux` as the policy has it: A's line passes when A
            // offered it, the relay writes it when A did not, and drops A's
            // when it splits RTCP towards B.
            rtcp_mux: bundled || (self.mux_offered_b() && !self.a_mux),
            drop_rtcp_mux: !self.mux_offered_b(),
            // No separate RTCP port advertised to a B taken to multiplex.
            rtcp_attr: if self.mux_policy == MuxPolicy::Require {
                sdp::RtcpAttr::Omit
            } else {
                sdp::RtcpAttr::AsInput
            },
            formats: [
                self.codec.map(CodecPlan::towards_b),
                match self.dtmf_plan {
                    Some(DtmfPlan::Offered(pt)) => Some(FormatEdit::Append(pt)),
                    _ => None,
                },
            ],
            dynamic: self.codec.and_then(|c| c.dynamic()[1]),
            telephone_event: match self.dtmf_plan {
                Some(DtmfPlan::Offered(pt)) => Some(pt),
                _ => None,
            },
            strip_zrtp: self.transforms(shared),
            ptime: self.ptime[1],
            passthrough: self.relay_candidate(),
            ..Relayed::ports(shared.ports.b.port(), shared.ports.b.port() + 1)
        }
    }

    /// What the relay writes into the SDP for side A (the answer).
    /// `shared` is the section whose transport A uses: itself, or the
    /// first member of its BUNDLE group (RFC 8843 §7.3: one port; the
    /// transport attributes in every member, candidates only in the first).
    pub(super) fn towards_a<'a>(
        &'a self,
        fingerprint: &'a str,
        shared: &'a MediaState,
        (trickle, srflx): (bool, Option<IpAddr>),
    ) -> Relayed<'a> {
        let bundled = self.a_bundled();
        let first = self.ports.id == shared.ports.id;
        Relayed {
            transport: (self.a_transport != Transport::Other).then_some(self.a_transport),
            crypto: self.a.outbound.map(|key| Crypto {
                tag: self.a_tag,
                key,
            }),
            dtls: shared.a_dtls.map(|d| DtlsAttrs {
                setup: match d.role {
                    DtlsRole::Server => Setup::Passive,
                    DtlsRole::Client => Setup::Active,
                },
                fingerprint,
            }),
            ice: shared.ice_a.as_ref().map(|c| IceAttrs {
                ufrag: &c.ufrag,
                pwd: &c.pwd,
                rtcp_candidate: !self.mux && !bundled,
                candidates: first,
                lite: c.lite,
                trickle: trickle && !c.lite,
                srflx,
            }),
            mid: if bundled {
                self.mid.as_ref().map(Mid::as_bytes)
            } else {
                None
            },
            // Answering for a bundled B: A gets `rtcp-mux` only if it
            // offered it, and no `a=mid` (it offered none).
            rtcp_mux: bundled || (self.b_bundled() && self.mux) || (self.mux && !self.b_mux),
            // B's line goes when the relay does not multiplex towards A.
            drop_rtcp_mux: !self.mux,
            unbundle: self.b_bundled(),
            formats: [self.a_formats, self.te_toward_a],
            dynamic: self.codec.and_then(|c| c.dynamic()[0]),
            telephone_event: match self.te_toward_a {
                Some(FormatEdit::Append(pt)) => Some(pt),
                _ => None,
            },
            strip_zrtp: self.transforms(shared),
            ptime: self.ptime[0],
            passthrough: self.relay_candidate(),
            ..Relayed::ports(shared.ports.a.port(), shared.ports.a.port() + 1)
        }
    }
}
