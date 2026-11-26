//! Keys and credentials of an offered or answered section: SRTP (SDES,
//! with its session parameters, and opportunistic SRTP), ICE credentials
//! and DTLS-SRTP roles.

#[allow(clippy::wildcard_imports)]
use super::*;

impl Control {
    /// DTLS-SRTP of both sides for an offered section (RFC 5763 §5): the
    /// relay answers A's `actpass` (or `active`) as the DTLS server and A's
    /// `passive` as the client; towards B it offers `actpass` and learns its
    /// role from the answer (server until then). B's state is kept on a
    /// re-offer.
    pub(super) fn offer_dtls(
        m: &Media,
        b_transport: Transport,
        prev: Option<&MediaState>,
        (dtls, reverse): (Option<DtlsOpt>, Option<DtlsOpt>),
    ) -> Result<(Option<DtlsSide>, Option<DtlsSide>), Error> {
        if b_transport.is_dtls() && dtls == Some(DtlsOpt::Off) {
            return Err(Error::Request(RequestError::DtlsOff));
        }
        let a = if m.transport.is_dtls() {
            let role = match m.setup {
                // `DTLS-reverse=active`: towards DTLS offered with
                // `actpass`, the relay takes the active role.
                None | Some(Setup::Actpass) if reverse == Some(DtlsOpt::Active) => DtlsRole::Client,
                None | Some(Setup::Actpass | Setup::Active) => DtlsRole::Server,
                Some(Setup::Passive) => DtlsRole::Client,
                Some(Setup::Holdconn) => {
                    return Err(Error::Sdp(SdpError::Holdconn));
                }
            };
            Some(DtlsSide {
                role,
                remote: Self::fingerprints(m)?,
            })
        } else {
            None
        };
        let b = match prev {
            Some(p) if p.b_transport == b_transport => p.b_dtls,
            _ => b_transport.is_dtls().then_some(DtlsSide {
                // `active` offered: the relay starts the handshake.
                role: if dtls == Some(DtlsOpt::Active) {
                    DtlsRole::Client
                } else {
                    DtlsRole::Server
                },
                remote: [None; MAX_FINGERPRINTS],
            }),
        };
        Ok((a, b))
    }

    pub(super) fn fingerprints(
        m: &Media,
    ) -> Result<[Option<rtpflux_core::dtls::Fingerprint>; MAX_FINGERPRINTS], Error> {
        if m.fingerprints.iter().all(Option::is_none) {
            return Err(Error::Sdp(SdpError::NoFingerprint));
        }
        Ok(m.fingerprints)
    }

    /// DTLS-SRTP of side B from its answer to an `offered` setup (RFC
    /// 5763 §5: an `active` answerer is the DTLS client, a `passive` one
    /// the server; RFC 4145 §4.1: the answer must fit the offer).
    pub(super) fn answer_dtls(m: &Media, offered: Setup) -> Result<DtlsSide, Error> {
        let answered = m.setup.unwrap_or(Setup::Active);
        if !rtpflux_core::dtls::compatible(offered, answered) {
            return Err(Error::Sdp(SdpError::SetupAnswer(answered)));
        }
        let role = match answered {
            Setup::Active => DtlsRole::Server,
            Setup::Passive => DtlsRole::Client,
            s => {
                return Err(Error::Sdp(SdpError::SetupAnswer(s)));
            }
        };
        Ok(DtlsSide {
            role,
            remote: Self::fingerprints(m)?,
        })
    }

    /// Fresh ICE credentials: `ice-char` is base64's alphabet (RFC 8839
    /// §5.4), so each random octet gives one character without bias.
    pub(super) fn new_ice(&mut self) -> Result<IceCreds, Error> {
        const ICE_CHARS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut raw = [0u8; ICE_UFRAG_LEN + ICE_PWD_LEN];
        self.random_bytes(&mut raw)?;
        let mut c = IceCreds {
            ufrag: [0; ICE_UFRAG_LEN],
            pwd: [0; ICE_PWD_LEN],
            lite: true,
        };
        for (o, r) in c.ufrag.iter_mut().chain(c.pwd.iter_mut()).zip(raw) {
            *o = ICE_CHARS[usize::from(r & 63)];
        }
        Ok(c)
    }

    /// The relay's ICE credentials towards A and B for an offered section:
    /// kept from `prev` on a re-offer, except towards A when A restarts ICE
    /// (`restart_a`). Each says whether the relay is a lite or a full agent
    /// there: the configured mode, or `ICE-lite`.
    pub(super) fn offer_ice(
        &mut self,
        m: &Media,
        o: &Opts,
        prev: Option<&MediaState>,
        restart_a: bool,
        b_transport: Transport,
    ) -> Result<(Option<IceCreds>, Option<IceCreds>), Error> {
        let wanted = match o.ice {
            IcePolicy::Default => m.ice,
            IcePolicy::Remove => false,
            IcePolicy::Force | IcePolicy::ForceRelay | IcePolicy::Optional => true,
        };
        if !wanted {
            return Ok((None, prev.and_then(|p| p.ice_b)));
        }
        // By default ICE goes towards B as well, except when a WebRTC
        // offer (DTLS-SRTP) is bridged to a SIP profile: the phone asked
        // for gets plain SIP media, not the browser's ICE.
        let wanted_b = o.ice == IcePolicy::Force || !m.transport.is_dtls() || b_transport.is_dtls();
        let lite = self.ice_mode == IceMode::Lite;
        let (lite_a, lite_b) = match o.ice_lite {
            None => (lite, lite),
            Some(IceLite::Off) => (false, false),
            Some(IceLite::Both) => (true, true),
            Some(IceLite::Forward) => (false, true),
            Some(IceLite::Backward) => (true, false),
        };
        let fresh = |s: &mut Self, lite: bool| s.new_ice().map(|c| IceCreds { lite, ..c });
        let a = match prev.and_then(|p| p.ice_a) {
            Some(c) if !restart_a => c,
            Some(c) => fresh(self, c.lite)?,
            None => fresh(self, lite_a)?,
        };
        let b = match prev {
            Some(p) => p.ice_b,
            None if wanted_b => Some(fresh(self, lite_b)?),
            None => None,
        };
        Ok((Some(a), b))
    }

    /// A fresh SRTP master key and salt from the system's CSPRNG.
    /// [`Self::new_key`] (or the proxy's `supplied` key) under `policy`
    /// (counter-mode suites only).
    pub(super) fn policed_key(
        &mut self,
        suite: Suite,
        policy: rtpflux_srtp::Policy,
        supplied: Option<MasterKey>,
    ) -> Result<MasterKey, Error> {
        supplied
            .map_or_else(|| self.new_key(suite), Ok)?
            .with_policy(policy)
            .ok_or(Error::Request(RequestError::Sdes(
                "unencrypted and unauthenticated SRTP need an AES_CM suite",
            )))
    }

    pub(super) fn new_key(&mut self, suite: Suite) -> Result<MasterKey, Error> {
        let mut key = [0u8; rtpflux_srtp::MAX_MASTER_LEN];
        let key = &mut key[..suite.master_len()];
        self.random_bytes(key)?;
        MasterKey::new(suite, key).ok_or_else(|| Error::Sdp(SdpError::KeyLength))
    }

    /// Fill `out` from the system's CSPRNG.
    pub(super) fn random_bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if self.random.is_none() {
            self.random =
                Some(std::fs::File::open("/dev/urandom").map_err(Error::io("/dev/urandom"))?);
        }
        self.random
            .as_mut()
            .map_or(Ok(()), |f| f.read_exact(out))
            .map_err(Error::io("/dev/urandom"))
    }

    /// SRTP of both sides for an offered media section, the tag of the
    /// offerer's accepted key, and the further keys offered to B (other
    /// suites, tags from 2); `prev` is the section's state when this is a
    /// re-offer (the relay's keys are kept).
    pub(super) fn offer_srtp(
        &mut self,
        m: &Media,
        b_transport: Transport,
        prev: Option<&MediaState>,
        sdes: &super::opts::SdesOpts,
    ) -> Result<(Srtp, Srtp, u32, AltKeys), Error> {
        let (a_in, a_tag, suite, a_policy) = if m.transport.is_sdes() {
            // With a protection policy asked for, A's lines that declare
            // one are usable too (their keys carry it).
            let lines = if sdes.policy.is_none() {
                &m.cryptos
            } else {
                &m.declared
            };
            let first = lines
                .iter()
                .flatten()
                .next()
                .copied()
                .ok_or(Error::Sdp(SdpError::NoCryptoOffered))?;
            // The `SDES` options choose among A's lines too.
            // `offerer_pref:` ranks A's lines; otherwise A's order.
            let c = if sdes.restricts() || sdes.ranks_offerer() || sdes.nonew {
                lines
                    .iter()
                    .flatten()
                    .filter(|c| sdes.allows(c.key.suite) || sdes.nonew)
                    .min_by_key(|c| sdes.offerer_rank(c.key.suite))
                    .copied()
                    .ok_or(Error::Request(RequestError::Sdes(
                        "none of the offerer's crypto suites is allowed",
                    )))?
            } else {
                first
            };
            (Inbound::Key(c.key), c.tag, c.key.suite, c.key.policy)
        } else {
            (
                Inbound::Plain,
                0,
                Suite::AesCm128HmacSha1_80,
                rtpflux_srtp::Policy::NONE,
            )
        };
        // Towards A, its own line's protection (the answer echoes it).
        let to_a = match prev.and_then(|p| p.a.outbound) {
            _ if !m.transport.is_sdes() => None,
            Some(k) if k.suite == suite && k.policy == a_policy => Some(k),
            _ => Some(self.policed_key(suite, a_policy, None)?),
        };
        // The suite offered to B: A's, unless the `SDES` options rule it
        // out.
        if b_transport.is_sdes() && sdes.off {
            return Err(Error::Request(RequestError::Sdes(
                "off, but the answerer is offered an SDES profile (set transport-protocol)",
            )));
        }
        let b_suite = if b_transport.is_sdes() && !sdes.nonew {
            sdes.pick(suite).ok_or(Error::Request(RequestError::Sdes(
                "the no-/only- options leave no crypto suite",
            )))?
        } else {
            // `nonew` (it takes precedence over no-/only-): A's own.
            suite
        };
        let b = match prev {
            Some(p)
                if p.b_transport == b_transport
                    && (!sdes.restricts()
                        || p.b
                            .outbound
                            .is_none_or(|k| k.suite == b_suite && k.policy == sdes.policy)) =>
            {
                p.b
            }
            _ if b_transport.is_sdes() => Srtp {
                inbound: Inbound::Pending,
                outbound: Some(self.policed_key(b_suite, sdes.policy, sdes.key_for(b_suite))?),
            },
            _ => Srtp::default(),
        };
        // Fresh keys for B: the other allowed suites are offered too, so
        // that B can take one it supports (RFC 4568 §5.1).
        let mut alt: AltKeys = [None; ALT_KEYS];
        let fresh = b_transport.is_sdes() && prev.is_none_or(|p| p.b != b);
        if fresh {
            // `nonew`: only A's other suites (none for a plain A).
            let a_suites = m.cryptos.iter().flatten().map(|c| c.key.suite);
            let others: Vec<Suite> = if sdes.nonew {
                a_suites.filter(|&s| s != b_suite).collect()
            } else {
                sdes.offer_order().filter(|&s| s != b_suite).collect()
            };
            for (slot, (suite, tag)) in alt.iter_mut().zip(others.into_iter().zip(2..)) {
                *slot = Some(Crypto {
                    tag,
                    key: self.policed_key(suite, sdes.policy, sdes.key_for(suite))?,
                });
            }
        }
        let a = Srtp {
            inbound: a_in,
            outbound: to_a,
        };
        Ok((a, b, a_tag, alt))
    }

    /// SRTP of side B from its answer for a section offered as `st`;
    /// `static_keys` (`SDES-static`): a re-offer's answer keeps the keys
    /// agreed.
    pub(super) fn answer_srtp(
        m: &Media,
        st: &MediaState,
        static_keys: bool,
    ) -> Result<Srtp, Error> {
        if static_keys && matches!(st.b.inbound, Inbound::Key(_)) && m.transport.is_sdes() {
            return Ok(st.b);
        }
        // Opportunistic SRTP offered in a plain profile, and taken.
        if !m.transport.is_sdes()
            && let (Some(offered), Some(c)) = (st.osrtp.b, m.crypto)
        {
            return Ok(Srtp {
                inbound: Inbound::Key(c.key),
                outbound: Some(offered),
            });
        }
        if !m.transport.is_sdes() {
            // B declined SRTP (or was never offered it).
            return Ok(Srtp::default());
        }
        let offered =
            st.b.outbound
                .ok_or_else(|| Error::Sdp(SdpError::SrtpNotOffered))?;
        // B echoes the protection offered (a line declaring it, when the
        // relay asked for any).
        let c = if offered.policy.is_none() {
            m.crypto
        } else {
            m.declared
                .iter()
                .flatten()
                .find(|c| c.key.policy == offered.policy)
                .copied()
        }
        .ok_or(Error::Sdp(SdpError::NoCryptoAnswered))?;
        // B took one of the suites offered: the relay's key of that suite.
        let outbound = if c.key.suite == offered.suite {
            offered
        } else {
            st.b_alt
                .iter()
                .flatten()
                .find(|k| k.key.suite == c.key.suite)
                .map_or(offered, |k| k.key)
        };
        Ok(Srtp {
            inbound: Inbound::Key(c.key),
            outbound: Some(outbound),
        })
    }
}

/// Further keys offered to B, one per other suite.
pub(super) const ALT_KEYS: usize = rtpflux_core::sdp::MAX_CRYPTOS - 1;
pub(super) type AltKeys = [Option<Crypto>; ALT_KEYS];

/// Opportunistic SRTP (RFC 8643) of a section, from its offer to its
/// answer: the offerer's `a=crypto` line in a plain profile (`a`) with the
/// relay's key towards it, and the relay's key offered to B in a plain
/// profile (`b`). Neither side uses SRTP until the answer agrees it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Osrtp {
    pub(super) a: Option<(Crypto, MasterKey)>,
    pub(super) b: Option<MasterKey>,
}

impl Control {
    /// The OSRTP of section `m` offered: what A offered, and what B is
    /// offered (when A offered it, or with `OSRTP: offer`, and B gets a
    /// plain profile). SRTP already agreed (`prev`) goes on: `a` and `b`
    /// are updated in place.
    pub(super) fn offer_osrtp(
        &mut self,
        m: &Media,
        b_transport: Transport,
        prev: Option<&MediaState>,
        (offer, a): (bool, &mut Srtp),
    ) -> Result<Osrtp, Error> {
        let plain = |t: Transport| matches!(t, Transport::Avp | Transport::Avpf);
        let mut o = Osrtp::default();
        if plain(m.transport)
            && let Some(c) = m.crypto
        {
            let to_a = match prev.and_then(|p| p.osrtp.a.map(|(_, k)| k).or(p.a.outbound)) {
                Some(k) if k.suite == c.key.suite => k,
                _ => self.new_key(c.key.suite)?,
            };
            o.a = Some((c, to_a));
            // Agreed before with the same key: it goes on.
            if let Some(p) = prev.filter(|p| p.a.inbound == Inbound::Key(c.key)) {
                *a = p.a;
            }
        }
        if plain(b_transport) && (o.a.is_some() || offer) {
            let suite = o.a.map_or(Suite::AesCm128HmacSha1_80, |(c, _)| c.key.suite);
            o.b = Some(match prev.and_then(|p| p.b.outbound.or(p.osrtp.b)) {
                Some(k) if k.suite == suite => k,
                _ => self.new_key(suite)?,
            });
        }
        Ok(o)
    }
}
