//! What a recording is turned into: the audio format, the channels, the
//! sample rate and the bitrate, set in `[recording]` and per call in
//! `start recording`.

use serde::{Deserialize, Serialize};

/// The file a recording ends as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// The packets themselves (pcap), not converted.
    #[default]
    Pcap,
    /// 16-bit PCM WAV.
    Wav,
    /// FLAC (lossless).
    Flac,
    /// Opus in Ogg (RFC 7845).
    Opus,
    /// MP3 (only in builds with the `mp3` feature).
    Mp3,
}

impl Format {
    pub const ALL: [Format; 5] = [
        Format::Pcap,
        Format::Wav,
        Format::Flac,
        Format::Opus,
        Format::Mp3,
    ];

    /// The name in the configuration and in `start recording`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Format::Pcap => "pcap",
            Format::Wav => "wav",
            Format::Flac => "flac",
            Format::Opus => "opus",
            Format::Mp3 => "mp3",
        }
    }

    /// The format of a name (case-insensitive).
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|f| f.name().as_bytes().eq_ignore_ascii_case(name))
    }

    /// The file name extension of the output.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Format::Pcap => "pcap",
            Format::Wav => "wav",
            Format::Flac => "flac",
            Format::Opus => "opus",
            Format::Mp3 => "mp3",
        }
    }

    /// Whether this build can write the format.
    #[must_use]
    pub const fn available(self) -> bool {
        !matches!(self, Format::Mp3) || cfg!(feature = "mp3")
    }

    /// Whether the format has a bitrate (lossy).
    #[must_use]
    pub const fn lossy(self) -> bool {
        matches!(self, Format::Opus | Format::Mp3)
    }
}

/// How the two parties are laid out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channels {
    /// The caller (the dialog's first offerer) on the left, the callee on
    /// the right.
    #[default]
    Stereo,
    /// Both parties mixed into one channel.
    Mono,
}

impl Channels {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Channels::Stereo => "stereo",
            Channels::Mono => "mono",
        }
    }

    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        [Channels::Stereo, Channels::Mono]
            .into_iter()
            .find(|c| c.name().as_bytes().eq_ignore_ascii_case(name))
    }

    /// The number of channels.
    #[must_use]
    pub const fn count(self) -> usize {
        match self {
            Channels::Stereo => 2,
            Channels::Mono => 1,
        }
    }
}

/// The sample rates a recording can have: multiples of G.711's 8 kHz that
/// Opus and MP3 also support.
pub const SAMPLE_RATES: [u32; 4] = [8000, 16_000, 24_000, 48_000];

/// The MP3 bitrates (kbit/s).
pub const MP3_BITRATES: [u32; 16] = [
    8, 16, 24, 32, 40, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
];

/// The Opus bitrates (kbit/s).
pub const OPUS_BITRATES: core::ops::RangeInclusive<u32> = 6..=510;

/// What a recording is turned into when it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub format: Format,
    pub channels: Channels,
    /// Samples per second of the output.
    pub sample_rate: u32,
    /// kbit/s, for Opus and MP3.
    pub bitrate: u32,
    /// Keep the pcap once it is converted.
    pub keep_pcap: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            format: Format::Pcap,
            channels: Channels::Stereo,
            sample_rate: 8000,
            bitrate: 32,
            keep_pcap: false,
        }
    }
}

/// A problem with recording settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// A format this build cannot encode.
    Unavailable(Format),
    /// A sample rate not among [`SAMPLE_RATES`].
    SampleRate(u32),
    /// An MP3 bitrate not among [`MP3_BITRATES`].
    Mp3Bitrate(u32),
    /// An Opus bitrate outside [`OPUS_BITRATES`].
    OpusBitrate(u32),
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::Unavailable(format) => {
                let n = format.name();
                write!(
                    f,
                    "format {n}: this build has no {} support (cargo feature `{n}`)",
                    n.to_uppercase()
                )
            }
            Problem::SampleRate(r) => {
                write!(f, "sample_rate {r}: one of {SAMPLE_RATES:?} is needed")
            }
            Problem::Mp3Bitrate(b) => {
                write!(f, "bitrate {b}: MP3 takes one of {MP3_BITRATES:?} kbit/s")
            }
            Problem::OpusBitrate(b) => write!(f, "bitrate {b}: Opus takes 6 to 510 kbit/s"),
        }
    }
}

impl Settings {
    /// Every problem with the settings.
    #[must_use]
    pub fn problems(&self) -> Vec<Problem> {
        let mut p = Vec::new();
        if !self.format.available() {
            p.push(Problem::Unavailable(self.format));
        }
        if !SAMPLE_RATES.contains(&self.sample_rate) {
            p.push(Problem::SampleRate(self.sample_rate));
        }
        match self.format {
            Format::Mp3 if !MP3_BITRATES.contains(&self.bitrate) => {
                p.push(Problem::Mp3Bitrate(self.bitrate));
            }
            Format::Opus if !OPUS_BITRATES.contains(&self.bitrate) => {
                p.push(Problem::OpusBitrate(self.bitrate));
            }
            _ => {}
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_rules() {
        for f in Format::ALL {
            assert_eq!(
                Format::from_name(f.name().to_uppercase().as_bytes()),
                Some(f)
            );
        }
        assert_eq!(Format::from_name(b"aac"), None);
        assert_eq!(Channels::from_name(b"Mono"), Some(Channels::Mono));
        assert_eq!(Channels::from_name(b"surround"), None);
        assert_eq!((Channels::Stereo.count(), Channels::Mono.count()), (2, 1));
        assert!(Format::Opus.lossy() && !Format::Flac.lossy());
        assert_eq!(Settings::default().problems(), Vec::new());
        let bad = Settings {
            format: Format::Opus,
            sample_rate: 44_100,
            bitrate: 1000,
            ..Settings::default()
        };
        assert_eq!(bad.problems().len(), 2, "{:?}", bad.problems());
        let mp3 = Settings {
            format: Format::Mp3,
            bitrate: 33,
            ..Settings::default()
        };
        let p = mp3.problems();
        assert!(p.contains(&Problem::Mp3Bitrate(33)), "{p:?}");
        assert_eq!(
            p.contains(&Problem::Unavailable(Format::Mp3)),
            !cfg!(feature = "mp3")
        );
        assert!(
            Problem::Mp3Bitrate(33)
                .to_string()
                .starts_with("bitrate 33: MP3 takes one of")
        );
    }
}
