//! Media files for `play media`, converted to the G.711 law the listener
//! receives: RIFF/WAVE at 8 kHz mono (16-bit linear PCM, A-law or μ-law)
//! as it is ([`load_wav`]); anything else symphonia decodes — MP3, FLAC,
//! WAV at another rate or with more channels — mixed down to mono and
//! resampled to 8 kHz ([`load_media`]).

use rtpflux_core::g711::{
    self, ALAW_TO_ULAW, PT_PCMA, PT_PCMU, ULAW_TO_ALAW, linear_to_alaw, linear_to_ulaw,
};
use rtpflux_core::rtp::Pt;

/// Why a media file cannot be played.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// The listener receives no G.711 (announcements are played in it).
    NotG711,
    /// Not a RIFF/WAVE file (and nothing else decodes it).
    NotWave,
    /// A RIFF chunk runs past the end of the file.
    TruncatedChunk,
    /// The `fmt ` chunk is too short.
    ShortFmt,
    /// A WAVE file that is not 8 kHz mono.
    NotMono8k { channels: u16, rate: u32 },
    /// A WAVE encoding other than 16-bit PCM or 8-bit A-law/μ-law.
    UnsupportedWave { tag: u16, bits: u16 },
    /// The `data` chunk comes before `fmt `.
    DataBeforeFmt,
    /// No `data` chunk.
    NoData,
    /// The file decodes to no samples.
    NoAudio,
    /// Not a format the decoder reads (its reason).
    Undecodable(String),
    /// No audio track.
    NoAudioTrack,
    /// The audio track gives no sample rate.
    NoSampleRate,
    /// The track's codec is not decoded here (its reason).
    UnsupportedCodec(String),
}

impl core::fmt::Display for MediaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MediaError::NotG711 => f.write_str("the listener does not receive G.711"),
            MediaError::NotWave => f.write_str("not a RIFF/WAVE file"),
            MediaError::TruncatedChunk => f.write_str("truncated chunk"),
            MediaError::ShortFmt => f.write_str("short fmt chunk"),
            MediaError::NotMono8k { channels, rate } => {
                write!(f, "{channels} channel(s) at {rate} Hz; 8 kHz mono needed")
            }
            MediaError::UnsupportedWave { tag, bits } => {
                write!(f, "WAVE format {tag} with {bits} bits is not supported")
            }
            MediaError::DataBeforeFmt => f.write_str("data before fmt"),
            MediaError::NoData => f.write_str("no data chunk"),
            MediaError::NoAudio => f.write_str("no audio"),
            MediaError::Undecodable(e) => write!(f, "not a media file rtpflux decodes: {e}"),
            MediaError::NoAudioTrack => f.write_str("no audio track"),
            MediaError::NoSampleRate => f.write_str("no sample rate"),
            MediaError::UnsupportedCodec(e) => write!(f, "its codec is not decoded: {e}"),
        }
    }
}

impl std::error::Error for MediaError {}

const WAVE_PCM: u16 = 1;
const WAVE_ALAW: u16 = 6;
const WAVE_ULAW: u16 = 7;

fn le16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// The samples of a WAV file as G.711 codes of payload type `pt` (0 or 8).
///
/// # Errors
///
/// Not RIFF/WAVE, not 8 kHz mono, an encoding other than PCM (16-bit),
/// A-law or μ-law, no data, or `pt` not G.711.
pub fn load_wav(bytes: &[u8], pt: Pt) -> Result<Vec<u8>, MediaError> {
    if pt != PT_PCMU && pt != PT_PCMA {
        return Err(MediaError::NotG711);
    }
    if bytes.get(0..4) != Some(b"RIFF") || bytes.get(8..12) != Some(b"WAVE") {
        return Err(MediaError::NotWave);
    }
    let mut at = 12;
    let mut format = None;
    while let (Some(id), Some(size)) = (bytes.get(at..at + 4), le32(bytes, at + 4)) {
        let size = size as usize;
        let body = bytes
            .get(at + 8..at + 8 + size)
            .ok_or(MediaError::TruncatedChunk)?;
        match id {
            b"fmt " => {
                let (tag, channels, rate, bits) = (
                    le16(body, 0).ok_or(MediaError::ShortFmt)?,
                    le16(body, 2).ok_or(MediaError::ShortFmt)?,
                    le32(body, 4).ok_or(MediaError::ShortFmt)?,
                    le16(body, 14).ok_or(MediaError::ShortFmt)?,
                );
                if channels != 1 || rate != 8000 {
                    return Err(MediaError::NotMono8k { channels, rate });
                }
                format = Some((tag, bits));
            }
            b"data" => {
                return match format {
                    Some((WAVE_PCM, 16)) => Ok(body
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|&s| {
                            let x = i16::from_le_bytes(s);
                            if pt == PT_PCMU {
                                linear_to_ulaw(x)
                            } else {
                                linear_to_alaw(x)
                            }
                        })
                        .collect()),
                    Some((WAVE_ULAW, 8)) if pt == PT_PCMU => Ok(body.to_vec()),
                    Some((WAVE_ALAW, 8)) if pt == PT_PCMA => Ok(body.to_vec()),
                    Some((WAVE_ULAW, 8)) => Ok(convert(&ULAW_TO_ALAW, body)),
                    Some((WAVE_ALAW, 8)) => Ok(convert(&ALAW_TO_ULAW, body)),
                    Some((tag, bits)) => Err(MediaError::UnsupportedWave { tag, bits }),
                    None => Err(MediaError::DataBeforeFmt),
                };
            }
            _ => {}
        }
        at += 8 + size + size % 2;
    }
    Err(MediaError::NoData)
}

fn convert(table: &[u8; 256], codes: &[u8]) -> Vec<u8> {
    let mut out = codes.to_vec();
    g711::transcode(table, &mut out);
    out
}

/// Silence in the law of `pt`.
#[must_use]
pub fn silence(pt: Pt) -> u8 {
    if pt == PT_PCMA { 0xD5 } else { 0xFF }
}

/// A media file as G.711 codes of payload type `pt` (0 or 8): an 8 kHz
/// mono WAV file directly, anything else decoded, mixed down to mono and
/// resampled to 8 kHz.
///
/// # Errors
///
/// `pt` not G.711, or a file that cannot be decoded (or holds no audio).
pub fn load_media(bytes: &[u8], pt: Pt) -> Result<Vec<u8>, MediaError> {
    if pt != PT_PCMU && pt != PT_PCMA {
        return Err(MediaError::NotG711);
    }
    let wav = load_wav(bytes, pt);
    if wav.is_ok() || !bytes.starts_with(b"RIFF") && !looks_decodable(bytes) {
        return wav;
    }
    let (rate, mono) = decode(bytes)?;
    if mono.is_empty() {
        return Err(MediaError::NoAudio);
    }
    let pcm = resample_to_8k(&mono, rate);
    Ok(pcm
        .iter()
        .map(|&x| {
            #[allow(clippy::cast_possible_truncation)]
            let v = (x.clamp(-1.0, 1.0) * 32767.0) as i16;
            if pt == PT_PCMU {
                linear_to_ulaw(v)
            } else {
                linear_to_alaw(v)
            }
        })
        .collect())
}

/// Not WAV but maybe another format: MP3 (an ID3 tag or a frame sync),
/// FLAC, Ogg.
fn looks_decodable(bytes: &[u8]) -> bool {
    bytes.starts_with(b"ID3")
        || bytes.starts_with(b"fLaC")
        || bytes.starts_with(b"OggS")
        || (bytes.len() > 1 && bytes[0] == 0xff && bytes[1] & 0xe0 == 0xe0)
}

/// Decode with symphonia: the sample rate and the samples mixed to mono.
fn decode(bytes: &[u8]) -> Result<(u32, Vec<f32>), MediaError> {
    use symphonia::core::codecs::audio::AudioDecoderOptions;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::formats::TrackType;
    use symphonia::core::formats::probe::Hint;
    use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
    use symphonia::core::meta::MetadataOptions;
    let source = Box::new(std::io::Cursor::new(bytes.to_vec()));
    let mss = MediaSourceStream::new(source, MediaSourceStreamOptions::default());
    let mut format = symphonia::default::get_probe()
        .probe(
            &Hint::new(),
            mss,
            FormatOptions::default(),
            MetadataOptions::default(),
        )
        .map_err(|e| MediaError::Undecodable(e.to_string()))?;
    let track = format
        .default_track(TrackType::Audio)
        .ok_or(MediaError::NoAudioTrack)?;
    let params = track
        .codec_params
        .as_ref()
        .and_then(|p| p.audio())
        .ok_or(MediaError::NoAudioTrack)?
        .clone();
    let id = track.id;
    let rate = params.sample_rate.ok_or(MediaError::NoSampleRate)?;
    let channels = params
        .channels
        .as_ref()
        .map_or(1, symphonia::core::audio::Channels::count)
        .max(1);
    let mut decoder = symphonia::default::get_codecs()
        .make_audio_decoder(&params, &AudioDecoderOptions::default())
        .map_err(|e| MediaError::UnsupportedCodec(e.to_string()))?;
    let mut mono = Vec::new();
    let mut chunk = Vec::new();
    while let Ok(Some(packet)) = format.next_packet() {
        if packet.track_id != id {
            continue;
        }
        let Ok(buf) = decoder.decode(&packet) else {
            continue;
        };
        chunk.resize(buf.samples_interleaved(), 0f32);
        buf.copy_to_slice_interleaved(&mut chunk);
        #[allow(clippy::cast_precision_loss)]
        let scale = 1.0 / channels as f32;
        mono.extend(
            chunk
                .chunks(channels)
                .map(|frame| frame.iter().sum::<f32>() * scale),
        );
    }
    Ok((rate, mono))
}

/// Resample `x` (at `rate`) to 8 kHz: windowed-sinc interpolation, low-pass
/// below 3.8 kHz (and below the input's own band), so that nothing above
/// the telephone band folds back.
fn resample_to_8k(input: &[f32], rate: u32) -> Vec<f32> {
    use std::f64::consts::PI;
    if rate == 8000 {
        return input.to_vec();
    }
    let rate = f64::from(rate);
    let cutoff = 3800f64.min(rate / 2.0 * 0.95) / rate; // cycles per input sample
    let half = (8.0 / cutoff).ceil() / 2.0; // taps each side, in input samples
    let step = rate / 8000.0;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let count = (input.len() as f64 / step).floor() as usize;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        #[allow(clippy::cast_precision_loss)]
        let at = index as f64 * step;
        #[allow(clippy::cast_possible_truncation)]
        let (first, last) = ((at - half).ceil() as i64, (at + half).floor() as i64);
        let mut acc = 0f64;
        for tap in first..=last {
            let Some(&sample) = usize::try_from(tap).ok().and_then(|t| input.get(t)) else {
                continue;
            };
            #[allow(clippy::cast_precision_loss)]
            let dist = at - tap as f64;
            let arg = 2.0 * cutoff * dist;
            let sinc = if arg.abs() < 1e-9 {
                1.0
            } else {
                (PI * arg).sin() / (PI * arg)
            };
            let window = 0.5 + 0.5 * (PI * dist / half).cos();
            acc += f64::from(sample) * 2.0 * cutoff * sinc * window;
        }
        #[allow(clippy::cast_possible_truncation)]
        out.push(acc as f32);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A WAV file of `data` in format `tag` with `bits` per sample.
    pub(crate) fn wav(tag: u16, bits: u16, data: &[u8]) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(
            &u32::try_from(4 + 8 + 16 + 8 + data.len())
                .unwrap()
                .to_le_bytes(),
        );
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&tag.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&8000u32.to_le_bytes());
        w.extend_from_slice(&(8000 * u32::from(bits) / 8).to_le_bytes());
        w.extend_from_slice(&(bits / 8).to_le_bytes());
        w.extend_from_slice(&bits.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        w.extend_from_slice(data);
        w
    }

    #[test]
    fn formats() {
        let pcm: Vec<u8> = [0i16, 1000, -1000]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        assert_eq!(
            load_wav(&wav(1, 16, &pcm), PT_PCMU).unwrap(),
            vec![
                linear_to_ulaw(0),
                linear_to_ulaw(1000),
                linear_to_ulaw(-1000)
            ]
        );
        assert_eq!(
            load_wav(&wav(7, 8, &[0xff, 0x7f]), PT_PCMA).unwrap(),
            vec![0xD5, 0xD5]
        );
        assert_eq!(load_wav(&wav(6, 8, &[1, 2]), PT_PCMA).unwrap(), vec![1, 2]);
        assert!(load_wav(&wav(3, 32, &[0; 8]), PT_PCMU).is_err());
        assert!(load_wav(b"RIFF0000WAVE", PT_PCMU).is_err());
        assert!(load_wav(&wav(1, 16, &pcm), Pt::G722).is_err());
    }

    #[test]
    fn unusable_files_say_why() {
        let err = |bytes: &[u8], pt: Pt| load_wav(bytes, pt).unwrap_err();
        assert_eq!(err(b"MThd", PT_PCMU), MediaError::NotWave);
        // A chunk longer than the file.
        let mut truncated = wav(WAVE_PCM, 16, &[0; 4]);
        truncated.truncate(truncated.len() - 2);
        assert_eq!(err(&truncated, PT_PCMU), MediaError::TruncatedChunk);
        // 16 kHz stereo.
        let mut wide = wav(WAVE_PCM, 16, &[0; 4]);
        wide[22] = 2;
        wide[24..28].copy_from_slice(&16_000u32.to_le_bytes());
        let e = err(&wide, PT_PCMU);
        assert_eq!(
            e,
            MediaError::NotMono8k {
                channels: 2,
                rate: 16_000
            }
        );
        // The reply keeps the reason's words.
        assert_eq!(e.to_string(), "2 channel(s) at 16000 Hz; 8 kHz mono needed");
        // A fmt chunk too short to read.
        let mut short = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
        short.extend_from_slice(&4u32.to_le_bytes());
        short.extend_from_slice(&[1, 0, 1, 0]);
        assert_eq!(err(&short, PT_PCMU), MediaError::ShortFmt);
        // Data before its format, and no data at all.
        let mut data_first = b"RIFF\0\0\0\0WAVEdata".to_vec();
        data_first.extend_from_slice(&2u32.to_le_bytes());
        data_first.extend_from_slice(&[0, 0]);
        assert_eq!(err(&data_first, PT_PCMU), MediaError::DataBeforeFmt);
        let no_data = wav(WAVE_PCM, 16, &[])[..36].to_vec();
        assert_eq!(err(&no_data, PT_PCMU), MediaError::NoData);
        // An odd-sized chunk is padded to an even length.
        let mut odd = b"RIFF\0\0\0\0WAVEjunk".to_vec();
        odd.extend_from_slice(&1u32.to_le_bytes());
        odd.extend_from_slice(&[7, 0]);
        odd.extend_from_slice(&wav(WAVE_ULAW, 8, &[0x11])[12..]);
        assert_eq!(load_wav(&odd, PT_PCMU).unwrap(), [0x11]);
    }

    /// A 16-bit PCM WAV file at `rate` with `channels`, every channel `f`
    /// Hz at half scale, `ms` long.
    fn tone_wav(rate: u32, channels: u16, f: f64, ms: u32) -> Vec<u8> {
        let n = rate * ms / 1000;
        let mut data = Vec::new();
        for i in 0..n {
            #[allow(clippy::cast_possible_truncation)]
            let v = (16_000.0
                * (2.0 * std::f64::consts::PI * f * f64::from(i) / f64::from(rate)).sin())
                as i16;
            for _ in 0..channels {
                data.extend_from_slice(&v.to_le_bytes());
            }
        }
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&u32::try_from(36 + data.len()).unwrap().to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&channels.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * u32::from(channels) * 2).to_le_bytes());
        w.extend_from_slice(&(channels * 2).to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        w.extend_from_slice(&data);
        w
    }

    /// Sign changes and mean power of μ-law codes.
    fn shape(codes: &[u8]) -> (usize, f64) {
        let x: Vec<f64> = codes
            .iter()
            .map(|&c| f64::from(g711::ulaw_to_linear(c)))
            .collect();
        let crossings = x
            .windows(2)
            .filter(|w| (w[0] < 0.0) != (w[1] < 0.0))
            .count();
        #[allow(clippy::cast_precision_loss)]
        let power = x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64;
        (crossings, power)
    }

    #[test]
    fn other_rates_and_channels_are_resampled() {
        // 1 kHz, 48 kHz stereo, one second: 8000 codes, 2000 sign changes.
        let codes = load_media(&tone_wav(48_000, 2, 1000.0, 1000), PT_PCMU).unwrap();
        assert!((7990..=8000).contains(&codes.len()), "{}", codes.len());
        let (crossings, power) = shape(&codes);
        assert!((1990..=2010).contains(&crossings), "{crossings}");
        // Half scale: a power near (16000²)/2.
        assert!((1.0e8..1.6e8).contains(&power), "{power}");
        // 6 kHz is above the band: filtered out, not folded down to 2 kHz.
        let codes = load_media(&tone_wav(48_000, 1, 6000.0, 500), PT_PCMA).unwrap();
        let x: Vec<f64> = codes
            .iter()
            .map(|&c| f64::from(g711::alaw_to_linear(c)))
            .collect();
        #[allow(clippy::cast_precision_loss)]
        let power = x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64;
        assert!(power < 1.0e5, "{power}");
        // Not media at all.
        assert!(load_media(b"hello, world", PT_PCMU).is_err());
    }

    #[cfg(feature = "mp3")]
    #[test]
    fn an_mp3_file_is_played() {
        use mp3lame_encoder::{Builder, FlushNoGap, MonoPcm};
        let pcm: Vec<i16> = (0..44_100)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let v = (16_000.0
                    * (2.0 * std::f64::consts::PI * 500.0 * f64::from(i) / 44_100.0).sin())
                    as i16;
                v
            })
            .collect();
        let mut b = Builder::new().unwrap();
        b.set_num_channels(1).unwrap();
        b.set_sample_rate(44_100).unwrap();
        let mut enc = b.build().unwrap();
        let mut mp3 = Vec::with_capacity(mp3lame_encoder::max_required_buffer_size(pcm.len()));
        enc.encode_to_vec(MonoPcm(&pcm), &mut mp3).unwrap();
        mp3.reserve(7200);
        enc.flush_to_vec::<FlushNoGap>(&mut mp3).unwrap();
        let codes = load_media(&mp3, PT_PCMU).unwrap();
        // About a second (the encoder adds a little), at 500 Hz.
        assert!((7900..8600).contains(&codes.len()), "{}", codes.len());
        let (crossings, _) = shape(&codes);
        assert!((950..1100).contains(&crossings), "{crossings}");
    }
}
