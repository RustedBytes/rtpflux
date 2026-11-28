//! Writing the mixed audio: WAV (16-bit PCM), FLAC, Ogg Opus (RFC 7845)
//! and, with the `mp3` feature, MP3. Each pulls blocks from a [`Pcm`]
//! source (a call's [`Mixer`], or a conference mixer's spool),
//! so memory does not grow with the call's length (FLAC keeps its
//! compressed stream until the end).
//!
//! Each carries the recording's tags ([`super::naming::tags`]) in its own
//! form: a `LIST`/`INFO` chunk (WAV), a `VORBIS_COMMENT` block (FLAC),
//! `OpusTags` comments (Opus), an ID3v2.4 tag (MP3).

#[cfg(doc)]
use super::mix::Mixer;
use super::settings::{Format, Settings};
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

/// Frames pulled per block.
const BLOCK: usize = 4096;

fn other(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Where the audio comes from: frames at the settings' rate and channel
/// count (interleaved).
pub(super) trait Pcm {
    /// Append up to `frames` frames to `out`; returns how many. 0: the
    /// end.
    fn fill(&mut self, frames: usize, out: &mut Vec<i16>) -> usize;
}

impl Pcm for super::mix::Mixer {
    fn fill(&mut self, frames: usize, out: &mut Vec<i16>) -> usize {
        super::mix::Mixer::fill(self, frames, out)
    }
}

/// Tags: (name, value), names in upper case.
pub(super) type Tags = [(String, String)];

/// Write `mixer`'s audio to `path` as `settings` say, with `tags`.
///
/// # Errors
///
/// I/O errors, or an encoder refusing its settings.
pub(super) fn encode(
    mixer: &mut impl Pcm,
    settings: &Settings,
    tags: &Tags,
    path: &Path,
) -> std::io::Result<()> {
    match settings.format {
        Format::Pcap => Ok(()),
        Format::Wav => wav(mixer, settings, tags, path),
        Format::Flac => flac(mixer, settings, tags, path),
        Format::Opus => opus(mixer, settings, tags, path),
        Format::Mp3 => mp3(mixer, settings, tags, path),
    }
}

/// The value of tag `name`, if any.
fn tag<'t>(tags: &'t Tags, name: &str) -> Option<&'t str> {
    tags.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// A WAV `LIST` chunk of type `INFO` (RIFF, Multimedia Programming
/// Interface and Data Specifications 1.0): the title (`INAM`), creation
/// date (`ICRD`), software (`ISFT`), and every tag as `NAME=value` lines in
/// the comment (`ICMT`), INFO having no free-form names.
fn wav_info(tags: &Tags) -> Vec<u8> {
    let mut body = b"INFO".to_vec();
    let mut sub = |id: &[u8; 4], text: &str| {
        let mut v = text.as_bytes().to_vec();
        v.push(0);
        body.extend_from_slice(id);
        body.extend_from_slice(&u32::try_from(v.len()).unwrap_or(0).to_le_bytes());
        body.extend_from_slice(&v);
        if v.len() % 2 == 1 {
            body.push(0);
        }
    };
    if let Some(t) = tag(tags, "TITLE") {
        sub(b"INAM", t);
    }
    if let Some(d) = tag(tags, "DATE") {
        sub(b"ICRD", d);
    }
    if let Some(e) = tag(tags, "ENCODER") {
        sub(b"ISFT", e);
    }
    let comment: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
    sub(b"ICMT", &comment.join("\n"));
    let mut chunk = b"LIST".to_vec();
    chunk.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_le_bytes());
    chunk.extend_from_slice(&body);
    chunk
}

/// A Vorbis comment structure (vendor and `NAME=value` comments), as in
/// FLAC's `VORBIS_COMMENT` block and `OpusTags` (RFC 7845 §5.2).
fn vorbis_comments(tags: &Tags) -> Vec<u8> {
    let vendor = concat!("rtpflux ", env!("CARGO_PKG_VERSION"));
    let mut v = u32::try_from(vendor.len())
        .unwrap_or(0)
        .to_le_bytes()
        .to_vec();
    v.extend_from_slice(vendor.as_bytes());
    let comments: Vec<String> = tags
        .iter()
        .filter(|(k, _)| k != "ENCODER")
        .map(|(k, val)| format!("{k}={val}"))
        .collect();
    v.extend_from_slice(&u32::try_from(comments.len()).unwrap_or(0).to_le_bytes());
    for c in comments {
        v.extend_from_slice(&u32::try_from(c.len()).unwrap_or(0).to_le_bytes());
        v.extend_from_slice(c.as_bytes());
    }
    v
}

/// A FLAC stream header with a `VORBIS_COMMENT` block of `tags` appended
/// as the last metadata block (RFC 9639 §8): the block that was last loses
/// its flag.
fn flac_with_comments(header: &[u8], tags: &Tags) -> std::io::Result<Vec<u8>> {
    let mut out = header.to_vec();
    let mut at = 4; // after "fLaC"
    loop {
        let Some(h) = out.get(at..at + 4) else {
            return Err(other("a FLAC header without a last metadata block"));
        };
        let len = (usize::from(h[1]) << 16) | (usize::from(h[2]) << 8) | usize::from(h[3]);
        if h[0] & 0x80 != 0 {
            out[at] &= 0x7f;
            break;
        }
        at += 4 + len;
    }
    let body = vorbis_comments(tags);
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&n| n < 1 << 24)
        .ok_or_else(|| other("tags too large for FLAC"))?;
    out.push(0x80 | 4);
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.extend_from_slice(&body);
    Ok(out)
}

/// An ID3v2.4 tag (id3.org, ID3 tag version 2.4.0): `TIT2` (title),
/// `TDRC` (recording time), `TSSE` (encoder), and a `TXXX` frame for every
/// other tag; all UTF-8.
#[cfg_attr(not(feature = "mp3"), allow(dead_code))]
fn id3(tags: &Tags) -> Vec<u8> {
    fn syncsafe(n: usize) -> [u8; 4] {
        // 7 bits per octet, the top bit clear (ID3v2.4 §6.2).
        let byte = |shift: u32| u8::try_from((n >> shift) & 0x7f).unwrap_or(0);
        [byte(21), byte(14), byte(7), byte(0)]
    }
    let mut frames = Vec::new();
    let mut frame = |id: &[u8; 4], body: &[u8]| {
        frames.extend_from_slice(id);
        frames.extend_from_slice(&syncsafe(body.len()));
        frames.extend_from_slice(&[0, 0]);
        frames.extend_from_slice(body);
    };
    let text = |v: &str| [&[3u8][..], v.as_bytes()].concat();
    for (k, v) in tags {
        match k.as_str() {
            "TITLE" => frame(b"TIT2", &text(v)),
            "DATE" => frame(b"TDRC", &text(v.trim_end_matches('Z'))),
            "ENCODER" => frame(b"TSSE", &text(v)),
            _ => frame(
                b"TXXX",
                &[&[3u8][..], k.as_bytes(), &[0], v.as_bytes()].concat(),
            ),
        }
    }
    let mut tag = b"ID3\x04\x00\x00".to_vec();
    tag.extend_from_slice(&syncsafe(frames.len()));
    tag.extend_from_slice(&frames);
    tag
}

fn wav(mixer: &mut impl Pcm, settings: &Settings, tags: &Tags, path: &Path) -> std::io::Result<()> {
    let channels = u16::try_from(settings.channels.count()).map_err(other)?;
    let rate = settings.sample_rate;
    let mut w = BufWriter::new(File::create(path)?);
    let mut header = Vec::with_capacity(44);
    header.extend_from_slice(b"RIFF\0\0\0\0WAVEfmt ");
    header.extend_from_slice(&16u32.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&channels.to_le_bytes());
    header.extend_from_slice(&rate.to_le_bytes());
    header.extend_from_slice(&(rate * u32::from(channels) * 2).to_le_bytes());
    header.extend_from_slice(&(channels * 2).to_le_bytes());
    header.extend_from_slice(&16u16.to_le_bytes());
    header.extend_from_slice(b"data\0\0\0\0");
    w.write_all(&header)?;
    let mut block = Vec::with_capacity(BLOCK * 2);
    let mut bytes: u64 = 0;
    loop {
        block.clear();
        if mixer.fill(BLOCK, &mut block) == 0 {
            break;
        }
        for s in &block {
            w.write_all(&s.to_le_bytes())?;
        }
        bytes += block.len() as u64 * 2;
    }
    let info = wav_info(tags);
    let riff = u32::try_from(info.len())
        .ok()
        .and_then(|i| u32::try_from(bytes).ok()?.checked_add(36)?.checked_add(i));
    let (Some(riff), Ok(data)) = (riff, u32::try_from(bytes)) else {
        return Err(other("longer than a WAV file holds"));
    };
    // The tags after the audio (a reader skips chunks it does not know).
    w.write_all(&info)?;
    let mut f = w
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    f.seek(SeekFrom::Start(4))?;
    f.write_all(&riff.to_le_bytes())?;
    f.seek(SeekFrom::Start(40))?;
    f.write_all(&data.to_le_bytes())?;
    f.sync_all()
}

/// The mixer as a FLAC encoder's sample source.
struct FlacSource<'m, P: Pcm> {
    mixer: &'m mut P,
    channels: usize,
    rate: usize,
    block: Vec<i16>,
    wide: Vec<i32>,
}

impl<P: Pcm> flacenc::source::Source for FlacSource<'_, P> {
    fn channels(&self) -> usize {
        self.channels
    }

    fn bits_per_sample(&self) -> usize {
        16
    }

    fn sample_rate(&self) -> usize {
        self.rate
    }

    fn read_samples<F: flacenc::source::Fill>(
        &mut self,
        block_size: usize,
        dest: &mut F,
    ) -> Result<usize, flacenc::error::SourceError> {
        self.block.clear();
        let n = self.mixer.fill(block_size, &mut self.block);
        self.wide.clear();
        self.wide.extend(self.block.iter().map(|&s| i32::from(s)));
        dest.fill_interleaved(&self.wide)?;
        Ok(n)
    }
}

/// FLAC, written frame by frame as it is encoded (not the whole stream in
/// memory first): the header goes first, each frame after it, and the
/// header again at the end with the totals (its size does not change).
fn flac(
    mixer: &mut impl Pcm,
    settings: &Settings,
    tags: &Tags,
    path: &Path,
) -> std::io::Result<()> {
    use flacenc::component::BitRepr as _;
    use flacenc::error::Verify as _;
    use flacenc::source::Source as _;
    use std::io::{Seek as _, SeekFrom};
    let config = flacenc::config::Encoder::default()
        .into_verified()
        .map_err(|(_, e)| other(e))?;
    let block_size = config.block_size;
    let mut source = FlacSource {
        mixer,
        channels: settings.channels.count(),
        rate: settings.sample_rate as usize,
        block: Vec::new(),
        wide: Vec::new(),
    };
    let (channels, rate) = (source.channels(), source.sample_rate());
    let mut stream = flacenc::component::Stream::new(rate, channels, 16).map_err(other)?;
    stream
        .stream_info_mut()
        .set_block_sizes(block_size, block_size)
        .map_err(other)?;
    let header = |stream: &flacenc::component::Stream| -> std::io::Result<Vec<u8>> {
        let mut sink = flacenc::bitsink::ByteSink::new();
        stream.write(&mut sink).map_err(other)?;
        flac_with_comments(sink.as_slice(), tags)
    };
    let mut f = std::io::BufWriter::new(File::create(path)?);
    let first = header(&stream)?;
    f.write_all(&first)?;
    let mut buf = (
        flacenc::source::FrameBuf::with_size(channels, block_size).map_err(other)?,
        flacenc::source::Context::new(16, channels),
    );
    let mut sink = flacenc::bitsink::ByteSink::new();
    loop {
        if source.read_samples(block_size, &mut buf).map_err(other)? == 0 {
            break;
        }
        let number = buf.1.current_frame_number().unwrap_or(0);
        let frame = flacenc::encode_fixed_size_frame(&config, &buf.0, number, stream.stream_info())
            .map_err(other)?;
        stream.stream_info_mut().update_frame_info(&frame);
        sink.clear();
        frame.write(&mut sink).map_err(other)?;
        f.write_all(sink.as_slice())?;
    }
    let info = stream.stream_info_mut();
    info.set_md5_digest(&buf.1.md5_digest());
    info.set_total_samples(buf.1.total_samples());
    // The minimum block size excludes the last block (RFC 9639 §8.2):
    // with fixed blocks it is the block size, even when the last one is
    // shorter (some decoders refuse the file otherwise). Each frame added
    // lowered it to that frame's size, the last one's included.
    info.set_block_sizes(block_size, block_size)
        .map_err(other)?;
    let last = header(&stream)?;
    if last.len() != first.len() {
        return Err(other("the FLAC header changed size"));
    }
    let mut f = f
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&last)?;
    f.sync_all()
}

/// The Ogg Opus identification header (RFC 7845 §5.1).
fn opus_head(channels: u8, pre_skip: u16, rate: u32) -> Vec<u8> {
    let mut h = b"OpusHead".to_vec();
    h.push(1);
    h.push(channels);
    h.extend_from_slice(&pre_skip.to_le_bytes());
    h.extend_from_slice(&rate.to_le_bytes());
    h.extend_from_slice(&0i16.to_le_bytes());
    h.push(0);
    h
}

/// The Ogg Opus comment header (RFC 7845 §5.2): the vendor and the tags.
fn opus_tags(tags: &Tags) -> Vec<u8> {
    let mut t = b"OpusTags".to_vec();
    t.extend_from_slice(&vorbis_comments(tags));
    t
}

fn opus(
    mixer: &mut impl Pcm,
    settings: &Settings,
    tags: &Tags,
    path: &Path,
) -> std::io::Result<()> {
    use ogg::writing::PacketWriteEndInfo;
    let channels = settings.channels.count();
    let rate = settings.sample_rate;
    let mut enc =
        opus_rs::OpusEncoder::new(rate.cast_signed(), channels, opus_rs::Application::Audio)
            .map_err(other)?;
    enc.bitrate_bps = i32::try_from(settings.bitrate * 1000).map_err(other)?;
    // Granule positions count 48 kHz samples (RFC 7845 §4).
    let scale = u64::from(48_000 / rate);
    let pre_skip = u16::try_from(enc.lookahead() as u64 * scale).map_err(other)?;
    let frame = rate as usize / 50;
    let serial = 0x7274_7066; // "rtpf"
    let mut w = ogg::writing::PacketWriter::new(BufWriter::new(File::create(path)?));
    let ch = u8::try_from(channels).map_err(other)?;
    w.write_packet(
        opus_head(ch, pre_skip, rate),
        serial,
        PacketWriteEndInfo::EndPage,
        0,
    )?;
    w.write_packet(opus_tags(tags), serial, PacketWriteEndInfo::EndPage, 0)?;
    let mut pcm = Vec::with_capacity(frame * channels);
    let mut packet = vec![0u8; 4000];
    let mut granule = u64::from(pre_skip);
    let mut pending: Option<(Vec<u8>, u64)> = None;
    loop {
        pcm.clear();
        let n = mixer.fill(frame, &mut pcm);
        if n == 0 {
            break;
        }
        // The last frame is padded; its granule position counts what is real.
        pcm.resize(frame * channels, 0);
        let len = enc.encode_i16(&pcm, frame, &mut packet).map_err(other)?;
        granule += n as u64 * scale;
        if let Some((p, g)) = pending.take() {
            w.write_packet(p, serial, PacketWriteEndInfo::NormalPacket, g)?;
        }
        pending = Some((packet[..len].to_vec(), granule));
    }
    let (last, g) = if let Some(p) = pending {
        p
    } else {
        // No audio: one packet of silence keeps the stream valid.
        pcm.clear();
        pcm.resize(frame * channels, 0);
        let len = enc.encode_i16(&pcm, frame, &mut packet).map_err(other)?;
        (packet[..len].to_vec(), u64::from(pre_skip))
    };
    w.write_packet(last, serial, PacketWriteEndInfo::EndStream, g)?;
    let mut f = w
        .into_inner()
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    f.flush()?;
    f.sync_all()
}

#[cfg(feature = "mp3")]
fn mp3(mixer: &mut impl Pcm, settings: &Settings, tags: &Tags, path: &Path) -> std::io::Result<()> {
    use mp3lame_encoder::{Bitrate, Builder, FlushNoGap, InterleavedPcm, MonoPcm, Quality};
    let bitrate = match settings.bitrate {
        8 => Bitrate::Kbps8,
        16 => Bitrate::Kbps16,
        24 => Bitrate::Kbps24,
        32 => Bitrate::Kbps32,
        40 => Bitrate::Kbps40,
        48 => Bitrate::Kbps48,
        64 => Bitrate::Kbps64,
        80 => Bitrate::Kbps80,
        96 => Bitrate::Kbps96,
        112 => Bitrate::Kbps112,
        128 => Bitrate::Kbps128,
        160 => Bitrate::Kbps160,
        192 => Bitrate::Kbps192,
        224 => Bitrate::Kbps224,
        256 => Bitrate::Kbps256,
        320 => Bitrate::Kbps320,
        b => return Err(other(format!("no MP3 bitrate of {b} kbit/s"))),
    };
    let stereo = settings.channels.count() == 2;
    let mut b = Builder::new().ok_or_else(|| other("LAME cannot start"))?;
    b.set_num_channels(if stereo { 2 } else { 1 })
        .map_err(other)?;
    b.set_sample_rate(settings.sample_rate).map_err(other)?;
    b.set_brate(bitrate).map_err(other)?;
    b.set_quality(Quality::Good).map_err(other)?;
    let mut enc = b.build().map_err(other)?;
    let mut w = BufWriter::new(File::create(path)?);
    w.write_all(&id3(tags))?;
    let mut pcm = Vec::with_capacity(BLOCK * 2);
    let mut out = Vec::new();
    loop {
        pcm.clear();
        if mixer.fill(BLOCK, &mut pcm) == 0 {
            break;
        }
        out.clear();
        out.reserve(mp3lame_encoder::max_required_buffer_size(pcm.len()));
        if stereo {
            enc.encode_to_vec(InterleavedPcm(&pcm), &mut out)
        } else {
            enc.encode_to_vec(MonoPcm(&pcm), &mut out)
        }
        .map_err(other)?;
        w.write_all(&out)?;
    }
    out.clear();
    out.reserve(7200);
    enc.flush_to_vec::<FlushNoGap>(&mut out).map_err(other)?;
    w.write_all(&out)?;
    let f = w
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    f.sync_all()
}

#[cfg(not(feature = "mp3"))]
fn mp3(_: &mut impl Pcm, _: &Settings, _: &Tags, _: &Path) -> std::io::Result<()> {
    Err(other("this build has no MP3 support (cargo feature `mp3`)"))
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    fn tags() -> Vec<(String, String)> {
        vec![
            ("AGENT".into(), "Jane Doe".into()),
            ("ENCODER".into(), "rtpflux".into()),
            ("TITLE".into(), "call (1)".into()),
        ]
    }

    #[test]
    fn flac_gets_a_last_vorbis_comment_block() {
        // "fLaC", then STREAMINFO (34 octets) flagged last.
        let mut h = b"fLaC".to_vec();
        h.extend_from_slice(&[0x80, 0, 0, 34]);
        h.extend_from_slice(&[0; 34]);
        let out = flac_with_comments(&h, &tags()).unwrap();
        assert_eq!(out[4], 0x00, "STREAMINFO is no longer last");
        assert_eq!(out[42], 0x84, "VORBIS_COMMENT, last");
        let len = (usize::from(out[43]) << 16) | (usize::from(out[44]) << 8) | usize::from(out[45]);
        assert_eq!(out.len(), 46 + len);
        let body = String::from_utf8_lossy(&out[46..]);
        assert!(
            body.contains("AGENT=Jane Doe") && body.contains("TITLE=call (1)"),
            "{body}"
        );
        assert!(!body.contains("ENCODER="), "the vendor string says it");
        // The same tags give the same length (the header is rewritten in place).
        assert_eq!(flac_with_comments(&h, &tags()).unwrap().len(), out.len());
    }

    #[test]
    fn wav_info_and_id3_are_well_formed() {
        let info = wav_info(&tags());
        assert_eq!(&info[..4], b"LIST");
        let size = u32::from_le_bytes(info[4..8].try_into().unwrap()) as usize;
        assert_eq!((size + 8, &info[8..12]), (info.len(), &b"INFO"[..]));
        assert!(size.is_multiple_of(2), "chunks are padded to even sizes");
        let s = String::from_utf8_lossy(&info);
        assert!(s.contains("INAM") && s.contains("call (1)") && s.contains("AGENT=Jane Doe"));

        let tag = id3(&tags());
        assert_eq!(&tag[..6], b"ID3\x04\x00\x00");
        let size = tag[6..10]
            .iter()
            .fold(0usize, |n, &b| (n << 7) | usize::from(b));
        assert_eq!(size + 10, tag.len(), "syncsafe size");
        assert!(tag.windows(4).any(|w| w == b"TIT2") && tag.windows(4).any(|w| w == b"TXXX"));
    }
}
