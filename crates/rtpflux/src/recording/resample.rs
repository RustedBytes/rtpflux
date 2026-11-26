//! Raising 8 or 16 kHz audio to a multiple of its rate: zero-stuffing and a
//! windowed-sinc low-pass filter, in polyphase form. The filter keeps a
//! little history, so one stream's packets join without clicks.

/// Taps per output phase.
const TAPS_PER_PHASE: usize = 16;

/// An integer-ratio upsampler for one stream.
#[derive(Debug, Clone)]
pub(super) struct Upsampler {
    factor: usize,
    /// `factor` phases of `TAPS_PER_PHASE` coefficients each.
    phases: Vec<[f32; TAPS_PER_PHASE]>,
    /// The latest input samples, newest first.
    history: [f32; TAPS_PER_PHASE],
}

impl Upsampler {
    /// An upsampler by `factor` (1 passes samples through).
    pub(super) fn new(factor: usize) -> Self {
        let factor = factor.max(1);
        let n = factor * TAPS_PER_PHASE;
        // Cut off at 45% of the input rate (3.6 kHz for 8 kHz G.711, which
        // carries up to about 3.4 kHz), as a fraction of the output rate;
        // Hann-windowed, gain `factor` for the zeros stuffed.
        #[allow(clippy::cast_precision_loss)]
        let cutoff = 0.45 / factor as f64;
        #[allow(clippy::cast_precision_loss)]
        let center = (n - 1) as f64 / 2.0;
        let mut taps = vec![0f64; n];
        for (i, t) in taps.iter_mut().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let x = i as f64 - center;
            let sinc = if x == 0.0 {
                2.0 * cutoff
            } else {
                (2.0 * std::f64::consts::PI * cutoff * x).sin() / (std::f64::consts::PI * x)
            };
            #[allow(clippy::cast_precision_loss)]
            let window = 0.5 - 0.5 * (2.0 * std::f64::consts::PI * i as f64 / (n - 1) as f64).cos();
            *t = sinc * window;
        }
        let sum: f64 = taps.iter().sum();
        #[allow(clippy::cast_precision_loss)]
        let gain = factor as f64 / sum;
        let mut phases = vec![[0f32; TAPS_PER_PHASE]; factor];
        for (i, t) in taps.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                phases[i % factor][i / factor] = (t * gain) as f32;
            }
        }
        Upsampler {
            factor,
            phases,
            history: [0.0; TAPS_PER_PHASE],
        }
    }

    /// Append `factor` output samples per input sample to `out`.
    pub(super) fn process(&mut self, input: &[i16], out: &mut Vec<i16>) {
        if self.factor == 1 {
            out.extend_from_slice(input);
            return;
        }
        for &x in input {
            self.history.copy_within(..TAPS_PER_PHASE - 1, 1);
            self.history[0] = f32::from(x);
            for phase in &self.phases {
                let y: f32 = phase.iter().zip(&self.history).map(|(h, s)| h * s).sum();
                #[allow(clippy::cast_possible_truncation)]
                out.push(y.round().clamp(-32_768.0, 32_767.0) as i16);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root-mean-square of `s`.
    #[allow(clippy::cast_precision_loss)]
    fn rms(s: &[i16]) -> f64 {
        (s.iter().map(|&x| f64::from(x).powi(2)).sum::<f64>() / s.len() as f64).sqrt()
    }

    #[test]
    fn keeps_speech_band_tones_and_their_level() {
        for factor in [2, 3, 6] {
            let mut up = Upsampler::new(factor);
            #[allow(clippy::cast_possible_truncation)]
            let tone: Vec<i16> = (0..8000)
                .map(|i| {
                    (10_000.0 * (2.0 * std::f64::consts::PI * 1000.0 * f64::from(i) / 8000.0).sin())
                        as i16
                })
                .collect();
            let mut out = Vec::new();
            up.process(&tone, &mut out);
            assert_eq!(out.len(), 8000 * factor);
            // Past the filter's start-up, the level is the input's.
            let ratio = rms(&out[out.len() / 2..]) / rms(&tone[tone.len() / 2..]);
            assert!((0.9..1.1).contains(&ratio), "factor {factor}: {ratio}");
        }
        let mut same = Upsampler::new(1);
        let mut out = Vec::new();
        same.process(&[1, -2, 3], &mut out);
        assert_eq!(out, [1, -2, 3]);
    }
}
