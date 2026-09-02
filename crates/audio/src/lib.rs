//! Audio output for the compatibility layer.
//!
//! Workstream D — host-facing crate. Exposes an [`AudioSink`] trait that the Win32
//! audio workstream (XAudio2 / WASAPI) will translate Win32 audio calls onto.
//!
//! # Backends
//!
//! The **default** build is a no-op [`NullSink`] so the crate compiles with **no**
//! system audio packages on this host. The real backends are opt-in features:
//!
//! - **cpal** (feature `cpal`, **off by default**): the [`CpalSink`] opens the
//!   default output stream via cpal's ALSA backend. Requires `libasound2-dev` to
//!   build (`alsa.pc` must be on the pkg-config path). The feature is off by default
//!   because ALSA dev headers are absent on this build host; the explicit fallback
//!   policy keeps the workspace green without extra system packages.
//! - **pipewire** (feature `pipewire`, **off by default**): a documented stub.
//!   `pipewire` needs `libpipewire-0.3-dev`, which is also absent on this host. See
//!   [`PipeWireSink`].
//!
//! With the default feature set the crate compiles and tests pass with no system
//! audio packages installed. Pick a backend at construction time via [`default_sink`]
//! (returns the best available, falling back to [`NullSink`]).

#[cfg(feature = "cpal")]
mod cpal_sink;

use thiserror::Error;

/// Audio sink errors.
#[derive(Debug, Error)]
pub enum AudioError {
    /// The selected backend could not be initialised (no device, no permission,
    /// host stream build failure, ...).
    #[error("audio backend error: {0}")]
    Backend(String),
    /// A frame was written with the wrong channel count for this sink.
    #[error("frame size {got} is not a multiple of {channels} channels")]
    BadFrameSize { got: usize, channels: u16 },
}

/// A sink that consumes interleaved `f32` PCM frames.
///
/// This is the trait the XAudio2 / WASAPI translation layer writes into. `frames` is
/// a flat slice of `f32` samples in `[−1.0, 1.0]`, interleaved by channel — i.e. a
/// stereo frame is `[L, R, L, R, ...]`. Implementations are responsible for feeding
/// the host backend at the right sample rate / channel count.
pub trait AudioSink {
    /// Sample rate in Hz.
    fn sample_rate(&self) -> u32;
    /// Channel count (1 = mono, 2 = stereo, ...).
    fn channels(&self) -> u16;

    /// Append interleaved `f32` frames to the backend's buffer.
    ///
    /// `frames.len()` must be a multiple of [`channels`](AudioSink::channels); a
    /// non-multiple returns [`AudioError::BadFrameSize`].
    fn write_frames(&mut self, frames: &[f32]) -> Result<(), AudioError>;

    /// Start the output stream. Idempotent: calling on an already-running sink is a
    /// no-op.
    fn start(&mut self) -> Result<(), AudioError>;

    /// Stop the output stream. Idempotent.
    fn stop(&mut self) -> Result<(), AudioError>;
}

/// A no-op sink that drops all audio. Always succeeds and needs no system packages.
///
/// This is the default backend so the crate — and the whole workspace — builds
/// without ALSA or PipeWire headers installed.
#[derive(Debug, Default)]
pub struct NullSink {
    sample_rate: u32,
    channels: u16,
}

impl NullSink {
    /// Create a `NullSink` configured for `sample_rate` Hz and `channels` channels.
    pub fn new(sample_rate: u32, channels: u16) -> Self {
        Self {
            sample_rate,
            channels: channels.max(1),
        }
    }
}

impl AudioSink for NullSink {
    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
    fn channels(&self) -> u16 {
        self.channels
    }
    fn write_frames(&mut self, frames: &[f32]) -> Result<(), AudioError> {
        check_frame_size(frames, self.channels)?;
        // NullSink discards audio; it never errors.
        Ok(())
    }
    fn start(&mut self) -> Result<(), AudioError> {
        Ok(())
    }
    fn stop(&mut self) -> Result<(), AudioError> {
        Ok(())
    }
}

/// Validate that a flat `f32` buffer is a whole number of frames for `channels`.
fn check_frame_size(frames: &[f32], channels: u16) -> Result<(), AudioError> {
    let ch = u32::from(channels.max(1));
    if ch == 0 {
        return Ok(());
    }
    let got = frames.len() as u32;
    if !got.is_multiple_of(ch) {
        return Err(AudioError::BadFrameSize {
            got: frames.len(),
            channels,
        });
    }
    Ok(())
}

/// Crate-public alias of [`check_frame_size`] for use from backend modules.
#[cfg(feature = "cpal")]
pub(crate) fn check_frame_size_pub(frames: &[f32], channels: u16) -> Result<(), AudioError> {
    check_frame_size(frames, channels)
}

/// Construct the best available audio sink for the configured features.
///
/// Resolution order (highest precedence first):
/// 1. `pipewire` feature on → [`PipeWireSink`] (stub for now → falls through).
/// 2. `cpal` feature on → [`CpalSink`].
/// 3. [`NullSink`] (always available).
///
/// `sample_rate` / `channels` describe the format the caller intends to write; the
/// chosen sink may negotiate with the host if it cannot match exactly.
pub fn default_sink(sample_rate: u32, channels: u16) -> Result<Box<dyn AudioSink>, AudioError> {
    #[cfg(feature = "cpal")]
    if let Ok(sink) = cpal_sink::CpalSink::new(sample_rate, channels) {
        return Ok(Box::new(sink));
    }
    // Everything else, and every feature-off path, falls back to the null sink.
    Ok(Box::new(NullSink::new(sample_rate, channels)))
}

/// PipeWire sink stub.
///
/// The real PipeWire backend (via the `pipewire` crate) is gated behind the
/// `pipewire` feature and not implemented in Phase 1 because `pipewire` needs
/// `libpipewire-0.3-dev` system headers, which are absent on this host. This type
/// exists so downstream code can be written against a stable name; constructing it
/// always returns [`AudioError::Backend`]. To enable it: install
/// `libpipewire-0.3-dev`, flip the `pipewire` feature on, and replace this stub with
/// a real `pipewire` implementation.
#[derive(Debug)]
pub struct PipeWireSink;

impl PipeWireSink {
    /// Always returns an error in Phase 1.
    pub fn new(_sample_rate: u32, _channels: u16) -> Result<Self, AudioError> {
        Err(AudioError::Backend(
            "pipewire backend not implemented (install libpipewire-0.3-dev and enable the \
             `pipewire` feature)"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_sink_reports_format() {
        let s = NullSink::new(48000, 2);
        assert_eq!(s.sample_rate(), 48000);
        assert_eq!(s.channels(), 2);
    }

    #[test]
    fn null_sink_accepts_aligned_frames() {
        let mut s = NullSink::new(48000, 2);
        // 4 samples = 2 stereo frames.
        assert!(s.write_frames(&[0.0; 4]).is_ok());
    }

    #[test]
    fn null_sink_rejects_misaligned_frames() {
        let mut s = NullSink::new(48000, 2);
        // 3 samples is not a multiple of 2 channels.
        let err = s.write_frames(&[0.0, 0.0, 0.0]).unwrap_err();
        assert!(matches!(
            err,
            AudioError::BadFrameSize {
                got: 3,
                channels: 2
            }
        ));
    }

    #[test]
    fn default_sink_falls_back_to_null() {
        // With no audio features enabled (the default) we always get a working sink.
        let mut sink = default_sink(44100, 2).unwrap();
        assert_eq!(sink.sample_rate(), 44100);
        assert_eq!(sink.channels(), 2);
        assert!(sink.write_frames(&[0.0; 8]).is_ok());
        assert!(sink.start().is_ok());
        assert!(sink.stop().is_ok());
    }

    #[test]
    fn pipewire_sink_is_stub() {
        assert!(PipeWireSink::new(48000, 2).is_err());
    }
}
