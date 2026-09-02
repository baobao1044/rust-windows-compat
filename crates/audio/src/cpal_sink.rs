//! cpal (ALSA) audio sink.
//!
//! Opens the default output device at the requested sample rate / channel count (or
//! the device's default config if an exact match is unavailable) and feeds it from a
//! shared ring buffer that [`CpalSink::write_frames`] appends to.
//!
//! Only compiled when the `cpal` feature is on. The feature requires
//! `libasound2-dev` (`alsa.pc`) to build.

use std::sync::{Arc, Mutex};
use std::vec::VecDeque;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{BufferSize, SampleRate, Stream, StreamConfig};

use crate::{AudioError, AudioSink};

/// A cpal-backed audio sink.
pub(crate) struct CpalSink {
    sample_rate: u32,
    channels: u16,
    /// Shared buffer the cpal callback drains.
    buffer: Arc<Mutex<VecDeque<f32>>>,
    stream: Option<Stream>,
}

impl CpalSink {
    /// Open the default output device and a stream draining `buffer`.
    pub(crate) fn new(sample_rate: u32, channels: u16) -> Result<Self, AudioError> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or_else(|| AudioError::Backend("no default output device".into()))?;

        // Negotiate a config close to the caller's request.
        let default_cfg = device
            .default_output_config()
            .map_err(|e| AudioError::Backend(e.to_string()))?;
        let sample_rate = if sample_rate > 0 {
            sample_rate
        } else {
            default_cfg.sample_rate().0
        };
        let channels = if channels > 0 {
            channels
        } else {
            default_cfg.channels()
        };

        let config = StreamConfig {
            channels,
            sample_rate: SampleRate(sample_rate),
            buffer_size: BufferSize::Default,
        };

        let buffer: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::with_capacity(8192)));
        let stream = build_stream(&device, &config, Arc::clone(&buffer))?;

        Ok(Self {
            sample_rate,
            channels,
            buffer,
            stream: Some(stream),
        })
    }
}

impl AudioSink for CpalSink {
    fn sample_rate(&self) -> u32 {
        self.sample_rate
    }
    fn channels(&self) -> u16 {
        self.channels
    }

    fn write_frames(&mut self, frames: &[f32]) -> Result<(), AudioError> {
        crate::check_frame_size_pub(frames, self.channels)?;
        let mut buf = self.buffer.lock().expect("audio buffer poisoned");
        for &s in frames {
            buf.push_back(s);
        }
        Ok(())
    }

    fn start(&mut self) -> Result<(), AudioError> {
        if let Some(stream) = &self.stream {
            stream
                .play()
                .map_err(|e| AudioError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), AudioError> {
        if let Some(stream) = &self.stream {
            stream
                .pause()
                .map_err(|e| AudioError::Backend(e.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for CpalSink {
    fn drop(&mut self) {
        // Dropping the stream stops and frees it.
        self.stream.take();
    }
}

/// Build a cpal output stream that fills its buffer from `shared`.
fn build_stream(
    device: &cpal::Device,
    config: &StreamConfig,
    shared: Arc<Mutex<VecDeque<f32>>>,
) -> Result<Stream, AudioError> {
    let err_cb = |e: cpal::StreamError| {
        log::error!("audio: cpal stream error: {e}");
    };
    let stream = device
        .build_output_stream::<f32, _, _>(
            config,
            move |data: &mut [f32], _info| {
                let mut buf = shared.lock().expect("audio buffer poisoned");
                for slot in data.iter_mut() {
                    *slot = buf.pop_front().unwrap_or(0.0);
                }
            },
            err_cb,
            None,
        )
        .map_err(|e| AudioError::Backend(e.to_string()))?;
    Ok(stream)
}
