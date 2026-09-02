//! evdev keyboard/mouse source.
//!
//! Scans `/dev/input/event*` for readable evdev devices and keeps those that look
//! like keyboards or pointers (devices exposing `KEY` events without absolute axes,
//! or devices exposing relative axes). Pure gamepads (absolute axes, no relative
//! axes) are left to the `gamepad` feature / `gilrs`.
//!
//! Events are buffered: each [`EvdevSource::poll`] call drains one translated
//! [`InputEvent`] from an internal queue, refilling it from all open devices when it
//! empties. The poll never blocks.

use std::fs;
use std::path::Path;

use evdev::raw_stream::RawDevice;
use evdev::{EventType, InputEventKind};

use crate::{InputError, InputEvent, MouseAxis, MouseButton};

/// The evdev button-code threshold: codes `>= 0x100` are mouse/joystick buttons,
/// below are keyboard keys.
const BUTTON_THRESHOLD: u16 = 0x100;

/// The `/dev/input` directory scanned for event devices.
const INPUT_DIR: &str = "/dev/input";

/// An evdev keyboard/mouse event source owning all open devices.
pub(crate) struct EvdevSource {
    devices: Vec<RawDevice>,
    /// Translated events waiting to be handed out by [`EvdevSource::poll`].
    buffer: Vec<InputEvent>,
}

impl EvdevSource {
    /// Open all usable evdev devices. Devices that cannot be opened (permission
    /// denied, no `/dev/input`) are silently skipped so the source degrades to
    /// "no devices" on a headless / unprivileged host.
    pub(crate) fn new() -> Self {
        let mut devices = Vec::new();
        if let Ok(entries) = fs::read_dir(INPUT_DIR) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !is_event_device(&path) {
                    continue;
                }
                match RawDevice::open(&path) {
                    Ok(dev) if looks_like_keyboard_or_pointer(&dev) => devices.push(dev),
                    Ok(_) => { /* a gamepad or other non-kb/pointer device — skip */ }
                    Err(e) => {
                        log::debug!("input: skipping {}: {e}", path.display());
                    }
                }
            }
        }
        log::info!(
            "input: opened {} evdev keyboard/pointer device(s)",
            devices.len()
        );
        Self {
            devices,
            buffer: Vec::new(),
        }
    }

    /// Poll one translated event. Returns `Ok(None)` when every device is drained.
    pub(crate) fn poll(&mut self) -> Result<Option<InputEvent>, InputError> {
        if self.buffer.is_empty() {
            self.refill()?;
        }
        Ok(self.buffer.pop())
    }

    /// Drain raw events from every open device into the translated buffer.
    fn refill(&mut self) -> Result<(), InputError> {
        for dev in &mut self.devices {
            let events = match dev.fetch_events() {
                Ok(it) => it,
                Err(e) => {
                    // A transient read error on one device should not kill the whole
                    // source; log and continue.
                    log::debug!("input: fetch_events error: {e}");
                    continue;
                }
            };
            for ev in events {
                if let Some(translated) = translate(&ev) {
                    self.buffer.push(translated);
                }
            }
        }
        Ok(())
    }
}

/// True if `path` looks like `/dev/input/eventN`.
fn is_event_device(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.starts_with("event") && name["event".len()..].chars().all(|c| c.is_ascii_digit())
}

/// Classify a device as a keyboard or pointer: keep it if it has relative axes (a
/// mouse/touchpad) or if it has key events but no absolute axes (a keyboard, not a
/// gamepad).
fn looks_like_keyboard_or_pointer(dev: &RawDevice) -> bool {
    let events = dev.supported_events();
    let has_rel = events.contains(EventType::RELATIVE);
    let has_key = events.contains(EventType::KEY);
    let has_abs = events.contains(EventType::ABSOLUTE);
    // Mice/touchpads: relative axes (keep even if they also have ABS, e.g. touchpads).
    // Keyboards: key events, no absolute axes (excludes gamepads, which have ABS).
    has_rel || (has_key && !has_abs)
}

/// Translate one raw evdev event into an [`InputEvent`]. Returns `None` for event
/// types we do not surface (sync, misc, absolute, etc.).
fn translate(ev: &evdev::InputEvent) -> Option<InputEvent> {
    match ev.kind() {
        InputEventKind::Key(key) => {
            let code = key.0;
            if code >= BUTTON_THRESHOLD {
                // A mouse / joystick button.
                Some(InputEvent::MouseButton {
                    button: MouseButton::from_code(code),
                    pressed: ev.value() != 0,
                })
            } else {
                Some(InputEvent::Key {
                    code,
                    pressed: ev.value() != 0,
                })
            }
        }
        InputEventKind::RelAxis(axis) => translate_rel_axis(axis.0, ev.value()),
        // Synchronization, misc, absolute axes, etc. are not surfaced in Phase 1.
        _ => None,
    }
}

/// Map a relative-axis event to a mouse-move or mouse-axis event.
fn translate_rel_axis(code: u16, value: i32) -> Option<InputEvent> {
    match code {
        0x00 => Some(InputEvent::MouseMove { x: value, y: 0 }), // REL_X
        0x01 => Some(InputEvent::MouseMove { x: 0, y: value }), // REL_Y
        0x08 => Some(InputEvent::MouseAxis {
            axis: MouseAxis::Wheel,
            value,
        }), // REL_WHEEL
        0x06 => Some(InputEvent::MouseAxis {
            axis: MouseAxis::HWheel,
            value,
        }), // REL_HWHEEL
        // High-res wheel variants map onto the same logical axes.
        0x0b => Some(InputEvent::MouseAxis {
            axis: MouseAxis::Wheel,
            value,
        }),
        0x0c => Some(InputEvent::MouseAxis {
            axis: MouseAxis::HWheel,
            value,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_device_filter() {
        assert!(is_event_device(Path::new("/dev/input/event0")));
        assert!(is_event_device(Path::new("/dev/input/event12")));
        assert!(!is_event_device(Path::new("/dev/input/mouse0")));
        assert!(!is_event_device(Path::new("/dev/input/js0")));
    }

    #[test]
    fn rel_axis_mapping() {
        assert_eq!(
            translate_rel_axis(0x00, 5),
            Some(InputEvent::MouseMove { x: 5, y: 0 })
        );
        assert_eq!(
            translate_rel_axis(0x01, -3),
            Some(InputEvent::MouseMove { x: 0, y: -3 })
        );
        assert_eq!(
            translate_rel_axis(0x08, 1),
            Some(InputEvent::MouseAxis {
                axis: MouseAxis::Wheel,
                value: 1,
            })
        );
        assert!(translate_rel_axis(0xff, 0).is_none());
    }

    #[test]
    fn empty_source_polls_none() {
        let mut src = EvdevSource::new();
        // On a host without /dev/input access this is empty; on a host with devices it
        // may yield events, so just assert poll never errors.
        assert!(src.poll().is_ok());
    }
}
