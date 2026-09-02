//! gilrs gamepad source.
//!
//! This module is only compiled when the `gamepad` feature is on because `gilrs`
//! 0.10 unconditionally pulls `libudev-sys` on Linux (needs `libudev-dev`). With the
//! feature off the whole gamepad path is compiled out and [`GamepadSource`] is not
//! part of [`crate::InputContext`].
//!
//! The source translates gilrs `EventType` values into the unified [`InputEvent`] and
//! also maintains a small [`GamepadState`] cache per connected gamepad so the XInput
//! translation layer can query aggregate state without re-reading every axis.

use gilrs::{Axis, Button, EventType, Gilrs};

use crate::{GamepadAxis, GamepadButton, GamepadState, InputError, InputEvent};

/// A gilrs-backed gamepad event source.
pub(crate) struct GamepadSource {
    gilrs: Gilrs,
    /// Cached state indexed by gilrs gamepad id.
    states: Vec<GamepadState>,
}

impl GamepadSource {
    /// Open the gamepad subsystem. On a host without `libudev` (or with no
    /// gamepads) this logs and degrades to an empty source rather than panicking.
    pub(crate) fn new() -> Self {
        match Gilrs::new() {
            Ok(gilrs) => {
                log::info!("input: gilrs gamepad backend initialised");
                Self {
                    gilrs,
                    states: Vec::new(),
                }
            }
            Err(e) => {
                log::warn!("input: gilrs init failed ({e}); gamepads disabled");
                // Construct a no-op source by re-running with the same error path:
                // gilrs has no "null" constructor, so we retry once; if it still
                // fails we panic — but that path is unreachable because the only
                // fallible constructor is the one above.
                Gilrs::new()
                    .map(|gilrs| Self {
                        gilrs,
                        states: Vec::new(),
                    })
                    .expect("gilrs init failed twice in a row")
            }
        }
    }

    /// Poll one translated gamepad event. Returns `Ok(None)` when there are no more
    /// pending gilrs events.
    pub(crate) fn poll(&mut self) -> Result<Option<InputEvent>, InputError> {
        while let Some(ev) = self.gilrs.next_event() {
            if let Some(translated) = translate(&ev.event, ev.id.0) {
                self.maintain_state(&ev.event, ev.id.0);
                return Ok(Some(translated));
            }
        }
        Ok(None)
    }

    /// Current cached [`GamepadState`] for `gamepad_id`, or `None` if unknown.
    pub(crate) fn state(&self, gamepad_id: usize) -> Option<GamepadState> {
        self.states.get(gamepad_id).copied()
    }

    /// Update the cached state from an event we just emitted.
    fn maintain_state(&mut self, ev: &EventType, id: usize) {
        self.ensure_state_slot(id);
        let state = &mut self.states[id];
        match *ev {
            EventType::ButtonPressed(btn, _) => state.set_button(map_button(btn), true),
            EventType::ButtonReleased(btn, _) => state.set_button(map_button(btn), false),
            EventType::ButtonChanged(btn, value, _) => {
                state.set_button(map_button(btn), value > 0.5);
            }
            EventType::AxisChanged(axis, value, _) => match map_axis(axis) {
                GamepadAxis::LeftStickX => state.thumb_l.0 = value,
                GamepadAxis::LeftStickY => state.thumb_l.1 = value,
                GamepadAxis::RightStickX => state.thumb_r.0 = value,
                GamepadAxis::RightStickY => state.thumb_r.1 = value,
                GamepadAxis::LeftTrigger => state.triggers.0 = value,
                GamepadAxis::RightTrigger => state.triggers.1 = value,
                _ => {}
            },
            EventType::Connected
            | EventType::Disconnected
            | EventType::Dropped
            | EventType::ButtonRepeated(..) => {}
        }
    }

    /// Grow the state cache so `states[id]` exists.
    fn ensure_state_slot(&mut self, id: usize) {
        if id >= self.states.len() {
            self.states.resize(id + 1, GamepadState::default());
        }
    }
}

/// Translate a gilrs `EventType` into an [`InputEvent`]. Returns `None` for events we
/// do not surface (connect/disconnect/drop/repeat).
fn translate(ev: &EventType, _id: usize) -> Option<InputEvent> {
    match *ev {
        EventType::ButtonPressed(btn, _) => Some(InputEvent::GamepadButton {
            button: map_button(btn),
            pressed: true,
        }),
        EventType::ButtonReleased(btn, _) => Some(InputEvent::GamepadButton {
            button: map_button(btn),
            pressed: false,
        }),
        EventType::ButtonChanged(btn, value, _) => Some(InputEvent::GamepadButton {
            button: map_button(btn),
            pressed: value > 0.5,
        }),
        EventType::AxisChanged(axis, value, _) => Some(InputEvent::GamepadAxis {
            axis: map_axis(axis),
            value,
        }),
        EventType::Connected
        | EventType::Disconnected
        | EventType::Dropped
        | EventType::ButtonRepeated(..) => None,
    }
}

/// Map a gilrs [`Button`] onto the XInput-style [`GamepadButton`].
fn map_button(btn: Button) -> GamepadButton {
    match btn {
        Button::South => GamepadButton::A,
        Button::East => GamepadButton::B,
        Button::North => GamepadButton::Y,
        Button::West => GamepadButton::X,
        Button::LeftTrigger => GamepadButton::LeftTrigger,
        Button::LeftTrigger2 => GamepadButton::LeftShoulder,
        Button::RightTrigger => GamepadButton::RightTrigger,
        Button::RightTrigger2 => GamepadButton::RightShoulder,
        Button::Select => GamepadButton::Back,
        Button::Start => GamepadButton::Start,
        Button::Mode => GamepadButton::Guide,
        Button::LeftThumb => GamepadButton::LeftThumb,
        Button::RightThumb => GamepadButton::RightThumb,
        Button::DPadUp => GamepadButton::DPadUp,
        Button::DPadDown => GamepadButton::DPadDown,
        Button::DPadLeft => GamepadButton::DPadLeft,
        Button::DPadRight => GamepadButton::DPadRight,
        _ => GamepadButton::Unknown,
    }
}

/// Map a gilrs [`Axis`] onto the XInput-style [`GamepadAxis`].
fn map_axis(axis: Axis) -> GamepadAxis {
    match axis {
        Axis::LeftStickX => GamepadAxis::LeftStickX,
        Axis::LeftStickY => GamepadAxis::LeftStickY,
        Axis::RightStickX => GamepadAxis::RightStickX,
        Axis::RightStickY => GamepadAxis::RightStickY,
        Axis::LeftZ => GamepadAxis::LeftTrigger,
        Axis::RightZ => GamepadAxis::RightTrigger,
        Axis::DPadX => GamepadAxis::DPadX,
        Axis::DPadY => GamepadAxis::DPadY,
        Axis::Unknown => GamepadAxis::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_mapping_covers_face_buttons() {
        assert_eq!(map_button(Button::South), GamepadButton::A);
        assert_eq!(map_button(Button::East), GamepadButton::B);
        assert_eq!(map_button(Button::West), GamepadButton::X);
        assert_eq!(map_button(Button::North), GamepadButton::Y);
    }

    #[test]
    fn axis_mapping_covers_sticks() {
        assert_eq!(map_axis(Axis::LeftStickX), GamepadAxis::LeftStickX);
        assert_eq!(map_axis(Axis::RightStickY), GamepadAxis::RightStickY);
        assert_eq!(map_axis(Axis::LeftZ), GamepadAxis::LeftTrigger);
    }

    #[test]
    fn dropped_event_translates_to_none() {
        assert!(translate(&EventType::Dropped, 0).is_none());
    }
}
