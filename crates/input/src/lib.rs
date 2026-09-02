//! Keyboard, mouse, and gamepad input for the compatibility layer.
//!
//! Workstream D — host-facing crate. Reads the Linux input subsystem directly and
//! exposes a unified [`InputEvent`] stream that the Win32 input workstream (user32 /
//! XInput) translates into Win32 messages and XInput state.
//!
//! # Backends
//!
//! - **evdev** (feature `evdev`, **on by default**): keyboard and mouse via the
//!   `evdev` crate. The workspace dep is pulled in with `default-features = false` so
//!   it does **not** drag in `libudev-sys` (which would need `libudev-dev`, absent on
//!   this host). Devices are discovered by scanning `/dev/input/event*` and opened
//!   with [`evdev::RawDevice::open`]; only keyboard- and pointer-class devices are
//!   kept.
//! - **gamepad** (feature `gamepad`, **off by default**): gamepads via `gilrs`.
//!   `gilrs` 0.10 unconditionally depends on `libudev-sys` on Linux, so enabling this
//!   feature requires `libudev-dev`. With it off, gamepad code paths compile to
//!   no-ops and [`InputContext`] still builds and runs.
//!
//! With the default feature set the crate compiles with **no** system libraries.
//! Opening evdev devices needs read permission on `/dev/input/event*` at runtime; on
//! a headless or unprivileged host [`InputContext::new`] simply finds no devices and
//! [`InputContext::poll`] returns an empty stream, so the crate and its example stay
//! CI-friendly.

#[cfg(feature = "evdev")]
mod evdev_backend;
#[cfg(feature = "gamepad")]
mod gamepad_backend;

use thiserror::Error;

/// A logical mouse button. Matches the WSI / X11 1-indexed convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MouseButton {
    Left = 1,
    Middle = 2,
    Right = 3,
    Other = 4,
}

impl MouseButton {
    /// Build a [`MouseButton`] from an evdev button code (1-indexed).
    pub fn from_code(code: u16) -> Self {
        match code {
            0x110 => MouseButton::Left,   // BTN_LEFT
            0x112 => MouseButton::Middle, // BTN_MIDDLE
            0x111 => MouseButton::Right,  // BTN_RIGHT
            _ => MouseButton::Other,
        }
    }
}

/// A relative/absolute mouse axis identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MouseAxis {
    /// Relative X movement (evdev `REL_X`).
    RelX,
    /// Relative Y movement (evdev `REL_Y`).
    RelY,
    /// Wheel (evdev `REL_WHEEL`).
    Wheel,
    /// Horizontal wheel (evdev `REL_HWHEEL`).
    HWheel,
}

/// A gamepad button, mapped onto the XInput face-button layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamepadButton {
    A,
    B,
    X,
    Y,
    LeftShoulder,
    RightShoulder,
    LeftTrigger,
    RightTrigger,
    Start,
    Back,
    LeftThumb,
    RightThumb,
    DPadUp,
    DPadDown,
    DPadLeft,
    DPadRight,
    Guide,
    Unknown,
}

/// A gamepad axis, mapped onto the XInput thumb/trigger layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamepadAxis {
    LeftStickX,
    LeftStickY,
    RightStickX,
    RightStickY,
    LeftTrigger,
    RightTrigger,
    DPadX,
    DPadY,
    Unknown,
}

/// The unified input event the rest of the compatibility layer consumes.
///
/// Coordinates and axis values are in the host's native units; the Win32 layer
/// translates them to its own coordinate space.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputEvent {
    /// A keyboard key transition. `code` is the Linux evdev keycode (e.g. `KEY_A`
    /// = 0x1e).
    Key { code: u16, pressed: bool },
    /// A mouse button transition.
    MouseButton { button: MouseButton, pressed: bool },
    /// Relative pointer motion in device units.
    MouseMove { x: i32, y: i32 },
    /// A mouse axis delta (wheel, etc.).
    MouseAxis { axis: MouseAxis, value: i32 },
    /// A gamepad button transition.
    GamepadButton {
        button: GamepadButton,
        pressed: bool,
    },
    /// A gamepad axis update. `value` is normalised to `[-1.0, 1.0]` (triggers to
    /// `[0.0, 1.0]`).
    GamepadAxis { axis: GamepadAxis, value: f32 },
}

/// XInput-style aggregate gamepad state.
///
/// Mirrors the fields a Win32 `XINPUT_STATE.Gamepad` carries so the XInput
/// translation layer can read it without re-deriving it every frame. Thumbsticks and
/// triggers are normalised; sticks have a deadzone applied by [`GamepadState::apply`].
#[derive(Debug, Clone, Copy, Default)]
pub struct GamepadState {
    /// Left thumb stick, `(x, y)` in `[-1.0, 1.0]`.
    pub thumb_l: (f32, f32),
    /// Right thumb stick, `(x, y)` in `[-1.0, 1.0]`.
    pub thumb_r: (f32, f32),
    /// Analog triggers: `(left, right)` in `[0.0, 1.0]`.
    pub triggers: (f32, f32),
    /// Bitset of pressed buttons (see [`GamepadButton`]).
    pub buttons: u16,
}

/// The XInput-style stick deadzone (square magnitude below which a stick reads as
/// zero). Matches the XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE constant scaled to the
/// normalised `[-1, 1]` range.
pub const STICK_DEADZONE: f32 = 0.24f32;

/// The XInput-style trigger deadzone below which a trigger reads as zero.
pub const TRIGGER_DEADZONE: f32 = 0.06f32;

impl GamepadState {
    /// Apply XInput-style deadzones to a raw `(x, y)` stick reading, returning the
    /// rescaled vector or `(0.0, 0.0)` if inside the deadzone.
    pub fn apply_deadzone(x: f32, y: f32) -> (f32, f32) {
        let mag = (x * x + y * y).sqrt();
        if mag <= STICK_DEADZONE {
            (0.0, 0.0)
        } else {
            // Rescale so the edge of the deadzone maps to 0 and the outer rim to 1.
            let scale = (mag - STICK_DEADZONE) / (1.0 - STICK_DEADZONE) / mag;
            (x * scale, y * scale)
        }
    }

    /// Apply the trigger deadzone: values below [`TRIGGER_DEADZONE`] read as zero.
    pub fn apply_trigger_deadzone(v: f32) -> f32 {
        if v.abs() < TRIGGER_DEADZONE {
            0.0
        } else {
            v
        }
    }

    /// Set a button bit in `self.buttons`.
    pub fn set_button(&mut self, button: GamepadButton, pressed: bool) {
        let bit = button_bit(button);
        if pressed {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
    }

    /// True if a button is currently pressed.
    pub fn is_pressed(&self, button: GamepadButton) -> bool {
        self.buttons & button_bit(button) != 0
    }
}

/// Map a [`GamepadButton`] to its bit position in `GamepadState::buttons`.
fn button_bit(button: GamepadButton) -> u16 {
    match button {
        GamepadButton::A => 1 << 0,
        GamepadButton::B => 1 << 1,
        GamepadButton::X => 1 << 2,
        GamepadButton::Y => 1 << 3,
        GamepadButton::LeftShoulder => 1 << 4,
        GamepadButton::RightShoulder => 1 << 5,
        GamepadButton::LeftTrigger => 1 << 6,
        GamepadButton::RightTrigger => 1 << 7,
        GamepadButton::Start => 1 << 8,
        GamepadButton::Back => 1 << 9,
        GamepadButton::LeftThumb => 1 << 10,
        GamepadButton::RightThumb => 1 << 11,
        GamepadButton::DPadUp => 1 << 12,
        GamepadButton::DPadDown => 1 << 13,
        GamepadButton::DPadLeft => 1 << 14,
        GamepadButton::DPadRight => 1 << 15,
        GamepadButton::Guide | GamepadButton::Unknown => 0,
    }
}

/// Errors from the input layer.
#[derive(Debug, Error)]
pub enum InputError {
    /// A low-level evdev/gilrs error.
    #[error("input backend error: {0}")]
    Backend(String),
}

/// A polling input context that drains keyboard, mouse, and gamepad events.
///
/// Construct with [`InputContext::new`], which discovers devices best-effort: on a
/// host without `/dev/input` permissions or with no gamepads, the context is simply
/// empty and [`InputContext::poll`] yields nothing. It never panics.
pub struct InputContext {
    #[cfg(feature = "evdev")]
    evdev: evdev_backend::EvdevSource,
    #[cfg(feature = "gamepad")]
    gamepad: gamepad_backend::GamepadSource,
}

impl InputContext {
    /// Open all available input devices.
    ///
    /// Always succeeds — device-open failures are logged and skipped so the context
    /// degrades gracefully on headless / unprivileged hosts.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "evdev")]
            evdev: evdev_backend::EvdevSource::new(),
            #[cfg(feature = "gamepad")]
            gamepad: gamepad_backend::GamepadSource::new(),
        }
    }

    /// Poll for one pending input event without blocking. Returns `Ok(None)` when all
    /// sources are drained.
    pub fn poll(&mut self) -> Result<Option<InputEvent>, InputError> {
        #[cfg(feature = "evdev")]
        if let Some(ev) = self.evdev.poll()? {
            return Ok(Some(ev));
        }
        #[cfg(feature = "gamepad")]
        if let Some(ev) = self.gamepad.poll()? {
            return Ok(Some(ev));
        }
        #[allow(unreachable_code)]
        Ok(None)
    }

    /// Current gamepad state for `gamepad_id` (0-indexed). Returns `None` if the
    /// `gamepad` feature is off or no such gamepad is connected.
    pub fn gamepad_state(&self, _gamepad_id: usize) -> Option<GamepadState> {
        #[cfg(feature = "gamepad")]
        {
            return self.gamepad.state(_gamepad_id);
        }
        #[allow(unreachable_code)]
        None
    }
}

impl Default for InputContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_button_from_evdev_codes() {
        assert_eq!(MouseButton::from_code(0x110), MouseButton::Left);
        assert_eq!(MouseButton::from_code(0x112), MouseButton::Middle);
        assert_eq!(MouseButton::from_code(0x111), MouseButton::Right);
        assert_eq!(MouseButton::from_code(0x113), MouseButton::Other);
    }

    #[test]
    fn deadzone_zeroes_small_stick() {
        assert_eq!(GamepadState::apply_deadzone(0.1, 0.0), (0.0, 0.0));
        // A clearly-outside reading is rescaled, not zeroed.
        let (x, y) = GamepadState::apply_deadzone(1.0, 0.0);
        assert!(x > 0.99 && x <= 1.0);
        assert!(y.abs() < 1e-6);
    }

    #[test]
    fn trigger_deadzone_zeroes_small() {
        assert_eq!(GamepadState::apply_trigger_deadzone(0.01), 0.0);
        assert!(GamepadState::apply_trigger_deadzone(0.5).abs() > 0.0);
    }

    #[test]
    fn button_bit_set_and_read() {
        let mut s = GamepadState::default();
        assert!(!s.is_pressed(GamepadButton::A));
        s.set_button(GamepadButton::A, true);
        assert!(s.is_pressed(GamepadButton::A));
        s.set_button(GamepadButton::A, false);
        assert!(!s.is_pressed(GamepadButton::A));
    }

    #[test]
    fn input_context_constructs_without_devices() {
        // Must not panic even on a headless host with no evdev/gilrs devices.
        let mut ctx = InputContext::new();
        // poll() may or may not yield events depending on the host, but must not error.
        let _ = ctx.poll();
    }
}
