//! XInput gamepad (`xinput1_3.dll`/`xinput1_4.dll`/`xinput9_1_0.dll`) and
//! XAudio2 (`xaudio2_7.dll`…`xaudio2_9.dll`) + DirectInput (`dinput8.dll`)
//! stubs — the two most-complaint-about missing APIs in games.
//!
//! Games load these DLLs at startup; if they fail to load the game bails out
//! with a " DirectX device not found" error. The stubs let a PE resolve the
//! imports, call `XInputGetState` (returns device-not-connected for index 0+
//! so the game's fallback path runs), and `XAudio2Create` (S_OK with a fake
//! object pointer so the game proceeds without audio).

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::ExportSpec;

/// `ERROR_SUCCESS` (0) — the Windows error-code success sentinel.
const ERROR_SUCCESS: u32 = 0;
/// `ERROR_DEVICE_NOT_CONNECTED` (1167) — "no gamepad attached".
const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;
/// `ERROR_EMPTY` (1168).
const ERROR_EMPTY: u32 = 1168;
/// `DI_OK` (0) for DirectInput8.
const DI_OK: i32 = 0;

// ---------------------------------------------------------------------------
// XINPUT_CAPABILITIES / XINPUT_STATE layouts
// ---------------------------------------------------------------------------

/// `XINPUT_GAMEPAD` — thumbsticks + triggers + buttons word.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XinputGamepad {
    pub w_buttons: u16,
    pub l_trigger: u8,
    pub r_trigger: u8,
    pub s_thumb_lx: i16,
    pub s_thumb_ly: i16,
    pub s_thumb_rx: i16,
    pub s_thumb_ry: i16,
}

/// `XINPUT_STATE` — packet number + gamepad.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XinputState {
    pub packet_number: u32,
    pub gamepad: XinputGamepad,
}

/// `XINPUT_CAPABILITIES` — device type + supported features.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XinputCapabilities {
    /// `XINPUT_DEVTYPE_GAMEPAD` = 1.
    pub dev_type: u8,
    /// `XINPUT_DEVSUBTYPE_GAMEPAD` = 1.
    pub sub_type: u8,
    pub flags: u16,
    pub gamepad: XinputGamepad,
    pub vibration: XinputVibration,
}

/// `XINPUT_VIBRATION` — motor speeds.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XinputVibration {
    pub w_left_motor_speed: u16,
    pub w_right_motor_speed: u16,
}

static PACKET_NUMBER: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// XInputGetState / SetState / GetCapabilities / ...
// ---------------------------------------------------------------------------

/// `xinput!XInputGetState(user_index, state*) -> DWORD`.
/// Returns ERROR_SUCCESS for index 0 (a virtual gamepad), ERROR_DEVICE_NOT_CONNECTED
/// for indices 1..3 (no second/third controller present).
pub extern "C" fn xinput_get_state(user_index: u32, state: *mut XinputState) -> u32 {
    if user_index > 0 {
        return ERROR_DEVICE_NOT_CONNECTED;
    }
    if state.is_null() {
        return ERROR_INVALID_PARAMETER_FALLBACK;
    }
    // SAFETY: the caller provides a valid writable XINPUT_STATE pointer per the
    // XInput API contract.
    unsafe {
        (*state).packet_number = PACKET_NUMBER.fetch_add(1, Ordering::Relaxed);
        (*state).gamepad = XinputGamepad {
            w_buttons: 0,
            l_trigger: 0,
            r_trigger: 0,
            s_thumb_lx: 0,
            s_thumb_ly: 0,
            s_thumb_rx: 0,
            s_thumb_ry: 0,
        };
    }
    ERROR_SUCCESS
}

/// `xinput!XInputSetState(user_index, vibration*) -> DWORD`. No-op success.
pub extern "C" fn xinput_set_state(_user_index: u32, _vibration: *mut XinputVibration) -> u32 {
    ERROR_SUCCESS
}

/// `xinput!XInputGetCapabilities(user_index, flags, caps*) -> DWORD`. Fills a
/// minimal `XINPUT_CAPABILITIES` and returns ERROR_SUCCESS for index 0.
pub extern "C" fn xinput_get_capabilities(
    user_index: u32,
    _flags: u32,
    caps: *mut XinputCapabilities,
) -> u32 {
    if user_index > 0 {
        return ERROR_DEVICE_NOT_CONNECTED;
    }
    if caps.is_null() {
        return ERROR_INVALID_PARAMETER_SENTINEL;
    }
    // SAFETY: the caller provides a valid writable XINPUT_CAPABILITIES pointer.
    unsafe {
        *caps = XinputCapabilities {
            dev_type: 1, // XINPUT_DEVTYPE_GAMEPAD
            sub_type: 1, // XINPUT_DEVSUBTYPE_GAMEPAD
            flags: 0,
            gamepad: XinputGamepad {
                w_buttons: 0,
                l_trigger: 0,
                r_trigger: 0,
                s_thumb_lx: 0,
                s_thumb_ly: 0,
                s_thumb_rx: 0,
                s_thumb_ry: 0,
            },
            vibration: XinputVibration {
                w_left_motor_speed: 0,
                w_right_motor_speed: 0,
            },
        };
    }
    ERROR_SUCCESS
}

/// `xinput!XInputGetBatteryType(user_index, battery*) -> DWORD`. No real battery
/// detection — return device-not-connected for every index.
pub extern "C" fn xinput_get_battery_type(_user_index: u32, _battery: *mut u8) -> u32 {
    ERROR_DEVICE_NOT_CONNECTED
}

/// `xinput!XInputGetKeystroke(user_index, reserve, keystroke*) -> DWORD`.
/// Returns ERROR_EMPTY (no keystroke queued).
pub extern "C" fn xinput_get_keystroke(
    _user_index: u32,
    _reserve: u32,
    _keystroke: *mut c_void,
) -> u32 {
    ERROR_EMPTY
}

/// `xinput!XInputGetDSoundAudioDeviceGuids(...) -> DWORD`. Returns
/// ERROR_DEVICE_NOT_CONNECTED (we don't have audio device GUIDs).
pub extern "C" fn xinput_get_dsound_audio_device_guids(
    _user_index: u32,
    _ds_render: *mut c_void,
    _ds_capture: *mut c_void,
    _render_id: *mut c_void,
    _capture_id: *mut c_void,
) -> u32 {
    ERROR_DEVICE_NOT_CONNECTED
}

/// Placeholder error code for null state/caps out pointers.
const ERROR_INVALID_PARAMETER_SENTINEL: u32 = 87; // ERROR_INVALID_PARAMETER
const ERROR_INVALID_PARAMETER_FALLBACK: u32 = 87;

// ---------------------------------------------------------------------------
// XAudio2Create (xaudio2_*.dll)
// ---------------------------------------------------------------------------

/// `xaudio2!XAudio2Create(ppXAudio2, flags, processor) -> HRESULT`.
/// Returns S_OK (0) and fills `*ppOut` with a fake COM object pointer.
pub extern "C" fn xaudio2_create(
    pp_xaudio2: *mut *mut c_void,
    _flags: u32,
    _processor: u32,
) -> c_int {
    if !pp_xaudio2.is_null() {
        // SAFETY: the caller provides a valid writable pointer per the COM contract.
        unsafe {
            *pp_xaudio2 = 0x3_0000 as *mut c_void; // fake XAudio2 COM handle
        }
    }
    0 // S_OK
}

/// `xaudio2!CoCreateInstance helper` — no-op (via direct export so a PE that imports
/// a named symbol from xaudio2_*.dll resolves).
pub extern "C" fn xaudio2_noop(_a: *mut c_void) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// DirectInput8 (dinput8.dll)
// ---------------------------------------------------------------------------

/// `dinput8!DirectInput8Create(hinst, version, riid, ppvOut, punkOuter) -> HRESULT`.
/// Returns DI_OK with a fake COM handle.
pub extern "C" fn direct_input8_create(
    _hinst: *mut c_void,
    _version: u32,
    _riid: *const u8,
    pp_out: *mut *mut c_void,
    _punk_outer: *mut c_void,
) -> c_int {
    if !pp_out.is_null() {
        // SAFETY: caller provides a valid writable pointer.
        unsafe {
            *pp_out = 0x4_0000 as *mut c_void; // fake DirectInput8 COM handle
        }
    }
    DI_OK
}

// ---------------------------------------------------------------------------
// Export registration
// ---------------------------------------------------------------------------

/// All xinput1_3 / xinput1_4 / xinput9_1_0 / xaudio2 / dinput8 exports.
pub fn xinput_exports() -> Vec<ExportSpec> {
    /// Build a single export for a specific DLL alias.
    fn x(dll: &'static str, sym: &'static str, f: *const c_void, n: u8) -> ExportSpec {
        ExportSpec {
            dll,
            sym,
            ptr: f,
            n_args: n,
            noreturn: false,
        }
    }

    // The three XInput DLL names Windows games import.
    const XI_DLLS: [&str; 3] = ["xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll"];
    // The four XAudio2 DLL names games commonly import.
    const XA_DLLS: [&str; 4] = [
        "xaudio2_7.dll",
        "xaudio2_8.dll",
        "xaudio2_9.dll",
        "xaudio2_10.dll",
    ];

    let mut out = Vec::new();

    for dll in XI_DLLS {
        out.push(x(
            dll,
            "XInputGetState",
            xinput_get_state as *const c_void,
            2,
        ));
        out.push(x(
            dll,
            "XInputSetState",
            xinput_set_state as *const c_void,
            2,
        ));
        out.push(x(
            dll,
            "XInputGetCapabilities",
            xinput_get_capabilities as *const c_void,
            3,
        ));
        out.push(x(
            dll,
            "XInputGetBatteryType",
            xinput_get_battery_type as *const c_void,
            2,
        ));
        out.push(x(
            dll,
            "XInputGetKeystroke",
            xinput_get_keystroke as *const c_void,
            3,
        ));
        out.push(x(
            dll,
            "XInputGetDSoundAudioDeviceGuids",
            xinput_get_dsound_audio_device_guids as *const c_void,
            5,
        ));
    }
    for dll in XA_DLLS {
        out.push(x(dll, "XAudio2Create", xaudio2_create as *const c_void, 3));
        out.push(x(dll, "CreateXAudio2", xaudio2_create as *const c_void, 3));
        out.push(x(dll, "CreateVoicePool", xaudio2_noop as *const c_void, 4));
    }

    // dinput8.dll exports
    out.push(x(
        "dinput8.dll",
        "DirectInput8Create",
        direct_input8_create as *const c_void,
        5,
    ));
    out.push(x("dinput8.dll", "DIDock", xaudio2_noop as *const c_void, 2));

    out
}
