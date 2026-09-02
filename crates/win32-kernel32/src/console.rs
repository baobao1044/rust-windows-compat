//! Console I/O: `GetStdHandle`, `WriteConsoleW`/`WriteConsoleA`, `GetConsoleMode`,
//! `SetConsoleMode`. `WriteFile`/`ReadFile` themselves live in [`crate::file`] (they apply
//! to both console and file handles, so a single implementation covers both).
//!
//! On Linux the three standard streams are plain fds 0/1/2; ntapi already models them as
//! handles whose low values are the fd itself (`GetStdHandle` returns 0/1/2). The console
//! helpers here therefore translate a stdio handle to its fd and call the matching POSIX
//! operation directly, so a console PE can read/write the terminal exactly as on Windows.
//!
//! Console-mode bits are accepted and stored in a tiny per-handle registry so a guest that
//! flips `ENABLE_ECHO_INPUT` etc. gets consistent read-back; we do not actually change any
//! terminal attributes (Linux termios changes are out of scope for the console-PE M2
//! acceptance target). Reads and writes succeed regardless of the recorded mode.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::OnceLock;

use crate::Handle;

/// `STD_INPUT_HANDLE` pseudo-value (`(DWORD)-10` == `0xFFFF_FFF7` under this loader's
/// ntapi mapping). We mirror ntapi's values exactly so `get_std_handle` dispatches correctly.
const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF7;
/// `STD_OUTPUT_HANDLE` pseudo-value (`(DWORD)-11` == `0xFFFF_FFF5`).
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
/// `STD_ERROR_HANDLE` pseudo-value (`(DWORD)-12` == `0xFFFF_FFF6`).
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF6;

/// `ERROR_INVALID_HANDLE` (6).
const ERROR_INVALID_HANDLE: u32 = 6;

/// Per-handle console mode registry. The three stdio handles each get a default mode; we
/// remember whatever the guest sets so `GetConsoleMode` round-trips. Non-stdio handles are
/// treated as un-modeled (their `GetConsoleMode` returns FALSE).
fn console_modes() -> &'static parking_lot::Mutex<HashMap<Handle, u32>> {
    static M: OnceLock<parking_lot::Mutex<HashMap<Handle, u32>>> = OnceLock::new();
    M.get_or_init(|| {
        // Windows defaults for a console attached to the process. The exact values don't
        // matter for our guests; we mirror the canonical console input/output modes.
        let mut m = HashMap::new();
        m.insert(0, 0x01F3u32); // ENABLE_PROCESSED_INPUT | ... default input mode
        m.insert(1, 0x0003u32); // ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT
        m.insert(2, 0x0003u32);
        parking_lot::Mutex::new(m)
    })
}

/// `kernel32!GetStdHandle(nStdHandle) -> HANDLE`. Delegates to ntapi, which maps the
/// `STD_*` pseudo-values to the matching fd.
pub extern "C" fn get_std_handle(std_handle: u32) -> Handle {
    nigg_ntapi::process::get_std_handle(std_handle)
}

/// `kernel32!WriteConsoleW(hConsole, lpBuffer, nNumberOfCharsToWrite,
/// lpNumberOfCharsWritten, lpReserved) -> BOOL`. Writes the UTF-16 string to the fd backing
/// `hConsole`, converting to UTF-8 first (Linux terminals are UTF-8). Returns the number
/// of *code units* written in `lpNumberOfCharsWritten` (matching Windows semantics).
pub extern "C" fn write_console_w(
    handle: Handle,
    buf: *const u16,
    n_chars: u32,
    written: *mut u32,
    _reserved: *mut c_void,
) -> i32 {
    if buf.is_null() || n_chars == 0 {
        if !written.is_null() {
            // SAFETY: `written` is a guest out-pointer valid for one u32.
            unsafe { std::ptr::write_unaligned(written, 0) };
        }
        return 1; // TRUE (no-op)
    }
    // SAFETY: the guest promises `n_chars` readable code units at `buf`.
    let units = unsafe { std::slice::from_raw_parts(buf, n_chars as usize) };
    let utf8 = String::from_utf16_lossy(units);

    let fd = match handle {
        0..=2 => handle as i32,
        _ => {
            // Resolve a file-style console handle to its fd via the handle table.
            let Some(f) = nigg_ntapi::handle::with_object(handle, |o| match o {
                nigg_ntapi::handle::Object::File(f) => Some(f.fd),
                _ => None,
            })
            .flatten() else {
                nigg_ntapi::process::set_last_error(ERROR_INVALID_HANDLE);
                return 0; // FALSE
            };
            f
        }
    };

    // SAFETY: `fd` is a valid open descriptor; `write` reads `utf8` bytes and returns the
    // byte count (or -1 on error). We never pass more than `isize::MAX` bytes.
    let n = unsafe {
        libc::write(
            fd,
            utf8.as_ptr() as *const c_void,
            utf8.len().min(isize::MAX as usize),
        )
    };
    if n < 0 {
        nigg_ntapi::process::set_last_error(6);
        return 0; // FALSE
    }
    // Windows reports the number of *characters* (code units) accepted, not bytes. Since we
    // only fail when `write` fails, we credit the whole requested character count.
    if !written.is_null() {
        // SAFETY: `written` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(written, n_chars) };
    }
    1
}

/// `kernel32!WriteConsoleA(hConsole, lpBuffer, nNumberOfCharsToWrite,
/// lpNumberOfCharsWritten, lpReserved) -> BOOL`. Like [`write_console_w`] but the input is
/// an ANSI byte string; we write the bytes verbatim (Linux terminals interpret them as
/// UTF-8 / the active locale, which matches the Windows A-API contract for the common case).
pub extern "C" fn write_console_a(
    handle: Handle,
    buf: *const u8,
    n_chars: u32,
    written: *mut u32,
    _reserved: *mut c_void,
) -> i32 {
    if buf.is_null() || n_chars == 0 {
        if !written.is_null() {
            // SAFETY: `written` is a guest out-pointer valid for one u32.
            unsafe { std::ptr::write_unaligned(written, 0) };
        }
        return 1;
    }
    let fd = match handle {
        0..=2 => handle as i32,
        _ => {
            let Some(f) = nigg_ntapi::handle::with_object(handle, |o| match o {
                nigg_ntapi::handle::Object::File(f) => Some(f.fd),
                _ => None,
            })
            .flatten() else {
                nigg_ntapi::process::set_last_error(ERROR_INVALID_HANDLE);
                return 0;
            };
            f
        }
    };
    // SAFETY: the guest promises `n_chars` readable bytes at `buf`.
    let n = unsafe {
        libc::write(
            fd,
            buf as *const c_void,
            (n_chars as usize).min(isize::MAX as usize),
        )
    };
    if n < 0 {
        nigg_ntapi::process::set_last_error(6);
        return 0;
    }
    if !written.is_null() {
        // SAFETY: `written` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(written, n as u32) };
    }
    1
}

/// `kernel32!GetConsoleMode(hConsoleHandle, lpMode) -> BOOL`. Reads the recorded console
/// mode for the handle into `lpMode`. Stdio handles have a default mode; other handles
/// return FALSE (they are not consoles).
pub extern "C" fn get_console_mode(handle: Handle, mode: *mut u32) -> i32 {
    let modes = console_modes().lock();
    if let Some(&m) = modes.get(&handle) {
        if !mode.is_null() {
            // SAFETY: `mode` is a guest out-pointer valid for one u32.
            unsafe { std::ptr::write_unaligned(mode, m) };
        }
        1 // TRUE
    } else {
        nigg_ntapi::process::set_last_error(ERROR_INVALID_HANDLE);
        0 // FALSE
    }
}

/// `kernel32!SetConsoleMode(hConsoleHandle, dwMode) -> BOOL`. Stores the requested mode for
/// the handle (we do not change Linux termios attributes — out of scope for M2).
pub extern "C" fn set_console_mode(handle: Handle, mode: u32) -> i32 {
    use std::collections::hash_map::Entry;
    let mut modes = console_modes().lock();
    match modes.entry(handle) {
        Entry::Occupied(mut e) => {
            e.insert(mode);
            1 // TRUE
        }
        Entry::Vacant(e) => {
            // For a stdio handle we have not registered yet, register it on first set so a
            // guest can opt a fresh handle into console mode. Non-stdio handles fail.
            if handle <= 2 {
                e.insert(mode);
                1 // TRUE
            } else {
                nigg_ntapi::process::set_last_error(ERROR_INVALID_HANDLE);
                0 // FALSE
            }
        }
    }
}

/// Silence unused warning for the stdio pseudo-value constants (kept for documentation and
/// cross-checking against the ntapi values).
#[allow(dead_code)]
const _STD_PSEUDO: (u32, u32, u32) = (STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_std_handle_returns_stdio_fds() {
        assert_eq!(get_std_handle(STD_OUTPUT_HANDLE), 1);
        assert_eq!(get_std_handle(STD_ERROR_HANDLE), 2);
        assert_eq!(get_std_handle(STD_INPUT_HANDLE), 0);
    }

    #[test]
    fn console_mode_round_trips_on_stdout() {
        let mut mode: u32 = 0;
        assert_eq!(
            get_console_mode(1, &mut mode),
            1,
            "stdout has a console mode"
        );
        assert_eq!(set_console_mode(1, 0x0007), 1);
        assert_eq!(get_console_mode(1, &mut mode), 1);
        assert_eq!(mode, 0x0007);
        // Restore a sane default so other tests are unaffected.
        set_console_mode(1, 0x0003);
    }

    #[test]
    fn write_console_a_to_stderr() {
        let bytes = b"console-test\n";
        let mut written: u32 = 0;
        let r = write_console_a(
            2,
            bytes.as_ptr(),
            bytes.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        );
        assert_eq!(r, 1);
        assert_eq!(written as usize, bytes.len());
    }
}
