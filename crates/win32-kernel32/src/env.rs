//! Environment-variable helpers: `GetEnvironmentVariableW`, `SetEnvironmentVariableW`,
//! `GetEnvironmentStringsW`, `FreeEnvironmentStringsW`.
//!
//! Windows represents the environment block as a sequence of `NAME=VALUE\0` UTF-16 strings
//! terminated by an extra `\0` code unit. We build that block from `std::env::vars()` and
//! hand the guest a pointer to a heap allocation it owns; `FreeEnvironmentStringsW` frees
//! it. We hold on to each allocation in a registry so a double-free is harmless and so the
//! pointer stays valid until explicitly freed (matching the Windows contract).

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::OnceLock;

use crate::Handle;

/// `ERROR_ENVVAR_NOT_FOUND` (203) — the requested environment variable does not exist.
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;

/// A Send+Sync wrapper around the raw heap allocation backing an environment block. The
/// pointer names process-local memory we own and hand out to the guest; it never crosses
/// processes, so manual `Send`/`Sync` is sound.
struct EnvBlock {
    ptr: *mut u16,
    len: usize,
}

// SAFETY: `EnvBlock` owns a process-local heap allocation whose address is stable and only
// ever dereferenced from the guest thread that requested it; the registry guards access with
// a mutex. The raw pointer is not actually shared across threads in a way that violates
// Rust's aliasing rules within this single-process guest.
unsafe impl Send for EnvBlock {}
// SAFETY: same justification as `Send` above — process-local allocation guarded by the
// registry mutex; no cross-thread aliasing violation within this single-process guest.
unsafe impl Sync for EnvBlock {}

/// Registry of outstanding `GetEnvironmentStringsW` allocations: payload pointer -> the
/// owning allocation (kept alive until `FreeEnvironmentStringsW` drops it). Keys are the
/// payload pointers handed to the guest so a lookup on free is O(1).
fn env_block_registry() -> &'static parking_lot::Mutex<HashMap<usize, EnvBlock>> {
    static R: OnceLock<parking_lot::Mutex<HashMap<usize, EnvBlock>>> = OnceLock::new();
    R.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// `kernel32!GetEnvironmentVariableW(lpName, lpBuffer, nSize) -> DWORD`.
///
/// Looks up the environment variable named by the NUL-terminated UTF-16 `lpName`, writes
/// its UTF-16 value into `lpBuffer` (up to `nSize` code units, NUL-terminated), and returns
/// the number of code units written excluding the NUL. If `lpBuffer` is null or too small,
/// returns the required length (including space for the NUL) and sets the last error to
/// `ERROR_ENVVAR_NOT_FOUND` if the variable is missing.
pub extern "C" fn get_environment_variable_w(
    name: *const u16,
    buffer: *mut u16,
    n_size: u32,
) -> u32 {
    // SAFETY: `name` is a NUL-terminated UTF-16 buffer (or null, handled internally).
    let name_str = unsafe { crate::string::utf16_to_string(name) };
    if name_str.is_empty() {
        nigg_ntapi::process::set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }
    let Some(value) = std::env::var(&name_str).ok() else {
        nigg_ntapi::process::set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    };
    let units: Vec<u16> = value.encode_utf16().collect();
    let need = units.len() as u32 + 1; // value code units + NUL

    // Query mode (no buffer / zero size): return the required length (value + NUL).
    if buffer.is_null() || n_size == 0 {
        return need;
    }
    if units.len() as u32 >= n_size {
        // Buffer too small: return the required length and set INSUFFICIENT_BUFFER.
        nigg_ntapi::process::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return need;
    }
    // SAFETY: `buffer` holds `n_size` code units; we have checked `units.len() < n_size`,
    // so the value + terminating NUL both fit.
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), buffer, units.len());
        std::ptr::write_unaligned(buffer.add(units.len()), 0);
    }
    units.len() as u32
}

/// `kernel32!SetEnvironmentVariableW(lpName, lpValue) -> BOOL`. Sets (or, with a null
/// value, removes) an environment variable in the host environment.
pub extern "C" fn set_environment_variable_w(name: *const u16, value: *const u16) -> i32 {
    // SAFETY: `name`/`value` are NUL-terminated UTF-16 buffers (or null).
    let name_str = unsafe { crate::string::utf16_to_string(name) };
    if name_str.is_empty() {
        return 0; // FALSE
    }
    if value.is_null() {
        // SAFETY: `std::env::remove_var` is the host-side unset; on Linux it is sound and
        // the host libc updates `environ` atomically enough for our single-threaded guest.
        std::env::remove_var(&name_str);
        return 1; // TRUE
    }
    // SAFETY: `value` is a NUL-terminated UTF-16 buffer (or null, handled internally by
    // `utf16_to_string` returning an empty string).
    let value_str = unsafe { crate::string::utf16_to_string(value) };
    std::env::set_var(&name_str, &value_str);
    1 // TRUE
}

/// `kernel32!GetEnvironmentStringsW() -> LPWCH`. Returns a pointer to a newly allocated
/// environment block: a sequence of `NAME=VALUE\0` UTF-16 strings followed by an extra
/// `\0` code unit. The caller frees it with `FreeEnvironmentStringsW`.
pub extern "C" fn get_environment_strings_w() -> *mut u16 {
    // Build the UTF-16 block: for each var, `NAME=VALUE\0`, then a final `\0`.
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in std::env::vars() {
        block.extend(k.encode_utf16());
        block.push(b'=' as u16);
        block.extend(v.encode_utf16());
        block.push(0);
    }
    block.push(0); // terminating extra NUL

    let len = block.len();
    let layout = std::alloc::Layout::array::<u16>(len).expect("env block layout");
    // SAFETY: `layout` is a valid non-zero allocation; `alloc_zeroed` returns a valid
    // pointer to `layout.size()` bytes or NULL.
    let raw = unsafe { std::alloc::alloc_zeroed(layout) } as *mut u16;
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `raw` is valid for `len` code units; copy the block into it.
    unsafe {
        std::ptr::copy_nonoverlapping(block.as_ptr(), raw, len);
    }
    let key = raw as usize;
    env_block_registry()
        .lock()
        .insert(key, EnvBlock { ptr: raw, len });
    raw
}

/// `kernel32!FreeEnvironmentStringsW(lpszEnvironmentBlock) -> BOOL`. Frees a block
/// returned by `GetEnvironmentStringsW`. A null or unknown pointer is a no-op success.
pub extern "C" fn free_environment_strings_w(block: *mut u16) -> i32 {
    if block.is_null() {
        return 1; // TRUE: freeing NULL is a no-op success
    }
    let key = block as usize;
    let entry = env_block_registry().lock().remove(&key);
    let Some(block) = entry else {
        // Not a block we handed out; return TRUE so a stray free does not abort the guest.
        return 1;
    };
    let layout = std::alloc::Layout::array::<u16>(block.len).expect("env block layout");
    // SAFETY: `block.ptr` was allocated with `layout` in `get_environment_strings_w`; we
    // deallocate it exactly once.
    unsafe {
        std::alloc::dealloc(block.ptr as *mut u8, layout);
    }
    let _ = key;
    1
}

/// Silence unused-import noise for `Handle`/`c_void` (kept in the module surface for
/// callers that pass handles through the env helpers).
#[allow(dead_code)]
fn _type_anchors() -> (Handle, *mut c_void) {
    (0, std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    #[test]
    fn set_and_get_round_trip() {
        let name = make_wide("NIGG_TEST_ENV_VAR");
        let value = make_wide("hello-env-value");
        assert_eq!(set_environment_variable_w(name.as_ptr(), value.as_ptr()), 1);

        let need = get_environment_variable_w(name.as_ptr(), std::ptr::null_mut(), 0);
        assert!(need >= 1, "query returns the required length");

        let mut buf = vec![0u16; need as usize];
        let got = get_environment_variable_w(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        assert_eq!(got, "hello-env-value".encode_utf16().count() as u32);
        let s = String::from_utf16_lossy(&buf[..got as usize]);
        assert_eq!(s, "hello-env-value");

        // Cleanup: unset the variable.
        assert_eq!(
            set_environment_variable_w(name.as_ptr(), std::ptr::null()),
            1
        );
    }

    #[test]
    fn get_missing_var_returns_zero() {
        let name = make_wide("NIGG_DEFINITELY_NOT_SET_42");
        let got = get_environment_variable_w(name.as_ptr(), std::ptr::null_mut(), 0);
        assert_eq!(got, 0);
    }

    #[test]
    fn environment_strings_block_round_trip() {
        std::env::set_var("NIGG_ENVBLOCK_K", "NIGG_ENVBLOCK_V");
        let block = get_environment_strings_w();
        assert!(!block.is_null());

        // Walk the block looking for our var: each `NAME=VALUE\0` until the extra NUL.
        let mut found = false;
        let mut i = 0usize;
        // SAFETY: `block` is NUL-NUL terminated; walk until two consecutive NULs.
        unsafe {
            loop {
                if *block.add(i) == 0 {
                    break;
                }
                // Read one entry into a String.
                let start = i;
                while *block.add(i) != 0 {
                    i += 1;
                }
                let entry = String::from_utf16_lossy(std::slice::from_raw_parts(
                    block.add(start),
                    i - start,
                ));
                if entry == "NIGG_ENVBLOCK_K=NIGG_ENVBLOCK_V" {
                    found = true;
                }
                i += 1; // skip the entry's NUL
            }
        }
        assert!(found, "the env block contains NIGG_ENVBLOCK_K=...");

        assert_eq!(free_environment_strings_w(block), 1);
        std::env::remove_var("NIGG_ENVBLOCK_K");
    }
}
