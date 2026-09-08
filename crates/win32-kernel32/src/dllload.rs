//! `LoadLibrary`/`GetProcAddress`/`FreeLibrary` — the kernel32 module-loading surface.
//!
//! Windows DLL loading is a loader kernel service: `LoadLibraryA(name)` searches the
//! DLL search path, maps the PE at an OS-chosen base, resolves its imports, applies
//! relocations, calls `DllMain(hModule, DLL_PROCESS_ATTACH = 1, NULL)`, and (on success)
//! registers the module whose handle is the image base. `GetProcAddress(hModule, name)`
//! then walks that module's export directory.
//!
//! Those capabilities live in `nigg-pe-loader` (the PE loader parses/maps PE images and
//! knows the export tables), but this crate must not depend on `nigg-pe-loader` — that
//! would be a reverse dependency (`nigg-pe-loader` already depends on this crate). The
//! bridge is a function-pointer registration: at loader startup
//! `nigg_pe_loader::dllmod::register_kernel32_bridge()` installs the real implementations
//! into the `OnceLock`s below (idempotent; first registration wins). Until the loader is
//! linked in — e.g. unit tests of this crate alone — the exports keep the historical
//! "cannot load DLLs" behavior (return NULL) and say so on the log.
//!
//! The exports below implement the Windows API semantics on top of the registered
//! functions: guest string conversion (ANSI + UTF-16), the DLL search-order
//! approximation, `LastError` codes on failure, the `MAKEINTRESOURCE` ordinal rule, and
//! the `LoadLibraryEx` flag handling.

use std::os::raw::{c_int, c_void};
use std::path::PathBuf;
use std::sync::OnceLock;

/// `ERROR_MOD_NOT_FOUND` — the Win32 last error `LoadLibrary*` sets when the module is
/// nowhere to be found.
const ERROR_MOD_NOT_FOUND: u32 = 126;
/// `ERROR_PROC_NOT_FOUND` — set by `GetProcAddress` for a missing export.
const ERROR_PROC_NOT_FOUND: u32 = 127;
/// `ERROR_INVALID_NAME` — for malformed/NULL name arguments.
const ERROR_INVALID_NAME: u32 = 123;

/// Cap for reading a NUL-terminated name string out of guest memory (Windows paths max
/// out at 32 KiB characters).
const MAX_GUEST_STR: usize = 32_768;

/// The registered DLL loader: maps, relocates, import-resolves, runs `DllMain(...)` when
/// `run_dll_main` is set, registers the module, and returns its `HMODULE` (image base)
/// — or NULL on failure. Set by `nigg-pe-loader` at load time.
pub type LoadDllFn = fn(path: &str, run_dll_main: bool) -> *mut c_void;

/// The registered export lookup: `GetProcAddress` against the registered module's
/// export directory. `name` is the guest NUL-terminated name pointer **or** a
/// `MAKEINTRESOURCE` ordinal (value < 0x10000) — the pe-loader side applies the
/// Windows rule, so the raw pointer is passed through.
pub type GetProcAddressFn = fn(h_module: *mut c_void, name: *const u8) -> *mut c_void;

/// The registered module unloader: unmaps and deregisters. Returns `true` when the
/// handle was a registered module.
pub type FreeLibraryFn = fn(h_module: *mut c_void) -> bool;

/// The registration slots. `pe-loader` fills them in exactly one place
/// (`dllmod::register_kernel32_bridge`, called from the load path), so plain `fn`
/// pointers are enough and the OnceLocks double as an idempotence guard.
static LOAD_DLL_FN: OnceLock<LoadDllFn> = OnceLock::new();
static GET_PROC_ADDRESS_FN: OnceLock<GetProcAddressFn> = OnceLock::new();
static FREE_LIBRARY_FN: OnceLock<FreeLibraryFn> = OnceLock::new();

/// Register the real DLL loading functions. Called by `nigg-pe-loader` when the loader
/// boots (before any guest code runs), breaking the crate dependency cycle.
pub fn register(
    load_dll: LoadDllFn,
    get_proc_address: GetProcAddressFn,
    free_library: FreeLibraryFn,
) {
    // Idempotent: a `OnceLock::set` after the first is a no-op (the first registration
    // stays authoritative — all registrations come from the same code, so they agree).
    let _ = LOAD_DLL_FN.set(load_dll);
    let _ = GET_PROC_ADDRESS_FN.set(get_proc_address);
    let _ = FREE_LIBRARY_FN.set(free_library);
    log::debug!("kernel32: DLL loading functions registered by the PE loader");
}

// ---------------------------------------------------------------------------
// LoadLibrary family
// ---------------------------------------------------------------------------

/// `kernel32!LoadLibraryA(name) -> HMODULE`. Loads a PE DLL from disk, runs its
/// `DllMain(DLL_PROCESS_ATTACH)`, and returns its base address as the module handle.
/// Returns NULL (and sets last error) when no DLL loader is registered, the file cannot
/// be found/loaded, or the DLL failed initialization.
pub extern "C" fn load_library_a(name: *const u8) -> *mut c_void {
    let Some(name) = read_guest_str_a(name) else {
        set_last_error(ERROR_INVALID_NAME);
        return std::ptr::null_mut();
    };
    load_with_search(&name, true)
}

/// `kernel32!LoadLibraryW(name) -> HMODULE`. Wide-string variant of [`load_library_a`].
pub extern "C" fn load_library_w(name: *const u16) -> *mut c_void {
    let Some(name) = read_guest_str_w(name) else {
        set_last_error(ERROR_INVALID_NAME);
        return std::ptr::null_mut();
    };
    load_with_search(&name, true)
}

/// `kernel32!LoadLibraryExA(name, hFile, flags) -> HMODULE`.
///
/// `LOAD_LIBRARY_AS_DATAFILE`/`DONT_RESOLVE_DLL_REFERENCES` (flags & 1) maps the DLL
/// without running `DllMain`; every other flag is accepted but treated as a plain load
/// (the search-order variants are not modeled).
pub extern "C" fn load_library_ex_a(
    name: *const u8,
    _h_file: *mut c_void,
    flags: u32,
) -> *mut c_void {
    let Some(name) = read_guest_str_a(name) else {
        set_last_error(ERROR_INVALID_NAME);
        return std::ptr::null_mut();
    };
    load_with_search(&name, flags & LOAD_LIBRARY_AS_DATAFILE == 0)
}

/// `kernel32!LoadLibraryExW(name, hFile, flags) -> HMODULE`. Wide-string variant of
/// [`load_library_ex_a`].
pub extern "C" fn load_library_ex_w(
    name: *const u16,
    _h_file: *mut c_void,
    flags: u32,
) -> *mut c_void {
    let Some(name) = read_guest_str_w(name) else {
        set_last_error(ERROR_INVALID_NAME);
        return std::ptr::null_mut();
    };
    load_with_search(&name, flags & LOAD_LIBRARY_AS_DATAFILE == 0)
}

/// `LOAD_LIBRARY_AS_DATAFILE` (equivalent effect to `DONT_RESOLVE_DLL_REFERENCES` for
/// our purposes: map the module, skip `DllMain`).
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x1;

/// Resolve `name` through the DLL search order and hand every candidate to the
/// registered loader until one succeeds. Sets last error on failure.
fn load_with_search(name: &str, run_dll_main: bool) -> *mut c_void {
    if name.is_empty() {
        set_last_error(ERROR_INVALID_NAME);
        return std::ptr::null_mut();
    }
    let Some(loader) = LOAD_DLL_FN.get() else {
        // Loader not registered (bare kernel32 unit tests): keep the "cannot load"
        // behavior loud but non-fatal.
        log::warn!("LoadLibrary({name}) requested but no DLL loader is registered");
        set_last_error(ERROR_MOD_NOT_FOUND);
        return std::ptr::null_mut();
    };

    let mut tried = 0usize;
    for candidate in candidate_paths(name) {
        let Some(path) = candidate.to_str() else {
            log::debug!("LoadLibrary: candidate path {candidate:?} is not UTF-8; skipped");
            continue;
        };
        tried += 1;
        let h = loader(path, run_dll_main);
        if !h.is_null() {
            return h; // the loader registered itself; the pe-loader logs the handle
        }
    }
    log::debug!("LoadLibrary({name}): module not found ({tried} candidate paths examined)");
    set_last_error(ERROR_MOD_NOT_FOUND);
    std::ptr::null_mut()
}

/// Build the ordered candidate file paths for a module name, approximating the Windows
/// `LoadLibrary` search:
///
/// 1. A name containing a path separator (`/` or the Windows `\`) is a (relative or
///    absolute) path and is tried verbatim; if it lacks a `.dll` extension, the
///    `.dll`-suffixed spelling is tried second.
/// 2. Otherwise — like Windows' search path minus the redirections — each directory in
///    `$NIGG_DLL_PATH` (a Linux stand-in for the search path, `:`- or `;`-separated) and
///    finally the current working directory (`.`) is joined with the name.
fn candidate_paths(name: &str) -> Vec<PathBuf> {
    let normalized = name.replace('\\', "/");
    let mut out = Vec::new();
    if normalized.contains('/') {
        push_candidates(&mut out, normalized);
    } else {
        for dir in search_dirs() {
            let joined = dir.join(&normalized);
            let as_str = joined.to_string_lossy().into_owned();
            push_candidates(&mut out, as_str);
        }
    }
    out
}

/// Push `base` (and `$base.dll` when it doesn't already end with the extension,
/// case-insensitively) onto the candidate list.
fn push_candidates(out: &mut Vec<PathBuf>, base: String) {
    let has_ext = base.len() >= 4 && base[base.len() - 4..].eq_ignore_ascii_case(".dll");
    out.push(PathBuf::from(&base));
    if !has_ext {
        out.push(PathBuf::from(format!("{base}.dll")));
    }
}

/// The DLL search directories: `$NIGG_DLL_PATH` entries (if set) then the cwd.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(list) = std::env::var_os("NIGG_DLL_PATH") {
        // Non-Windows stand-in for the real search path: a list of dirs separated by
        // `:` (POSIX convention) or `;` (the Windows convention) — both accepted.
        dirs.extend(
            list.to_string_lossy()
                .split([':', ';'])
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
        );
    }
    dirs.push(PathBuf::from("."));
    dirs
}

// ---------------------------------------------------------------------------
// GetProcAddress / FreeLibrary
// ---------------------------------------------------------------------------

/// `kernel32!GetProcAddress(hModule, name) -> FARPROC`. Resolves `name` (a guest string,
/// or a `MAKEINTRESOURCE` ordinal when the pointer value is < 0x10000) in the module's
/// export directory. Returns the export's Win64 code address, or NULL + last error
/// 127 (`ERROR_PROC_NOT_FOUND`).
pub extern "C" fn get_proc_address(h_module: *mut c_void, name: *const u8) -> *mut c_void {
    if h_module.is_null() {
        set_last_error(ERROR_PROC_NOT_FOUND);
        return std::ptr::null_mut();
    }
    let Some(func) = GET_PROC_ADDRESS_FN.get() else {
        log::warn!("GetProcAddress requested but no export resolver is registered");
        set_last_error(ERROR_PROC_NOT_FOUND);
        return std::ptr::null_mut();
    };
    let result = func(h_module, name);
    if result.is_null() {
        set_last_error(ERROR_PROC_NOT_FOUND);
    }
    result
}

/// `kernel32!FreeLibrary(hModule) -> BOOL`. Unloads a registered module. Windows
/// ref-counts repeated loads; we do not, so the first `FreeLibrary` unmarks the module.
pub extern "C" fn free_library(h_module: *mut c_void) -> c_int {
    let Some(func) = FREE_LIBRARY_FN.get() else {
        log::warn!("FreeLibrary requested but no module registry is registered");
        return 0;
    };
    if func(h_module) {
        1
    } else {
        0
    }
}

/// `kernel32!DisableThreadLibraryCalls(hModule) -> BOOL`. No-op returning TRUE (we
/// never send thread-attach/detach notifications anyway, so "disabling" them is
/// trivially satisfied).
pub extern "C" fn disable_thread_library_calls(_h_module: *mut c_void) -> c_int {
    1
}

// ---------------------------------------------------------------------------
// Guest string readers
// ---------------------------------------------------------------------------

/// Convert a guest NUL-terminated ANSI string (LPCSTR) into a Rust `String`.
///
/// The read is bounded (Windows path names fit far below the cap) and lossily decoded.
/// `None` when the pointer is NULL.
fn read_guest_str_a(name: *const u8) -> Option<String> {
    let bytes = guest_cstring(name, 1)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Convert a guest NUL-terminated UTF-16 string (LPCWSTR) into a Rust `String`.
/// `None` when the pointer is NULL.
fn read_guest_str_w(name: *const u16) -> Option<String> {
    let units = guest_cstring(name as *const u8, 2)?;
    let units: Vec<u16> = units
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Read a NUL-terminated byte string from guest memory, stopping at the NUL byte or
/// after `MAX_GUEST_STR / stride` bytes, where `stride` is 1 for ANSI and 2 for UTF-16
/// (the terminator is a `u16` zero, so the scan halts on a two-zero pair).
///
/// Returns the bytes read (not including the terminator), or `None` when the pointer is
/// NULL.
fn guest_cstring(name: *const u8, stride: usize) -> Option<Vec<u8>> {
    if name.is_null() {
        return None;
    }
    let max = MAX_GUEST_STR / stride;
    let mut out = Vec::new();
    // SAFETY: guest code hands us a NUL-terminated string pointer per the LoadLibraryA/W
    // contract; we stop at the terminator (2 zero bytes for UTF-16) or after `max`
    // elements so a bad pointer cannot loop forever.
    unsafe {
        let mut p = name;
        for _ in 0..max {
            let b0 = *p;
            let b1 = if stride == 2 { *p.add(1) } else { 0 };
            if b0 == 0 && b1 == 0 {
                break;
            }
            out.push(b0);
            if stride == 2 {
                out.push(b1);
            }
            p = p.add(stride);
        }
    }
    Some(out)
}

/// Set the Windows last-error code through the ntapi surface.
fn set_last_error(code: u32) {
    nigg_ntapi::process::set_last_error(code);
}
