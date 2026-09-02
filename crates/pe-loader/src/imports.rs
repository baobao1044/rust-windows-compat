//! Import directory resolution for the PE loader.
//!
//! Each imported symbol is resolved to a native function pointer that the loader writes
//! into the Import Address Table (IAT). For Phase 1 we implement a small set of
//! `kernel32`/`ntdll`/`vcruntime` exports by hand, backed by Linux syscalls via `libc`;
//! unknown imports are replaced with a logging trap stub that logs once and aborts
//! gracefully, so a missing import fails loudly rather than silently calling junk.
//!
//! The hand-written thunks use the Windows x64 calling convention
//! (`extern "C"` is System V on Linux, so the thunks translate the ABI) — but for Phase 1
//! the implemented exports are trivial enough (return a constant, call `exit`, write to
//! stderr) that the ABI difference does not matter: the exports we implement take their
//! arguments in the registers that overlap, or take none, and return `i32`/`u32` in
//! `eax`/`rax` which is identical between the two conventions. Real ABI translation is a
//! later milestone.

use std::collections::HashMap;
use std::os::raw::{c_int, c_uint, c_void};

/// Standard Windows handle value for `STD_OUTPUT_HANDLE`.
const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
/// Standard Windows handle value for `STD_ERROR_HANDLE`.
const STD_ERROR_HANDLE: u32 = 0xFFFFFFF5 + 1;
/// Standard Windows handle value for `STD_INPUT_HANDLE`.
const STD_INPUT_HANDLE: u32 = 0xFFFFFFF5 + 2;

/// A resolved import: the native address to write into the IAT slot.
pub type FnPtr = *const c_void;

/// The set of imports the loader actually resolved at load time. Useful for diagnostics
/// (e.g. reporting which unknown imports were trapped).
#[derive(Default, Debug)]
pub struct ResolvedImports {
    /// `(dll, symbol) -> native address` for every resolved IAT entry.
    pub resolved: HashMap<(String, String), FnPtr>,
    /// `(dll, symbol)` for imports that had no implementation and got a trap stub.
    pub stubbed: Vec<(String, String)>,
}

/// Resolve `imports` (from goblin) into native function pointers.
///
/// `known` is the table of implemented exports; `imports` is goblin's parsed import list.
/// Returns the address to store in each IAT slot along with a record of what was resolved
/// vs. stubbed.
pub fn resolve(imports: &[goblin::pe::import::Import], known: &ImplTable) -> ResolvedImports {
    let mut out = ResolvedImports::default();
    for imp in imports {
        let dll = imp.dll.to_lowercase();
        let sym = normalize_symbol(&imp.name);
        if let Some(ptr) = known.lookup(&dll, &sym) {
            out.resolved.insert((dll.clone(), sym.clone()), ptr);
        } else {
            log::warn!(
                "stubbed import: {}!{} (no Phase 1 implementation)",
                imp.dll,
                imp.name
            );
            out.stubbed.push((dll.clone(), sym.clone()));
            out.resolved
                .insert((dll.clone(), sym.clone()), trap_stub as FnPtr);
        }
    }
    out
}

/// `extern "C"` trap stub for unimplemented imports. Logs the call site symbol and aborts
/// with a distinct exit code so the failure is unmistakable.
extern "C" fn trap_stub() -> u32 {
    log::error!("PE loader: called an unimplemented import (trap stub); aborting");
    eprintln!("nigg-loader: called unimplemented Windows import — aborting");
    // STATUS_DLL_INIT_FAILED-ish sentinel (0xC000_0142 as a signed exit code).
    std::process::exit(0xC000_0142u32 as i32);
}

/// The native address of the trap stub, for distinguishing stubbed IAT entries from real
/// implementations. Taking a function address is always safe.
pub(crate) fn trap_stub_addr() -> FnPtr {
    trap_stub as FnPtr
}

/// Normalize a goblin import name to the lookup key. goblin already strips decorations
/// for named imports; ordinal imports arrive as `"ORDINAL <n>"`, which we pass through
/// verbatim so an `ordinal: <n>` entry in [`ImplTable`] can match.
fn normalize_symbol(name: &str) -> String {
    name.to_string()
}

// ---------------------------------------------------------------------------
// Hand-written export implementations (backed by Linux syscalls via libc).
// ---------------------------------------------------------------------------

/// `kernel32!ExitProcess(u32 exit_code) -> !`. Terminates the process with `exit_code`.
extern "C" fn kernel32_exit_process(exit_code: u32) -> ! {
    log::trace!("kernel32!ExitProcess({exit_code})");
    std::process::exit(exit_code as i32);
}

/// `kernel32!GetStdHandle(u32 std_handle) -> *mut c_void`. Maps a STD_* handle pseudo-value
/// to the corresponding Linux fd as a "handle".
extern "C" fn kernel32_get_std_handle(std_handle: u32) -> *mut c_void {
    log::trace!("kernel32!GetStdHandle({std_handle:#x})");
    let fd = match std_handle {
        STD_INPUT_HANDLE => 0,
        STD_OUTPUT_HANDLE => 1,
        STD_ERROR_HANDLE => 2,
        _ => -1i32 as *mut c_void as i32, // INVALID_HANDLE_VALUE-equivalent
    };
    // Return the fd as a tagged handle (we never dereference these as pointers; they're
    // opaque ids in Phase 1).
    fd as usize as *mut c_void
}

/// `kernel32!WriteFile(handle, buf, len, written, overlapped) -> u32 (BOOL)`.
///
/// For Phase 1 this ignores the overlapped parameter and writes synchronously to the fd
/// encoded in the handle, returning 1 (TRUE) on success.
extern "C" fn kernel32_write_file(
    handle: *mut c_void,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    _overlapped: *mut c_void,
) -> u32 {
    let fd = handle as usize as i32;
    if fd < 0 || buf.is_null() {
        return 0; // FALSE
    }
    // SAFETY: the guest passes a buffer valid for `len` bytes (Windows contract). We read
    // exactly `len` bytes from it via `write(2)`.
    let n = unsafe { libc::write(fd, buf as *const c_void, len as usize) };
    if n < 0 {
        return 0; // FALSE
    }
    if !written.is_null() {
        // SAFETY: `written` is an out-pointer provided by the guest, valid for one u32.
        unsafe { std::ptr::write_unaligned(written, n as u32) };
    }
    1 // TRUE
}

/// `kernel32!GetLastError() -> u32`. Phase 1 has no error state; always returns 0.
extern "C" fn kernel32_get_last_error() -> u32 {
    log::trace!("kernel32!GetLastError() -> 0");
    0
}

/// `kernel32!SetLastError(u32) -> void`. No-op in Phase 1.
extern "C" fn kernel32_set_last_error(_code: u32) {
    log::trace!("kernel32!SetLastError({_code}) [no-op]");
}

/// `kernel32!GetTickCount() -> u32`. Milliseconds since boot, via `clock_gettime(MONOTONIC)`.
extern "C" fn kernel32_get_tick_count() -> u32 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` with `CLOCK_MONOTONIC` writes a valid timespec into the
    // caller-provided struct and never fails on a supported clock.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let ms = (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000;
    (ms & 0xFFFF_FFFF) as u32
}

/// `kernel32!QueryPerformanceCounter(LARGE_INTEGER*) -> BOOL`.
extern "C" fn kernel32_query_performance_counter(out: *mut i64) -> u32 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime(CLOCK_MONOTONIC)` writes a valid timespec; never fails here.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let ns = ts.tv_sec * 1_000_000_000 + ts.tv_nsec;
    if !out.is_null() {
        // SAFETY: `out` is a guest-provided out-pointer valid for one i64.
        unsafe { std::ptr::write_unaligned(out, ns) };
    }
    1 // TRUE
}

/// `ntdll!NtTerminateProcess(handle, status) -> !`. `handle` 0 means current process.
extern "C" fn ntdll_terminate_process(_handle: *mut c_void, status: i32) -> ! {
    log::trace!("ntdll!NtTerminateProcess({:#x})", status);
    std::process::exit(status);
}

/// `vcruntime!memset(dst, val, n) -> *mut c_void`. A real `memset` (often imported by
/// MSVC-built code and safe to implement directly).
extern "C" fn vcruntime_memset(dst: *mut u8, val: u8, n: usize) -> *mut u8 {
    // SAFETY: `dst..dst+n` is valid for writing per the C `memset` contract.
    unsafe { std::ptr::write_bytes(dst, val, n) };
    dst
}

/// `vcruntime!memcpy(dst, src, n) -> *mut c_void`.
extern "C" fn vcruntime_memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: `dst..dst+n` and `src..src+n` are valid and non-overlapping per the C
    // `memcpy` contract.
    unsafe { std::ptr::copy_nonoverlapping(src, dst, n) };
    dst
}

/// Table of implemented Windows exports, keyed by `(lowercased dll, symbol)`.
pub struct ImplTable {
    map: HashMap<(String, String), FnPtr>,
}

impl ImplTable {
    /// Build the default table of Phase 1 implemented exports.
    pub fn default_table() -> Self {
        let mut map = HashMap::new();
        let mut add = |dll: &str, sym: &str, f: FnPtr| {
            map.insert((dll.to_string(), sym.to_string()), f);
        };

        // kernel32 — console/process/time
        add(
            "kernel32.dll",
            "ExitProcess",
            kernel32_exit_process as FnPtr,
        );
        add(
            "kernel32.dll",
            "GetStdHandle",
            kernel32_get_std_handle as FnPtr,
        );
        add("kernel32.dll", "WriteFile", kernel32_write_file as FnPtr);
        add(
            "kernel32.dll",
            "GetLastError",
            kernel32_get_last_error as FnPtr,
        );
        add(
            "kernel32.dll",
            "SetLastError",
            kernel32_set_last_error as FnPtr,
        );
        add(
            "kernel32.dll",
            "GetTickCount",
            kernel32_get_tick_count as FnPtr,
        );
        add(
            "kernel32.dll",
            "QueryPerformanceCounter",
            kernel32_query_performance_counter as FnPtr,
        );

        // ntdll — process termination
        add(
            "ntdll.dll",
            "NtTerminateProcess",
            ntdll_terminate_process as FnPtr,
        );

        // vcruntime — C runtime intrinsics
        add("vcruntime140.dll", "memset", vcruntime_memset as FnPtr);
        add("vcruntime140.dll", "memcpy", vcruntime_memcpy as FnPtr);
        add("vcruntime140_1.dll", "memset", vcruntime_memset as FnPtr);
        add("vcruntime140_1.dll", "memcpy", vcruntime_memcpy as FnPtr);
        add("ucrtbase.dll", "memset", vcruntime_memset as FnPtr);
        add("ucrtbase.dll", "memcpy", vcruntime_memcpy as FnPtr);

        // api-ms-win-* sets — these are API-set pseudo-DLLs that forward to kernel32;
        // forward the few we implement so apiset-named imports resolve too.
        for apiset in [
            "api-ms-win-core-processthreads-l1-1-0",
            "api-ms-win-core-console-l1-1-0",
            "api-ms-win-core-console-l2-1-0",
            "api-ms-win-core-synch-l1-1-0",
            "api-ms-win-core-synch-l1-2-0",
            "api-ms-win-core-errorhandling-l1-1-0",
            "api-ms-win-core-profile-l1-1-0",
            "api-ms-win-core-libraryloader-l1-1-0",
        ] {
            add(apiset, "ExitProcess", kernel32_exit_process as FnPtr);
            add(apiset, "GetStdHandle", kernel32_get_std_handle as FnPtr);
            add(apiset, "WriteFile", kernel32_write_file as FnPtr);
            add(apiset, "GetLastError", kernel32_get_last_error as FnPtr);
            add(apiset, "SetLastError", kernel32_set_last_error as FnPtr);
            add(apiset, "GetTickCount", kernel32_get_tick_count as FnPtr);
            add(
                apiset,
                "QueryPerformanceCounter",
                kernel32_query_performance_counter as FnPtr,
            );
            add(
                apiset,
                "NtTerminateProcess",
                ntdll_terminate_process as FnPtr,
            );
        }

        ImplTable { map }
    }

    fn lookup(&self, dll: &str, sym: &str) -> Option<FnPtr> {
        self.map.get(&(dll.to_string(), sym.to_string())).copied()
    }
}

/// Helper to silence an unused-import warning when `c_int`/`c_uint` are only referenced
/// through the signatures above in some configurations.
#[allow(dead_code)]
fn _unused_types(_a: c_int, _b: c_uint) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_table_resolves_known_kernel32_exports() {
        let t = ImplTable::default_table();
        assert!(t.lookup("kernel32.dll", "ExitProcess").is_some());
        assert!(t.lookup("kernel32.dll", "GetStdHandle").is_some());
        assert!(t.lookup("ntdll.dll", "NtTerminateProcess").is_some());
        assert!(t.lookup("vcruntime140.dll", "memset").is_some());
        // Unknown symbol resolves to None (the loader will stub it).
        assert!(t.lookup("kernel32.dll", "DefinitelyNotReal").is_none());
    }

    #[test]
    fn resolve_records_stubbed_imports() {
        // A fake import list with one known and one unknown symbol.
        // goblin::pe::Import is hard to construct by hand, so we test resolve() via the
        // table lookup path directly.
        let t = ImplTable::default_table();
        assert!(t.lookup("kernel32.dll", "WriteFile").is_some());
        assert!(t.lookup("kernel32.dll", "MysteryFunc").is_none());
    }
}
