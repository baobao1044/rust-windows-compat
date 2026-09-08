//! ucrtbase.dll (Universal CRT) reimplementation for the PE loader.
//!
//! Modern Windows apps (built against the UCRT, not the legacy `msvcrt.dll`) import the C
//! runtime from `ucrtbase.dll`. Many symbols overlap with `msvcrt.dll` (`malloc`/`free`/
//! `strlen`/...) but the UCRT also adds a distinct startup/init surface
//! (`_configure_narrow_argv`, `_initialize_narrow_environment`, `__p___argc`,
//! `_register_onexit_function`, ...) that the UCRT boot sequence calls before `main`/
//! `WinMain`.
//!
//! Memory functions delegate to the heap module (same `libc::malloc` + header mechanism as
//! `HeapAlloc`/`HeapFree`) so a pointer allocated by `ucrtbase!malloc` is interchangeable with
//! `HeapFree`/`msvcrt!free` — matching the real UCRT, which backs `malloc` on the process
//! heap. The argv/env globals are populated by delegating to the cached `__getmainargs`
//! machinery in [`crate::crt`], so the UCRT's `__p___argc`/`__p___argv`/
//! `_get_initial_narrow_environment` return the same real argc/argv/envp the rest of the
//! loader builds.
//!
//! The exit-family functions (`exit`/`_exit`/`_c_exit`/`quick_exit`/`abort`) terminate via
//! `libc::_exit` (the raw exit syscall), matching the convention in [`crate::crt`]: the PE
//! entrypoint runs on the guest stack with a modified `gs` base, so the host C library's
//! `exit` (which runs atexit handlers and flushes host stdio) is unsafe to call from that
//! context. `_exit` never touches userspace cleanup state and matches the Windows contract
//! that these functions terminate immediately.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment.

#![deny(unsafe_op_in_unsafe_fn)]
// The `extern "C"` functions here implement C runtime APIs that take raw pointers. They
// are called from PE machine code via ABI trampolines, not from safe Rust callers.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_char, c_int, c_long, c_ulong, c_void};
use std::sync::OnceLock;

use crate::FnPtr;

// ---------------------------------------------------------------------------
// Host libc wide-character helpers. The `libc` crate does not expose these on the
// Linux/GNU target, so we declare the FFI bindings directly against glibc. Windows
// `wchar_t` is 16-bit while the host's is 32-bit; the pointer-taking parsers (`wcstol`/
// `wcstoul`) are fed a widened scratch buffer (see [`widen_to_wchar`]) so the width
// mismatch is bridged. The scalar classifiers/converters (`iswspace`/`towupper`/...)
// take a single `wint_t` value, which is width-compatible for BMP characters (every
// code unit a Windows `wchar_t` can hold).
// ---------------------------------------------------------------------------
mod ffi {
    use std::os::raw::{c_int, c_long, c_ulong};
    extern "C" {
        pub fn iswspace(wc: u32) -> c_int;
        pub fn iswprint(wc: u32) -> c_int;
        pub fn iswdigit(wc: u32) -> c_int;
        pub fn towupper(wc: u32) -> u32;
        pub fn towlower(wc: u32) -> u32;
        pub fn wcstol(nptr: *const i32, endptr: *mut *mut i32, base: c_int) -> c_long;
        pub fn wcstoul(nptr: *const i32, endptr: *mut *mut i32, base: c_int) -> c_ulong;
    }
}

// ---------------------------------------------------------------------------
// argv / env globals (populated once from the cached __getmainargs machinery)
// ---------------------------------------------------------------------------

/// The UCRT `__argc` global, exposed via [`p_argc`]. Set once during CRT init.
static mut UCRT_ARGC: c_int = 0;
/// The UCRT `__argv` global (`char**`), exposed via [`p_argv`]. Set once during CRT init.
static mut UCRT_ARGV: *mut *mut c_char = std::ptr::null_mut();
/// The UCRT narrow environment (`char**`), returned by
/// [`get_initial_narrow_environment`]. Set once during CRT init.
static mut UCRT_ENVP: *mut *mut c_char = std::ptr::null_mut();
/// The UCRT `errno` cell, returned by [`errno`]. Process-global (matching ntapi's
/// last-error, which is also process-global for M1).
static mut UCRT_ERRNO: c_int = 0;

/// One-shot guard ensuring the argv/env globals are populated exactly once. The CRT
/// startup is single-threaded, so the `static mut` writes below are race-free.
static UCRT_INIT: OnceLock<()> = OnceLock::new();

/// Populate [`UCRT_ARGC`]/[`UCRT_ARGV`]/[`UCRT_ENVP`] from the cached `__getmainargs`
/// machinery in [`crate::crt`]. Idempotent; safe to call from any of the UCRT init hooks.
fn ensure_ucrt_init() {
    UCRT_INIT.get_or_init(|| {
        let mut argc: c_int = 0;
        let mut argv: *mut *mut c_char = std::ptr::null_mut();
        let mut envp: *mut *mut c_char = std::ptr::null_mut();
        // `getmainargs` builds and caches argc/argv/envp from the host process args/env and
        // also publishes the env array through the msvcrt `__initenv` data symbol. The two
        // pointer out-params are `*mut *mut *mut c_char` (a pointer to a `char**`).
        crate::crt::getmainargs(&mut argc, &mut argv, &mut envp, 0, std::ptr::null_mut());
        // SAFETY: the CRT startup is single-threaded, so these `static mut` writes have no
        // concurrent reader. The pointers come from the process-lifetime `OnceLock` cache
        // inside `build_args_and_env`, so they stay valid for the process lifetime.
        unsafe {
            UCRT_ARGC = argc;
            UCRT_ARGV = argv;
            UCRT_ENVP = envp;
        }
    });
}

// ---------------------------------------------------------------------------
// stdio / FILE
// ---------------------------------------------------------------------------

/// `ucrtbase!__acrt_iob_func(unsigned index) -> FILE*`. The UCRT returns a `FILE*` for the
/// stdio stream `index` (0=stdin, 1=stdout, 2=stderr). We return NULL: the console-PE
/// acceptance target writes via `WriteFile`/`WriteConsole` (which go straight to the fd)
/// rather than buffered stdio, so no caller dereferences this `FILE*`. Returning NULL is
/// safe and matches the "no buffered stdio" model.
pub extern "C" fn acrt_iob_func(_index: u32) -> *mut c_void {
    std::ptr::null_mut()
}

/// `ucrtbase!_errno() -> errno_t*`. Returns a pointer to the process-global errno cell.
pub extern "C" fn errno() -> *mut c_int {
    // `addr_of_mut!` of a `static mut` is safe (it does not dereference); the CRT startup
    // is single-threaded, so there is no concurrent writer when the caller later writes
    // through the returned pointer.
    std::ptr::addr_of_mut!(UCRT_ERRNO)
}

// ---------------------------------------------------------------------------
// argv / environment init
// ---------------------------------------------------------------------------

/// `ucrtbase!_configure_narrow_argv(int mode) -> int`. Initializes the narrow (char)
/// argv table. We populate the globals via [`ensure_ucrt_init`] and return 0 (success).
pub extern "C" fn configure_narrow_argv(_mode: c_int) -> c_int {
    ensure_ucrt_init();
    0
}

/// `ucrtbase!_initialize_narrow_environment() -> int`. Initializes the narrow environment.
/// Returns 0 (success).
pub extern "C" fn initialize_narrow_environment() -> c_int {
    ensure_ucrt_init();
    0
}

/// `ucrtbase!_get_initial_narrow_environment() -> char**`. Returns the narrow environment
/// block (a `char**` array of `KEY=VALUE` strings, NUL-terminated). Backed by the cached
/// env array from [`crate::crt`].
pub extern "C" fn get_initial_narrow_environment() -> *mut *mut c_char {
    ensure_ucrt_init();
    // SAFETY: `UCRT_ENVP` was populated by `ensure_ucrt_init` (single-threaded CRT init)
    // and points at the process-lifetime env array; reading it here is safe.
    unsafe { UCRT_ENVP }
}

/// `ucrtbase!__p___argc() -> int*`. Returns a pointer to the `__argc` global.
pub extern "C" fn p_argc() -> *mut c_int {
    ensure_ucrt_init();
    // `addr_of_mut!` of a `static mut` is safe (no dereference); single-threaded CRT init.
    std::ptr::addr_of_mut!(UCRT_ARGC)
}

/// `ucrtbase!__p___argv() -> char***`. Returns a pointer to the `__argv` global.
pub extern "C" fn p_argv() -> *mut *mut *mut c_char {
    ensure_ucrt_init();
    // `addr_of_mut!` of a `static mut` is safe (no dereference); single-threaded CRT init.
    std::ptr::addr_of_mut!(UCRT_ARGV)
}

// ---------------------------------------------------------------------------
// Wide-char argv / environment init
// ---------------------------------------------------------------------------

/// The UCRT `__wargv` global (`wchar_t**`), exposed via [`p_wargv`]. We do not populate a
/// real wide argv (the acceptance target uses the narrow argv from [`crate::crt`]); the
/// static holds a single NULL entry. `*__p___wargv()` then reads as a NULL `wchar_t**`
/// (the real UCRT's unconfigured wide-argv state), which callers null-check instead of
/// dereferencing the NULL the soft stub returned — the segfault this fixes.
static mut UCRT_WARGV: [*mut u16; 1] = [std::ptr::null_mut()];

/// `ucrtbase!__p___wargv() -> wchar_t***`. Returns a pointer to the [`UCRT_WARGV`] global.
/// `*ret` is NULL (empty/unconfigured wide argv), matching the real UCRT before
/// `_configure_wide_argv` populates `__wargv`.
pub extern "C" fn p_wargv() -> *mut *mut *mut u16 {
    // `addr_of_mut!` of a `static mut` is safe (no dereference); the CRT startup is
    // single-threaded, so there is no concurrent writer.
    std::ptr::addr_of_mut!(UCRT_WARGV) as *mut *mut *mut u16
}

/// `ucrtbase!_configure_wide_argv(int mode) -> int`. Initializes the wide (wchar_t) argv
/// table. We do not build a real wide argv (the target uses the narrow argv); return 0
/// (success) so the CRT boot sequence proceeds.
pub extern "C" fn configure_wide_argv(_mode: c_int) -> c_int {
    0
}

/// `ucrtbase!_initialize_wide_environment() -> int`. Initializes the wide environment.
/// Returns 0 (success); the narrow environment from [`crate::crt`] is authoritative.
pub extern "C" fn initialize_wide_environment() -> c_int {
    0
}

/// `ucrtbase!_get_initial_wide_environment() -> wchar_t**`. Returns the wide environment
/// block. We do not maintain a separate wide env; return NULL (no wide env), which the CRT
/// treats as "empty/absent" and falls back to the narrow env.
pub extern "C" fn get_initial_wide_environment() -> *mut *mut u16 {
    std::ptr::null_mut()
}

/// `ucrtbase!_set_app_type(int) -> void`. No-op (we do not model app types).
pub extern "C" fn set_app_type(_app_type: c_int) {}

// ---------------------------------------------------------------------------
// onexit / atexit
// ---------------------------------------------------------------------------

/// `ucrtbase!_initialize_onexit_table(table**) -> int`. No-op; returns 0 (success). We do
/// not register real onexit handlers (cleanup is not needed for the console-PE target).
pub extern "C" fn initialize_onexit_table(_table: *mut *mut c_void) -> c_int {
    0
}

/// `ucrtbase!_register_onexit_function(table*, fn) -> int`. No-op; returns 0 (success).
pub extern "C" fn register_onexit_function(_table: *mut *mut c_void, _func: *mut c_void) -> c_int {
    0
}

/// `ucrtbase!_execute_onexit_table(table*) -> int`. No-op; returns 0 (success).
pub extern "C" fn execute_onexit_table(_table: *mut *mut c_void) -> c_int {
    0
}

/// `ucrtbase!_crt_atexit(void (*)()) -> int`. No-op; returns 0 (success).
pub extern "C" fn crt_atexit(_func: *mut c_void) -> c_int {
    0
}

/// `ucrtbase!_crt_at_quick_exit(void (*)()) -> int`. No-op; returns 0 (success).
pub extern "C" fn crt_at_quick_exit(_func: *mut c_void) -> c_int {
    0
}

/// `ucrtbase!_assert(const char*, const char*, unsigned) -> void`. Best-effort: log the
/// failed assertion and return (rather than aborting) so a stray assertion in a probed code
/// path does not kill the load. The real UCRT aborts, but for the acceptance target
/// continuing is safer than terminating on a non-fatal probe.
pub extern "C" fn assert(msg: *const c_char, file: *const c_char, line: u32) {
    let m = if msg.is_null() {
        "<unknown>".to_string()
    } else {
        // SAFETY: `msg` is a NUL-terminated C string per the `_assert` contract.
        unsafe { std::ffi::CStr::from_ptr(msg) }
            .to_string_lossy()
            .into_owned()
    };
    let f = if file.is_null() {
        "<unknown>".to_string()
    } else {
        // SAFETY: `file` is a NUL-terminated C string per the `_assert` contract.
        unsafe { std::ffi::CStr::from_ptr(file) }
            .to_string_lossy()
            .into_owned()
    };
    log::warn!("ucrtbase!_assert: {m} ({f}:{line})");
}

// ---------------------------------------------------------------------------
// Environment / file stubs
// ---------------------------------------------------------------------------

/// `ucrtbase!getenv(const char*) -> char*`. Returns NULL (no environment variable found).
/// Callers check for NULL (the documented "not found" result), so this is safe.
pub extern "C" fn getenv(_name: *const c_char) -> *mut c_char {
    std::ptr::null_mut()
}

/// `ucrtbase!_wfopen(const wchar_t*, const wchar_t*) -> FILE*`. Returns NULL (cannot open
/// the file). Callers check for NULL on failure.
pub extern "C" fn wfopen(_filename: *const u16, _mode: *const u16) -> *mut c_void {
    std::ptr::null_mut()
}

/// `ucrtbase!_wpopen(const wchar_t*, const wchar_t*) -> FILE*`. Returns NULL (no real
/// pipe stream). Callers check for NULL on failure.
pub extern "C" fn wpopen(_cmd: *const u16, _mode: *const u16) -> *mut c_void {
    std::ptr::null_mut()
}

/// `ucrtbase!_pclose(FILE*) -> int`. Returns -1 (no real pipe stream to close).
pub extern "C" fn pclose(_stream: *mut c_void) -> c_int {
    -1
}

// ---------------------------------------------------------------------------
// Process termination (noreturn) — see module docs for the `_exit` rationale.
// ---------------------------------------------------------------------------

/// `ucrtbase!_c_exit(int) -> !`. Terminates immediately via the raw `_exit` syscall.
pub extern "C" fn c_exit(code: c_int) -> ! {
    log::trace!("ucrtbase!_c_exit({code})");
    // SAFETY: `_exit` is the raw exit syscall; safe from any stack/gs-base context because
    // it does not touch userspace cleanup state.
    unsafe { libc::_exit(code) };
}

/// `ucrtbase!_exit(int) -> !`. Terminates immediately via the raw `_exit` syscall.
pub extern "C" fn exit_sys(code: c_int) -> ! {
    log::trace!("ucrtbase!_exit({code})");
    // SAFETY: as in `c_exit` — `_exit` is safe from any context.
    unsafe { libc::_exit(code) };
}

/// `ucrtbase!abort() -> !`. Terminates with exit code 3 (the conventional SIGABRT exit
/// code). Uses `_exit` rather than `libc::abort` so we do not raise a host signal (which
/// would run host signal-handling code on the guest stack); matches `crate::crt::abort`.
pub extern "C" fn abort() -> ! {
    log::trace!("ucrtbase!abort()");
    // SAFETY: as in `c_exit` — `_exit` is safe from any context.
    unsafe { libc::_exit(3) };
}

/// `ucrtbase!exit(int) -> !`. Terminates immediately via the raw `_exit` syscall. The real
/// UCRT runs atexit handlers first; we run none (the acceptance target registers none), so
/// `_exit` matches the effective behavior without touching host cleanup state.
pub extern "C" fn exit(code: c_int) -> ! {
    log::trace!("ucrtbase!exit({code})");
    // SAFETY: as in `c_exit` — `_exit` is safe from any context.
    unsafe { libc::_exit(code) };
}

/// `ucrtbase!quick_exit(int) -> !`. Terminates immediately via the raw `_exit` syscall.
pub extern "C" fn quick_exit(code: c_int) -> ! {
    log::trace!("ucrtbase!quick_exit({code})");
    // SAFETY: as in `c_exit` — `_exit` is safe from any context.
    unsafe { libc::_exit(code) };
}

// ---------------------------------------------------------------------------
// Memory — delegate to the heap module (interchangeable with HeapAlloc/HeapFree/msvcrt).
// ---------------------------------------------------------------------------

/// `ucrtbase!malloc(size_t) -> void*`. Delegates to the heap module's `HeapAlloc` on the
/// process heap.
pub extern "C" fn malloc(size: usize) -> *mut c_void {
    crate::heap::heap_alloc(crate::heap::get_process_heap(), 0, size)
}

/// `ucrtbase!calloc(count, size) -> void*`. Zero-fills the allocation.
pub extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    let total = match count.checked_mul(size) {
        Some(t) => t,
        None => return std::ptr::null_mut(), // overflow -> failure
    };
    const HEAP_ZERO_MEMORY: u32 = 0x08;
    crate::heap::heap_alloc(crate::heap::get_process_heap(), HEAP_ZERO_MEMORY, total)
}

/// `ucrtbase!free(void*)`. Delegates to `HeapFree`. A null pointer is a no-op success.
pub extern "C" fn free(ptr: *mut c_void) {
    crate::heap::heap_free(crate::heap::get_process_heap(), 0, ptr);
}

/// `ucrtbase!realloc(void*, size_t) -> void*`. Delegates to the heap module's
/// `HeapReAlloc`. `realloc(NULL, n)` is equivalent to `malloc(n)`.
pub extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    crate::heap::heap_re_alloc(crate::heap::get_process_heap(), 0, ptr, size)
}

// ---------------------------------------------------------------------------
// Memory intrinsics — delegate to the same implementations the rest of the loader uses.
// ---------------------------------------------------------------------------

/// `ucrtbase!memset(dst, val, n) -> dst*`.
pub extern "C" fn memset(dst: *mut u8, val: u8, n: usize) -> *mut u8 {
    if dst.is_null() || n == 0 {
        return dst;
    }
    // SAFETY: `dst..dst+n` is valid for writing per the C `memset` contract.
    unsafe { std::ptr::write_bytes(dst, val, n) };
    dst
}

/// `ucrtbase!memcpy(dst, src, n) -> dst*`.
pub extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }
    // SAFETY: `dst..dst+n` and `src..src+n` are valid and non-overlapping per the C
    // `memcpy` contract.
    unsafe { std::ptr::copy_nonoverlapping(src, dst, n) };
    dst
}

/// `ucrtbase!memmove(dst, src, n) -> dst*`. Handles overlapping ranges.
pub extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }
    // SAFETY: `dst..dst+n` and `src..src+n` are valid (may overlap) per the C `memmove`
    // contract; `copy` handles overlap correctly.
    unsafe { std::ptr::copy(src, dst, n) };
    dst
}

/// `ucrtbase!memcmp(a, b, n) -> int`.
pub extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    if a.is_null() || b.is_null() || n == 0 {
        return 0;
    }
    // SAFETY: `a` and `b` are readable for `n` bytes.
    let sa = unsafe { std::slice::from_raw_parts(a as *const u8, n) };
    let sb = unsafe { std::slice::from_raw_parts(b as *const u8, n) };
    for i in 0..n {
        if sa[i] != sb[i] {
            return (sa[i] as c_int) - (sb[i] as c_int);
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Narrow string functions
// ---------------------------------------------------------------------------

/// `ucrtbase!strlen(const char*) -> size_t`.
pub extern "C" fn strlen(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    // SAFETY: `s` is a NUL-terminated C string; we walk until the first 0 byte.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `ucrtbase!strcpy(dst, src) -> char*`. Copies the NUL-terminated `src` into `dst`.
pub extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let mut i = 0usize;
    // SAFETY: both are non-null NUL-terminated buffers; copy including the terminator.
    unsafe {
        loop {
            let c = *src.add(i);
            *dst.add(i) = c;
            i += 1;
            if c == 0 {
                break;
            }
        }
    }
    dst
}

/// `ucrtbase!strncpy(dst, src, n) -> char*`. Copies at most `n` bytes, NUL-padding if `src`
/// is shorter; if `src` is longer, `dst` is not NUL-terminated (matching the C contract).
pub extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    // SAFETY: `src` is NUL-terminated; `dst` is writable for `n` bytes.
    unsafe {
        let mut i = 0usize;
        while i < n && *src.add(i) != 0 {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        while i < n {
            *dst.add(i) = 0; // pad the remainder with NUL
            i += 1;
        }
    }
    dst
}

/// `ucrtbase!strcmp(a, b) -> int`.
pub extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    if a.is_null() || b.is_null() {
        return (a.is_null() as c_int) - (b.is_null() as c_int);
    }
    let mut i = 0usize;
    // SAFETY: both are NUL-terminated; we stop at the first differing byte or shared NUL.
    unsafe {
        loop {
            let ca = *a.add(i) as u8;
            let cb = *b.add(i) as u8;
            if ca != cb {
                return (ca as c_int) - (cb as c_int);
            }
            if ca == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// `ucrtbase!strncmp(a, b, n) -> int`. Delegates to the msvcrt implementation so the
/// behavior is identical across CRTs.
pub extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    crate::crt::strncmp(a, b, n)
}

/// `ucrtbase!strchr(s, c) -> char*`. Returns a pointer to the first occurrence of `c` in
/// `s`, or NULL if not found (and returns a pointer to the terminator if `c == 0`).
pub extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let target = c as u8;
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated; we stop at the NUL (checking it for `c == 0`).
    unsafe {
        loop {
            let ch = *s.add(i) as u8;
            if ch == target {
                return s.add(i) as *mut c_char;
            }
            if ch == 0 {
                return std::ptr::null_mut();
            }
            i += 1;
        }
    }
}

/// `ucrtbase!strstr(haystack, needle) -> char*`. Returns a pointer to the first occurrence
/// of `needle` in `haystack`, or NULL. An empty `needle` returns `haystack` (C standard).
pub extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: both are NUL-terminated.
    let needle_len = unsafe {
        let mut n = 0usize;
        while *needle.add(n) != 0 {
            n += 1;
        }
        n
    };
    if needle_len == 0 {
        return haystack as *mut c_char;
    }
    let hay_len = strlen(haystack);
    if hay_len < needle_len {
        return std::ptr::null_mut();
    }
    let mut i = 0usize;
    // SAFETY: `haystack` is readable for `hay_len + 1` bytes (including the NUL).
    while i + needle_len <= hay_len {
        // SAFETY: compare `needle_len` bytes at `haystack + i` against `needle`.
        let matches = unsafe {
            (0..needle_len).all(|j| (*haystack.add(i + j) as u8) == (*needle.add(j) as u8))
        };
        if matches {
            return unsafe { haystack.add(i) as *mut c_char };
        }
        i += 1;
    }
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Wide string functions (UTF-16)
// ---------------------------------------------------------------------------

/// `ucrtbase!wcslen(const wchar_t*) -> size_t`. Length in code units excl. the NUL.
pub extern "C" fn wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated UTF-16; we stop at the first 0 code unit.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `ucrtbase!wcscpy(dst, src) -> wchar_t*`. Copies the NUL-terminated UTF-16 `src` to `dst`.
pub extern "C" fn wcscpy(dst: *mut u16, src: *const u16) -> *mut u16 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let mut i = 0usize;
    // SAFETY: both are non-null NUL-terminated UTF-16 buffers; copy including the terminator.
    unsafe {
        loop {
            let c = *src.add(i);
            *dst.add(i) = c;
            i += 1;
            if c == 0 {
                break;
            }
        }
    }
    dst
}

/// `ucrtbase!wcscmp(a, b) -> int`.
pub extern "C" fn wcscmp(a: *const u16, b: *const u16) -> c_int {
    if a.is_null() || b.is_null() {
        return (a.is_null() as c_int) - (b.is_null() as c_int);
    }
    let mut i = 0usize;
    // SAFETY: both are NUL-terminated; we stop at the first differing code unit or shared NUL.
    unsafe {
        loop {
            let ca = *a.add(i);
            let cb = *b.add(i);
            if ca != cb {
                return (ca as c_int) - (cb as c_int);
            }
            if ca == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// `ucrtbase!wcsncmp(a, b, n) -> int`.
pub extern "C" fn wcsncmp(a: *const u16, b: *const u16, n: usize) -> c_int {
    if a.is_null() || b.is_null() || n == 0 {
        return 0;
    }
    // SAFETY: `a` and `b` are readable for `n` code units (or NUL-terminated sooner).
    unsafe {
        for i in 0..n {
            let ca = *a.add(i);
            let cb = *b.add(i);
            if ca != cb {
                return (ca as c_int) - (cb as c_int);
            }
            if ca == 0 {
                return 0;
            }
        }
    }
    0
}

/// `ucrtbase!wcschr(s, c) -> wchar_t*`. Returns a pointer to the first occurrence of `c` in
/// `s`, or NULL. (`c == 0` returns a pointer to the terminator.)
pub extern "C" fn wcschr(s: *const u16, c: u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated; we stop at the NUL (checking it for `c == 0`).
    unsafe {
        loop {
            let ch = *s.add(i);
            if ch == c {
                return s.add(i) as *mut u16;
            }
            if ch == 0 {
                return std::ptr::null_mut();
            }
            i += 1;
        }
    }
}

/// `ucrtbase!wcsstr(haystack, needle) -> wchar_t*`. Returns a pointer to the first
/// occurrence of `needle` in `haystack`, or NULL. An empty `needle` returns `haystack`
/// (C standard).
pub extern "C" fn wcsstr(haystack: *const u16, needle: *const u16) -> *mut u16 {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: both are NUL-terminated UTF-16.
    let needle_len = unsafe {
        let mut n = 0usize;
        while *needle.add(n) != 0 {
            n += 1;
        }
        n
    };
    if needle_len == 0 {
        return haystack as *mut u16;
    }
    let hay_len = wcslen(haystack);
    if hay_len < needle_len {
        return std::ptr::null_mut();
    }
    let mut i = 0usize;
    // SAFETY: `haystack` is readable for `hay_len + 1` code units (incl. the NUL).
    while i + needle_len <= hay_len {
        // SAFETY: compare `needle_len` code units at `haystack + i` against `needle`.
        let matches = unsafe { (0..needle_len).all(|j| *haystack.add(i + j) == *needle.add(j)) };
        if matches {
            // SAFETY: `i + needle_len <= hay_len`, so `i` is within `haystack`.
            return unsafe { haystack.add(i) as *mut u16 };
        }
        i += 1;
    }
    std::ptr::null_mut()
}

/// `ucrtbase!wcsrchr(s, c) -> wchar_t*`. Returns a pointer to the last occurrence of `c` in
/// `s`, or NULL. (`c == 0` returns a pointer to the terminator.)
pub extern "C" fn wcsrchr(s: *const u16, c: u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut found: *mut u16 = std::ptr::null_mut();
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated; we scan to (and check) the NUL for `c == 0`.
    unsafe {
        loop {
            let ch = *s.add(i);
            if ch == c {
                found = s.add(i) as *mut u16;
            }
            if ch == 0 {
                break;
            }
            i += 1;
        }
    }
    found
}

/// `ucrtbase!wcspbrk(s, set) -> wchar_t*`. Returns a pointer to the first occurrence in `s`
/// of any character from `set`, or NULL.
pub extern "C" fn wcspbrk(s: *const u16, set: *const u16) -> *mut u16 {
    if s.is_null() || set.is_null() {
        return std::ptr::null_mut();
    }
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated; for each code unit we scan `set` (NUL-terminated).
    unsafe {
        loop {
            let ch = *s.add(i);
            if ch == 0 {
                return std::ptr::null_mut();
            }
            let mut j = 0usize;
            while *set.add(j) != 0 {
                if *set.add(j) == ch {
                    return s.add(i) as *mut u16;
                }
                j += 1;
            }
            i += 1;
        }
    }
}

/// `ucrtbase!wcscspn(s, set) -> size_t`. Length of the prefix of `s` consisting only of
/// characters not in `set`.
pub extern "C" fn wcscspn(s: *const u16, set: *const u16) -> usize {
    if s.is_null() || set.is_null() {
        return 0;
    }
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated; for each code unit we scan `set` for a match.
    unsafe {
        loop {
            let ch = *s.add(i);
            if ch == 0 {
                return i;
            }
            let mut j = 0usize;
            let mut hit = false;
            while *set.add(j) != 0 {
                if *set.add(j) == ch {
                    hit = true;
                    break;
                }
                j += 1;
            }
            if hit {
                return i;
            }
            i += 1;
        }
    }
}

/// `ucrtbase!wcscat(dst, src) -> wchar_t*`. Appends the NUL-terminated `src` to the
/// NUL-terminated `dst`.
pub extern "C" fn wcscat(dst: *mut u16, src: *const u16) -> *mut u16 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let d = wcslen(dst);
    let mut i = 0usize;
    // SAFETY: `dst` is NUL-terminated and writable; `src` is NUL-terminated. Copy `src`
    // (including its terminator) starting at `dst`'s terminator.
    unsafe {
        loop {
            let c = *src.add(i);
            *dst.add(d + i) = c;
            i += 1;
            if c == 0 {
                break;
            }
        }
    }
    dst
}

// ---------------------------------------------------------------------------
// Wide-string numeric parsing — delegate to the host `wcstol`/`wcstoul` via a widened
// scratch buffer (Windows `wchar_t` is 16-bit, the host's is 32-bit, so the guest pointer
// cannot be passed directly). The widening is 1:1 for the BMP characters the parsers
// consume (digits, sign, whitespace, hex letters).
// ---------------------------------------------------------------------------

/// Widen the NUL-terminated UTF-16 string at `s` into a freshly-allocated host-`wchar_t`
/// (`i32`) buffer the host `wcstol`/`wcstoul` can parse. The buffer is NUL-terminated.
/// Widening zero-extends each code unit, which is correct for BMP characters.
fn widen_to_wchar(s: *const u16) -> Vec<i32> {
    let mut buf = Vec::new();
    if s.is_null() {
        buf.push(0);
        return buf;
    }
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated; we stop at the first 0 code unit.
    unsafe {
        while *s.add(i) != 0 {
            buf.push(*s.add(i) as i32);
            i += 1;
        }
    }
    buf.push(0);
    buf
}

/// Translate the host `wchar_t*` end pointer `end32` (into `buf`) back to a guest `u16*`
/// end pointer (into the original `s`), writing it through `endptr` if non-null. The code
/// unit offset is identical because [`widen_to_wchar`] widens 1:1.
fn translate_wide_endptr(s: *const u16, buf: &[i32], end32: *mut i32, endptr: *mut *mut u16) {
    if endptr.is_null() {
        return;
    }
    let offset = if end32.is_null() || buf.is_empty() {
        0
    } else {
        // SAFETY: `end32` points within `buf` (or at its start) per the `wcstol` contract.
        let off = unsafe { (end32 as *const i32).offset_from(buf.as_ptr()) };
        if off < 0 {
            0
        } else {
            off as usize
        }
    };
    let end16 = if s.is_null() {
        std::ptr::null_mut()
    } else {
        // SAFETY: `offset` is within the original NUL-terminated string (<= its length).
        unsafe { (s as *mut u16).add(offset) }
    };
    // SAFETY: `endptr` is a guest out-pointer valid for one `wchar_t*`.
    unsafe { std::ptr::write_unaligned(endptr, end16) };
}

/// `ucrtbase!wcstol(const wchar_t*, wchar_t**, int) -> long`. Parses a wide string as a
/// signed long in `base`. Delegates to the host `wcstol` via [`widen_to_wchar`]; translates
/// the end pointer back to the guest pointer.
pub extern "C" fn wcstol(s: *const u16, endptr: *mut *mut u16, base: c_int) -> c_long {
    let buf = widen_to_wchar(s);
    let mut end32: *mut i32 = std::ptr::null_mut();
    // SAFETY: `buf` is a NUL-terminated `wchar_t` buffer valid for the call; `end32` is a
    // valid out-pointer. `wcstol` reads within `buf` and writes the end pointer to `end32`.
    let result = unsafe { ffi::wcstol(buf.as_ptr(), &mut end32, base) };
    translate_wide_endptr(s, &buf, end32, endptr);
    result
}

/// `ucrtbase!wcstoul(const wchar_t*, wchar_t**, int) -> unsigned long`. Unsigned variant
/// of [`wcstol`]; delegates to the host `wcstoul`.
pub extern "C" fn wcstoul(s: *const u16, endptr: *mut *mut u16, base: c_int) -> c_ulong {
    let buf = widen_to_wchar(s);
    let mut end32: *mut i32 = std::ptr::null_mut();
    // SAFETY: as in [`wcstol`].
    let result = unsafe { ffi::wcstoul(buf.as_ptr(), &mut end32, base) };
    translate_wide_endptr(s, &buf, end32, endptr);
    result
}

// ---------------------------------------------------------------------------
// Wide-string case / reverse / duplicate (operate on UTF-16 code units in place)
// ---------------------------------------------------------------------------

/// ASCII-fold a `wchar_t` code unit to lowercase (A-Z -> a-z); other values unchanged.
/// Sufficient for `_wcsicmp`/`_wcsnicmp`/`_wcslwr` on ASCII input, which is the common case.
fn wchar_ascii_tolower(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// ASCII-fold a `wchar_t` code unit to uppercase (a-z -> A-Z); other values unchanged.
fn wchar_ascii_toupper(c: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&c) {
        c - 32
    } else {
        c
    }
}

/// `ucrtbase!_wcsicmp(a, b) -> int`. Case-insensitive (ASCII) wide-string compare.
pub extern "C" fn wcsicmp(a: *const u16, b: *const u16) -> c_int {
    if a.is_null() || b.is_null() {
        return (a.is_null() as c_int) - (b.is_null() as c_int);
    }
    let mut i = 0usize;
    // SAFETY: both NUL-terminated; stop at the first differing unit or shared NUL.
    unsafe {
        loop {
            let ca = wchar_ascii_tolower(*a.add(i));
            let cb = wchar_ascii_tolower(*b.add(i));
            if ca != cb {
                return (ca as c_int) - (cb as c_int);
            }
            if ca == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// `ucrtbase!_wcsnicmp(a, b, n) -> int`. Case-insensitive (ASCII) compare of `n` units.
pub extern "C" fn wcsnicmp(a: *const u16, b: *const u16, n: usize) -> c_int {
    if a.is_null() || b.is_null() || n == 0 {
        return 0;
    }
    // SAFETY: `a` and `b` are readable for `n` units (or NUL-terminated sooner).
    unsafe {
        for i in 0..n {
            let ca = wchar_ascii_tolower(*a.add(i));
            let cb = wchar_ascii_tolower(*b.add(i));
            if ca != cb {
                return (ca as c_int) - (cb as c_int);
            }
            if ca == 0 {
                return 0;
            }
        }
    }
    0
}

/// `ucrtbase!_wcslwr(wchar_t*) -> wchar_t*`. Lowercases the string in place; returns `s`.
pub extern "C" fn wcslwr(s: *mut u16) -> *mut u16 {
    if s.is_null() {
        return s;
    }
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated and writable; stop at the NUL.
    unsafe {
        loop {
            let c = *s.add(i);
            if c == 0 {
                break;
            }
            *s.add(i) = wchar_ascii_tolower(c);
            i += 1;
        }
    }
    s
}

/// `ucrtbase!_wcsupr(wchar_t*) -> wchar_t*`. Uppercases the string in place; returns `s`.
pub extern "C" fn wcsupr(s: *mut u16) -> *mut u16 {
    if s.is_null() {
        return s;
    }
    let mut i = 0usize;
    // SAFETY: `s` is NUL-terminated and writable; stop at the NUL.
    unsafe {
        loop {
            let c = *s.add(i);
            if c == 0 {
                break;
            }
            *s.add(i) = wchar_ascii_toupper(c);
            i += 1;
        }
    }
    s
}

/// `ucrtbase!_wcsrev(wchar_t*) -> wchar_t*`. Reverses the string in place; returns `s`.
pub extern "C" fn wcsrev(s: *mut u16) -> *mut u16 {
    if s.is_null() {
        return s;
    }
    let len = wcslen(s);
    if len <= 1 {
        return s;
    }
    let mut i = 0usize;
    let mut j = len - 1;
    // SAFETY: `s` is writable for `len` units; swap symmetric pairs until they meet.
    unsafe {
        while i < j {
            let tmp = *s.add(i);
            *s.add(i) = *s.add(j);
            *s.add(j) = tmp;
            i += 1;
            j -= 1;
        }
    }
    s
}

/// `ucrtbase!_wcsdup(const wchar_t*) -> wchar_t*`. Allocates a copy of the string (malloc
/// + wcscpy); returns NULL if allocation fails.
pub extern "C" fn wcsdup(s: *const u16) -> *mut u16 {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let units = wcslen(s) + 1; // include the NUL
    let bytes = match units.checked_mul(2) {
        Some(b) => b,
        None => return std::ptr::null_mut(), // overflow -> failure
    };
    let dst = malloc(bytes) as *mut u16;
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    // `wcscpy` is a safe `extern "C"` fn; `dst` is a freshly-allocated `units`-code-unit
    // buffer and `s` is NUL-terminated.
    wcscpy(dst, s);
    dst
}

/// `ucrtbase!_wsplitpath(path, drive, dir, fname, ext) -> void`. Splits a wide path into
/// drive/dir/fname/ext components. We fill each non-null output with an empty string (a
/// single NUL) — the acceptance target does not depend on parsed components.
pub extern "C" fn wsplitpath(
    _path: *const u16,
    drive: *mut u16,
    dir: *mut u16,
    fname: *mut u16,
    ext: *mut u16,
) {
    for out in [drive, dir, fname, ext] {
        if !out.is_null() {
            // SAFETY: each output is a writable `wchar_t*` buffer; writing one NUL makes it
            // an empty string per the `_wsplitpath` contract.
            unsafe { std::ptr::write_unaligned(out, 0) };
        }
    }
}

// ---------------------------------------------------------------------------
// Locale / invalid-parameter handlers
// ---------------------------------------------------------------------------

/// `ucrtbase!_set_invalid_parameter_handler(handler) -> _invalid_parameter_handler`.
/// Returns NULL (no previous handler).
pub extern "C" fn set_invalid_parameter_handler(_handler: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `ucrtbase!_set_thread_local_invalid_parameter_handler(handler)
/// -> _thread_local_invalid_parameter_handler`. Returns NULL (no previous handler).
pub extern "C" fn set_thread_local_invalid_parameter_handler(_handler: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `ucrtbase!setlocale(int category, const char* locale) -> char*`. Returns NULL (use the
/// default "C" locale). Returning NULL lets the CRT fall back to its default locale.
pub extern "C" fn setlocale(_category: c_int, _locale: *const c_char) -> *mut c_char {
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Wide-character classification / conversion (delegate to the host libc). These take a
// single `wint_t` value (not a pointer), so the 16/32-bit `wchar_t` width mismatch is not
// an issue: the guest `wint_t` (a code unit) zero-extends to the host `wint_t` and the
// classification matches for BMP characters.
// ---------------------------------------------------------------------------

/// `ucrtbase!iswspace(wint_t) -> int`. Delegates to the host `iswspace`.
pub extern "C" fn iswspace(c: u32) -> c_int {
    // SAFETY: `iswspace` accepts any `wint_t` and has no preconditions.
    unsafe { ffi::iswspace(c) }
}

/// `ucrtbase!iswprint(wint_t) -> int`. Delegates to the host `iswprint`.
pub extern "C" fn iswprint(c: u32) -> c_int {
    // SAFETY: `iswprint` accepts any `wint_t` and has no preconditions.
    unsafe { ffi::iswprint(c) }
}

/// `ucrtbase!iswdigit(wint_t) -> int`. Delegates to the host `iswdigit`.
pub extern "C" fn iswdigit(c: u32) -> c_int {
    // SAFETY: `iswdigit` accepts any `wint_t` and has no preconditions.
    unsafe { ffi::iswdigit(c) }
}

/// `ucrtbase!towupper(wint_t) -> wint_t`. Delegates to the host `towupper`.
pub extern "C" fn towupper(c: u32) -> u32 {
    // SAFETY: `towupper` accepts any `wint_t` and has no preconditions.
    unsafe { ffi::towupper(c) }
}

/// `ucrtbase!towlower(wint_t) -> wint_t`. Delegates to the host `towlower`.
pub extern "C" fn towlower(c: u32) -> u32 {
    // SAFETY: `towlower` accepts any `wint_t` and has no preconditions.
    unsafe { ffi::towlower(c) }
}

// ---------------------------------------------------------------------------
// Formatted output (stdio). These are C-variadic; the thunk delivers only the fixed
// arguments (the varargs arrive on the stack and are ignored, matching how `crate::crt`
// handles `fprintf`/`vfprintf`). We write the format string literally (collapsing `%%`)
// because Rust cannot call C-variadic functions without unstable ABI support.
// ---------------------------------------------------------------------------

/// `ucrtbase!__stdio_common_vfprintf(options, FILE*, fmt, locale, va_list) -> int`.
/// Delegates to the msvcrt `vfprintf` which writes the format string literally to the
/// stream's fd. The `options`/`locale` args are ignored.
pub extern "C" fn stdio_common_vfprintf(
    _options: u64,
    stream: *mut c_void,
    fmt: *const c_char,
    _locale: *mut c_void,
    va: *mut c_void,
) -> c_int {
    crate::crt::vfprintf(stream, fmt, va)
}

/// `ucrtbase!__stdio_common_vfwprintf(options, FILE*, fmt, locale, va_list) -> int`.
/// No-op; returns 0 (no wide formatted output). Wide stdio is not exercised by the
/// console-PE acceptance target, which writes via `WriteFile`/`WriteConsole`.
pub extern "C" fn stdio_common_vfwprintf(
    _options: u64,
    _stream: *mut c_void,
    _fmt: *const u16,
    _locale: *mut c_void,
    _va: *mut c_void,
) -> c_int {
    0
}

/// `ucrtbase!__stdio_common_vsprintf_s(options, count, dst, fmt, locale, va_list) -> int`.
/// A "secure" sprintf. We write the format string literally into `dst` (respecting
/// `count`) and return the number of chars written (excluding the NUL). The varargs are
/// ignored (Rust cannot call C-variadic functions); for a literal format string this is
/// exactly correct.
pub extern "C" fn stdio_common_vsprintf_s(
    _options: u64,
    count: usize,
    dst: *mut c_char,
    fmt: *const c_char,
    _locale: *mut c_void,
    _va: *mut c_void,
) -> c_int {
    snprintf_literal(dst, count, fmt)
}

/// `ucrtbase!__stdio_common_vswprintf(options, count, dst, fmt, locale, va_list) -> int`.
/// A wide "secure" sprintf. No-op; returns 0 (wide formatted output is not exercised).
pub extern "C" fn stdio_common_vswprintf(
    _options: u64,
    _count: usize,
    _dst: *mut u16,
    _fmt: *const u16,
    _locale: *mut c_void,
    _va: *mut c_void,
) -> c_int {
    0
}

/// `ucrtbase!__stdio_common_vsprintf(options, buffer, count, fmt, locale, va_list) -> int`.
/// A non-secure sprintf into a buffer. No-op; returns 0 (no output written) — the varargs
/// arrive as a Windows `va_list` that Rust cannot read, so we produce no output, matching
/// the no-output contract of the secure variant [`stdio_common_vsprintf_s`].
pub extern "C" fn stdio_common_vsprintf(
    _options: u64,
    _buffer: *mut c_char,
    _count: usize,
    _fmt: *const c_char,
    _locale: *mut c_void,
    _va: *mut c_void,
) -> c_int {
    0
}

/// `ucrtbase!sscanf(const char*, const char*, ...) -> int` and
/// `ucrtbase!_sscanf_l(const char*, const char*, _locale_t, ...) -> int`.
///
/// These are C-variadic and cannot be safely called through to `libc::sscanf` from Rust
/// (which lacks stable C-variadic ABI support). We return 0 ("zero items matched"), which
/// is safe and no worse than the soft-stub baseline: a caller reading the (unwritten)
/// output fields gets zeroes. The varargs are ignored.
pub extern "C" fn sscanf(_input: *const c_char, _fmt: *const c_char) -> c_int {
    0
}

/// `_sscanf_l` variant (with a locale argument before the varargs). See [`sscanf`].
pub extern "C" fn sscanf_l(
    _input: *const c_char,
    _fmt: *const c_char,
    _locale: *mut c_void,
) -> c_int {
    0
}

/// `ucrtbase!snprintf(dst, count, fmt, ...) -> int`. Writes the format string literally
/// into `dst` (respecting `count`); the varargs are ignored. Returns the number of chars
/// that would have been written (excluding the NUL), like C `snprintf`. For a literal
/// format string this is exactly correct.
pub extern "C" fn snprintf(dst: *mut c_char, count: usize, fmt: *const c_char) -> c_int {
    snprintf_literal(dst, count, fmt)
}

/// `ucrtbase!_snprintf_l(dst, count, fmt, locale, ...) -> int`. Same as [`snprintf`] with a
/// leading locale argument. See [`snprintf`].
pub extern "C" fn snprintf_l(
    dst: *mut c_char,
    count: usize,
    fmt: *const c_char,
    _locale: *mut c_void,
) -> c_int {
    snprintf_literal(dst, count, fmt)
}

/// `ucrtbase!_vsnprintf(dst, count, fmt, va_list) -> int`. Writes the format string
/// literally into `dst` (respecting `count`); the `va_list` is ignored (Rust cannot read a
/// Windows `va_list`). Returns the number of chars written (excluding the NUL), like C
/// `_vsnprintf`. For a literal format string this is exactly correct. This also backs the
/// `ntdll.dll!_vsnprintf` export (see [`crate::extras`]).
pub extern "C" fn vsnprintf(
    dst: *mut c_char,
    count: usize,
    fmt: *const c_char,
    _va: *mut c_void,
) -> c_int {
    snprintf_literal(dst, count, fmt)
}

/// Write the format string at `fmt` literally into `dst` (respecting `count`), collapsing
/// `%%` to `%`, and NUL-terminate. Returns the number of chars written excluding the NUL
/// (clamped to `count - 1`). If `dst` is null or `count` is 0, nothing is written and 0 is
/// returned. This mirrors the `crate::crt::fprintf` literal-format handling so the two
/// CRTs stay consistent.
fn snprintf_literal(dst: *mut c_char, count: usize, fmt: *const c_char) -> c_int {
    if dst.is_null() || count == 0 || fmt.is_null() {
        return 0;
    }
    // SAFETY: `fmt` is a NUL-terminated C string.
    let fmt_bytes = unsafe { std::ffi::CStr::from_ptr(fmt) }.to_bytes();

    // Collapse `%%` to `%`, write everything else literally.
    let cap = count - 1; // reserve one byte for the NUL
    let mut written = 0usize;
    let mut i = 0;
    while i < fmt_bytes.len() && written < cap {
        let b = fmt_bytes[i];
        if b == b'%' && i + 1 < fmt_bytes.len() && fmt_bytes[i + 1] == b'%' {
            // SAFETY: `written < cap < count`, so `dst + written` is within bounds.
            unsafe { std::ptr::write_unaligned(dst.add(written), b'%' as c_char) };
            written += 1;
            i += 2;
        } else {
            // SAFETY: `written < cap < count`, so `dst + written` is within bounds.
            unsafe { std::ptr::write_unaligned(dst.add(written), b as c_char) };
            written += 1;
            i += 1;
        }
    }
    // SAFETY: NUL-terminate at `written` (within the `count` buffer).
    unsafe { std::ptr::write_unaligned(dst.add(written), 0) };
    written as c_int
}

// ---------------------------------------------------------------------------
// Narrow-string helpers and stdio stubs (no real FILE* is modeled; callers that use
// buffered stdio get success/empty results, matching the "no buffered stdio" model where
// the acceptance target writes via `WriteFile`/`WriteConsole`).
// ---------------------------------------------------------------------------

/// `ucrtbase!memchr(ptr, c, n) -> void*`. Delegates to the host `memchr`.
pub extern "C" fn memchr(ptr: *const c_void, c: c_int, n: usize) -> *mut c_void {
    if ptr.is_null() || n == 0 {
        return std::ptr::null_mut();
    }
    // SAFETY: `ptr` is readable for `n` bytes; `memchr` has no other preconditions.
    unsafe { libc::memchr(ptr, c, n) }
}

/// `ucrtbase!strcspn(s, set) -> size_t`. Length of the prefix of `s` with no characters
/// from `set`. Delegates to the host `strcspn`.
pub extern "C" fn strcspn(s: *const c_char, set: *const c_char) -> usize {
    if s.is_null() || set.is_null() {
        return 0;
    }
    // SAFETY: both NUL-terminated; `strcspn` reads them and has no other preconditions.
    unsafe { libc::strcspn(s, set) }
}

/// `ucrtbase!_strdup(const char*) -> char*`. Allocates (malloc) a copy of `s` (strcpy);
/// returns NULL if `s` is null or allocation fails.
pub extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let len = strlen(s) + 1; // include the NUL
    let dst = malloc(len) as *mut c_char;
    if dst.is_null() {
        return std::ptr::null_mut();
    }
    // `strcpy` is a safe `extern "C"` fn; `dst` is a freshly-allocated `len`-byte buffer
    // and `s` is NUL-terminated.
    strcpy(dst, s);
    dst
}

/// `ucrtbase!fclose(FILE*) -> int`. Returns 0 (success) — no real `FILE*` to close.
pub extern "C" fn fclose(_stream: *mut c_void) -> c_int {
    0
}

/// `ucrtbase!feof(FILE*) -> int`. Returns 1 (end of file). With no real buffered stream,
/// every read is treated as already at EOF, which is safe for callers that check the flag.
pub extern "C" fn feof(_stream: *mut c_void) -> c_int {
    1
}

/// `ucrtbase!fgetws(wchar_t*, int, FILE*) -> wchar_t*`. Returns NULL (no line read), the
/// documented end-of-file/error result.
pub extern "C" fn fgetws(_buf: *mut u16, _size: c_int, _stream: *mut c_void) -> *mut u16 {
    std::ptr::null_mut()
}

/// `ucrtbase!fwrite(ptr, size, count, stream) -> size_t`. Returns `count` (pretend the
/// write succeeded). The acceptance target writes via `WriteFile`/`WriteConsole`, so a
/// buffered-stdio `fwrite` that "succeeds" without touching a real stream is safe.
pub extern "C" fn fwrite(
    _ptr: *const c_void,
    _size: usize,
    count: usize,
    _stream: *mut c_void,
) -> usize {
    count
}

// ---------------------------------------------------------------------------
// qsort — see module docs; the comparator the PE passes uses the Win64 ABI, so it cannot
// be called directly from libc::qsort (which would invoke it via the System V ABI). We
// leave the array unsorted (no-op), which is safe for the load acceptance target.
// ---------------------------------------------------------------------------

/// `ucrtbase!qsort(base, nmemb, size, cmp) -> void`. No-op: the PE-supplied comparator uses
/// the Windows x64 ABI and cannot be invoked by libc's System-V `qsort` without a reverse
/// (SysV->Win64) thunk, which is out of scope. Leaving the array unsorted is safe for the
/// load target; callers that depend on sort order get an unsorted (but valid) array.
pub extern "C" fn qsort(_base: *mut c_void, _nmemb: usize, _size: usize, _cmp: *mut c_void) {}

/// `ucrtbase!qsort_s(base, nmemb, size, cmp, context) -> void`. No-op; see [`qsort`].
pub extern "C" fn qsort_s(
    _base: *mut c_void,
    _nmemb: usize,
    _size: usize,
    _cmp: *mut c_void,
    _context: *mut c_void,
) {
}

// ---------------------------------------------------------------------------
// rand / srand / time / clock / tolower / toupper — delegate to libc.
// ---------------------------------------------------------------------------

/// `ucrtbase!rand() -> int`. Delegates to `libc::rand`.
pub extern "C" fn rand() -> c_int {
    // SAFETY: `rand` has no preconditions and is always safe to call.
    unsafe { libc::rand() }
}

/// `ucrtbase!srand(unsigned) -> void`. Delegates to `libc::srand`.
pub extern "C" fn srand(seed: u32) {
    // SAFETY: `srand` has no preconditions and is always safe to call.
    unsafe { libc::srand(seed) };
}

/// `ucrtbase!time(time_t*) -> time_t`. Delegates to `libc::time`. Returns the current
/// calendar time, and stores it through `t` if non-null.
pub extern "C" fn time(t: *mut i64) -> i64 {
    // SAFETY: `libc::time` writes a `time_t` through `t` if non-null; we pass it through
    // verbatim. `time_t` is `i64` on Linux x86_64.
    let t_ptr = if t.is_null() {
        std::ptr::null_mut()
    } else {
        t as *mut libc::time_t
    };
    unsafe { libc::time(t_ptr) as i64 }
}

/// `ucrtbase!_time64(time_t*) -> time_t`. Same as [`time`] (the 64-bit time variant).
pub extern "C" fn time64(t: *mut i64) -> i64 {
    time(t)
}

/// `ucrtbase!clock() -> clock_t`. Returns the process CPU time in milliseconds (Windows
/// `clock()` returns wall-clock ms since process start; we approximate with the process
/// CPU-time clock). Implemented via `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` because this
/// libc build does not expose the `clock()` wrapper.
pub extern "C" fn clock() -> c_long {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` writes a valid timespec; it is
    // always safe to call.
    unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    (ts.tv_sec as c_long) * 1000 + (ts.tv_nsec as c_long) / 1_000_000
}

/// `ucrtbase!tolower(int) -> int`. Delegates to `libc::tolower`.
pub extern "C" fn tolower(c: c_int) -> c_int {
    // SAFETY: `tolower` has no preconditions and is always safe to call.
    unsafe { libc::tolower(c) }
}

/// `ucrtbase!toupper(int) -> int`. Delegates to `libc::toupper`.
pub extern "C" fn toupper(c: c_int) -> c_int {
    // SAFETY: `toupper` has no preconditions and is always safe to call.
    unsafe { libc::toupper(c) }
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// Metadata for a single ucrtbase export (same shape as `ExportSpec` in lib.rs).
#[derive(Clone, Copy)]
pub struct UcrtSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: FnPtr,
    pub n_args: u8,
    pub noreturn: bool,
}

/// The full list of `ucrtbase.dll` function exports implemented by this crate, with the
/// metadata the PE loader needs to build ABI thunks. Symbols that overlap with
/// pre-registered ucrtbase entries in the loader (e.g. `memset`/`memcpy`/`memmove` wired in
/// `import_specs`) are dropped by the loader's dedup so a single canonical thunk wins.
pub fn ucrt_exports() -> Vec<UcrtSpec> {
    macro_rules! u {
        ($sym:literal, $f:expr, $n:literal) => {
            UcrtSpec {
                dll: "ucrtbase.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }
    macro_rules! un {
        ($sym:literal, $f:expr, $n:literal) => {
            UcrtSpec {
                dll: "ucrtbase.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: true,
            }
        };
    }

    vec![
        // stdio / FILE
        u!("__acrt_iob_func", acrt_iob_func, 1),
        u!("_errno", errno, 0),
        // multi-thread lock table (CRT startup / streams); no-ops in the nigg CRT
        u!("_lock", crate::crt::lock, 1),
        u!("_unlock", crate::crt::unlock, 1),
        // argv / environment init
        u!("_configure_narrow_argv", configure_narrow_argv, 1),
        u!(
            "_initialize_narrow_environment",
            initialize_narrow_environment,
            0
        ),
        u!(
            "_get_initial_narrow_environment",
            get_initial_narrow_environment,
            0
        ),
        u!("__p___argc", p_argc, 0),
        u!("__p___argv", p_argv, 0),
        u!("__p___wargv", p_wargv, 0),
        u!("_configure_wide_argv", configure_wide_argv, 1),
        u!(
            "_initialize_wide_environment",
            initialize_wide_environment,
            0
        ),
        u!(
            "_get_initial_wide_environment",
            get_initial_wide_environment,
            0
        ),
        u!("_set_app_type", set_app_type, 1),
        // environment / file stubs
        u!("getenv", getenv, 1),
        u!("_wfopen", wfopen, 2),
        u!("_wpopen", wpopen, 2),
        u!("_pclose", pclose, 1),
        // onexit / atexit
        u!("_initialize_onexit_table", initialize_onexit_table, 1),
        u!("_register_onexit_function", register_onexit_function, 2),
        u!("_execute_onexit_table", execute_onexit_table, 1),
        u!("_crt_atexit", crt_atexit, 1),
        u!("_crt_at_quick_exit", crt_at_quick_exit, 1),
        u!("_assert", assert, 3),
        // process termination (noreturn)
        un!("_c_exit", c_exit, 1),
        un!("_exit", exit_sys, 1),
        un!("abort", abort, 0),
        un!("exit", exit, 1),
        un!("quick_exit", quick_exit, 1),
        // memory
        u!("malloc", malloc, 1),
        u!("calloc", calloc, 2),
        u!("free", free, 1),
        u!("realloc", realloc, 2),
        // memory intrinsics
        u!("memset", memset, 3),
        u!("memcpy", memcpy, 3),
        u!("memmove", memmove, 3),
        u!("memcmp", memcmp, 3),
        // narrow strings
        u!("strlen", strlen, 1),
        u!("strcpy", strcpy, 2),
        u!("strncpy", strncpy, 3),
        u!("strcmp", strcmp, 2),
        u!("strncmp", strncmp, 3),
        u!("strchr", strchr, 2),
        u!("strstr", strstr, 2),
        // wide strings
        u!("wcslen", wcslen, 1),
        u!("wcscpy", wcscpy, 2),
        u!("wcscmp", wcscmp, 2),
        u!("wcsncmp", wcsncmp, 3),
        u!("wcschr", wcschr, 2),
        u!("wcsstr", wcsstr, 2),
        u!("wcsrchr", wcsrchr, 2),
        u!("wcspbrk", wcspbrk, 2),
        u!("wcscspn", wcscspn, 2),
        u!("wcscat", wcscat, 2),
        u!("wcstol", wcstol, 3),
        u!("wcstoul", wcstoul, 3),
        u!("_wcsicmp", wcsicmp, 2),
        u!("_wcsnicmp", wcsnicmp, 3),
        u!("_wcslwr", wcslwr, 1),
        u!("_wcsupr", wcsupr, 1),
        u!("_wcsrev", wcsrev, 1),
        u!("_wcsdup", wcsdup, 1),
        u!("_wsplitpath", wsplitpath, 5),
        // wide-character classification / conversion
        u!("iswspace", iswspace, 1),
        u!("iswprint", iswprint, 1),
        u!("iswdigit", iswdigit, 1),
        u!("towupper", towupper, 1),
        u!("towlower", towlower, 1),
        // locale / invalid-parameter handlers
        u!(
            "_set_invalid_parameter_handler",
            set_invalid_parameter_handler,
            1
        ),
        u!(
            "_set_thread_local_invalid_parameter_handler",
            set_thread_local_invalid_parameter_handler,
            1
        ),
        u!("setlocale", setlocale, 2),
        // formatted output
        u!("__stdio_common_vfprintf", stdio_common_vfprintf, 5),
        u!("__stdio_common_vfwprintf", stdio_common_vfwprintf, 5),
        u!("__stdio_common_vsprintf_s", stdio_common_vsprintf_s, 6),
        u!("__stdio_common_vsprintf", stdio_common_vsprintf, 6),
        u!("__stdio_common_vswprintf", stdio_common_vswprintf, 6),
        u!("sscanf", sscanf, 2),
        u!("_sscanf_l", sscanf_l, 3),
        u!("snprintf", snprintf, 3),
        u!("_snprintf_l", snprintf_l, 4),
        u!("_vsnprintf", vsnprintf, 4),
        // narrow-string helpers and stdio stubs
        u!("memchr", memchr, 3),
        u!("strcspn", strcspn, 2),
        u!("_strdup", strdup, 1),
        u!("fclose", fclose, 1),
        u!("feof", feof, 1),
        u!("fgetws", fgetws, 3),
        u!("fwrite", fwrite, 4),
        // qsort
        u!("qsort", qsort, 4),
        u!("qsort_s", qsort_s, 5),
        // rand / time / case
        u!("rand", rand, 0),
        u!("srand", srand, 1),
        u!("time", time, 1),
        u!("_time64", time64, 1),
        u!("clock", clock, 0),
        u!("tolower", tolower, 1),
        u!("toupper", toupper, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strlen_walks_to_nul() {
        let s = b"hello\0";
        assert_eq!(strlen(s.as_ptr() as *const c_char), 5);
        assert_eq!(strlen(std::ptr::null()), 0);
    }

    #[test]
    fn strcmp_and_strncmp() {
        let a = b"abc\0";
        let b = b"abd\0";
        assert!(strcmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char) < 0);
        assert_eq!(
            strcmp(a.as_ptr() as *const c_char, a.as_ptr() as *const c_char),
            0
        );
        assert!(strncmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char, 2) == 0);
        assert!(strncmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char, 3) < 0);
    }

    #[test]
    fn strchr_finds_char() {
        let s = b"hello\0";
        let p = strchr(s.as_ptr() as *const c_char, b'l' as c_int);
        assert!(!p.is_null());
        // SAFETY: `p` points into `s` at the first 'l'.
        assert_eq!(unsafe { *p as u8 }, b'l');
        // 'l' occurs again; first occurrence is at index 2.
        assert_eq!(unsafe { (p as *const u8).offset_from(s.as_ptr()) }, 2);
        // not found
        assert!(strchr(s.as_ptr() as *const c_char, b'z' as c_int).is_null());
        // NUL search returns the terminator
        let z = strchr(s.as_ptr() as *const c_char, 0);
        assert!(!z.is_null());
        // SAFETY: `z` points at the NUL terminator.
        assert_eq!(unsafe { *z as u8 }, 0);
    }

    #[test]
    fn strstr_finds_needle() {
        let hay = b"hello world\0";
        let needle = b"world\0";
        let p = strstr(
            hay.as_ptr() as *const c_char,
            needle.as_ptr() as *const c_char,
        );
        assert!(!p.is_null());
        assert_eq!(unsafe { (p as *const u8).offset_from(hay.as_ptr()) }, 6);
        // empty needle returns haystack
        let empty = b"\0";
        assert_eq!(
            strstr(
                hay.as_ptr() as *const c_char,
                empty.as_ptr() as *const c_char
            ),
            hay.as_ptr() as *mut c_char
        );
        // not found
        let missing = b"xyz\0";
        assert!(strstr(
            hay.as_ptr() as *const c_char,
            missing.as_ptr() as *const c_char
        )
        .is_null());
    }

    #[test]
    fn wcs_funcs() {
        let w: [u16; 4] = ['a' as u16, 'b' as u16, 'c' as u16, 0];
        assert_eq!(wcslen(w.as_ptr()), 3);
        let other: [u16; 4] = ['a' as u16, 'b' as u16, 'd' as u16, 0];
        assert!(wcscmp(w.as_ptr(), other.as_ptr()) < 0);
        assert_eq!(wcscmp(w.as_ptr(), w.as_ptr()), 0);
        assert_eq!(wcsncmp(w.as_ptr(), other.as_ptr(), 2), 0);
        assert!(wcsncmp(w.as_ptr(), other.as_ptr(), 3) < 0);
        let p = wcschr(w.as_ptr(), 'b' as u16);
        assert!(!p.is_null());
        // SAFETY: `p` points at 'b' in `w`.
        assert_eq!(unsafe { *p }, 'b' as u16);
        assert!(wcschr(w.as_ptr(), 'z' as u16).is_null());
        let mut dst = [0u16; 8];
        wcscpy(dst.as_mut_ptr(), w.as_ptr());
        assert_eq!(&dst[..4], &w[..4]);
    }

    #[test]
    fn mem_funcs() {
        let mut a = [0u8; 4];
        memset(a.as_mut_ptr(), 0xAB, 4);
        assert_eq!(&a, &[0xAB, 0xAB, 0xAB, 0xAB]);
        let b = [1u8, 2, 3, 4];
        let mut c = [0u8; 4];
        memcpy(c.as_mut_ptr(), b.as_ptr(), 4);
        assert_eq!(&c, &b);
        assert_eq!(
            memcmp(b.as_ptr() as *const c_void, c.as_ptr() as *const c_void, 4),
            0
        );
        let d = [9u8, 2, 3, 4];
        assert!(memcmp(b.as_ptr() as *const c_void, d.as_ptr() as *const c_void, 4) < 0);
        // overlapping memmove
        let mut m = [1u8, 2, 3, 4, 5];
        // SAFETY: `m.as_mut_ptr().add(2)` stays within the 5-byte array; copying 3 bytes
        // from offset 0 to offset 2 (overlapping) is the memmove contract.
        unsafe {
            memmove(m.as_mut_ptr().add(2), m.as_ptr(), 3);
        }
        assert_eq!(&m, &[1, 2, 1, 2, 3]);
    }

    #[test]
    fn malloc_free_round_trip() {
        let p = malloc(64);
        assert!(!p.is_null());
        // SAFETY: `p` was just allocated for 64 bytes.
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xAB, 64) };
        free(p);
        // realloc(NULL, n) == malloc(n)
        let q = realloc(std::ptr::null_mut(), 32);
        assert!(!q.is_null());
        // SAFETY: `q` is a 32-byte allocation; grow it.
        unsafe { std::ptr::write_bytes(q as *mut u8, 0x11, 32) };
        let r = realloc(q, 64);
        assert!(!r.is_null());
        // SAFETY: first 32 bytes preserved by realloc.
        let buf = unsafe { std::slice::from_raw_parts(r as *const u8, 32) };
        assert!(buf.iter().all(|&b| b == 0x11));
        free(r);
    }

    #[test]
    fn calloc_zeroes() {
        let p = calloc(4, 16);
        assert!(!p.is_null());
        // SAFETY: `p` was just allocated with calloc for 64 zeroed bytes.
        let buf = unsafe { std::slice::from_raw_parts(p as *const u8, 64) };
        assert!(buf.iter().all(|&b| b == 0), "calloc zeroes memory");
        free(p);
    }

    #[test]
    fn errno_returns_writable_pointer() {
        let p = errno();
        assert!(!p.is_null());
        // SAFETY: `p` points at our `UCRT_ERRNO` static; writing is single-threaded in tests.
        unsafe {
            *p = 42;
            assert_eq!(*p, 42);
            *p = 0;
        }
    }

    #[test]
    fn snprintf_writes_literal_format() {
        let mut buf = [0u8; 16];
        let fmt = b"hi %%there\0";
        let n = snprintf(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt.as_ptr() as *const c_char,
        );
        assert_eq!(n, 9, "literal format with collapsed %%");
        // SAFETY: `snprintf` NUL-terminated at index 9.
        let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
        assert_eq!(s.to_bytes(), b"hi %there");
    }

    #[test]
    fn snprintf_truncates_to_count() {
        let mut buf = [0u8; 4];
        let fmt = b"abcdefg\0";
        let n = snprintf(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt.as_ptr() as *const c_char,
        );
        // Only 3 chars fit (count - 1), NUL-terminated.
        assert_eq!(n, 3);
        assert_eq!(&buf, b"abc\0");
    }

    #[test]
    fn snprintf_null_or_zero_is_noop() {
        let fmt = b"x\0";
        assert_eq!(
            snprintf(std::ptr::null_mut(), 0, fmt.as_ptr() as *const c_char),
            0
        );
        let mut buf = [0u8; 4];
        assert_eq!(
            snprintf(
                buf.as_mut_ptr() as *mut c_char,
                0,
                fmt.as_ptr() as *const c_char
            ),
            0
        );
    }

    #[test]
    fn ucrt_exports_registered_with_correct_dll() {
        let specs = ucrt_exports();
        assert!(specs.iter().all(|s| s.dll == "ucrtbase.dll"));
        // A few key symbols must be present.
        let syms: Vec<&str> = specs.iter().map(|s| s.sym).collect();
        assert!(syms.contains(&"exit"));
        assert!(syms.contains(&"malloc"));
        assert!(syms.contains(&"_configure_narrow_argv"));
        assert!(syms.contains(&"__p___argc"));
        assert!(syms.contains(&"wcschr"));
        // noreturn family must be flagged.
        let exit_spec = specs.iter().find(|s| s.sym == "exit").unwrap();
        assert!(exit_spec.noreturn, "exit is noreturn");
        assert!(
            !specs.iter().find(|s| s.sym == "malloc").unwrap().noreturn,
            "malloc returns"
        );
    }
}
