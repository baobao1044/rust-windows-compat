//! msvcrt.dll (Microsoft C Runtime) reimplementation for the PE loader.
//!
//! Implements the subset of `msvcrt.dll` exports that the mingw-w64 CRT startup sequence
//! calls when booting a console PE: memory (`malloc`/`calloc`/`free`), string
//! (`strlen`/`strncmp`/`memcmp`), stdio (`__iob_func`/`fprintf`/`vfprintf`), and
//! process/init (`__getmainargs`/`__initenv`/`exit`/`abort`/`atexit`/`signal`/`_initterm`/
//! etc.). These are registered under `msvcrt.dll` in the PE loader's import table.
//!
//! Memory functions delegate to the heap module (same `libc::malloc` + header mechanism as
//! `HeapAlloc`/`HeapFree`) so a pointer allocated by `malloc` can be freed by `HeapFree` and
//! vice-versa — matching the real mingw-w64 CRT which backs `malloc` on `HeapAlloc`.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment.

#![deny(unsafe_op_in_unsafe_fn)]
// The `extern "C"` functions here implement C runtime APIs that take raw pointers. They
// are called from PE machine code via ABI trampolines, not from safe Rust callers.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use crate::FnPtr;

/// Offset of the `_file` (fd) field within the mingw-w64 `FILE` struct (`struct _iobuf`).
/// Layout: _ptr(8) _cnt(4) [pad 4] _base(8) _flag(4) _file(4) _charbuf(4) _bufsiz(4)
/// _tmpfname(8) = 48 bytes total. `_file` sits at byte 28.
const FILE_FD_OFFSET: usize = 28;
/// `sizeof(FILE)` on mingw-w64 x86_64 (non-UCRT). Used by `__iob_func` callers to index the
/// stdin/stdout/stderr array.
const FILE_SIZE: usize = 48;

// ---------------------------------------------------------------------------
// Data symbols (imported as addresses, not functions)
// ---------------------------------------------------------------------------

/// The `__initenv` global: a `char**` pointing to the environment string array. The PE reads
/// the IAT slot for `__initenv` to get the address of this variable, then dereferences it to
/// get the env array. Set by [`getmainargs`].
static mut INITENV: *mut *mut c_char = std::ptr::null_mut();

/// The `_commode` global: an `int` the CRT writes to set the default comm mode.
static mut COMMODE: c_int = 0;

/// The `_fmode` global: an `int` the CRT writes to set the default file translation mode.
static mut FMODE: c_int = 0;

/// Return the list of msvcrt **data** exports (variables, not functions). Each entry is
/// `(dll, sym, address_of_static)`. The PE loader writes these addresses directly into the
/// IAT slot — no ABI thunk is needed because the PE reads the slot as a data pointer.
pub fn data_exports() -> Vec<(&'static str, &'static str, FnPtr)> {
    vec![
        ("msvcrt.dll", "__initenv", &raw const INITENV as FnPtr),
        ("msvcrt.dll", "_commode", &raw const COMMODE as FnPtr),
        ("msvcrt.dll", "_fmode", &raw const FMODE as FnPtr),
    ]
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// `msvcrt!malloc(size_t) -> void*`. Delegates to the heap module's `HeapAlloc` on the
/// process heap so CRT allocations are interchangeable with `HeapAlloc`/`HeapFree`.
pub extern "C" fn malloc(size: usize) -> *mut c_void {
    crate::heap::heap_alloc(crate::heap::get_process_heap(), 0, size)
}

/// `msvcrt!calloc(count, size) -> void*`. Zero-fills the allocation.
pub extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    let total = match count.checked_mul(size) {
        Some(t) => t,
        None => return std::ptr::null_mut(), // overflow -> failure
    };
    const HEAP_ZERO_MEMORY: u32 = 0x08;
    crate::heap::heap_alloc(crate::heap::get_process_heap(), HEAP_ZERO_MEMORY, total)
}

/// `msvcrt!free(void*)`. Delegates to `HeapFree`. A null pointer is a no-op success.
pub extern "C" fn free(ptr: *mut c_void) {
    crate::heap::heap_free(crate::heap::get_process_heap(), 0, ptr);
}

// ---------------------------------------------------------------------------
// String
// ---------------------------------------------------------------------------

/// `msvcrt!strlen(const char*) -> size_t`.
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

/// `msvcrt!strncmp(a, b, n) -> int`.
pub extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    if a.is_null() || b.is_null() || n == 0 {
        return 0;
    }
    // SAFETY: `a` and `b` are readable for at least `n` bytes (or NUL-terminated sooner).
    unsafe {
        for i in 0..n {
            let ca = *a.add(i) as u8;
            let cb = *b.add(i) as u8;
            if ca != cb {
                return (ca as c_int) - (cb as c_int);
            }
            if ca == 0 {
                return 0; // both NUL at the same position
            }
        }
    }
    0
}

/// `msvcrt!memcmp(a, b, n) -> int`.
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
// stdio
// ---------------------------------------------------------------------------

/// The fake `FILE` array returned by `__iob_func`: three 48-byte entries for stdin (fd 0),
/// stdout (fd 1), stderr (fd 2). Only the `_file` field (fd) is meaningful; `fprintf` reads
/// it to know which fd to write to.
static IOB: [u8; FILE_SIZE * 3] = {
    let mut arr = [0u8; FILE_SIZE * 3];
    // stdin fd = 0 (already zero)
    // stdout fd = 1
    arr[FILE_SIZE + FILE_FD_OFFSET] = 1;
    // stderr fd = 2
    arr[2 * FILE_SIZE + FILE_FD_OFFSET] = 2;
    arr
};

/// `msvcrt!__iob_func() -> FILE*`. Returns a pointer to a 3-element `FILE` array
/// (stdin/stdout/stderr). The PE indexes it with `sizeof(FILE)=48` to get each stream.
pub extern "C" fn iob_func() -> *mut c_void {
    IOB.as_ptr() as *mut c_void
}

/// Read the fd from a `FILE*` produced by [`iob_func`]. Returns -1 if `file` is null.
fn file_fd(file: *const c_void) -> i32 {
    if file.is_null() {
        return -1;
    }
    // SAFETY: `file` points into the `IOB` array (or a PE-side copy of a `FILE*` from
    // `__iob_func`); offset `FILE_FD_OFFSET` is within the 48-byte struct.
    unsafe { std::ptr::read_unaligned((file as *const u8).add(FILE_FD_OFFSET) as *const i32) }
}

/// Write a byte slice to the fd extracted from `file`. Returns the number of bytes written
/// or 0 on failure.
fn write_to_stream(file: *const c_void, bytes: &[u8]) -> usize {
    let fd = file_fd(file);
    if fd < 0 || bytes.is_empty() {
        return 0;
    }
    // SAFETY: `fd` is a valid open descriptor (0/1/2 for stdio); `write` reads `bytes` and
    // returns the byte count or -1 on error.
    let n = unsafe {
        libc::write(
            fd,
            bytes.as_ptr() as *const c_void,
            bytes.len().min(isize::MAX as usize),
        )
    };
    if n < 0 {
        0
    } else {
        n as usize
    }
}

/// `msvcrt!fprintf(FILE*, const char* fmt, ...) -> int`. A minimal implementation that writes
/// the format string to the stream's fd, handling `%%` and skipping other `%` specifiers
/// (the varargs are not accessible from Rust without C-variadic ABI support). For the common
/// case of a literal format string (no specifiers), this is exactly correct. The thunk is
/// built with `n_args=2` so we receive `FILE*` (rdi) and `fmt` (rsi); varargs are ignored.
pub extern "C" fn fprintf(file: *mut c_void, fmt: *const c_char) -> c_int {
    if fmt.is_null() {
        return 0;
    }
    // SAFETY: `fmt` is a NUL-terminated C string.
    let fmt_str = unsafe { std::ffi::CStr::from_ptr(fmt) };
    let bytes = fmt_str.to_bytes();

    // Process %% sequences: write everything literally, collapsing %% to %.
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 1 < bytes.len() && bytes[i + 1] == b'%' {
            out.push(b'%');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    write_to_stream(file, &out) as c_int
}

/// `msvcrt!vfprintf(FILE*, const char* fmt, va_list) -> int`. Like [`fprintf`] but the
/// varargs arrive as a `va_list`; we ignore it and write the format string literally.
pub extern "C" fn vfprintf(file: *mut c_void, fmt: *const c_char, _va: *mut c_void) -> c_int {
    fprintf(file, fmt)
}

// ---------------------------------------------------------------------------
// Process / init
// ---------------------------------------------------------------------------

/// `msvcrt!__getmainargs(argc*, argv**, envp**, expand, startup*) -> int`. Builds argc/argv
/// from the host process args and envp from the host environment, then stores them through
/// the caller's output pointers. Also sets the `__initenv` global to the env array.
pub extern "C" fn getmainargs(
    argc: *mut c_int,
    argv: *mut *mut *mut c_char,
    envp: *mut *mut *mut c_char,
    _expand: c_int,
    _startup: *mut c_void,
) -> c_int {
    let (arg_count, argv_ptr, envp_ptr) = build_args_and_env();

    if !argc.is_null() {
        // SAFETY: `argc` is a guest out-pointer valid for one int.
        unsafe { std::ptr::write_unaligned(argc, arg_count as c_int) };
    }
    if !argv.is_null() {
        // SAFETY: `argv` is a guest out-pointer valid for one `char**`.
        unsafe { std::ptr::write_unaligned(argv, argv_ptr) };
    }
    if !envp.is_null() {
        // SAFETY: `envp` is a guest out-pointer valid for one `char**`.
        unsafe { std::ptr::write_unaligned(envp, envp_ptr) };
    }
    // Also publish the env array through the `__initenv` data symbol.
    // SAFETY: `INITENV` is a `static mut` we own; no other thread accesses it concurrently
    // (the CRT startup is single-threaded).
    unsafe {
        INITENV = envp_ptr;
    }
    0 // success
}

/// Build `(argc, argv, envp)` from the host process, cached for the process lifetime. The
/// returned pointers stay valid forever (leaked via `OnceLock`). `argv` and `envp` are
/// NUL-terminated arrays of `char*` (a trailing NULL entry).
fn build_args_and_env() -> (usize, *mut *mut c_char, *mut *mut c_char) {
    // The CString storage is kept alive (never read directly) so the pointers in
    // `argv`/`envp` remain valid for the process lifetime.
    #[allow(dead_code)]
    struct ArgEnv {
        // Owned CString storage (keeps the strings alive).
        arg_strings: Vec<CString>,
        env_strings: Vec<CString>,
        // NUL-terminated pointer arrays.
        argv: Vec<*mut c_char>,
        envp: Vec<*mut c_char>,
    }

    // SAFETY: `ArgEnv` is process-global data populated once during the single-threaded CRT
    // init and only read afterward. The raw pointers inside point at the owned `CString`s
    // which live for the process lifetime, so sharing them across threads is sound.
    unsafe impl Send for ArgEnv {}
    unsafe impl Sync for ArgEnv {}

    static CACHE: OnceLock<ArgEnv> = OnceLock::new();

    let ae = CACHE.get_or_init(|| {
        // Use the host args as the PE's command line. The loader's argv[0] is the loader
        // exe and argv[1] is the PE path; the PE's main sees these as its command line.
        let arg_strings: Vec<CString> = std::env::args()
            .map(|s| CString::new(s).unwrap_or_else(|_| CString::new("").unwrap()))
            .collect();
        let env_strings: Vec<CString> = std::env::vars()
            .map(|(k, v)| {
                let pair = format!("{k}={v}");
                CString::new(pair).unwrap_or_else(|_| CString::new("").unwrap())
            })
            .collect();

        let mut argv: Vec<*mut c_char> = arg_strings
            .iter()
            .map(|s| s.as_ptr() as *mut c_char)
            .collect();
        argv.push(std::ptr::null_mut()); // NUL terminator

        let mut envp: Vec<*mut c_char> = env_strings
            .iter()
            .map(|s| s.as_ptr() as *mut c_char)
            .collect();
        envp.push(std::ptr::null_mut()); // NUL terminator

        ArgEnv {
            arg_strings,
            env_strings,
            argv,
            envp,
        }
    });

    let argc = ae.argv.len().saturating_sub(1); // exclude the NUL terminator
    let argv_ptr = ae.argv.as_ptr() as *mut *mut c_char;
    let envp_ptr = ae.envp.as_ptr() as *mut *mut c_char;
    (argc, argv_ptr, envp_ptr)
}

/// `msvcrt!__set_app_type(int) -> void`. No-op (we don't model app types).
pub extern "C" fn set_app_type(_app_type: c_int) {}

/// `msvcrt!__setusermatherr(handler) -> void`. No-op (we don't deliver math errors).
pub extern "C" fn setusermatherr(_handler: *mut c_void) {}

/// `msvcrt!_fpreset() -> void`. No-op (the FPU is always in a sane state on x86_64).
pub extern "C" fn fpreset() {}

/// `msvcrt!_initterm(start, end) -> void`. Iterates `[start, end)` calling each non-null
/// function pointer. For Rust + mingw this range is typically empty (no C++ static
/// constructors), so this is effectively a no-op. We do not call the function pointers
/// because they use the Windows x64 ABI and would need a Win64->SysV call mechanism; for
/// the console-PE acceptance target there are no constructors to run.
pub extern "C" fn initterm(_start: *mut *mut c_void, _end: *mut *mut c_void) {}

/// `msvcrt!atexit(void (*)()) -> int`. Returns 0 (success). We do not register the handler
/// (atexit cleanup is not needed for the console-PE acceptance target).
pub extern "C" fn atexit(_fn: *mut c_void) -> c_int {
    0
}

/// `msvcrt!_cexit() -> void`. No-op (CRT cleanup without exit).
pub extern "C" fn cexit() {}

/// `msvcrt!_lock(int locknum)`. Acquires one of the msvcrt multi-thread lock-table
/// entries the CRT uses to serialize streams/startup. The nigg CRT surface runs on the
/// loader's single guest thread (and `fprintf`-family outputs go straight to the fd with
/// no shared buffered state), so acquiring is a no-op — the mingw CRT init and DLL
/// startup sequences call it though, so the symbol must exist to avoid a trap stub.
pub extern "C" fn lock(_locknum: c_int) {}

/// `msvcrt!_unlock(int locknum)`. Releases the lock acquired by [`lock`]; no-op for the
/// same reason.
pub extern "C" fn unlock(_locknum: c_int) {}

/// `msvcrt!_amsg_exit(int) -> !`. Terminates with the given exit code.
pub extern "C" fn amsg_exit(code: c_int) -> ! {
    log::trace!("msvcrt!_amsg_exit({code})");
    // SAFETY: `_exit` is the raw exit syscall; safe from any stack/gs-base context.
    unsafe { libc::_exit(code) };
}

/// `msvcrt!abort() -> !`. Terminates with exit code 3 (SIGABRT).
pub extern "C" fn abort() -> ! {
    log::trace!("msvcrt!abort()");
    // SAFETY: as in `amsg_exit` — `_exit` is safe from any context.
    unsafe { libc::_exit(3) };
}

/// `msvcrt!exit(int) -> !`. Terminates with the given exit code. Does not run atexit
/// handlers (the console-PE acceptance target has none); the output (WriteFile) goes
/// directly to the fd so there is no stdio buffer to flush.
pub extern "C" fn exit(code: c_int) -> ! {
    log::trace!("msvcrt!exit({code})");
    // SAFETY: as in `amsg_exit` — `_exit` is safe from any context.
    unsafe { libc::_exit(code) };
}

/// `msvcrt!signal(int sig, void (*handler)(int)) -> void(*)(int)`. Returns 0 (SIG_DFL);
/// we do not deliver signals.
pub extern "C" fn signal(_sig: c_int, _handler: *mut c_void) -> *mut c_void {
    std::ptr::null_mut() // SIG_DFL
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// Metadata for a single msvcrt function export (function, not data).
#[derive(Clone, Copy)]
pub struct CrtSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: FnPtr,
    pub n_args: u8,
    pub noreturn: bool,
}

/// The full list of msvcrt function exports (excluding data symbols; see [`data_exports`]).
pub fn crt_export_specs() -> Vec<CrtSpec> {
    macro_rules! c {
        ($sym:literal, $f:expr, $n:literal) => {
            CrtSpec {
                dll: "msvcrt.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }
    macro_rules! cn {
        ($sym:literal, $f:expr, $n:literal) => {
            CrtSpec {
                dll: "msvcrt.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: true,
            }
        };
    }

    vec![
        // memory
        c!("malloc", malloc, 1),
        c!("calloc", calloc, 2),
        c!("free", free, 1),
        // string
        c!("strlen", strlen, 1),
        c!("strncmp", strncmp, 3),
        c!("memcmp", memcmp, 3),
        // stdio
        c!("__iob_func", iob_func, 0),
        c!("fprintf", fprintf, 2),
        c!("vfprintf", vfprintf, 3),
        // multi-thread lock table (mingw CRT init / DLL startup calls it)
        c!("_lock", lock, 1),
        c!("_unlock", unlock, 1),
        // process / init
        c!("__getmainargs", getmainargs, 5),
        c!("__set_app_type", set_app_type, 1),
        c!("__setusermatherr", setusermatherr, 1),
        c!("_fpreset", fpreset, 0),
        c!("_initterm", initterm, 2),
        c!("atexit", atexit, 1),
        c!("_cexit", cexit, 0),
        c!("signal", signal, 2),
        // noreturn
        cn!("abort", abort, 0),
        cn!("exit", exit, 1),
        cn!("_amsg_exit", amsg_exit, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strlen_basic() {
        let s = b"hello\0";
        assert_eq!(strlen(s.as_ptr() as *const c_char), 5);
        assert_eq!(strlen(std::ptr::null()), 0);
    }

    #[test]
    fn strncmp_compares() {
        let a = b"abc\0";
        let b = b"abd\0";
        assert!(strncmp(a.as_ptr() as *const c_char, b.as_ptr() as *const c_char, 3) < 0);
        assert_eq!(
            strncmp(a.as_ptr() as *const c_char, a.as_ptr() as *const c_char, 3),
            0
        );
    }

    #[test]
    fn memcmp_compares() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 4];
        assert!(memcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 3) < 0);
        assert_eq!(
            memcmp(a.as_ptr() as *const c_void, a.as_ptr() as *const c_void, 3),
            0
        );
    }

    #[test]
    fn malloc_free_round_trip() {
        let p = malloc(64);
        assert!(!p.is_null());
        // SAFETY: `p` was just allocated for 64 bytes.
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xAB, 64) };
        free(p);
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
    fn iob_func_returns_three_streams() {
        let iob = iob_func();
        assert!(!iob.is_null());
        // stdin fd = 0
        assert_eq!(file_fd(iob), 0);
        // stdout fd = 1
        assert_eq!(
            file_fd(unsafe { (iob as *const u8).add(FILE_SIZE) as *const c_void }),
            1
        );
        // stderr fd = 2
        assert_eq!(
            file_fd(unsafe { (iob as *const u8).add(2 * FILE_SIZE) as *const c_void }),
            2
        );
    }

    #[test]
    fn data_exports_contain_initenv_commode_fmode() {
        let exports = data_exports();
        let syms: Vec<&str> = exports.iter().map(|e| e.1).collect();
        assert!(syms.contains(&"__initenv"));
        assert!(syms.contains(&"_commode"));
        assert!(syms.contains(&"_fmode"));
    }
}
