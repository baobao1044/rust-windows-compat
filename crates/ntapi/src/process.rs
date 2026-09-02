//! Process termination, time, and minimal file/console primitives reimplemented on Linux.
//!
//! Covers `ExitProcess`/`NtTerminateProcess`, `GetTickCount`/`GetTickCount64`,
//! `QueryPerformanceCounter`/`QueryPerformanceFrequency`, `GetStdHandle`/`WriteFile`/
//! `GetLastError`/`SetLastError`, and the `NtCreateFile`/`NtReadFile`/`NtWriteFile`/
//! `NtClose` file layer backed by Linux `openat`/`read`/`write`/`close`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;
use std::sync::OnceLock;

use crate::handle::{self, FileObject, Handle, Object};

/// Standard Windows handle value for `STD_OUTPUT_HANDLE`.
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFFF - 10; // 0xFFFF_FFF5
/// Standard Windows handle value for `STD_ERROR_HANDLE`.
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFFF - 9; // 0xFFFF_FFF6
/// Standard Windows handle value for `STD_INPUT_HANDLE`.
const STD_INPUT_HANDLE: u32 = 0xFFFF_FFFF - 8; // 0xFFFF_FFF7

/// `INFINITE` (used by some callers that pass it to functions we route here).
#[allow(dead_code)]
const INFINITE: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Process termination
// ---------------------------------------------------------------------------

/// `kernel32!ExitProcess(u32 exit_code) -> !`. Terminates the process immediately.
///
/// Uses `libc::_exit` (the raw `_exit` syscall) rather than `std::process::exit` because the
/// latter runs the Rust runtime cleanup (atexit handlers, stack-overflow-guard teardown),
/// which is unsafe while executing on the guest stack with a modified `gs` base — the
/// cleanup code touches thread-local/stack state that is invalid in that context. Windows
/// `ExitProcess` also terminates immediately, so `_exit` matches the intended semantics.
pub extern "C" fn exit_process(exit_code: u32) -> ! {
    log::trace!("ntapi!ExitProcess({exit_code})");
    // SAFETY: `_exit` is the raw exit syscall; it never returns and is safe to call from any
    // stack/gs-base context because it does not touch userspace state.
    unsafe { libc::_exit(exit_code as i32) };
}

/// `ntdll!NtTerminateProcess(HANDLE, NTSTATUS) -> !`. `handle` 0 / -1 = current process.
pub extern "C" fn nt_terminate_process(_handle: Handle, status: i32) -> ! {
    log::trace!("ntapi!NtTerminateProcess({status:#x})");
    // SAFETY: as in `exit_process` — `_exit` is safe from any context.
    unsafe { libc::_exit(status) };
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// `kernel32!GetTickCount() -> u32`. Milliseconds since boot (32-bit, wraps every ~49 days).
pub extern "C" fn get_tick_count() -> u32 {
    let ns = monotonic_ns();
    ((ns / 1_000_000) & 0xFFFF_FFFF) as u32
}

/// `kernel32!GetTickCount64() -> u64`. Milliseconds since boot (64-bit, never wraps).
pub extern "C" fn get_tick_count_64() -> u64 {
    monotonic_ns() / 1_000_000
}

/// `kernel32!QueryPerformanceCounter(LARGE_INTEGER*) -> BOOL`.
pub extern "C" fn query_performance_counter(out: *mut i64) -> i32 {
    let ns = monotonic_ns() as i64;
    if !out.is_null() {
        // SAFETY: `out` is a guest out-pointer valid for one i64.
        unsafe { std::ptr::write_unaligned(out, ns) };
    }
    1 // TRUE
}

/// `kernel32!QueryPerformanceFrequency(LARGE_INTEGER*) -> BOOL`. We report 1 GHz (10^9 Hz)
/// since our counter is in nanoseconds, matching a common QPC resolution.
pub extern "C" fn query_performance_frequency(out: *mut i64) -> i32 {
    if !out.is_null() {
        // SAFETY: `out` is a guest out-pointer valid for one i64.
        unsafe { std::ptr::write_unaligned(out, 1_000_000_000) };
    }
    1 // TRUE
}

/// Monotonic time in nanoseconds via `clock_gettime(CLOCK_MONOTONIC)`.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime(CLOCK_MONOTONIC)` writes a valid timespec; never fails here.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

// ---------------------------------------------------------------------------
// Console / stdio / last error
// ---------------------------------------------------------------------------

/// Process-global last-error value (per-thread on Windows; M1 keeps it process-global).
fn last_error() -> &'static parking_lot::Mutex<u32> {
    static E: OnceLock<parking_lot::Mutex<u32>> = OnceLock::new();
    E.get_or_init(|| parking_lot::Mutex::new(0))
}

/// `kernel32!GetLastError() -> u32`.
pub extern "C" fn get_last_error() -> u32 {
    *last_error().lock()
}

/// `kernel32!SetLastError(u32) -> void`.
pub extern "C" fn set_last_error(code: u32) {
    *last_error().lock() = code;
}

/// `kernel32!GetStdHandle(u32) -> HANDLE`. Maps a STD_* pseudo-value to a small fd handle.
pub extern "C" fn get_std_handle(std_handle: u32) -> Handle {
    let fd: i32 = match std_handle {
        STD_INPUT_HANDLE => 0,
        STD_OUTPUT_HANDLE => 1,
        STD_ERROR_HANDLE => 2,
        _ => -1,
    };
    if fd < 0 {
        return u64::MAX; // INVALID_HANDLE_VALUE
    }
    fd as Handle // stdio fds are used directly as handles (closed as no-ops)
}

/// `kernel32!WriteFile(h, buf, len, written*, overlapped*) -> BOOL`.
pub extern "C" fn write_file(
    handle: Handle,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    _overlapped: *mut c_void,
) -> i32 {
    // Stdio handles are small fds; file handles are in the handle table.
    let fd = resolve_fd(handle);
    if fd < 0 || buf.is_null() {
        set_last_error(6); // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }
    // SAFETY: the guest passes a buffer valid for `len` bytes (Windows contract).
    let n = unsafe { libc::write(fd, buf as *const c_void, len as usize) };
    if n < 0 {
        set_last_error(errno_to_win());
        return 0; // FALSE
    }
    if !written.is_null() {
        // SAFETY: `written` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(written, n as u32) };
    }
    1 // TRUE
}

/// `kernel32!ReadFile(h, buf, len, read*, overlapped*) -> BOOL`.
pub extern "C" fn read_file(
    handle: Handle,
    buf: *mut u8,
    len: u32,
    read_out: *mut u32,
    _overlapped: *mut c_void,
) -> i32 {
    let fd = resolve_fd(handle);
    if fd < 0 || buf.is_null() {
        set_last_error(6); // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }
    // SAFETY: the guest passes a buffer valid for `len` bytes (Windows contract).
    let n = unsafe { libc::read(fd, buf as *mut c_void, len as usize) };
    if n < 0 {
        set_last_error(errno_to_win());
        return 0; // FALSE
    }
    if !read_out.is_null() {
        // SAFETY: `read_out` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(read_out, n as u32) };
    }
    1 // TRUE
}

/// Resolve a Windows handle to a Linux fd. Stdio handles (0/1/2) pass through; file handles
/// in the table carry their fd.
///
/// This reads the fd *without* cloning the `FileObject`: `Object::clone_ref` would copy the
/// raw fd into a temporary `FileObject` whose `Drop` calls `libc::close(fd)`, which would
/// close the real descriptor as soon as the temporary dropped. Reading the fd directly via
/// the closure (returning a plain `i32`, not a `FileObject`) avoids the spurious close.
fn resolve_fd(handle: Handle) -> i32 {
    if handle <= 2 {
        return handle as i32;
    }
    handle::with_object(handle, |o| match o {
        Object::File(f) => Some(f.fd),
        _ => None,
    })
    .flatten()
    .unwrap_or(-1)
}

/// `kernel32!CloseHandle(HANDLE) -> BOOL`.
pub extern "C" fn close_handle(handle: Handle) -> i32 {
    if handle::close(handle) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// `ntdll!NtClose(HANDLE) -> NTSTATUS`. 0 = STATUS_SUCCESS.
pub extern "C" fn nt_close(handle: Handle) -> i32 {
    if handle::close(handle) {
        0
    } else {
        0xC000_0008u32 as i32 // STATUS_INVALID_HANDLE
    }
}

/// Best-effort mapping of a Linux errno to a Windows error code.
fn errno_to_win() -> u32 {
    // SAFETY: `__errno_location` returns a thread-local pointer safe to read.
    let e = unsafe { *libc::__errno_location() };
    match e {
        libc::EBADF => 6,    // ERROR_INVALID_HANDLE
        libc::EINVAL => 87,  // ERROR_INVALID_PARAMETER
        libc::ENOENT => 2,   // ERROR_FILE_NOT_FOUND
        libc::EACCES => 5,   // ERROR_ACCESS_DENIED
        libc::EEXIST => 80,  // ERROR_FILE_EXISTS
        libc::ENOSPC => 112, // ERROR_DISK_FULL
        _ => 1597,           // ERROR_UNEXPECTED — generic sentinel
    }
}

// ---------------------------------------------------------------------------
// Files (NtCreateFile / NtReadFile / NtWriteFile)
// ---------------------------------------------------------------------------

/// `ntdll!NtCreateFile(...) -> NTSTATUS`. A minimal subset: opens `path` (a UTF-16 path
/// is expected by the full Windows API; M1 accepts a host-side fd wrapped via the kernel32
/// `CreateFileW` path in pe-loader, so this stub returns the handle for an already-open fd
/// passed in `handle_out`'s place). For M1 we expose a simpler `nt_create_file_fd` helper
/// that the pe-loader can call with a host path.
pub extern "C" fn nt_create_file(
    handle_out: *mut Handle,
    _desired_access: u32,
    _obj_attrs: *mut c_void,
    _io_status: *mut c_void,
    _alloc_size: *mut i64,
    _file_attrs: u32,
    _share_access: u32,
    _disposition: u32,
    _create_options: u32,
    _ea: *mut c_void,
    _ea_len: u32,
) -> i32 {
    // The full NT path is not implemented in M1; callers route file opens through
    // kernel32!CreateFileW (which we provide a thin fd-opening wrapper for below). This
    // stub records a "not implemented" status and a NULL handle so callers fail loudly.
    if !handle_out.is_null() {
        // SAFETY: out-pointer valid for one u64.
        unsafe { std::ptr::write_unaligned(handle_out, 0) };
    }
    0xC000_0022u32 as i32 // STATUS_ACCESS_DENIED (sentinel for "not implemented")
}

/// Open a host file at `path` with `flags` (Linux `open(2)` flags) and return a Windows
/// handle wrapping the resulting fd. Used by the pe-loader's `CreateFileW` thunk. Returns
/// `INVALID_HANDLE_VALUE` (u64::MAX) on failure.
pub fn open_file_handle(path: &std::ffi::CString, flags: i32, mode: u32) -> Handle {
    // SAFETY: `open` reads `path` (a valid NUL-terminated CString) and returns an fd or -1.
    let fd = unsafe { libc::open(path.as_ptr(), flags, mode) };
    if fd < 0 {
        return u64::MAX;
    }
    handle::create(Object::File(FileObject { fd }))
}

// ---------------------------------------------------------------------------
// NtReadFile / NtWriteFile — used by the Rust std `Handle` synchronous I/O path.
//
// `IO_STATUS_BLOCK` is `#[repr(C)] { Anonymous: union { Status: NTSTATUS (i32),
// Pointer: *mut c_void }, Information: usize }` — 16 bytes on x64. The guest passes
// a pointer to one; we write the final NTSTATUS into `Status` and the byte count
// into `Information`, then return the NTSTATUS. Synchronous (no Event/Apc) I/O
// completes inline and returns STATUS_SUCCESS (0) on success.
// ---------------------------------------------------------------------------

/// `ntdll!NtWriteFile(handle, event, apc, apc_ctx, io_status, buf, len, byte_offset, key)
/// -> NTSTATUS`. Performs a synchronous write for stdio/file handles and fills the
/// `IO_STATUS_BLOCK`. Async I/O (non-null `event`/`apc`) is treated as synchronous.
pub extern "C" fn nt_write_file(
    handle: Handle,
    _event: Handle,
    _apc: *mut c_void,
    _apc_ctx: *mut c_void,
    io_status: *mut c_void,
    buf: *const u8,
    len: u32,
    _byte_offset: *const i64,
    _key: *const u32,
) -> i32 {
    let fd = resolve_fd(handle);
    if fd < 0 || buf.is_null() {
        set_nt_status(io_status, 0xC000_0008u32 as i32); // STATUS_INVALID_HANDLE
        return 0xC000_0008u32 as i32;
    }
    // SAFETY: the guest passes a buffer valid for `len` bytes (Windows contract).
    let n = unsafe { libc::write(fd, buf as *const c_void, len as usize) };
    if n < 0 {
        let status = errno_to_nt();
        set_nt_status(io_status, status);
        return status;
    }
    set_io_status(io_status, 0, n as usize); // STATUS_SUCCESS, bytes written
    0 // STATUS_SUCCESS
}

/// `ntdll!NtReadFile(handle, event, apc, apc_ctx, io_status, buf, len, byte_offset, key)
/// -> NTSTATUS`. Performs a synchronous read for stdio/file handles and fills the
/// `IO_STATUS_BLOCK`. Returns STATUS_END_OF_FILE (0xC0000011) for a zero-length read
/// on a terminal EOF.
pub extern "C" fn nt_read_file(
    handle: Handle,
    _event: Handle,
    _apc: *mut c_void,
    _apc_ctx: *mut c_void,
    io_status: *mut c_void,
    buf: *mut u8,
    len: u32,
    _byte_offset: *const i64,
    _key: *const u32,
) -> i32 {
    let fd = resolve_fd(handle);
    if fd < 0 || buf.is_null() {
        set_nt_status(io_status, 0xC000_0008u32 as i32); // STATUS_INVALID_HANDLE
        return 0xC000_0008u32 as i32;
    }
    // SAFETY: the guest passes a buffer valid for `len` bytes (Windows contract).
    let n = unsafe { libc::read(fd, buf as *mut c_void, len as usize) };
    if n < 0 {
        let status = errno_to_nt();
        set_nt_status(io_status, status);
        return status;
    }
    if n == 0 {
        // EOF on a read of >0 requested bytes.
        set_io_status(io_status, 0xC000_0011u32 as i32, 0); // STATUS_END_OF_FILE
        return 0xC000_0011u32 as i32;
    }
    set_io_status(io_status, 0, n as usize); // STATUS_SUCCESS, bytes read
    0 // STATUS_SUCCESS
}

/// Write just the `Status` field (offset 0) of an `IO_STATUS_BLOCK`.
///
/// SAFETY: `io_status` must be a valid guest pointer to a 16-byte `IO_STATUS_BLOCK`
/// (or null, in which case this is a no-op).
fn set_nt_status(io_status: *mut c_void, status: i32) {
    if io_status.is_null() {
        return;
    }
    // SAFETY: `IO_STATUS_BLOCK` starts with a union whose `Status` variant is an i32
    // at offset 0; the caller guarantees the pointer is valid for 16 bytes.
    unsafe { std::ptr::write_unaligned(io_status as *mut i32, status) };
}

/// Write both `Status` (offset 0) and `Information` (offset 8) of an `IO_STATUS_BLOCK`.
///
/// SAFETY: `io_status` must be a valid guest pointer to a 16-byte `IO_STATUS_BLOCK`
/// (or null, in which case this is a no-op).
fn set_io_status(io_status: *mut c_void, status: i32, information: usize) {
    if io_status.is_null() {
        return;
    }
    // SAFETY: `IO_STATUS_BLOCK` is `#[repr(C)]` with `Status` (i32) at offset 0 and
    // `Information` (usize) at offset 8 on x64; the caller guarantees validity.
    unsafe {
        std::ptr::write_unaligned(io_status as *mut i32, status);
        std::ptr::write_unaligned(io_status.add(8) as *mut usize, information);
    }
}

/// Map the current thread's Linux errno to an NTSTATUS (best-effort).
fn errno_to_nt() -> i32 {
    // SAFETY: `__errno_location` returns a thread-local pointer safe to read.
    let e = unsafe { *libc::__errno_location() };
    match e {
        libc::EBADF => 0xC000_0008u32 as i32,  // STATUS_INVALID_HANDLE
        libc::EINVAL => 0xC000_000Du32 as i32, // STATUS_INVALID_PARAMETER
        libc::ENOENT => 0xC000_0034u32 as i32, // STATUS_OBJECT_NAME_NOT_FOUND
        libc::EACCES => 0xC000_0022u32 as i32, // STATUS_ACCESS_DENIED
        libc::EEXIST => 0xC000_0035u32 as i32, // STATUS_OBJECT_NAME_COLLISION
        libc::ENOSPC => 0xC000_0079u32 as i32, // STATUS_DISK_FULL
        _ => 0xC000_0001u32 as i32,            // STATUS_UNSUCCESSFUL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_std_handle_maps_stdio() {
        assert_eq!(get_std_handle(STD_OUTPUT_HANDLE), 1);
        assert_eq!(get_std_handle(STD_ERROR_HANDLE), 2);
        assert_eq!(get_std_handle(STD_INPUT_HANDLE), 0);
        assert_eq!(
            get_std_handle(0),
            u64::MAX,
            "unknown -> INVALID_HANDLE_VALUE"
        );
    }

    #[test]
    fn last_error_round_trip() {
        set_last_error(123);
        assert_eq!(get_last_error(), 123);
        set_last_error(0);
        assert_eq!(get_last_error(), 0);
    }

    #[test]
    fn tick_count_is_monotonic_nondecreasing() {
        let a = get_tick_count_64();
        let b = get_tick_count_64();
        assert!(b >= a, "GetTickCount64 is monotonic nondecreasing");
    }

    #[test]
    fn query_performance_frequency_is_one_ghz() {
        let mut freq = 0i64;
        assert_eq!(query_performance_frequency(&mut freq), 1);
        assert_eq!(freq, 1_000_000_000);
    }

    #[test]
    fn write_file_to_stderr_succeeds() {
        // Write a harmless byte to stderr (fd 2); the write must report 1 byte written.
        let buf = b"\n";
        let mut written: u32 = 0;
        let r = write_file(2, buf.as_ptr(), 1, &mut written, std::ptr::null_mut());
        assert_eq!(r, 1, "WriteFile to stderr returns TRUE");
        assert_eq!(written, 1, "one byte written");
    }
}
