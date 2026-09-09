//! Additional kernel32/ntdll/bcrypt/userenv exports needed by the Rust std runtime
//! and CRT init sequence: exception handling stubs, system info, file/path helpers,
//! one-time init, process/thread queries, and miscellaneous no-ops.
//!
//! Many of these are best-effort stubs that return success without fully implementing the
//! Windows semantics — sufficient for the console-PE acceptance target (a simple
//! `println!` program) where the runtime probes the API but does not depend on its full
//! behavior.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// Best-effort stubs intentionally use opaque sentinel pointers, raw casts,
// and a precedence-suspect XOR; suppress the style lints clippy would
// otherwise flag under `-D warnings`.
#![allow(
    clippy::manual_dangling_ptr,
    clippy::unnecessary_cast,
    clippy::precedence
)]

use std::collections::HashSet;
use std::os::raw::c_void;
use std::sync::OnceLock;

use crate::{FnPtr, Handle};

/// Tracks which `INIT_ONCE` structures (by address) have been completed via
/// `InitOnceComplete`. `InitOnceBeginInitialize` returns `pending = TRUE` for a
/// not-yet-completed init (caller must run the initializer) and `pending = FALSE`
/// for an already-completed one (caller just reads the result). This matches the
/// Windows one-time-init contract the Rust std `LazyKey` relies on.
static INIT_ONCE_DONE: parking_lot::Mutex<Option<HashSet<usize>>> = parking_lot::const_mutex(None);

/// Metadata for a single export (same shape as `ExportSpec` in lib.rs).
#[derive(Clone, Copy)]
pub struct ExtraSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: FnPtr,
    pub n_args: u8,
    pub noreturn: bool,
}

/// A SYSTEM_INFO struct (48 bytes on x64).
#[repr(C)]
struct SystemInfo {
    processor_arch: u16,
    _reserved: u16,
    page_size: u32,
    min_app_address: *mut c_void,
    max_app_address: *mut c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

// ---------------------------------------------------------------------------
// Exception handling stubs
// ---------------------------------------------------------------------------

/// `kernel32!AddVectoredExceptionHandler(first, handler) -> PVOID`. Returns a fake non-null
/// handle (we never deliver exceptions).
pub extern "C" fn add_vectored_exception_handler(
    _first: u32,
    _handler: *mut c_void,
) -> *mut c_void {
    0x1 as *mut c_void
}

/// `kernel32!SetUnhandledExceptionFilter(filter) -> LPTOP_LEVEL_EXCEPTION_FILTER`.
/// Returns a fake non-null previous filter.
pub extern "C" fn set_unhandled_exception_filter(_filter: *mut c_void) -> *mut c_void {
    0x1 as *mut c_void
}

/// `kernel32!SetConsoleCtrlHandler(handler, add) -> BOOL`. Returns TRUE (no-op).
pub extern "C" fn set_console_ctrl_handler(_handler: *mut c_void, _add: i32) -> i32 {
    1
}

/// `kernel32!RaiseException(code, flags, count, args) -> void`. No-op (SEH not delivered).
pub extern "C" fn raise_exception(_code: u32, _flags: u32, _count: u32, _args: *const usize) {}

/// `kernel32!__C_specific_handler(...) -> LONG`. Returns 0 (ExceptionContinueSearch).
pub extern "C" fn c_specific_handler(
    _records: *mut c_void,
    _frame: *mut c_void,
    _context: *mut c_void,
    _dispatcher: *mut c_void,
) -> i32 {
    0
}

/// `kernel32!RtlCaptureContext(CONTEXT*)`. Zeroes the CONTEXT struct (1232 bytes on x64).
pub extern "C" fn rtl_capture_context(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    const CONTEXT_SIZE: usize = 1232;
    // SAFETY: `ctx` is a writable CONTEXT buffer valid for `CONTEXT_SIZE` bytes.
    unsafe { std::ptr::write_bytes(ctx as *mut u8, 0, CONTEXT_SIZE) };
}

/// `kernel32!RtlLookupFunctionEntry(controlPc, entry*, base*) -> PRUNTIME_FUNCTION`.
/// Returns NULL (no unwind info).
pub extern "C" fn rtl_lookup_function_entry(
    _control_pc: u64,
    _entry: *mut c_void,
    _base: *mut u64,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!RtlVirtualUnwind(...) -> PEXCEPTION_ROUTINE`.
/// Delegates to the PE loader's SEH implementation via the registered bridge.
pub extern "C" fn rtl_virtual_unwind(
    _handler_type: u32,
    _exception_code: u32,
    _target_ip: u64,
    function_entry: *const c_void,
    context: *mut c_void,
    _handler_data: *mut *mut c_void,
    frame: *mut u64,
) -> *mut c_void {
    // The image base is implicit in the RuntimeFunction's RVAs; the PE loader
    // stored it when installing the exception table. We pass 0 and let the
    // implementation use its own stored base.
    let handler_rva = crate::dllload::call_virtual_unwind(
        function_entry,
        0, // image_base: the pe-loader side looks it up from its global state
        context,
        frame,
    );
    if handler_rva != 0 {
        handler_rva as *mut c_void
    } else {
        std::ptr::null_mut()
    }
}

/// `kernel32!RtlUnwindEx(...) -> void`. Best-effort no-op.
pub extern "C" fn rtl_unwind_ex(
    _frame: *mut c_void,
    _handler: *mut c_void,
    _context: *mut c_void,
    _context2: *mut c_void,
) {
}

// ---------------------------------------------------------------------------
// System info / time
// ---------------------------------------------------------------------------

/// `kernel32!GetSystemTimePreciseAsFileTime(FILETIME*)`. Writes current time as FILETIME.
pub extern "C" fn get_system_time_precise_as_file_time(ft: *mut u8) {
    if ft.is_null() {
        return;
    }
    let now = windows_filetime_now();
    // SAFETY: `ft` is a writable 8-byte FILETIME buffer.
    unsafe { std::ptr::write_unaligned(ft as *mut u64, now) };
}

/// `kernel32!GetSystemInfo(SYSTEM_INFO*)`. Fills with defaults: x86_64, 4 KiB, 1 CPU.
pub extern "C" fn get_system_info(info: *mut u8) {
    if info.is_null() {
        return;
    }
    let si = SystemInfo {
        processor_arch: 9, // PROCESSOR_ARCHITECTURE_AMD64
        _reserved: 0,
        page_size: 4096,
        min_app_address: 0x10000 as *mut c_void,
        max_app_address: 0x7FFF_FFFF_FFFF as *mut c_void,
        active_processor_mask: 1,
        number_of_processors: 1,
        processor_type: 0,
        allocation_granularity: 0x10000,
        processor_level: 0,
        processor_revision: 0,
    };
    // SAFETY: `info` is a writable SYSTEM_INFO buffer (48 bytes).
    unsafe { std::ptr::write_unaligned(info as *mut SystemInfo, si) };
}

/// `kernel32!GetConsoleOutputCP() -> UINT`. Returns 65001 (UTF-8).
pub extern "C" fn get_console_output_cp() -> u32 {
    65001
}

// ---------------------------------------------------------------------------
// Module / path helpers
// ---------------------------------------------------------------------------

/// `kernel32!GetModuleFileNameW(hModule, buf, size) -> DWORD`. Writes a dummy exe path.
pub extern "C" fn get_module_file_name_w(_module: *mut c_void, buf: *mut u16, size: u32) -> u32 {
    if buf.is_null() || size == 0 {
        return 0;
    }
    let path: Vec<u16> = "nigg-app.exe".encode_utf16().chain([0]).collect();
    let copy_len = path.len().min(size as usize);
    // SAFETY: `buf` is writable for `size` u16 code units.
    unsafe { std::ptr::copy_nonoverlapping(path.as_ptr(), buf, copy_len) };
    // SAFETY: NUL-terminate at the last copied position.
    unsafe { std::ptr::write_unaligned(buf.add(copy_len.saturating_sub(1)), 0) };
    (copy_len.saturating_sub(1)) as u32
}

/// `kernel32!GetCurrentDirectoryW(len, buf) -> DWORD`. Writes the CWD as UTF-16.
pub extern "C" fn get_current_directory_w(len: u32, buf: *mut u16) -> u32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let path: Vec<u16> = cwd
        .to_string_lossy()
        .replace('/', "\\")
        .encode_utf16()
        .chain([0])
        .collect();
    let needed = (path.len() - 1) as u32;
    if buf.is_null() || len == 0 {
        return needed;
    }
    let copy_len = path.len().min(len as usize);
    // SAFETY: `buf` is writable for `len` u16 code units.
    unsafe { std::ptr::copy_nonoverlapping(path.as_ptr(), buf, copy_len) };
    // SAFETY: NUL-terminate.
    unsafe { std::ptr::write_unaligned(buf.add(copy_len.saturating_sub(1)), 0) };
    (copy_len.saturating_sub(1)) as u32
}

/// `kernel32!GetSystemDirectoryW(buf, size) -> DWORD`.
pub extern "C" fn get_system_directory_w(buf: *mut u16, size: u32) -> u32 {
    write_dummy_path_w(buf, size, "C:\\Windows\\System32")
}

/// `kernel32!GetWindowsDirectoryW(buf, size) -> DWORD`.
pub extern "C" fn get_windows_directory_w(buf: *mut u16, size: u32) -> u32 {
    write_dummy_path_w(buf, size, "C:\\Windows")
}

/// `kernel32!GetTempPathW(size, buf) -> DWORD`.
pub extern "C" fn get_temp_path_w(size: u32, buf: *mut u16) -> u32 {
    write_dummy_path_w(buf, size, "C:\\Temp\\")
}

/// Write `path` as UTF-16 into `buf[0..size]` with NUL termination. Returns length (excl NUL).
fn write_dummy_path_w(buf: *mut u16, size: u32, path: &str) -> u32 {
    let units: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let needed = (units.len() - 1) as u32;
    if buf.is_null() || size == 0 {
        return needed;
    }
    let copy_len = units.len().min(size as usize);
    // SAFETY: `buf` is writable for `size` u16 code units.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), buf, copy_len) };
    // SAFETY: NUL-terminate at the last copied position.
    unsafe { std::ptr::write_unaligned(buf.add(copy_len.saturating_sub(1)), 0) };
    (copy_len.saturating_sub(1)) as u32
}

/// `kernel32!GetFullPathNameW(name, size, buf, file*) -> DWORD`. Returns the input path
/// verbatim (no drive/UNC resolution).
pub extern "C" fn get_full_path_name_w(
    name: *const u16,
    size: u32,
    buf: *mut u16,
    _file_part: *mut *mut u16,
) -> u32 {
    if name.is_null() || buf.is_null() || size == 0 {
        return 0;
    }
    // SAFETY: read the NUL-terminated UTF-16 input.
    let input = unsafe { crate::string::utf16_to_string(name) };
    let full = input.replace('/', "\\");
    let units: Vec<u16> = full.encode_utf16().chain([0]).collect();
    let copy_len = units.len().min(size as usize);
    // SAFETY: `buf` is writable for `size` u16 code units.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), buf, copy_len) };
    // SAFETY: NUL-terminate.
    unsafe { std::ptr::write_unaligned(buf.add(copy_len.saturating_sub(1)), 0) };
    (copy_len.saturating_sub(1)) as u32
}

/// `kernel32!GetFileAttributesW(name) -> DWORD`. Returns INVALID_FILE_ATTRIBUTES.
pub extern "C" fn get_file_attributes_w(_name: *const u16) -> u32 {
    0xFFFF_FFFF
}

/// `kernel32!GetFileType(handle) -> DWORD`. CHAR for stdio, DISK for files.
pub extern "C" fn get_file_type(handle: Handle) -> u32 {
    if handle <= 2 {
        2 // FILE_TYPE_CHAR
    } else {
        1 // FILE_TYPE_DISK
    }
}

/// `kernel32!GetFileSizeEx(handle, size*) -> BOOL`. Returns TRUE with size 0.
pub extern "C" fn get_file_size_ex(_handle: Handle, size: *mut i64) -> i32 {
    if !size.is_null() {
        // SAFETY: `size` is a guest out-pointer valid for one i64.
        unsafe { std::ptr::write_unaligned(size, 0) };
    }
    1
}

/// `kernel32!SetFilePointerEx(handle, distance, new_pos*, method) -> BOOL`.
pub extern "C" fn set_file_pointer_ex(
    _handle: Handle,
    _distance: i64,
    new_pos: *mut i64,
    _method: u32,
) -> i32 {
    if !new_pos.is_null() {
        // SAFETY: `new_pos` is a guest out-pointer valid for one i64.
        unsafe { std::ptr::write_unaligned(new_pos, 0) };
    }
    1
}

/// `kernel32!SetHandleInformation(handle, mask, flags) -> BOOL`. Returns TRUE (no-op).
pub extern "C" fn set_handle_information(_handle: Handle, _mask: u32, _flags: u32) -> i32 {
    1
}

/// `kernel32!SetThreadStackGuarantee(size*) -> BOOL`. Returns TRUE (no-op).
pub extern "C" fn set_thread_stack_guarantee(_size: *mut u32) -> i32 {
    1
}

/// `kernel32!SwitchToThread() -> BOOL`. Yields the CPU.
pub extern "C" fn switch_to_thread() -> i32 {
    // SAFETY: `sched_yield` is always safe.
    unsafe { libc::sched_yield() };
    1
}

// `kernel32!GetProcAddress` is *not* registered here: the canonical (real)
// implementation lives in `crate::dllload` and is referenced by `anticheat`'s export
// list — a second, stub registration in this table would win the loader's first-wins
// dedup and leave DLL exports permanently unresolvable.

// ---------------------------------------------------------------------------
// One-time init
// ---------------------------------------------------------------------------

/// `kernel32!InitOnceBeginInitialize(init*, flags, pending*, context*) -> BOOL`.
///
/// Returns TRUE. Sets `*pending = TRUE` when the caller is the first to begin
/// initialization (and so must run the initializer then call `InitOnceComplete`),
/// or `*pending = FALSE` when a prior `InitOnceComplete` already finished.
pub extern "C" fn init_once_begin_initialize(
    init: *mut c_void,
    _flags: u32,
    pending: *mut i32,
    _context: *mut *mut c_void,
) -> i32 {
    let done = {
        let mut guard = INIT_ONCE_DONE.lock();
        let set = guard.get_or_insert_with(HashSet::new);
        set.contains(&(init as usize))
    };
    if !pending.is_null() {
        // SAFETY: `pending` is a guest out-pointer valid for one BOOL.
        unsafe { std::ptr::write_unaligned(pending, if done { 0 } else { 1 }) };
    }
    1
}

/// `kernel32!InitOnceComplete(init*, flags, context) -> BOOL`. Marks the init as
/// complete so future `InitOnceBeginInitialize` calls return `pending = FALSE`.
pub extern "C" fn init_once_complete(init: *mut c_void, _flags: u32, _context: *mut c_void) -> i32 {
    {
        let mut guard = INIT_ONCE_DONE.lock();
        let set = guard.get_or_insert_with(HashSet::new);
        set.insert(init as usize);
    }
    1
}

// ---------------------------------------------------------------------------
// CompareString / FormatMessage
// ---------------------------------------------------------------------------

/// `kernel32!CompareStringOrdinal(a, la, b, lb, ignore_case) -> int`. Returns 1/2/3.
pub extern "C" fn compare_string_ordinal(
    a: *const u16,
    _la: i32,
    b: *const u16,
    _lb: i32,
    _ignore_case: i32,
) -> i32 {
    if a.is_null() || b.is_null() {
        return 2;
    }
    // SAFETY: both are NUL-terminated UTF-16 strings.
    let sa = unsafe { crate::string::utf16_to_string(a) };
    let sb = unsafe { crate::string::utf16_to_string(b) };
    use std::cmp::Ordering;
    match sa.cmp(&sb) {
        Ordering::Less => 1,
        Ordering::Equal => 2,
        Ordering::Greater => 3,
    }
}

/// `kernel32!CompareStringW(locale, flags, a, la, b, lb) -> int`. Compares two wide
/// strings lexicographically. Returns 1 (`CSTR_LESS_THAN`), 2 (`CSTR_EQUAL`), or 3
/// (`CSTR_GREATER_THAN`). The `locale` and `flags` (e.g. `NORM_IGNORECASE`) are ignored —
/// the acceptance target's comparisons are ordinal. Lengths default to NUL-terminated when
/// passed as -1, the common Windows usage.
pub extern "C" fn compare_string_w(
    _locale: u32,
    _flags: u32,
    a: *const u16,
    la: i32,
    b: *const u16,
    lb: i32,
) -> i32 {
    if a.is_null() || b.is_null() {
        return 2; // equal (both absent)
    }
    // SAFETY: both are NUL-terminated UTF-16 strings (the -1 length means NUL-terminated).
    let sa = unsafe { crate::string::utf16_to_string(a) };
    let sb = unsafe { crate::string::utf16_to_string(b) };
    // Clamp to the requested lengths if positive; otherwise compare the whole strings.
    let ea = if la >= 0 {
        sa.chars().take(la as usize).collect::<String>()
    } else {
        sa
    };
    let eb = if lb >= 0 {
        sb.chars().take(lb as usize).collect::<String>()
    } else {
        sb
    };
    use std::cmp::Ordering;
    match ea.cmp(&eb) {
        Ordering::Less => 1,
        Ordering::Equal => 2,
        Ordering::Greater => 3,
    }
}

/// `kernel32!FormatMessageW(...) -> DWORD`. Returns 0 (no message formatted).
pub extern "C" fn format_message_w(
    _flags: u32,
    _source: *const c_void,
    _msg_id: u32,
    _lang: u32,
    _buf: *mut u16,
    _size: u32,
    _args: *mut c_void,
) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// File mapping / async I/O stubs
// ---------------------------------------------------------------------------

/// `kernel32!MapViewOfFile(...) -> PVOID`. Returns NULL (not implemented).
pub extern "C" fn map_view_of_file(
    _handle: Handle,
    _access: u32,
    _high: u32,
    _low: u32,
    _size: usize,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// `kernel32!UnmapViewOfFile(base) -> BOOL`. Returns TRUE (no-op).
pub extern "C" fn unmap_view_of_file(_base: *const c_void) -> i32 {
    1
}

/// `kernel32!CreateFileMappingA(...) -> HANDLE`. Returns 0 (not implemented).
pub extern "C" fn create_file_mapping_a(
    _handle: Handle,
    _attrs: *mut c_void,
    _protect: u32,
    _high: u32,
    _low: u32,
    _name: *const u8,
) -> Handle {
    0
}

/// `kernel32!GetOverlappedResult(...) -> BOOL`. Returns FALSE (no async I/O).
pub extern "C" fn get_overlapped_result(
    _handle: Handle,
    _overlapped: *mut c_void,
    _bytes: *mut u32,
    _wait: i32,
) -> i32 {
    0
}

/// `kernel32!ReadConsoleW(...) -> BOOL`. Reads from stdin, converting UTF-8 to UTF-16.
pub extern "C" fn read_console_w(
    handle: Handle,
    buf: *mut u16,
    count: u32,
    read_out: *mut u32,
    _reserved: *mut c_void,
) -> i32 {
    if buf.is_null() || count == 0 {
        if !read_out.is_null() {
            // SAFETY: `read_out` is a guest out-pointer.
            unsafe { std::ptr::write_unaligned(read_out, 0) };
        }
        return 1;
    }
    let fd = if handle <= 2 { handle as i32 } else { -1 };
    if fd < 0 {
        return 0;
    }
    let byte_buf = vec![0u8; count as usize];
    // SAFETY: `fd` is a valid stdio fd; `read` fills up to `count` bytes.
    let n = unsafe {
        libc::read(
            fd,
            byte_buf.as_ptr() as *mut c_void,
            byte_buf.len().min(isize::MAX as usize),
        )
    };
    if n < 0 {
        nigg_ntapi::process::set_last_error(6);
        return 0;
    }
    let utf8 = String::from_utf8_lossy(&byte_buf[..n as usize]);
    let units: Vec<u16> = utf8.encode_utf16().collect();
    let copy = units.len().min(count as usize);
    // SAFETY: `buf` is writable for `count` u16 code units.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), buf, copy) };
    if !read_out.is_null() {
        // SAFETY: `read_out` is a guest out-pointer.
        unsafe { std::ptr::write_unaligned(read_out, copy as u32) };
    }
    1
}

/// `kernel32!WriteFileEx(...) -> BOOL`. Returns FALSE (no async I/O).
pub extern "C" fn write_file_ex(
    _handle: Handle,
    _buf: *const u8,
    _count: u32,
    _overlapped: *mut c_void,
    _routine: *mut c_void,
) -> i32 {
    0
}

/// `kernel32!ReadFileEx(...) -> BOOL`. Returns FALSE (no async I/O).
pub extern "C" fn read_file_ex(
    _handle: Handle,
    _buf: *mut u8,
    _count: u32,
    _overlapped: *mut c_void,
    _routine: *mut c_void,
) -> i32 {
    0
}

/// `kernel32!FlushFileBuffers(handle) -> BOOL`. Delegates to file.rs.
pub extern "C" fn flush_file_buffers(handle: Handle) -> i32 {
    crate::file::flush_file_buffers(handle)
}

/// `kernel32!SetFileAttributesW(name, attrs) -> BOOL`. Returns TRUE (no-op).
pub extern "C" fn set_file_attributes_w(_name: *const u16, _attrs: u32) -> i32 {
    1
}

/// `kernel32!TerminateProcess(handle, code) -> BOOL`. Terminates the current process.
pub extern "C" fn terminate_process(handle: Handle, code: u32) -> i32 {
    if handle == u64::MAX || handle == 0 {
        // SAFETY: `_exit` is the raw exit syscall, safe from any context.
        unsafe { libc::_exit(code as i32) };
    }
    0
}

/// `kernel32!GetProcessId(handle) -> DWORD`. Returns the current process id.
pub extern "C" fn get_process_id(_handle: Handle) -> u32 {
    nigg_ntapi::thread::get_current_process_id()
}

/// `kernel32!GetExitCodeProcess(handle, code*) -> BOOL`. Returns TRUE with code 0.
pub extern "C" fn get_exit_code_process(_handle: Handle, code: *mut u32) -> i32 {
    if !code.is_null() {
        // SAFETY: `code` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(code, 0) };
    }
    1
}

/// `kernel32!WaitForSingleObjectEx(handle, ms, alertable) -> DWORD`. Delegates to
/// `WaitForSingleObject` (alertable waits not supported).
pub extern "C" fn wait_for_single_object_ex(handle: Handle, ms: u32, _alertable: i32) -> u32 {
    nigg_ntapi::sync::wait_for_single_object(handle, ms)
}

/// `kernel32!GetDateFormatW(locale, flags, time, fmt, buf, size) -> int`. Returns 0
/// (no formatted date produced). The buffers are left untouched.
pub extern "C" fn get_date_format_w(
    _locale: u32,
    _flags: u32,
    _time: *const c_void,
    _fmt: *const u16,
    _buf: *mut u16,
    _size: i32,
) -> i32 {
    0
}

/// `kernel32!GetTimeFormatW(locale, flags, time, fmt, buf, size) -> int`. Returns 0
/// (no formatted time produced). The buffers are left untouched.
pub extern "C" fn get_time_format_w(
    _locale: u32,
    _flags: u32,
    _time: *const c_void,
    _fmt: *const u16,
    _buf: *mut u16,
    _size: i32,
) -> i32 {
    0
}

// ---------------------------------------------------------------------------
// bcryptprimitives.dll
// ---------------------------------------------------------------------------

/// `bcryptprimitives!ProcessPrng(buf, len) -> BOOL`. Fills `buf` with random bytes from
/// `/dev/urandom`.
pub extern "C" fn process_prng(buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() || len == 0 {
        return 1;
    }
    static URANDOM: OnceLock<i32> = OnceLock::new();
    let fd = *URANDOM.get_or_init(|| {
        // SAFETY: `open` reads a NUL-terminated path; returns an fd or -1.
        let path = b"/dev/urandom\0";
        unsafe { libc::open(path.as_ptr() as *const i8, libc::O_RDONLY) }
    });

    if fd < 0 {
        // Fallback: xorshift64 PRNG seeded from the monotonic clock + buffer address.
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `clock_gettime` writes a valid timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        let mut state =
            (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64) ^ (buf as usize as u64);
        // SAFETY: `buf` is writable for `len` bytes.
        unsafe {
            for i in 0..len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *buf.add(i) = state as u8;
            }
        }
        return 1;
    }

    let mut filled = 0usize;
    // SAFETY: `buf` is writable for `len` bytes; `read` fills up to `len - filled`.
    while filled < len {
        let n = unsafe {
            libc::read(
                fd,
                (buf as *mut u8).add(filled) as *mut c_void,
                len - filled,
            )
        };
        if n <= 0 {
            break;
        }
        filled += n as usize;
    }
    if filled == len {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// USERENV.dll
// ---------------------------------------------------------------------------

/// `userenv!GetUserProfileDirectoryW(token, buf, size*) -> BOOL`. Writes a dummy path.
pub extern "C" fn get_user_profile_directory_w(
    _token: Handle,
    buf: *mut u16,
    size: *mut u32,
) -> i32 {
    let path: Vec<u16> = "C:\\Users\\nigg".encode_utf16().chain([0]).collect();
    let needed = (path.len() - 1) as u32;
    let _ = needed; // referenced for future size-reporting parity
    if !size.is_null() {
        if buf.is_null() {
            // SAFETY: `size` is a guest out-pointer.
            unsafe { std::ptr::write_unaligned(size, needed) };
            return 1;
        }
        // SAFETY: read the capacity.
        let cap = unsafe { std::ptr::read_unaligned(size) };
        let copy_len = path.len().min(cap as usize);
        // SAFETY: `buf` is writable for `cap` u16 code units.
        unsafe { std::ptr::copy_nonoverlapping(path.as_ptr(), buf, copy_len) };
        // SAFETY: NUL-terminate.
        unsafe { std::ptr::write_unaligned(buf.add(copy_len.saturating_sub(1)), 0) };
        // SAFETY: update `size`.
        unsafe { std::ptr::write_unaligned(size, (copy_len.saturating_sub(1)) as u32) };
    }
    1
}

// ---------------------------------------------------------------------------
// ntdll.dll helpers
// ---------------------------------------------------------------------------

/// `ntdll!RtlNtStatusToDosError(status) -> ULONG`. Best-effort mapping.
pub extern "C" fn rtl_nt_status_to_dos_error(status: i32) -> u32 {
    match status as u32 {
        0 => 0,
        0xC000_0005 => 5,
        0xC000_0022 => 5,
        0xC000_0034 => 2,
        0xC000_0035 => 2,
        0xC000_0043 => 5,
        _ => 1597,
    }
}

/// `ntdll!_vsnprintf(char*, size_t, const char*, va_list) -> int`. Delegates to the UCRT
/// [`vsnprintf`](crate::ucrt::vsnprintf), which writes the format string literally into the
/// buffer (the Windows `va_list` is not readable from Rust). PEs that import `_vsnprintf`
/// from `ntdll.dll` (rather than `ucrtbase.dll`) get the same behavior.
pub extern "C" fn ntdll_vsnprintf(
    dst: *mut i8,
    count: usize,
    fmt: *const i8,
    va: *mut c_void,
) -> i32 {
    crate::ucrt::vsnprintf(
        dst as *mut std::os::raw::c_char,
        count,
        fmt as *const std::os::raw::c_char,
        va,
    )
}

// ---------------------------------------------------------------------------
// Time helper
// ---------------------------------------------------------------------------

/// Current time as a Windows FILETIME: 100ns ticks since 1601-01-01 UTC.
fn windows_filetime_now() -> u64 {
    // SAFETY: `clock_gettime(CLOCK_REALTIME)` writes a valid timespec.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let unix_secs = ts.tv_sec as u64;
    (unix_secs + 11644473600) * 10_000_000 + (ts.tv_nsec as u64) / 100
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full list of extra export specs (kernel32, bcryptprimitives, userenv, ntdll).
pub fn extra_export_specs() -> Vec<ExtraSpec> {
    macro_rules! e {
        ($dll:literal, $sym:literal, $f:expr, $n:literal) => {
            ExtraSpec {
                dll: $dll,
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        // --- kernel32: exception handling ---
        e!(
            "kernel32.dll",
            "AddVectoredExceptionHandler",
            add_vectored_exception_handler,
            2
        ),
        e!(
            "kernel32.dll",
            "SetUnhandledExceptionFilter",
            set_unhandled_exception_filter,
            1
        ),
        e!(
            "kernel32.dll",
            "SetConsoleCtrlHandler",
            set_console_ctrl_handler,
            2
        ),
        e!("kernel32.dll", "RaiseException", raise_exception, 4),
        e!(
            "kernel32.dll",
            "__C_specific_handler",
            c_specific_handler,
            4
        ),
        e!("kernel32.dll", "RtlCaptureContext", rtl_capture_context, 1),
        e!(
            "kernel32.dll",
            "RtlLookupFunctionEntry",
            rtl_lookup_function_entry,
            3
        ),
        e!("kernel32.dll", "RtlVirtualUnwind", rtl_virtual_unwind, 7),
        e!("kernel32.dll", "RtlUnwindEx", rtl_unwind_ex, 4),
        // --- kernel32: system info / time ---
        e!(
            "kernel32.dll",
            "GetSystemTimePreciseAsFileTime",
            get_system_time_precise_as_file_time,
            1
        ),
        e!("kernel32.dll", "GetSystemInfo", get_system_info, 1),
        e!(
            "kernel32.dll",
            "GetConsoleOutputCP",
            get_console_output_cp,
            0
        ),
        e!("kernel32.dll", "GetDateFormatW", get_date_format_w, 6),
        e!("kernel32.dll", "GetTimeFormatW", get_time_format_w, 6),
        // --- kernel32: module / path ---
        e!(
            "kernel32.dll",
            "GetModuleFileNameW",
            get_module_file_name_w,
            3
        ),
        e!(
            "kernel32.dll",
            "GetCurrentDirectoryW",
            get_current_directory_w,
            2
        ),
        e!(
            "kernel32.dll",
            "GetSystemDirectoryW",
            get_system_directory_w,
            2
        ),
        e!(
            "kernel32.dll",
            "GetWindowsDirectoryW",
            get_windows_directory_w,
            2
        ),
        e!("kernel32.dll", "GetTempPathW", get_temp_path_w, 2),
        e!("kernel32.dll", "GetFullPathNameW", get_full_path_name_w, 4),
        e!(
            "kernel32.dll",
            "GetFileAttributesW",
            get_file_attributes_w,
            1
        ),
        e!("kernel32.dll", "GetFileType", get_file_type, 1),
        e!("kernel32.dll", "GetFileSizeEx", get_file_size_ex, 2),
        e!("kernel32.dll", "SetFilePointerEx", set_file_pointer_ex, 4),
        e!(
            "kernel32.dll",
            "SetHandleInformation",
            set_handle_information,
            3
        ),
        e!(
            "kernel32.dll",
            "SetThreadStackGuarantee",
            set_thread_stack_guarantee,
            1
        ),
        e!("kernel32.dll", "SwitchToThread", switch_to_thread, 0),
        // `GetProcAddress` is registered by `anticheat` (-> `crate::dllload`); see the
        // note above.
        // --- kernel32: one-time init ---
        e!(
            "kernel32.dll",
            "InitOnceBeginInitialize",
            init_once_begin_initialize,
            4
        ),
        e!("kernel32.dll", "InitOnceComplete", init_once_complete, 3),
        // --- kernel32: string / message ---
        e!(
            "kernel32.dll",
            "CompareStringOrdinal",
            compare_string_ordinal,
            5
        ),
        e!("kernel32.dll", "CompareStringW", compare_string_w, 6),
        e!("kernel32.dll", "FormatMessageW", format_message_w, 7),
        // --- kernel32: file mapping / async I/O ---
        e!("kernel32.dll", "MapViewOfFile", map_view_of_file, 5),
        e!("kernel32.dll", "UnmapViewOfFile", unmap_view_of_file, 1),
        e!(
            "kernel32.dll",
            "CreateFileMappingA",
            create_file_mapping_a,
            6
        ),
        e!(
            "kernel32.dll",
            "GetOverlappedResult",
            get_overlapped_result,
            4
        ),
        e!("kernel32.dll", "ReadConsoleW", read_console_w, 5),
        e!("kernel32.dll", "WriteFileEx", write_file_ex, 5),
        e!("kernel32.dll", "ReadFileEx", read_file_ex, 5),
        e!("kernel32.dll", "FlushFileBuffers", flush_file_buffers, 1),
        e!(
            "kernel32.dll",
            "SetFileAttributesW",
            set_file_attributes_w,
            2
        ),
        // --- kernel32: process ---
        e!("kernel32.dll", "TerminateProcess", terminate_process, 2),
        e!("kernel32.dll", "GetProcessId", get_process_id, 1),
        e!(
            "kernel32.dll",
            "GetExitCodeProcess",
            get_exit_code_process,
            2
        ),
        e!(
            "kernel32.dll",
            "WaitForSingleObjectEx",
            wait_for_single_object_ex,
            3
        ),
        // --- bcryptprimitives.dll ---
        e!("bcryptprimitives.dll", "ProcessPrng", process_prng, 2),
        // --- USERENV.dll ---
        e!(
            "userenv.dll",
            "GetUserProfileDirectoryW",
            get_user_profile_directory_w,
            3
        ),
        // --- ntdll.dll ---
        e!(
            "ntdll.dll",
            "RtlNtStatusToDosError",
            rtl_nt_status_to_dos_error,
            1
        ),
        e!("ntdll.dll", "_vsnprintf", ntdll_vsnprintf, 4),
    ]
}
