//! Additional kernel32/ntdll exports needed by real Windows PEs (cmd.exe, regedit.exe,
//! games, installers): file/directory operations, console screen-buffer helpers, time
//! conversions, process/handle stubs, and disk/volume queries.
//!
//! Most of these are best-effort stubs that return success (TRUE) without fully
//! implementing the Windows semantics — sufficient for import resolution so a PE's loader
//! and CRT init sequence can proceed. The file operations that have a direct POSIX
//! equivalent (`mkdir`/`unlink`/`rmdir`/`rename`/`link`/`symlink`/`chdir`/copy) convert the
//! UTF-16 path to a NUL-terminated UTF-8 `CString` and delegate to `libc`. Windows paths
//! (`C:\...`) do not map onto the Linux filesystem, so such calls fail and return FALSE —
//! which is acceptable: the goal here is import resolution, not a faithful FS model.
//!
//! The FILETIME <-> SYSTEMTIME conversions use Howard Hinnant's public-domain
//! "days_from_civil"/"civil_from_days" algorithms (pure arithmetic, no Wine code).
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment.

#![deny(unsafe_op_in_unsafe_fn)]
// The `extern "C"` functions here implement Windows APIs that take raw pointers. They are
// called from PE machine code via ABI trampolines, not from safe Rust callers.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::c_void;

use crate::{ExportSpec, FnPtr, Handle};

/// `TRUE` (1) — the BOOL success value returned by most kernel32 stubs.
const TRUE: i32 = 1;
/// `FALSE` (0) — the BOOL failure value.
const FALSE: i32 = 0;

/// `STATUS_SUCCESS` (0) — returned by `RtlGetVersion`.
const STATUS_SUCCESS: i32 = 0;

/// `VER_PLATFORM_WIN32_NT` (2) — the platform id reported by `RtlGetVersion`.
const VER_PLATFORM_WIN32_NT: u32 = 2;

/// Windows ticks per second: a FILETIME is in 100-nanosecond units.
const FILETIME_TICKS_PER_SEC: i64 = 10_000_000;
/// FILETIME epoch offset: 1601-01-01 -> 1970-01-01 in 100-ns ticks (11644473600 seconds).
/// Referenced by the unit tests (the lib build sees it as dead code without the attribute).
#[allow(dead_code)]
const EPOCH_OFFSET_TICKS: i64 = 11_644_473_600 * FILETIME_TICKS_PER_SEC;
/// FILETIME epoch offset in seconds (1601-01-01 -> 1970-01-01).
const EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

// ---------------------------------------------------------------------------
// Layout structs
// ---------------------------------------------------------------------------

/// `CONSOLE_SCREEN_BUFFER_INFO` (22 bytes on x64): two `COORD`s, a `WORD` attribute, a
/// `SMALL_RECT`, and a final `COORD`. All members are 16-bit so the struct is 11 x u16.
#[repr(C)]
struct ConsoleScreenBufferInfo {
    size_x: i16,
    size_y: i16,
    cursor_x: i16,
    cursor_y: i16,
    attributes: u16,
    win_left: i16,
    win_top: i16,
    win_right: i16,
    win_bottom: i16,
    max_x: i16,
    max_y: i16,
}

/// `WIN32_FILE_ATTRIBUTE_DATA` is 36 bytes on x64.
const WIN32_FILE_ATTRIBUTE_DATA_SIZE: usize = 36;
/// `BY_HANDLE_FILE_INFORMATION` is 52 bytes on x64.
const BY_HANDLE_FILE_INFORMATION_SIZE: usize = 52;

// ---------------------------------------------------------------------------
// Path / string helpers
// ---------------------------------------------------------------------------

/// Convert a NUL-terminated UTF-16 path at `p` into a NUL-terminated UTF-8 `CString`.
/// Returns `None` for a null pointer or a path containing an interior NUL code unit
/// (which cannot be represented as a C string for the libc call).
fn path_to_cstring(p: *const u16) -> Option<std::ffi::CString> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller provides a NUL-terminated UTF-16 buffer per the Windows contract.
    let s = unsafe { crate::string::utf16_to_string(p) };
    std::ffi::CString::new(s).ok()
}

/// Read a wide string at `s` with the Windows length convention: `len == -1` means
/// NUL-terminated, `len > 0` is an explicit code-unit count, `len <= 0` (other than -1)
/// is empty. Returns the owned code units (no terminator).
///
/// # Safety
///
/// `s` must be readable for `len` code units (or up to the NUL terminator when
/// `len == -1`), or null (caller must guard).
unsafe fn read_wide(s: *const u16, len: i32) -> Vec<u16> {
    if len == -1 {
        let mut n = 0usize;
        // SAFETY: caller guarantees NUL-termination; we stop at the first 0 code unit.
        while unsafe { *s.add(n) } != 0 {
            n += 1;
        }
        // SAFETY: `n` code units precede the terminator and are valid to read.
        unsafe { std::slice::from_raw_parts(s, n) }.to_vec()
    } else if len > 0 {
        // SAFETY: caller guarantees `len` readable code units at `s`.
        unsafe { std::slice::from_raw_parts(s, len as usize) }.to_vec()
    } else {
        Vec::new()
    }
}

/// Write `path` as UTF-16 into `buf[0..len]` with NUL termination. Returns the length in
/// code units excluding the NUL. If `buf` is null or `len` is 0, returns the required
/// length (excl. NUL) without writing.
fn write_path_w(buf: *mut u16, len: u32, path: &str) -> u32 {
    let units: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let needed = (units.len() - 1) as u32;
    if buf.is_null() || len == 0 {
        return needed;
    }
    let copy = units.len().min(len as usize);
    // SAFETY: `buf` is writable for `len` u16 code units per the Windows contract.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), buf, copy) };
    // SAFETY: NUL-terminate at the last copied position (in case the buffer was too small).
    unsafe { std::ptr::write_unaligned(buf.add(copy.saturating_sub(1)), 0) };
    (copy.saturating_sub(1)) as u32
}

// ---------------------------------------------------------------------------
// FILETIME <-> SYSTEMTIME arithmetic (Howard Hinnant, public domain)
// ---------------------------------------------------------------------------

/// Convert days-since-1970-01-01 (`z`) to `(year, month, day)` with 1-based month/day.
/// Algorithm by Howard Hinnant (public domain); pure arithmetic, no Wine code.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Convert `(year, month, day)` (1-based month/day) to days-since-1970-01-01. Algorithm by
/// Howard Hinnant (public domain); pure arithmetic, no Wine code.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Decompose a Unix epoch second count into `(days, seconds_of_day)` where
/// `seconds_of_day` is in `0..86400`. Uses Euclidean division so negative timestamps
/// (pre-1970) decompose correctly.
fn split_unix_secs(unix_secs: i64) -> (i64, i64) {
    (unix_secs.div_euclid(86400), unix_secs.rem_euclid(86400))
}

/// Day-of-week (0 = Sunday) for a days-since-1970 value. 1970-01-01 was a Thursday (4).
fn day_of_week(days: i64) -> u16 {
    (days + 4).rem_euclid(7) as u16
}

// ---------------------------------------------------------------------------
// File / directory operations
// ---------------------------------------------------------------------------

/// `kernel32!CreateDirectoryW(path, sa) -> BOOL`. Delegates to `libc::mkdir` (mode 0777).
pub extern "C" fn create_directory_w(path: *const u16, _sa: *mut c_void) -> i32 {
    let Some(cstr) = path_to_cstring(path) else {
        return FALSE;
    };
    // SAFETY: `cstr` is a NUL-terminated UTF-8 path; `mkdir` creates the directory.
    let rc = unsafe { libc::mkdir(cstr.as_ptr(), 0o777) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!DeleteFileW(path) -> BOOL`. Delegates to `libc::unlink`.
pub extern "C" fn delete_file_w(path: *const u16) -> i32 {
    let Some(cstr) = path_to_cstring(path) else {
        return FALSE;
    };
    // SAFETY: `cstr` is a NUL-terminated UTF-8 path; `unlink` removes the file.
    let rc = unsafe { libc::unlink(cstr.as_ptr()) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!RemoveDirectoryW(path) -> BOOL`. Delegates to `libc::rmdir`.
pub extern "C" fn remove_directory_w(path: *const u16) -> i32 {
    let Some(cstr) = path_to_cstring(path) else {
        return FALSE;
    };
    // SAFETY: `cstr` is a NUL-terminated UTF-8 path; `rmdir` removes the directory.
    let rc = unsafe { libc::rmdir(cstr.as_ptr()) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!CopyFileW(src, dst, fail_if_exists) -> BOOL`. Copies the file contents via
/// `libc::open`/`read`/`write`. If `fail_if_exists` is nonzero and `dst` already exists,
/// returns FALSE.
pub extern "C" fn copy_file_w(src: *const u16, dst: *const u16, fail_if_exists: i32) -> i32 {
    let Some(src_c) = path_to_cstring(src) else {
        return FALSE;
    };
    let Some(dst_c) = path_to_cstring(dst) else {
        return FALSE;
    };

    if fail_if_exists != 0 {
        // SAFETY: `dst_c` is NUL-terminated; `stat` writes into the uninitialized buffer.
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::stat(dst_c.as_ptr(), st.as_mut_ptr()) } == 0 {
            return FALSE; // destination exists
        }
    }

    // SAFETY: `src_c` is NUL-terminated; `open` returns a read-only fd or -1.
    let in_fd = unsafe { libc::open(src_c.as_ptr(), libc::O_RDONLY) };
    if in_fd < 0 {
        return FALSE;
    }
    // SAFETY: `dst_c` is NUL-terminated; `open` creates/truncates a writable fd or -1.
    let out_fd = unsafe {
        libc::open(
            dst_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o666,
        )
    };
    if out_fd < 0 {
        // SAFETY: `in_fd` is a valid open fd; `close` releases it.
        unsafe { libc::close(in_fd) };
        return FALSE;
    }

    let mut ok = TRUE;
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: `in_fd` is valid; `read` fills up to `buf.len()` bytes.
        let n = unsafe { libc::read(in_fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            ok = FALSE;
            break;
        }
        if n == 0 {
            break;
        }
        let mut written = 0usize;
        while written < n as usize {
            // SAFETY: `out_fd` is valid; `write` writes the remaining bytes.
            let w = unsafe {
                libc::write(
                    out_fd,
                    buf.as_ptr().add(written) as *const c_void,
                    n as usize - written,
                )
            };
            if w < 0 {
                ok = FALSE;
                break;
            }
            written += w as usize;
        }
        if ok == FALSE {
            break;
        }
    }
    // SAFETY: both fds are valid (or were); `close` releases them.
    unsafe {
        libc::close(in_fd);
        libc::close(out_fd);
    }
    ok
}

/// `kernel32!MoveFileW(src, dst) -> BOOL`. Delegates to `libc::rename`.
pub extern "C" fn move_file_w(src: *const u16, dst: *const u16) -> i32 {
    let Some(src_c) = path_to_cstring(src) else {
        return FALSE;
    };
    let Some(dst_c) = path_to_cstring(dst) else {
        return FALSE;
    };
    // SAFETY: both are NUL-terminated UTF-8 paths; `rename` atomically moves the file.
    let rc = unsafe { libc::rename(src_c.as_ptr(), dst_c.as_ptr()) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!MoveFileExW(src, dst, flags) -> BOOL`. Same as `MoveFileW` (flags ignored).
pub extern "C" fn move_file_ex_w(src: *const u16, dst: *const u16, _flags: u32) -> i32 {
    move_file_w(src, dst)
}

/// `kernel32!CreateHardLinkW(link, target, sa) -> BOOL`. Delegates to `libc::link`.
pub extern "C" fn create_hard_link_w(
    link: *const u16,
    target: *const u16,
    _sa: *mut c_void,
) -> i32 {
    let Some(link_c) = path_to_cstring(link) else {
        return FALSE;
    };
    let Some(target_c) = path_to_cstring(target) else {
        return FALSE;
    };
    // SAFETY: both are NUL-terminated UTF-8 paths; `link` creates a hard link.
    let rc = unsafe { libc::link(target_c.as_ptr(), link_c.as_ptr()) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!CreateSymbolicLinkW(link, target, flags) -> BOOLEAN`. Delegates to
/// `libc::symlink`. `flags` selects file/directory target (ignored on Linux).
pub extern "C" fn create_symbolic_link_w(link: *const u16, target: *const u16, _flags: u32) -> i32 {
    let Some(link_c) = path_to_cstring(link) else {
        return FALSE;
    };
    let Some(target_c) = path_to_cstring(target) else {
        return FALSE;
    };
    // SAFETY: both are NUL-terminated UTF-8 paths; `symlink` creates a symbolic link.
    let rc = unsafe { libc::symlink(target_c.as_ptr(), link_c.as_ptr()) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!SearchPathW(path, file, ext, buf, buf_len, found) -> DWORD`. Returns 0 (not
/// found) — we do not model the Windows search path.
pub extern "C" fn search_path_w(
    _path: *const u16,
    _file: *const u16,
    _ext: *const u16,
    _buf: *mut u16,
    _buf_len: u32,
    _found: *mut *mut u16,
) -> u32 {
    0
}

/// `kernel32!GetFileAttributesExW(path, info_level, info) -> BOOL`. Fills the
/// `WIN32_FILE_ATTRIBUTE_DATA` (36 bytes) with zeros and returns TRUE.
pub extern "C" fn get_file_attributes_ex_w(
    _path: *const u16,
    _info_level: u32,
    info: *mut c_void,
) -> i32 {
    if info.is_null() {
        return FALSE;
    }
    // SAFETY: `info` is a writable WIN32_FILE_ATTRIBUTE_DATA buffer (36 bytes).
    unsafe { std::ptr::write_bytes(info as *mut u8, 0, WIN32_FILE_ATTRIBUTE_DATA_SIZE) };
    TRUE
}

/// `kernel32!GetFileInformationByHandle(h, info) -> BOOL`. Fills the
/// `BY_HANDLE_FILE_INFORMATION` (52 bytes) with zeros and returns TRUE.
pub extern "C" fn get_file_information_by_handle(_h: Handle, info: *mut c_void) -> i32 {
    if info.is_null() {
        return FALSE;
    }
    // SAFETY: `info` is a writable BY_HANDLE_FILE_INFORMATION buffer (52 bytes).
    unsafe { std::ptr::write_bytes(info as *mut u8, 0, BY_HANDLE_FILE_INFORMATION_SIZE) };
    TRUE
}

/// `kernel32!GetShortPathNameW(path, buf, len) -> DWORD`. Copies the input path verbatim
/// (no 8.3 short-name resolution) and returns its length in code units (excl. NUL).
pub extern "C" fn get_short_path_name_w(path: *const u16, buf: *mut u16, len: u32) -> u32 {
    if path.is_null() {
        return 0;
    }
    // SAFETY: `path` is a NUL-terminated UTF-16 buffer per the Windows contract.
    let s = unsafe { crate::string::utf16_to_string(path) };
    write_path_w(buf, len, &s)
}

/// `kernel32!GetTempFileNameW(path, prefix, unique, buf) -> UINT`. Writes a fixed
/// `C:\tmp\nigg.tmp` into `buf` and returns 0 (per the requested stub behavior).
pub extern "C" fn get_temp_file_name_w(
    _path: *const u16,
    _prefix: *const u16,
    _unique: u32,
    buf: *mut u16,
) -> u32 {
    if buf.is_null() {
        return 0;
    }
    let units: Vec<u16> = "C:\\tmp\\nigg.tmp".encode_utf16().chain([0]).collect();
    // SAFETY: `buf` is writable for at least MAX_PATH (260) u16 per the Windows contract.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), buf, units.len()) };
    0
}

/// `kernel32!GetTempPathW(len, buf) -> DWORD`. Writes `C:\tmp\` as the temp directory.
///
/// NOTE: `extras::get_temp_path_w` also implements `GetTempPathW` (returning `C:\Temp\`)
/// and is wired before this module, so that implementation wins in the import table; this
/// entry is kept for completeness and is a no-op under the standard wiring order.
pub extern "C" fn get_temp_path_w(len: u32, buf: *mut u16) -> u32 {
    write_path_w(buf, len, "C:\\tmp\\")
}

/// `kernel32!SetCurrentDirectoryW(path) -> BOOL`. Delegates to `libc::chdir`.
pub extern "C" fn set_current_directory_w(path: *const u16) -> i32 {
    let Some(cstr) = path_to_cstring(path) else {
        return FALSE;
    };
    // SAFETY: `cstr` is a NUL-terminated UTF-8 path; `chdir` changes the working directory.
    let rc = unsafe { libc::chdir(cstr.as_ptr()) };
    if rc == 0 {
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!FindNextFileW(hFind, find_data) -> BOOL`. Returns FALSE (no more files) — we
/// do not implement file enumeration (`FindFirstFileW` returns INVALID_HANDLE_VALUE).
pub extern "C" fn find_next_file_w(_h_find: Handle, _find_data: *mut c_void) -> i32 {
    FALSE
}

// ---------------------------------------------------------------------------
// Console operations
// ---------------------------------------------------------------------------

/// `kernel32!GetConsoleCP() -> UINT`. Returns 437 (OEM US codepage).
pub extern "C" fn get_console_cp() -> u32 {
    437
}

/// `kernel32!GetConsoleOutputCP() -> UINT`. Returns 437 (OEM US codepage).
///
/// NOTE: `extras::get_console_output_cp` also implements `GetConsoleOutputCP` (returning
/// 65001/UTF-8) and is wired before this module, so that implementation wins in the import
/// table; this entry is kept for completeness under the standard wiring order.
pub extern "C" fn get_console_output_cp() -> u32 {
    437
}

/// `kernel32!GetOEMCP() -> UINT`. Returns 437 (OEM US codepage).
pub extern "C" fn get_oemcp() -> u32 {
    437
}

/// `kernel32!GetConsoleScreenBufferInfo(h, info) -> BOOL`. Fills a
/// `CONSOLE_SCREEN_BUFFER_INFO` with an 80x25 buffer and returns TRUE.
pub extern "C" fn get_console_screen_buffer_info(_h: Handle, info: *mut c_void) -> i32 {
    if info.is_null() {
        return FALSE;
    }
    let csbi = ConsoleScreenBufferInfo {
        size_x: 80,
        size_y: 25,
        cursor_x: 0,
        cursor_y: 0,
        attributes: 0x0007, // white-on-black
        win_left: 0,
        win_top: 0,
        win_right: 79,
        win_bottom: 24,
        max_x: 80,
        max_y: 25,
    };
    // SAFETY: `info` is a writable CONSOLE_SCREEN_BUFFER_INFO buffer (22 bytes).
    unsafe { std::ptr::write_unaligned(info as *mut ConsoleScreenBufferInfo, csbi) };
    TRUE
}

/// `kernel32!SetConsoleCursorPosition(h, pos) -> BOOL`. No-op; returns TRUE.
pub extern "C" fn set_console_cursor_position(_h: Handle, _pos: u32) -> i32 {
    TRUE
}

/// `kernel32!SetConsoleTextAttribute(h, attr) -> BOOL`. No-op; returns TRUE.
pub extern "C" fn set_console_text_attribute(_h: Handle, _attr: u16) -> i32 {
    TRUE
}

/// `kernel32!SetConsoleTitleW(title) -> BOOL`. No-op; returns TRUE.
pub extern "C" fn set_console_title_w(_title: *const u16) -> i32 {
    TRUE
}

/// `kernel32!FillConsoleOutputAttribute(h, attr, count, pos, written) -> BOOL`. Sets
/// `*written = 0` and returns TRUE (no console output buffer modeled).
pub extern "C" fn fill_console_output_attribute(
    _h: Handle,
    _attr: u16,
    _count: u32,
    _pos: u32,
    written: *mut u32,
) -> i32 {
    if !written.is_null() {
        // SAFETY: `written` is a guest out-pointer valid for one DWORD.
        unsafe { std::ptr::write_unaligned(written, 0) };
    }
    TRUE
}

/// `kernel32!FillConsoleOutputCharacterW(h, ch, count, pos, written) -> BOOL`. Sets
/// `*written = 0` and returns TRUE.
pub extern "C" fn fill_console_output_character_w(
    _h: Handle,
    _ch: u16,
    _count: u32,
    _pos: u32,
    written: *mut u32,
) -> i32 {
    if !written.is_null() {
        // SAFETY: `written` is a guest out-pointer valid for one DWORD.
        unsafe { std::ptr::write_unaligned(written, 0) };
    }
    TRUE
}

/// `kernel32!VerifyConsoleIoHandle(h) -> BOOL`. Returns TRUE (treat any handle as valid).
pub extern "C" fn verify_console_io_handle(_h: Handle) -> i32 {
    TRUE
}

// ---------------------------------------------------------------------------
// Time operations
// ---------------------------------------------------------------------------

/// `kernel32!GetSystemTime(lpSystemTime)`. Fills a `SYSTEMTIME` (8 x u16 = 16 bytes) with
/// the current UTC time.
pub extern "C" fn get_system_time(lp_system_time: *mut u16) {
    if lp_system_time.is_null() {
        return;
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime(CLOCK_REALTIME)` writes a valid timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let unix_secs = ts.tv_sec;
    let (days, rem) = split_unix_secs(unix_secs);
    let (y, m, d) = civil_from_days(days);
    let hour = (rem / 3600) as u16;
    let minute = ((rem % 3600) / 60) as u16;
    let second = (rem % 60) as u16;
    let millis = (ts.tv_nsec / 1_000_000) as u16;
    // SAFETY: `lp_system_time` is a writable SYSTEMTIME buffer (8 u16 fields).
    unsafe {
        *lp_system_time.add(0) = y as u16;
        *lp_system_time.add(1) = m as u16;
        *lp_system_time.add(2) = day_of_week(days);
        *lp_system_time.add(3) = d as u16;
        *lp_system_time.add(4) = hour;
        *lp_system_time.add(5) = minute;
        *lp_system_time.add(6) = second;
        *lp_system_time.add(7) = millis;
    }
}

/// `kernel32!FileTimeToLocalFileTime(ft, local_ft) -> BOOL`. Copies the 8-byte FILETIME
/// verbatim (we treat all times as UTC; no timezone offset applied).
pub extern "C" fn file_time_to_local_file_time(ft: *const u8, local_ft: *mut u8) -> i32 {
    if ft.is_null() || local_ft.is_null() {
        return FALSE;
    }
    // SAFETY: `ft` is an 8-byte FILETIME; `local_ft` is a writable 8-byte FILETIME.
    unsafe {
        let v = std::ptr::read_unaligned(ft as *const u64);
        std::ptr::write_unaligned(local_ft as *mut u64, v);
    }
    TRUE
}

/// `kernel32!FileTimeToSystemTime(ft, st) -> BOOL`. Converts a FILETIME (100-ns ticks
/// since 1601-01-01 UTC) into a `SYSTEMTIME`.
pub extern "C" fn file_time_to_system_time(ft: *const u8, st: *mut u16) -> i32 {
    if ft.is_null() || st.is_null() {
        return FALSE;
    }
    // SAFETY: `ft` is an 8-byte FILETIME buffer (little-endian u64 on x64).
    let ticks = unsafe { std::ptr::read_unaligned(ft as *const u64) } as i64;
    let secs_since_1601 = ticks / FILETIME_TICKS_PER_SEC;
    let sub_ticks = ticks % FILETIME_TICKS_PER_SEC; // sub-second 100-ns count
    let unix_secs = secs_since_1601 - EPOCH_OFFSET_SECS;
    let (days, rem) = split_unix_secs(unix_secs);
    let (y, m, d) = civil_from_days(days);
    let hour = (rem / 3600) as u16;
    let minute = ((rem % 3600) / 60) as u16;
    let second = (rem % 60) as u16;
    let millis = (sub_ticks / 10_000) as u16;
    // SAFETY: `st` is a writable SYSTEMTIME buffer (8 u16 fields).
    unsafe {
        *st.add(0) = y as u16;
        *st.add(1) = m as u16;
        *st.add(2) = day_of_week(days);
        *st.add(3) = d as u16;
        *st.add(4) = hour;
        *st.add(5) = minute;
        *st.add(6) = second;
        *st.add(7) = millis;
    }
    TRUE
}

/// `kernel32!SystemTimeToFileTime(st, ft) -> BOOL`. Converts a `SYSTEMTIME` into a
/// FILETIME (100-ns ticks since 1601-01-01 UTC).
pub extern "C" fn system_time_to_file_time(st: *const u16, ft: *mut u8) -> i32 {
    if st.is_null() || ft.is_null() {
        return FALSE;
    }
    // SAFETY: `st` is a readable SYSTEMTIME buffer (8 u16 fields).
    let (y, m, _dow, d, hour, minute, second, millis) = unsafe {
        (
            *st.add(0) as i64,
            *st.add(1) as u32,
            *st.add(2),
            *st.add(3) as u32,
            *st.add(4) as i64,
            *st.add(5) as i64,
            *st.add(6) as i64,
            *st.add(7) as i64,
        )
    };
    let days = days_from_civil(y, m, d);
    let secs_since_1601 = days * 86400 + hour * 3600 + minute * 60 + second + EPOCH_OFFSET_SECS;
    let ticks = secs_since_1601 * FILETIME_TICKS_PER_SEC + millis * 10_000;
    // SAFETY: `ft` is a writable 8-byte FILETIME buffer.
    unsafe { std::ptr::write_unaligned(ft as *mut u64, ticks as u64) };
    TRUE
}

/// `kernel32!SetFileTime(h, create, access, write) -> BOOL`. No-op; returns TRUE.
pub extern "C" fn set_file_time(
    _h: Handle,
    _create: *const u8,
    _access: *const u8,
    _write: *const u8,
) -> i32 {
    TRUE
}

/// `kernel32!GetLocaleInfoW(locale, lctype, buf, len) -> int`. Returns 0 (no locale info
/// produced); the output buffer is left untouched.
pub extern "C" fn get_locale_info_w(_locale: u32, _lctype: u32, _buf: *mut u16, _len: i32) -> i32 {
    0
}

// ---------------------------------------------------------------------------
// Process operations
// ---------------------------------------------------------------------------

/// `kernel32!CreateProcessW(app, cmd, sa, ts, inherit, flags, env, dir, startup,
/// proc_info) -> BOOL`. Returns FALSE — we cannot spawn a Windows process.
pub extern "C" fn create_process_w(
    _app: *const u16,
    _cmd: *mut u16,
    _sa: *mut c_void,
    _ts: *mut c_void,
    _inherit: i32,
    _flags: u32,
    _env: *mut c_void,
    _dir: *const u16,
    _startup: *mut c_void,
    _proc_info: *mut c_void,
) -> i32 {
    FALSE
}

/// `kernel32!DuplicateHandle(src_proc, src_h, dst_proc, dst_h, access, inherit, options)
/// -> BOOL`. Copies the source handle value into `*dst_h` and returns TRUE.
pub extern "C" fn duplicate_handle(
    _src_proc: Handle,
    src_h: Handle,
    _dst_proc: Handle,
    dst_h: *mut Handle,
    _access: u32,
    _inherit: i32,
    _options: u32,
) -> i32 {
    if !dst_h.is_null() {
        // SAFETY: `dst_h` is a guest out-pointer valid for one HANDLE.
        unsafe { std::ptr::write_unaligned(dst_h, src_h) };
    }
    TRUE
}

/// `kernel32!LocalAlloc(flags, size) -> LPVOID`. Backed by `libc::malloc`. The flags
/// (`LMEM_FIXED`/`LMEM_ZEROINIT`) are honored for the zero-init case (0x0040).
pub extern "C" fn local_alloc(flags: u32, size: usize) -> *mut c_void {
    const LMEM_ZEROINIT: u32 = 0x0040;
    // Allocate at least 1 byte so a zero-size request still yields a non-null handle.
    let n = size.max(1);
    // SAFETY: `malloc(n)` returns a valid pointer to `n` bytes or NULL.
    let p = unsafe { libc::malloc(n) };
    if p.is_null() {
        return std::ptr::null_mut();
    }
    if flags & LMEM_ZEROINIT != 0 {
        // SAFETY: `p` is valid for `n` bytes; zero the payload.
        unsafe { std::ptr::write_bytes(p as *mut u8, 0, n) };
    }
    p
}

/// `kernel32!SetStdHandle(std, handle) -> BOOL`. No-op; returns TRUE.
pub extern "C" fn set_std_handle(_std: u32, _handle: Handle) -> i32 {
    TRUE
}

/// `kernel32!IsBadStringPtrW(ptr, max) -> BOOL`. Returns FALSE (we trust guest pointers).
pub extern "C" fn is_bad_string_ptr_w(_ptr: *const u16, _max: usize) -> i32 {
    FALSE
}

// ---------------------------------------------------------------------------
// Disk / volume operations
// ---------------------------------------------------------------------------

/// `kernel32!GetDiskFreeSpaceExW(path, free, total_free, total) -> BOOL`. Reports ~1 GiB
/// free and ~1 GiB total (a nonzero, plausible placeholder) and returns TRUE.
pub extern "C" fn get_disk_free_space_ex_w(
    _path: *const u16,
    free: *mut u64,
    total_free: *mut u64,
    total: *mut u64,
) -> i32 {
    const ONE_GB: u64 = 1024 * 1024 * 1024;
    // SAFETY: each out-pointer is a guest buffer valid for one u64, or null.
    unsafe {
        if !free.is_null() {
            std::ptr::write_unaligned(free, ONE_GB);
        }
        if !total_free.is_null() {
            std::ptr::write_unaligned(total_free, ONE_GB);
        }
        if !total.is_null() {
            std::ptr::write_unaligned(total, ONE_GB);
        }
    }
    TRUE
}

/// `kernel32!GetVolumeInformationW(root, name, name_size, serial, max_len, flags, fs,
/// fs_size) -> BOOL`. Zeros the integer out-parameters and returns TRUE.
pub extern "C" fn get_volume_information_w(
    _root: *const u16,
    _name: *mut u16,
    _name_size: u32,
    serial: *mut u32,
    max_len: *mut u32,
    flags: *mut u32,
    _fs: *mut u16,
    _fs_size: u32,
) -> i32 {
    // SAFETY: each out-pointer is a guest buffer valid for one u32, or null.
    unsafe {
        if !serial.is_null() {
            std::ptr::write_unaligned(serial, 0);
        }
        if !max_len.is_null() {
            std::ptr::write_unaligned(max_len, 0);
        }
        if !flags.is_null() {
            std::ptr::write_unaligned(flags, 0);
        }
    }
    TRUE
}

/// `kernel32!SetVolumeLabelW(root, label) -> BOOL`. No-op; returns TRUE.
pub extern "C" fn set_volume_label_w(_root: *const u16, _label: *const u16) -> i32 {
    TRUE
}

// ---------------------------------------------------------------------------
// String / locale
// ---------------------------------------------------------------------------

/// `kernel32!CompareStringW(locale, flags, s1, l1, s2, l2) -> int`. Returns 2 (CSTR_EQUAL)
/// if the strings are equal, 1 (CSTR_LESS_THAN) if `s1 < s2`, 3 (CSTR_GREATER_THAN) if
/// `s1 > s2`. Locale and flags are ignored (simple code-unit comparison).
pub extern "C" fn compare_string_w(
    _locale: u32,
    _flags: u32,
    s1: *const u16,
    l1: i32,
    s2: *const u16,
    l2: i32,
) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 2;
    }
    // SAFETY: both pointers are non-null; lengths follow the Windows convention.
    let v1 = unsafe { read_wide(s1, l1) };
    let v2 = unsafe { read_wide(s2, l2) };
    use std::cmp::Ordering;
    match v1.cmp(&v2) {
        Ordering::Less => 1,
        Ordering::Equal => 2,
        Ordering::Greater => 3,
    }
}

// ---------------------------------------------------------------------------
// ntdll.dll
// ---------------------------------------------------------------------------

/// `ntdll!RtlGetVersion(version_info) -> NTSTATUS`. Fills an `OSVERSIONINFOEXW` with
/// Windows 10 (build 19041) values and returns `STATUS_SUCCESS` (0). Respects the
/// caller-supplied `dwOSVersionInfoSize` so both `OSVERSIONINFOW` (276) and
/// `OSVERSIONINFOEXW` (284) buffers are handled safely.
pub extern "C" fn rtl_get_version(version_info: *mut c_void) -> i32 {
    if version_info.is_null() {
        return STATUS_SUCCESS;
    }
    let base = version_info as *mut u8;
    // SAFETY: `base` points to an OSVERSIONINFO(EX)W buffer; offset 0 holds the size.
    let size = unsafe { std::ptr::read_unaligned(base as *const u32) };

    // Field offsets (both OSVERSIONINFOW and OSVERSIONINFOEXW share this prefix):
    //   0:  dwOSVersionInfoSize (u32)   4: dwMajorVersion (u32)
    //   8:  dwMinorVersion (u32)       12: dwBuildNumber  (u32)
    //  16:  dwPlatformId (u32)         20: szCSDVersion[128] (256 bytes)
    // The EX fields follow at offset 276.
    // SAFETY: the version fields (offsets 4..20) are always present; we write within the
    // caller-declared buffer.
    unsafe {
        std::ptr::write_unaligned(base.add(4) as *mut u32, 10); // major
        std::ptr::write_unaligned(base.add(8) as *mut u32, 0); // minor
        std::ptr::write_unaligned(base.add(12) as *mut u32, 19041); // build
        std::ptr::write_unaligned(base.add(16) as *mut u32, VER_PLATFORM_WIN32_NT);
        if size >= 276 {
            // Zero szCSDVersion (256 bytes at offset 20).
            std::ptr::write_bytes(base.add(20), 0, 256);
        }
        if size >= 284 {
            // Zero the EX fields (8 bytes at offset 276: sp major/minor, suite mask,
            // product type, reserved).
            std::ptr::write_bytes(base.add(276), 0, 8);
        }
        if size == 0 {
            // Echo the EX size back if the caller left it uninitialized.
            std::ptr::write_unaligned(base as *mut u32, 284);
        }
    }
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full list of extra kernel32/ntdll exports implemented in this module, with the
/// metadata the PE loader needs to build ABI thunks. Dedup in the loader's `import_specs`
/// keeps the first-registered implementation for any symbol also defined elsewhere (e.g.
/// `GetConsoleOutputCP`/`GetTempPathW` in `extras`).
pub fn extras2_exports() -> Vec<ExportSpec> {
    macro_rules! k {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "kernel32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }
    macro_rules! n {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "ntdll.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        // --- file / directory ---
        k!("CreateDirectoryW", create_directory_w, 2),
        k!("DeleteFileW", delete_file_w, 1),
        k!("RemoveDirectoryW", remove_directory_w, 1),
        k!("CopyFileW", copy_file_w, 3),
        k!("MoveFileW", move_file_w, 2),
        k!("MoveFileExW", move_file_ex_w, 3),
        k!("CreateHardLinkW", create_hard_link_w, 3),
        k!("CreateSymbolicLinkW", create_symbolic_link_w, 3),
        k!("SearchPathW", search_path_w, 6),
        k!("GetFileAttributesExW", get_file_attributes_ex_w, 3),
        k!(
            "GetFileInformationByHandle",
            get_file_information_by_handle,
            2
        ),
        k!("GetShortPathNameW", get_short_path_name_w, 3),
        k!("GetTempFileNameW", get_temp_file_name_w, 4),
        k!("GetTempPathW", get_temp_path_w, 2),
        k!("SetCurrentDirectoryW", set_current_directory_w, 1),
        k!("FindNextFileW", find_next_file_w, 2),
        // --- console ---
        k!("GetConsoleCP", get_console_cp, 0),
        k!("GetConsoleOutputCP", get_console_output_cp, 0),
        k!("GetOEMCP", get_oemcp, 0),
        k!(
            "GetConsoleScreenBufferInfo",
            get_console_screen_buffer_info,
            2
        ),
        k!("SetConsoleCursorPosition", set_console_cursor_position, 2),
        k!("SetConsoleTextAttribute", set_console_text_attribute, 2),
        k!("SetConsoleTitleW", set_console_title_w, 1),
        k!(
            "FillConsoleOutputAttribute",
            fill_console_output_attribute,
            5
        ),
        k!(
            "FillConsoleOutputCharacterW",
            fill_console_output_character_w,
            5
        ),
        k!("VerifyConsoleIoHandle", verify_console_io_handle, 1),
        // --- time ---
        k!("GetSystemTime", get_system_time, 1),
        k!("FileTimeToLocalFileTime", file_time_to_local_file_time, 2),
        k!("FileTimeToSystemTime", file_time_to_system_time, 2),
        k!("SystemTimeToFileTime", system_time_to_file_time, 2),
        k!("SetFileTime", set_file_time, 4),
        k!("GetLocaleInfoW", get_locale_info_w, 4),
        // --- process ---
        k!("CreateProcessW", create_process_w, 10),
        k!("DuplicateHandle", duplicate_handle, 7),
        k!("LocalAlloc", local_alloc, 2),
        k!("SetStdHandle", set_std_handle, 2),
        k!("IsBadStringPtrW", is_bad_string_ptr_w, 2),
        // --- disk / volume ---
        k!("GetDiskFreeSpaceExW", get_disk_free_space_ex_w, 4),
        k!("GetVolumeInformationW", get_volume_information_w, 8),
        k!("SetVolumeLabelW", set_volume_label_w, 2),
        // --- string / locale ---
        k!("CompareStringW", compare_string_w, 6),
        // --- ntdll ---
        n!("RtlGetVersion", rtl_get_version, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a Rust string as a NUL-terminated UTF-16 buffer (test helper).
    fn wstr(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn exports_registered_with_correct_dll_and_counts() {
        let specs = extras2_exports();
        // All kernel32 entries report the right DLL; the single ntdll entry too.
        assert!(specs
            .iter()
            .filter(|s| s.sym != "RtlGetVersion")
            .all(|s| s.dll == "kernel32.dll"));
        assert_eq!(
            specs.iter().find(|s| s.sym == "RtlGetVersion").unwrap().dll,
            "ntdll.dll"
        );
        // Spot-check a few argument counts (the thunk sizes the trampoline from these).
        let n = |sym: &str| {
            specs
                .iter()
                .find(|s| s.sym == sym)
                .unwrap_or_else(|| panic!("missing {sym}"))
                .n_args
        };
        assert_eq!(n("CreateDirectoryW"), 2);
        assert_eq!(n("CopyFileW"), 3);
        assert_eq!(n("CreateProcessW"), 10);
        assert_eq!(n("GetVolumeInformationW"), 8);
        assert_eq!(n("CompareStringW"), 6);
        assert_eq!(n("RtlGetVersion"), 1);
        assert_eq!(n("GetConsoleCP"), 0);
        // None of these are noreturn.
        assert!(specs.iter().all(|s| !s.noreturn));
    }

    #[test]
    fn oem_and_console_codepages_are_437() {
        assert_eq!(get_console_cp(), 437);
        assert_eq!(get_oemcp(), 437);
        assert_eq!(get_console_output_cp(), 437);
    }

    #[test]
    fn console_screen_buffer_info_is_80x25() {
        let mut info = ConsoleScreenBufferInfo {
            size_x: 0,
            size_y: 0,
            cursor_x: 0,
            cursor_y: 0,
            attributes: 0,
            win_left: 0,
            win_top: 0,
            win_right: 0,
            win_bottom: 0,
            max_x: 0,
            max_y: 0,
        };
        let rc = get_console_screen_buffer_info(1, &mut info as *mut _ as *mut c_void);
        assert_eq!(rc, TRUE);
        assert_eq!(info.size_x, 80);
        assert_eq!(info.size_y, 25);
        assert_eq!(info.win_right, 79);
        assert_eq!(info.win_bottom, 24);
        assert_eq!(info.max_x, 80);
        assert_eq!(info.max_y, 25);
    }

    #[test]
    fn stubs_return_true() {
        assert_eq!(set_console_cursor_position(1, 0), TRUE);
        assert_eq!(set_console_text_attribute(1, 7), TRUE);
        assert_eq!(set_console_title_w(std::ptr::null()), TRUE);
        assert_eq!(verify_console_io_handle(1), TRUE);
        assert_eq!(
            set_file_time(1, std::ptr::null(), std::ptr::null(), std::ptr::null()),
            TRUE
        );
        assert_eq!(set_std_handle(0, 0), TRUE);
        assert_eq!(set_volume_label_w(std::ptr::null(), std::ptr::null()), TRUE);
        assert_eq!(is_bad_string_ptr_w(std::ptr::null(), 0), FALSE);
        assert_eq!(find_next_file_w(0, std::ptr::null_mut()), FALSE);
        assert_eq!(
            search_path_w(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut()
            ),
            0
        );
        assert_eq!(get_locale_info_w(0, 0, std::ptr::null_mut(), 0), 0);
    }

    #[test]
    fn fill_console_output_zeroes_written_count() {
        let mut written: u32 = 0xFFFF_FFFF;
        let rc = fill_console_output_attribute(1, 7, 10, 0, &mut written);
        assert_eq!(rc, TRUE);
        assert_eq!(written, 0);
        let mut written2: u32 = 0xFFFF_FFFF;
        let rc = fill_console_output_character_w(1, b' ' as u16, 10, 0, &mut written2);
        assert_eq!(rc, TRUE);
        assert_eq!(written2, 0);
    }

    #[test]
    fn get_file_attribute_and_handle_info_zero_fill() {
        let mut buf = [0xAAu8; 64];
        let rc = get_file_attributes_ex_w(std::ptr::null(), 0, buf.as_mut_ptr() as *mut c_void);
        assert_eq!(rc, TRUE);
        assert!(buf[..WIN32_FILE_ATTRIBUTE_DATA_SIZE]
            .iter()
            .all(|&b| b == 0));

        let mut buf2 = [0xAAu8; 64];
        let rc = get_file_information_by_handle(1, buf2.as_mut_ptr() as *mut c_void);
        assert_eq!(rc, TRUE);
        assert!(buf2[..BY_HANDLE_FILE_INFORMATION_SIZE]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn disk_free_space_reports_one_gb() {
        let mut free: u64 = 0;
        let mut total_free: u64 = 0;
        let mut total: u64 = 0;
        let rc = get_disk_free_space_ex_w(std::ptr::null(), &mut free, &mut total_free, &mut total);
        assert_eq!(rc, TRUE);
        assert_eq!(free, 1024 * 1024 * 1024);
        assert_eq!(total_free, 1024 * 1024 * 1024);
        assert_eq!(total, 1024 * 1024 * 1024);
    }

    #[test]
    fn volume_information_zeroes_out_params() {
        let mut serial: u32 = 0xFFFF_FFFF;
        let mut max_len: u32 = 0xFFFF_FFFF;
        let mut flags: u32 = 0xFFFF_FFFF;
        let rc = get_volume_information_w(
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            &mut max_len,
            &mut flags,
            std::ptr::null_mut(),
            0,
        );
        assert_eq!(rc, TRUE);
        assert_eq!(serial, 0);
        assert_eq!(max_len, 0);
        assert_eq!(flags, 0);
    }

    #[test]
    fn duplicate_handle_copies_value() {
        let mut dst: Handle = 0;
        let rc = duplicate_handle(0, 0x1234_5678, 0, &mut dst, 0, 0, 0);
        assert_eq!(rc, TRUE);
        assert_eq!(dst, 0x1234_5678);
    }

    #[test]
    fn local_alloc_returns_writable_pointer() {
        let p = local_alloc(0, 32);
        assert!(!p.is_null());
        // SAFETY: `p` was just allocated for 32 bytes.
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xAB, 32) };
        // SAFETY: read it back to confirm.
        let buf = unsafe { std::slice::from_raw_parts(p as *const u8, 32) };
        assert!(buf.iter().all(|&b| b == 0xAB));
        // SAFETY: free the allocation.
        unsafe { libc::free(p) };
    }

    #[test]
    fn local_alloc_zero_init() {
        let p = local_alloc(0x0040, 16);
        assert!(!p.is_null());
        // SAFETY: `p` was allocated for 16 bytes with LMEM_ZEROINIT.
        let buf = unsafe { std::slice::from_raw_parts(p as *const u8, 16) };
        assert!(buf.iter().all(|&b| b == 0));
        // SAFETY: free the allocation.
        unsafe { libc::free(p) };
    }

    #[test]
    fn compare_string_w_orderings() {
        let a = wstr("apple");
        let b = wstr("banana");
        let a2 = wstr("apple");
        assert_eq!(
            compare_string_w(0, 0, a.as_ptr(), -1, b.as_ptr(), -1),
            1,
            "apple < banana"
        );
        assert_eq!(
            compare_string_w(0, 0, b.as_ptr(), -1, a.as_ptr(), -1),
            3,
            "banana > apple"
        );
        assert_eq!(
            compare_string_w(0, 0, a.as_ptr(), -1, a2.as_ptr(), -1),
            2,
            "equal"
        );
        // Explicit lengths too.
        assert_eq!(compare_string_w(0, 0, a.as_ptr(), 3, b.as_ptr(), 3), 1);
    }

    #[test]
    fn temp_file_name_writes_fixed_path() {
        let mut buf = [0u16; 260];
        let rc = get_temp_file_name_w(std::ptr::null(), std::ptr::null(), 0, buf.as_mut_ptr());
        assert_eq!(rc, 0);
        let s: String = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect();
        assert_eq!(s, "C:\\tmp\\nigg.tmp");
    }

    #[test]
    fn short_path_name_echoes_input() {
        let path = wstr("C:\\some\\path\\file.txt");
        let mut buf = [0u16; 260];
        let n = get_short_path_name_w(path.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
        assert_eq!(n as usize, "C:\\some\\path\\file.txt".len());
        let s: String = buf
            .iter()
            .take(n as usize)
            .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
            .collect();
        assert_eq!(s, "C:\\some\\path\\file.txt");
    }

    #[test]
    fn file_time_to_system_time_known_value() {
        // 1970-01-01 00:00:00 UTC as FILETIME = EPOCH_OFFSET_TICKS (116444736000000000).
        let ft: u64 = EPOCH_OFFSET_TICKS as u64;
        let mut st = [0u16; 8];
        let rc = file_time_to_system_time(ft.to_le_bytes().as_ptr(), st.as_mut_ptr());
        assert_eq!(rc, TRUE);
        assert_eq!(st[0], 1970, "year");
        assert_eq!(st[1], 1, "month");
        assert_eq!(st[3], 1, "day");
        assert_eq!(st[4], 0, "hour");
        assert_eq!(st[5], 0, "minute");
        assert_eq!(st[6], 0, "second");
        // 1970-01-01 was a Thursday -> dayOfWeek 4 (0=Sunday).
        assert_eq!(st[2], 4, "day of week");
    }

    #[test]
    fn system_time_to_file_time_round_trip() {
        // Start from a SYSTEMTIME, convert to FILETIME, then back.
        let st: [u16; 8] = [2021, 6, 0, 15, 12, 30, 45, 123]; // 2021-06-15 12:30:45.123
        let mut ft_bytes = [0u8; 8];
        let rc = system_time_to_file_time(st.as_ptr(), ft_bytes.as_mut_ptr());
        assert_eq!(rc, TRUE);
        // Confirm a nonzero FILETIME was produced (the conversion is exercised below).
        assert_ne!(u64::from_le_bytes(ft_bytes), 0);
        let mut st2 = [0u16; 8];
        let rc = file_time_to_system_time(ft_bytes.as_ptr(), st2.as_mut_ptr());
        assert_eq!(rc, TRUE);
        assert_eq!(st2[0], 2021);
        assert_eq!(st2[1], 6);
        assert_eq!(st2[3], 15);
        assert_eq!(st2[4], 12);
        assert_eq!(st2[5], 30);
        assert_eq!(st2[6], 45);
        assert_eq!(st2[7], 123);
    }

    #[test]
    fn file_time_to_local_file_time_copies_value() {
        let ft: u64 = 0x0123_4567_89AB_CDEF;
        let mut local_bytes = [0u8; 8];
        let rc = file_time_to_local_file_time(ft.to_le_bytes().as_ptr(), local_bytes.as_mut_ptr());
        assert_eq!(rc, TRUE);
        assert_eq!(u64::from_le_bytes(local_bytes), ft);
    }

    #[test]
    fn get_system_time_fills_plausible_fields() {
        let mut st = [0u16; 8];
        get_system_time(st.as_mut_ptr());
        // Year must be a plausible recent Gregorian year (allow some slack for clock skew).
        assert!(
            st[0] >= 2020 && st[0] <= 2100,
            "year {} out of range",
            st[0]
        );
        assert!(st[1] >= 1 && st[1] <= 12, "month {} out of range", st[1]);
        assert!(st[3] >= 1 && st[3] <= 31, "day {} out of range", st[3]);
        assert!(st[4] <= 23, "hour {} out of range", st[4]);
        assert!(st[5] <= 59, "minute {} out of range", st[5]);
        assert!(st[6] <= 60, "second {} out of range", st[6]);
        assert!(st[7] <= 999, "millis {} out of range", st[7]);
    }

    #[test]
    fn rtl_get_version_reports_windows_10_19041() {
        // OSVERSIONINFOEXW buffer (284 bytes), caller pre-sets the size.
        let mut info = [0u8; 284];
        // SAFETY: write the size field at offset 0.
        unsafe { std::ptr::write_unaligned(info.as_mut_ptr() as *mut u32, 284) };
        let rc = rtl_get_version(info.as_mut_ptr() as *mut c_void);
        assert_eq!(rc, STATUS_SUCCESS);
        // SAFETY: read back the version fields.
        let major = unsafe { std::ptr::read_unaligned(info.as_ptr().add(4) as *const u32) };
        let minor = unsafe { std::ptr::read_unaligned(info.as_ptr().add(8) as *const u32) };
        let build = unsafe { std::ptr::read_unaligned(info.as_ptr().add(12) as *const u32) };
        let platform = unsafe { std::ptr::read_unaligned(info.as_ptr().add(16) as *const u32) };
        assert_eq!(major, 10);
        assert_eq!(minor, 0);
        assert_eq!(build, 19041);
        assert_eq!(platform, VER_PLATFORM_WIN32_NT);
        // szCSDVersion must be zeroed (offset 20, 256 bytes).
        assert!(info[20..276].iter().all(|&b| b == 0));
        // EX fields (offset 276, 8 bytes) must be zeroed.
        assert!(info[276..284].iter().all(|&b| b == 0));
    }

    #[test]
    fn rtl_get_version_handles_smaller_osversioninfo_size() {
        // An OSVERSIONINFOW-sized buffer (276 bytes): EX fields must not be touched.
        let mut info = vec![0xFFu8; 276];
        // SAFETY: write the size field at offset 0.
        unsafe { std::ptr::write_unaligned(info.as_mut_ptr() as *mut u32, 276) };
        let rc = rtl_get_version(info.as_mut_ptr() as *mut c_void);
        assert_eq!(rc, STATUS_SUCCESS);
        // SAFETY: read back the build field.
        let build = unsafe { std::ptr::read_unaligned(info.as_ptr().add(12) as *const u32) };
        assert_eq!(build, 19041);
        // szCSDVersion zeroed.
        assert!(info[20..276].iter().all(|&b| b == 0));
    }
}
