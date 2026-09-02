//! File layer: `CreateFileW`/`CreateFileA`, `ReadFile`/`WriteFile`/`CloseHandle` (delegate
//! to ntapi), `GetFileSize`, `SetFilePointer`, `FlushFileBuffers`.
//!
//! `CreateFile{W,A}` converts the path to a host byte string and opens it with `libc::open`,
//! wrapping the resulting fd in an ntapi handle (`Object::File`). The remaining operations
//! resolve that handle back to the fd via ntapi and issue the matching POSIX call.
//!
//! The Windows access-mode / disposition / share / flags values are mapped to Linux
//! `open(2)` flags by best effort. We implement the common subset (read/write/read-write,
//! create-or-open, truncate, append); exotic flags (security descriptors, overlapped-only
//! devices) are accepted but ignored, which is enough for console-PE file use.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;

use crate::Handle;

/// `GENERIC_READ` access right (Windows bit).
const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE` access right (Windows bit).
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `FILE_SHARE_READ` (Windows share bit).
const FILE_SHARE_READ: u32 = 0x0000_0001;
/// `FILE_SHARE_WRITE` (Windows share bit).
const FILE_SHARE_WRITE: u32 = 0x0000_0002;

/// `CREATE_ALWAYS` disposition (Windows).
const CREATE_ALWAYS: u32 = 2;
/// `CREATE_NEW` disposition (Windows) — fail if the file exists.
const CREATE_NEW: u32 = 1;
/// `OPEN_EXISTING` disposition (Windows).
const OPEN_EXISTING: u32 = 3;
/// `OPEN_ALWAYS` disposition (Windows) — open or create.
const OPEN_ALWAYS: u32 = 4;
/// `TRUNCATE_EXISTING` disposition (Windows).
const TRUNCATE_EXISTING: u32 = 5;

/// `FILE_ATTRIBUTE_NORMAL` (Windows) — accepted but ignored.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `FILE_FLAG_WRITE_THROUGH` / `FILE_FLAG_OVERLAPPED`-style bits we ignore but accept.
const FILE_FLAG_IGNORED: u32 = 0xFFFF_FFFF;

/// `ERROR_OPEN_FAILED` (110) — used when `open(2)` returns -1.
const ERROR_OPEN_FAILED: u32 = 110;
/// `ERROR_INVALID_PARAMETER` (87).
const ERROR_INVALID_PARAMETER: u32 = 87;

/// `INVALID_HANDLE_VALUE` — returned by `CreateFile*` on failure.
const INVALID_HANDLE_VALUE: Handle = u64::MAX;

/// `FILE_BEGIN` whence value for `SetFilePointer`.
const FILE_BEGIN: u32 = 0;
/// `FILE_CURRENT` whence value for `SetFilePointer`.
const FILE_CURRENT: u32 = 1;
/// `FILE_END` whence value for `SetFilePointer`.
const FILE_END: u32 = 2;

/// `kernel32!CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
/// dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) -> HANDLE`.
///
/// Converts the UTF-16 path to a host byte string and opens it via `libc::open`, returning
/// an ntapi handle wrapping the fd. Returns `INVALID_HANDLE_VALUE` on failure.
pub extern "C" fn create_file_w(
    file_name: *const u16,
    desired_access: u32,
    share_mode: u32,
    _security_attrs: *mut c_void,
    creation_disposition: u32,
    flags_and_attrs: u32,
    _template: Handle,
) -> Handle {
    // SAFETY: `file_name` is a NUL-terminated UTF-16 path (or null, handled internally).
    let path = unsafe { crate::string::utf16_to_string(file_name) };
    open_path(
        &path,
        desired_access,
        share_mode,
        creation_disposition,
        flags_and_attrs,
    )
}

/// `kernel32!CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
/// dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) -> HANDLE`.
///
/// Like [`create_file_w`] but takes an ANSI (NUL-terminated byte) path.
pub extern "C" fn create_file_a(
    file_name: *const u8,
    desired_access: u32,
    share_mode: u32,
    _security_attrs: *mut c_void,
    creation_disposition: u32,
    flags_and_attrs: u32,
    _template: Handle,
) -> Handle {
    // SAFETY: `file_name` is a NUL-terminated byte string (or null).
    let path = unsafe { crate::string::bytes_to_string(file_name) };
    open_path(
        &path,
        desired_access,
        share_mode,
        creation_disposition,
        flags_and_attrs,
    )
}

/// Shared body of `CreateFileW`/`CreateFileA`: map the Windows flags to Linux `open(2)`
/// flags and open the path via the ntapi fd-opening helper.
fn open_path(
    path: &str,
    desired_access: u32,
    share_mode: u32,
    creation_disposition: u32,
    flags_and_attrs: u32,
) -> Handle {
    if path.is_empty() {
        nigg_ntapi::process::set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    // Convert the path to a host byte string. CString would fail on interior NULs.
    let cpath = match std::ffi::CString::new(path) {
        Ok(c) => c,
        Err(_) => {
            nigg_ntapi::process::set_last_error(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    };

    let mut flags: i32 = 0;
    let want_read = desired_access & GENERIC_READ != 0;
    let want_write = desired_access & GENERIC_WRITE != 0;
    match (want_read, want_write) {
        (true, true) => flags |= libc::O_RDWR,
        (true, false) => flags |= libc::O_RDONLY,
        (false, true) => flags |= libc::O_WRONLY,
        (false, false) => flags |= libc::O_RDONLY, // probe-style open (rare)
    }

    // Creation disposition -> Linux create/trunc flags.
    match creation_disposition {
        CREATE_NEW => flags |= libc::O_CREAT | libc::O_EXCL,
        CREATE_ALWAYS => flags |= libc::O_CREAT | libc::O_TRUNC,
        OPEN_EXISTING => {}
        OPEN_ALWAYS => flags |= libc::O_CREAT,
        TRUNCATE_EXISTING => flags |= libc::O_TRUNC,
        _ => {
            nigg_ntapi::process::set_last_error(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Accept (but ignore) the attribute/share bits we don't model; honor read/write share
    // minimally by not blocking the open (Linux does not have mandatory locking).
    let _ = share_mode & (FILE_SHARE_READ | FILE_SHARE_WRITE);
    let _ = flags_and_attrs & (FILE_ATTRIBUTE_NORMAL | FILE_FLAG_IGNORED);

    let mode: u32 = 0o644;
    let h = nigg_ntapi::process::open_file_handle(&cpath, flags, mode);
    if h == INVALID_HANDLE_VALUE {
        nigg_ntapi::process::set_last_error(ERROR_OPEN_FAILED);
        return INVALID_HANDLE_VALUE;
    }
    h
}

/// `kernel32!ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
/// lpOverlapped) -> BOOL`. Delegates to ntapi, which resolves the handle to an fd.
pub extern "C" fn read_file(
    handle: Handle,
    buf: *mut u8,
    len: u32,
    read_out: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    nigg_ntapi::process::read_file(handle, buf, len, read_out, overlapped)
}

/// `kernel32!WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten,
/// lpOverlapped) -> BOOL`. Delegates to ntapi.
pub extern "C" fn write_file(
    handle: Handle,
    buf: *const u8,
    len: u32,
    written: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    nigg_ntapi::process::write_file(handle, buf, len, written, overlapped)
}

/// `kernel32!CloseHandle(hObject) -> BOOL`. Delegates to ntapi's `NtClose`/`CloseHandle`.
pub extern "C" fn close_handle(handle: Handle) -> i32 {
    nigg_ntapi::process::close_handle(handle)
}

/// Resolve a Windows file/console handle to its backing Linux fd, mirroring the logic in
/// ntapi (`resolve_fd`): stdio fds (0/1/2) pass through; file handles look up the fd in the
/// ntapi handle table. Returns -1 on failure.
fn resolve_fd(handle: Handle) -> i32 {
    if handle <= 2 {
        return handle as i32;
    }
    nigg_ntapi::handle::with_object(handle, |o| match o {
        nigg_ntapi::handle::Object::File(f) => Some(f.fd),
        _ => None,
    })
    .flatten()
    .unwrap_or(-1)
}

/// `kernel32!GetFileSize(hFile, lpFileSizeHigh) -> DWORD`. Returns the low 32 bits of the
/// file size and writes the high 32 bits to `lpFileSizeHigh` if non-null. Returns
/// `INVALID_FILE_SIZE` (0xFFFF_FFFF) on error.
pub extern "C" fn get_file_size(handle: Handle, size_high: *mut u32) -> u32 {
    let fd = resolve_fd(handle);
    if fd < 0 {
        nigg_ntapi::process::set_last_error(6); // ERROR_INVALID_HANDLE
        return u32::MAX; // INVALID_FILE_SIZE
    }
    // SAFETY: `fstat` reads metadata for the open `fd` into `st`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid open file descriptor; `fstat` writes a valid `stat`.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        nigg_ntapi::process::set_last_error(6);
        return u32::MAX;
    }
    let size = st.st_size as u64;
    if !size_high.is_null() {
        // SAFETY: `size_high` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(size_high, (size >> 32) as u32) };
    }
    size as u32
}

/// `kernel32!SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh,
/// dwMoveMethod) -> DWORD`. Sets the file pointer and returns the low 32 bits of the new
/// position. Returns `INVALID_SET_FILE_POINTER` (0xFFFF_FFFF) on error.
pub extern "C" fn set_file_pointer(
    handle: Handle,
    distance: i32,
    distance_high: *mut i32,
    move_method: u32,
) -> u32 {
    let fd = resolve_fd(handle);
    if fd < 0 {
        nigg_ntapi::process::set_last_error(6);
        return u32::MAX;
    }
    // Combine the 32-bit low/high distance into a signed 64-bit offset when the caller
    // supplies the high word; otherwise sign-extend the low word alone.
    let offset: i64 = if distance_high.is_null() {
        distance as i64
    } else {
        // SAFETY: `distance_high` is a guest in/out-pointer valid for one i32.
        let hi = unsafe { std::ptr::read_unaligned(distance_high) } as i64;
        let combined = ((hi as u64) << 32) | (distance as u32 as u64);
        combined as i64
    };
    let whence: i32 = match move_method {
        FILE_BEGIN => libc::SEEK_SET,
        FILE_CURRENT => libc::SEEK_CUR,
        FILE_END => libc::SEEK_END,
        _ => {
            nigg_ntapi::process::set_last_error(87); // ERROR_INVALID_PARAMETER
            return u32::MAX;
        }
    };
    // SAFETY: `fd` is a valid open descriptor; `lseek` is a pure syscall, no memory read.
    let pos = unsafe { libc::lseek(fd, offset, whence) };
    if pos < 0 {
        nigg_ntapi::process::set_last_error(6);
        return u32::MAX;
    }
    if !distance_high.is_null() {
        // SAFETY: `distance_high` is a guest out-pointer valid for one i32.
        unsafe { std::ptr::write_unaligned(distance_high, (pos >> 32) as i32) };
    }
    pos as u32
}

/// `kernel32!FlushFileBuffers(hFile) -> BOOL`. Flushes the kernel page cache for the file
/// backing `handle`. Returns TRUE on success, FALSE on error.
pub extern "C" fn flush_file_buffers(handle: Handle) -> i32 {
    let fd = resolve_fd(handle);
    if fd < 0 {
        nigg_ntapi::process::set_last_error(6);
        return 0;
    }
    // SAFETY: `fd` is a valid open descriptor; `fsync` is a pure syscall.
    let rc = unsafe { libc::fsync(fd) };
    if rc != 0 {
        nigg_ntapi::process::set_last_error(6);
        return 0;
    }
    1
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
    fn create_write_read_close_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nigg_file_test.txt");
        // Use the host-native path (forward slashes); our CreateFileW passes the UTF-8
        // string straight to libc::open, which on Linux treats `/` as the separator.
        let wpath = make_wide(path.to_str().unwrap());

        // CREATE_ALWAYS + GENERIC_WRITE: create/truncate for writing.
        let h = create_file_w(
            wpath.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        assert_ne!(
            h, INVALID_HANDLE_VALUE,
            "CreateFileW(GENERIC_WRITE, CREATE_ALWAYS) succeeded"
        );

        let payload = b"hello-kernel32-file";
        let mut written: u32 = 0;
        let r = write_file(
            h,
            payload.as_ptr(),
            payload.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        );
        assert_eq!(r, 1);
        assert_eq!(written as usize, payload.len());
        assert_eq!(flush_file_buffers(h), 1);
        assert_eq!(close_handle(h), 1);

        // Reopen READ and confirm the size and contents.
        let h = create_file_w(
            wpath.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        assert_ne!(h, INVALID_HANDLE_VALUE);
        assert_eq!(get_file_size(h, std::ptr::null_mut()), payload.len() as u32);

        let mut buf = vec![0u8; payload.len()];
        let mut read: u32 = 0;
        let r = read_file(
            h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        );
        assert_eq!(r, 1);
        assert_eq!(read as usize, payload.len());
        assert_eq!(&buf, payload);

        // Seek to offset 6 ("kernel32-file") and read 7 bytes -> "kernel3".
        assert_eq!(set_file_pointer(h, 6, std::ptr::null_mut(), FILE_BEGIN), 6);
        let mut tail = [0u8; 7];
        let mut got: u32 = 0;
        read_file(h, tail.as_mut_ptr(), 7, &mut got, std::ptr::null_mut());
        assert_eq!(got, 7);
        assert_eq!(&tail, b"kernel3");
        assert_eq!(close_handle(h), 1);
    }

    #[test]
    fn create_a_path_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nigg_ansi.txt");
        let bytes = {
            let mut v = path.to_str().unwrap().as_bytes().to_vec();
            v.push(0);
            v
        };
        let h = create_file_a(
            bytes.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        assert_ne!(h, INVALID_HANDLE_VALUE);
        let payload: &[u8] = b"x";
        let mut written: u32 = 0;
        assert_eq!(
            write_file(h, payload.as_ptr(), 1, &mut written, std::ptr::null_mut()),
            1
        );
        close_handle(h);
        let meta = std::fs::metadata(&path).expect("file was created");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 1);
    }
}
