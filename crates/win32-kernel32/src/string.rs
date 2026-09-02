//! String / code-page conversion helpers: `MultiByteToWideChar`, `WideCharToMultiByte`,
//! and the `lstrlen`/`lstrcpy`/`lstrcat` family.
//!
//! We support the code pages a console PE realistically uses: UTF-8 (`CP_UTF8` = 65001)
//! and the current ANSI code page, which we treat as UTF-8 (Linux has no OEM/ANSI split).
//! Any other code page falls back to a byte-wise identity (one byte -> one U+0000_00xx
//! code unit) which is correct for the 7-bit ASCII subset and never panics for arbitrary
//! bytes; callers that request an unsupported code page still get a deterministic result.
//!
//! The Windows signatures are honored exactly so the PE loader's ABI thunk can call these
//! with the Windows x64 calling convention. Buffers and lengths are guest-supplied; we
//! validate them defensively (null/length checks) and return 0 on error, matching the
//! Windows contract that a zero return means "error" (the caller then reads `GetLastError`).

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;

use crate::Handle;

/// `CP_UTF8` (65001) — the only code page with bespoke conversion.
pub const CP_UTF8: u32 = 65001;
/// `CP_ACP` (0) — the "ANSI code page"; we map it to UTF-8.
pub const CP_ACP: u32 = 0;

/// `ERROR_INSUFFICIENT_BUFFER` (122) — written to the last-error slot when an output
/// buffer is too small.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// `ERROR_INVALID_PARAMETER` (87) — written for a null/zero combination we cannot honor.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// `kernel32!MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte,
/// lpWideCharStr, cchWideChar) -> int`.
///
/// Converts `cbMultiByte` bytes of a multibyte string at `lpMultiByteStr` into UTF-16
/// code units. If `lpWideCharStr` is null (or `cchWideChar` is 0), returns the required
/// number of UTF-16 code units without writing anything. Returns 0 on error.
///
/// `cbMultiByte == -1` means the input is NUL-terminated; the trailing NUL is converted to
/// a trailing `0x0000` code unit (matching Windows).
pub extern "C" fn multi_byte_to_wide_char(
    code_page: u32,
    _flags: u32,
    multi_byte_str: *const u8,
    cb_multi_byte: i32,
    wide_char_str: *mut u16,
    cch_wide_char: i32,
) -> i32 {
    // Resolve the input slice. cbMultiByte == -1 means NUL-terminated.
    let input: Vec<u8> = if cb_multi_byte == -1 {
        if multi_byte_str.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // SAFETY: the guest passed a NUL-terminated C string; `from_ptr` walks until the NUL.
        let cstr = unsafe { std::ffi::CStr::from_ptr(multi_byte_str as *const i8) };
        cstr.to_bytes().to_vec()
    } else if cb_multi_byte <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    } else {
        if multi_byte_str.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // SAFETY: the guest promises `cb_multi_byte` readable bytes at `multi_byte_str`.
        unsafe { std::slice::from_raw_parts(multi_byte_str, cb_multi_byte as usize) }.to_vec()
    };

    let units = if code_page == CP_UTF8 || code_page == CP_ACP {
        match String::from_utf8(input.clone()) {
            Ok(s) => s.encode_utf16().collect::<Vec<u16>>(),
            Err(_) => {
                // Fall back to a byte-wise identity so arbitrary bytes never panic. Each
                // byte becomes one UTF-16 code unit in the U+0000..U+00FF range.
                input.iter().map(|&b| b as u16).collect()
            }
        }
    } else {
        // Unsupported code page: byte-wise identity (deterministic, ASCII-correct).
        input.iter().map(|&b| b as u16).collect()
    };

    // cbMultiByte == -1 includes the trailing NUL as one extra UTF-16 code unit.
    let n = if cb_multi_byte == -1 {
        units.len() + 1
    } else {
        units.len()
    };

    // "Query length" mode: no output buffer requested.
    if wide_char_str.is_null() || cch_wide_char <= 0 {
        return n as i32;
    }

    if (n as i32) > cch_wide_char {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the guest supplies a writable buffer of `cch_wide_char` code units; we have
    // just checked `n <= cch_wide_char`, so the write stays in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), wide_char_str, units.len());
        if cb_multi_byte == -1 {
            std::ptr::write_unaligned(wide_char_str.add(units.len()), 0);
        }
    }
    n as i32
}

/// `kernel32!WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar,
/// lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar) -> int`.
///
/// Converts `cchWideChar` UTF-16 code units at `lpWideCharStr` into the multibyte
/// representation for `CodePage` (we always emit UTF-8). If `lpMultiByteStr` is null (or
/// `cbMultiByte` is 0), returns the required byte count without writing. `cchWideChar ==
/// -1` means NUL-terminated (a trailing `0x0000` is dropped from the output, matching
/// Windows). Returns 0 on error.
pub extern "C" fn wide_char_to_multi_byte(
    code_page: u32,
    _flags: u32,
    wide_char_str: *const u16,
    cch_wide_char: i32,
    multi_byte_str: *mut u8,
    cb_multi_byte: i32,
    _default_char: *const u8,
    _used_default_char: *mut i32,
) -> i32 {
    // Resolve the input slice.
    let units: Vec<u16> = if cch_wide_char == -1 {
        if wide_char_str.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // Walk until the first 0x0000 code unit (NUL-terminated UTF-16).
        let mut len = 0usize;
        // SAFETY: the guest passed a NUL-terminated UTF-16 string; we stop at the first 0.
        unsafe {
            while *wide_char_str.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(wide_char_str, len).to_vec()
        }
    } else if cch_wide_char <= 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    } else {
        if wide_char_str.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        // SAFETY: the guest promises `cch_wide_char` readable code units at `wide_char_str`.
        unsafe { std::slice::from_raw_parts(wide_char_str, cch_wide_char as usize) }.to_vec()
    };

    let utf8: Vec<u8> = if code_page == CP_UTF8 || code_page == CP_ACP {
        String::from_utf16_lossy(&units).into_bytes()
    } else {
        // Unsupported code page: byte-wise identity (lossy for non-Latin1 code units).
        units.iter().map(|&u| u as u8).collect()
    };

    // "Query length" mode: no output buffer requested.
    if multi_byte_str.is_null() || cb_multi_byte <= 0 {
        return utf8.len() as i32;
    }

    if (utf8.len() as i32) > cb_multi_byte {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the guest supplies a writable buffer of `cb_multi_byte` bytes; we have just
    // checked `utf8.len() <= cb_multi_byte`, so the write stays in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(utf8.as_ptr(), multi_byte_str, utf8.len());
    }
    utf8.len() as i32
}

/// `kernel32!lstrlenW(lpwcsz) -> int`. Length in code units excluding the terminating NUL.
pub extern "C" fn lstrlen_w(s: *const u16) -> i32 {
    if s.is_null() {
        return 0;
    }
    let mut len = 0usize;
    // SAFETY: the guest passed a NUL-terminated UTF-16 string; we stop at the first 0.
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len as i32
}

/// `kernel32!lstrlenA(lpcsz) -> int`. Length in bytes excluding the terminating NUL.
pub extern "C" fn lstrlen_a(s: *const u8) -> i32 {
    if s.is_null() {
        return 0;
    }
    // SAFETY: the guest passed a NUL-terminated byte string; `CStr::from_ptr` walks to NUL.
    let cstr = unsafe { std::ffi::CStr::from_ptr(s as *const i8) };
    cstr.to_bytes().len() as i32
}

/// `kernel32!lstrcpyW(dst, src) -> LPWSTR`. Copies a NUL-terminated UTF-16 string.
pub extern "C" fn lstrcpy_w(dst: *mut u16, src: *const u16) -> *mut u16 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let mut i = 0usize;
    // SAFETY: both pointers are non-null NUL-terminated UTF-16 buffers; we copy code unit
    // by code unit (including the terminator) until the source NUL is copied.
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

/// `kernel32!lstrcatW(dst, src) -> LPWSTR`. Appends `src` to the NUL-terminated `dst`.
pub extern "C" fn lstrcat_w(dst: *mut u16, src: *const u16) -> *mut u16 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    let mut d = 0usize;
    // SAFETY: `dst` is NUL-terminated; walk to its terminator.
    unsafe {
        while *dst.add(d) != 0 {
            d += 1;
        }
        let mut i = 0usize;
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
// Helpers shared with the other modules (env/file use these to bridge UTF-16 paths).
// ---------------------------------------------------------------------------

/// Convert a NUL-terminated UTF-16 buffer at `p` into a Rust `String`, dropping the NUL.
/// Returns an empty string for a null pointer (callers treat empty as "absent").
///
/// # Safety
///
/// `p` must be a NUL-terminated UTF-16 buffer (a terminating `0x0000` code unit), or null.
pub(crate) unsafe fn utf16_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL-termination; we stop at the first 0 code unit.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` code units are valid to read per the NUL-termination contract.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// Convert a NUL-terminated byte string at `p` into a Rust `String`, dropping the NUL.
/// Returns an empty string for a null pointer.
///
/// # Safety
///
/// `p` must be a NUL-terminated byte string (a `CStr`), or null.
pub(crate) unsafe fn bytes_to_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: caller guarantees NUL-termination; `CStr::from_ptr` walks to the NUL.
    let cstr = unsafe { std::ffi::CStr::from_ptr(p as *const i8) };
    String::from_utf8_lossy(cstr.to_bytes()).into_owned()
}

/// Set the thread/process last-error value via the ntapi helper. This crate delegates to
/// `nigg_ntapi::process::set_last_error`, which is the same store the rest of the loader
/// uses (and that `GetLastError` reads from).
fn set_last_error(code: u32) {
    nigg_ntapi::process::set_last_error(code);
}

/// Silence the unused-import warning for `Handle`/`c_void`; they are part of the module's
/// public surface for callers that pass handles through the string helpers.
#[allow(dead_code)]
fn _type_anchors() -> (Handle, *mut c_void) {
    (0, std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ascii_through_utf16() {
        let s = b"hello\0";
        let n = multi_byte_to_wide_char(
            CP_UTF8,
            0,
            s.as_ptr(),
            5, // exclude the NUL on purpose
            std::ptr::null_mut(),
            0,
        );
        assert_eq!(n, 5);
        let mut wide = vec![0u16; 5];
        let n = multi_byte_to_wide_char(
            CP_UTF8,
            0,
            s.as_ptr(),
            5,
            wide.as_mut_ptr(),
            wide.len() as i32,
        );
        assert_eq!(n, 5);
        assert_eq!(
            &wide,
            &['h' as u16, 'e' as u16, 'l' as u16, 'l' as u16, 'o' as u16]
        );

        let mut out = vec![0u8; 16];
        let m = wide_char_to_multi_byte(
            CP_UTF8,
            0,
            wide.as_ptr(),
            5,
            out.as_mut_ptr(),
            out.len() as i32,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        assert_eq!(m, 5);
        assert_eq!(&out[..5], b"hello");
    }

    #[test]
    fn round_trip_multibyte_utf8() {
        let s = "héllo, 世界";
        let bytes = s.as_bytes();
        let n = multi_byte_to_wide_char(
            CP_UTF8,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        let mut wide = vec![0u16; n as usize];
        multi_byte_to_wide_char(
            CP_UTF8,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            wide.len() as i32,
        );
        let back = String::from_utf16(&wide).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn query_length_without_buffer() {
        let s = b"abc\0";
        // NUL-terminated: returns 4 (abc + NUL).
        let n = multi_byte_to_wide_char(CP_UTF8, 0, s.as_ptr(), -1, std::ptr::null_mut(), 0);
        assert_eq!(n, 4);
    }

    #[test]
    fn lstrlen_walks_to_nul() {
        let wide: [u16; 4] = ['a' as u16, 'b' as u16, 'c' as u16, 0];
        assert_eq!(lstrlen_w(wide.as_ptr()), 3);
        let bytes = b"abc\0";
        assert_eq!(lstrlen_a(bytes.as_ptr()), 3);
    }

    #[test]
    fn lstrcpy_and_lstrcat() {
        let src: [u16; 4] = ['a' as u16, 'b' as u16, 'c' as u16, 0];
        let mut dst = [0u16; 8];
        lstrcpy_w(dst.as_mut_ptr(), src.as_ptr());
        assert_eq!(&dst[..4], &src[..4]);

        let app: [u16; 3] = ['X' as u16, 'Y' as u16, 0];
        lstrcat_w(dst.as_mut_ptr(), app.as_ptr());
        assert_eq!(
            &dst[..6],
            &['a' as u16, 'b' as u16, 'c' as u16, 'X' as u16, 'Y' as u16, 0]
        );
    }
}
