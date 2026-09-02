//! shlwapi.dll reimplementation for the PE loader.
//!
//! Implements the path and string utility exports from `shlwapi.dll` that real Windows PEs
//! link against: `PathFindFileNameW`/`PathFindExtensionW`/`PathRemoveFileSpecW`/
//! `PathAppendW`/`PathCombineW`/`PathIsRelativeW`, and the `StrCmp*`/`StrStr*` string
//! helpers. The path functions operate on NUL-terminated UTF-16LE buffers (Windows wide
//! strings); the `StrCmpIC` twin uses NUL-terminated byte strings.
//!
//! These are real implementations (not no-ops) of the documented semantics — enough for a
//! PE that walks its own command line, parses file paths, or does string comparisons to
//! behave correctly.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment. The exports take raw pointers (called from PE machine code via ABI
//! trampolines), so `clippy::not_unsafe_ptr_arg_deref` is allowed.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::{ExportSpec, FnPtr};

/// Maximum path length, matching the Windows `MAX_PATH` constant (in UTF-16 code units).
const MAX_PATH: usize = 260;

// ---------------------------------------------------------------------------
// Small ASCII / UTF-16 helpers
// ---------------------------------------------------------------------------

/// ASCII lowercase of a byte (A-Z -> a-z, everything else unchanged).
fn to_lower8(c: u8) -> u8 {
    if c.is_ascii_uppercase() {
        c + 32
    } else {
        c
    }
}

/// ASCII lowercase of a UTF-16 code unit (A-Z -> a-z, everything else unchanged).
fn to_lower16(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// TRUE if `c` is an ASCII alphabetic code unit (A-Z, a-z).
fn is_ascii_alpha16(c: u16) -> bool {
    (b'A' as u16..=b'Z' as u16).contains(&c) || (b'a' as u16..=b'z' as u16).contains(&c)
}

/// Length in code units of the NUL-terminated UTF-16 string at `p` (0 if null).
fn wlen(p: *const u16) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0usize;
    // SAFETY: caller passes a NUL-terminated UTF-16 buffer; we stop at the first 0.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// Compare two NUL-terminated UTF-16 strings, optionally case-insensitively, optionally
/// limited to `n` code units. Returns the difference of the first differing (lowercased)
/// code unit, or 0 if equal (the NUL terminators are compared so shorter sorts first).
fn cmp_wide(s1: *const u16, s2: *const u16, n: Option<usize>, ignore_case: bool) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    let mut i = 0usize;
    loop {
        if let Some(max) = n {
            if i >= max {
                return 0;
            }
        }
        // SAFETY: both buffers are NUL-terminated; `i` is the current position and we read
        // exactly one code unit from each. The NUL terminator is included so the loop
        // terminates before running past the valid region.
        let (c1, c2) = unsafe { (*s1.add(i), *s2.add(i)) };
        let a = if ignore_case { to_lower16(c1) } else { c1 };
        let b = if ignore_case { to_lower16(c2) } else { c2 };
        if a != b {
            return (a as i32) - (b as i32);
        }
        // a == b and c1 == 0 => b == 0 => c2 == 0 (to_lower never maps a non-zero unit to
        // zero), so both strings ended together.
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Compare two NUL-terminated byte strings, optionally case-insensitively, optionally
/// limited to `n` bytes. Same contract as [`cmp_wide`].
fn cmp_cstr(s1: *const u8, s2: *const u8, n: Option<usize>, ignore_case: bool) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    let mut i = 0usize;
    loop {
        if let Some(max) = n {
            if i >= max {
                return 0;
            }
        }
        // SAFETY: both buffers are NUL-terminated; `i` is the current position and we read
        // exactly one byte from each, including the NUL so the loop terminates in bounds.
        let (c1, c2) = unsafe { (*s1.add(i), *s2.add(i)) };
        let a = if ignore_case { to_lower8(c1) } else { c1 };
        let b = if ignore_case { to_lower8(c2) } else { c2 };
        if a != b {
            return (a as i32) - (b as i32);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Copy the NUL-terminated UTF-16 string at `src` into the `cap`-code-unit buffer at `dest`,
/// truncating and NUL-terminating. Writes a single NUL if `src` is null.
fn copy_wide(dest: *mut u16, src: *const u16, cap: usize) {
    if dest.is_null() {
        return;
    }
    if src.is_null() {
        // SAFETY: `dest` is non-null and writable for at least one u16.
        unsafe { *dest = 0 };
        return;
    }
    let n = wlen(src).min(cap.saturating_sub(1));
    // SAFETY: `n` <= cap-1, so `dest[0..n]` and the NUL at `dest[n]` are in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(src, dest, n);
        *dest.add(n) = 0;
    }
}

// ---------------------------------------------------------------------------
// Path functions
// ---------------------------------------------------------------------------

/// `shlwapi!PathFindFileNameW(path) -> LPWSTR`. Returns a pointer to the character after
/// the last `\` or `/`, or to the start of the string if there is no separator.
pub extern "C" fn path_find_file_name_w(path: *const u16) -> *const u16 {
    if path.is_null() {
        return path;
    }
    let len = wlen(path);
    let mut i = len;
    while i > 0 {
        i -= 1;
        // SAFETY: `i` is in 0..len, so `path.add(i)` reads a valid (pre-NUL) code unit.
        let c = unsafe { *path.add(i) };
        if c == b'\\' as u16 || c == b'/' as u16 {
            // SAFETY: `i + 1` is in 0..=len; if `i` was the last char this points at the NUL.
            return unsafe { path.add(i + 1) };
        }
    }
    path
}

/// `shlwapi!PathFindFileNameA(path) -> LPSTR`. ASCII twin of [`path_find_file_name_w`].
pub extern "C" fn path_find_file_name_a(path: *const u8) -> *const u8 {
    if path.is_null() {
        return path;
    }
    // SAFETY: `path` is a NUL-terminated byte string; `CStr::from_ptr` walks to the NUL.
    let bytes = unsafe { std::ffi::CStr::from_ptr(path as *const i8) };
    let s = bytes.to_bytes();
    let mut i = s.len();
    while i > 0 {
        i -= 1;
        let c = s[i];
        if c == b'\\' || c == b'/' {
            // SAFETY: `i + 1` is in 0..=s.len(); the NUL is at `s.len()`.
            return unsafe { path.add(i + 1) };
        }
    }
    path
}

/// `shlwapi!PathFindExtensionW(path) -> LPWSTR`. Returns a pointer to the last `.` that
/// starts an extension (after the final path separator), or to the NUL terminator if there
/// is no extension.
pub extern "C" fn path_find_extension_w(path: *const u16) -> *const u16 {
    if path.is_null() {
        return path;
    }
    let len = wlen(path);
    let mut last_dot: Option<usize> = None;
    let mut last_sep: Option<usize> = None;
    for i in 0..len {
        // SAFETY: `i` is in 0..len, so `path.add(i)` reads a valid pre-NUL code unit.
        let c = unsafe { *path.add(i) };
        if c == b'.' as u16 {
            last_dot = Some(i);
        }
        if c == b'\\' as u16 || c == b'/' as u16 {
            last_sep = Some(i);
        }
    }
    match last_dot {
        Some(dot) => {
            // If the last separator is after the last dot, the dot belongs to a directory
            // component — no file extension.
            if last_sep.is_some_and(|sep| sep > dot) {
                // SAFETY: `len` is the NUL index; `path.add(len)` is a valid pointer.
                unsafe { path.add(len) }
            } else {
                // SAFETY: `dot` is in 0..len, so `path.add(dot)` is a valid pointer.
                unsafe { path.add(dot) }
            }
        }
        None => {
            // No dot at all: extension is the empty string at the NUL terminator.
            // SAFETY: `len` is the NUL index.
            unsafe { path.add(len) }
        }
    }
}

/// `shlwapi!PathRemoveFileSpecW(path) -> BOOL`. Truncates `path` at the last path separator
/// (removing the trailing filename) and returns TRUE; returns FALSE if there is no
/// separator (the path is left unchanged).
pub extern "C" fn path_remove_file_spec_w(path: *mut u16) -> i32 {
    if path.is_null() {
        return 0;
    }
    let len = wlen(path);
    let mut i = len;
    while i > 0 {
        i -= 1;
        // SAFETY: `i` is in 0..len; reading the pre-NUL code unit is valid.
        let c = unsafe { *path.add(i) };
        if c == b'\\' as u16 || c == b'/' as u16 {
            // SAFETY: `i` is in 0..len; writing the NUL at `i` truncates the path.
            unsafe {
                *path.add(i) = 0;
            }
            return 1;
        }
    }
    0
}

/// `shlwapi!PathAppendW(path, more) -> BOOL`. Appends `more` to `path`, ensuring exactly
/// one `\` separator between them: leading separators are stripped from `more` when `path`
/// already ends with one, and a `\` is inserted when neither side contributes one. The
/// `path` buffer must be at least `MAX_PATH` code units. Returns TRUE.
pub extern "C" fn path_append_w(path: *mut u16, more: *const u16) -> i32 {
    if path.is_null() || more.is_null() {
        return 1;
    }
    let plen = wlen(path);
    let mlen = wlen(more);
    if mlen == 0 {
        return 1;
    }
    let cap = MAX_PATH - 1; // reserve one slot for the NUL terminator
                            // TRUE if `path` is non-empty and already ends with a path separator.
    let end_sep = plen > 0 && {
        // SAFETY: `plen > 0`, so index `plen - 1` is a valid pre-NUL read.
        let last = unsafe { *path.add(plen - 1) };
        last == b'\\' as u16 || last == b'/' as u16
    };
    // When appending to a non-empty path, strip leading separators from `more` so we never
    // produce a doubled `\\`; an empty `path` keeps `more` verbatim (it is the whole path).
    let strip_leading = plen > 0;
    let mut skip = 0usize;
    if strip_leading {
        // SAFETY: `skip < mlen` guards each read; `more` is NUL-terminated at index `mlen`.
        while skip < mlen {
            let c = unsafe { *more.add(skip) };
            if c == b'\\' as u16 || c == b'/' as u16 {
                skip += 1;
            } else {
                break;
            }
        }
    }
    // `more` reduced to all separators -> nothing meaningful to append; leave `path` as-is.
    if skip == mlen {
        return 1;
    }
    // Insert a separator iff `path` is non-empty and does not already end with one (we have
    // already stripped leading separators from `more`, so there is no doubling risk).
    let add_sep = plen > 0 && !end_sep;
    let mut pos = plen;
    // SAFETY: `path` is a writable MAX_PATH (260) u16 buffer. Content writes are bounded to
    // `pos < cap` (= 259); the final NUL is written at `pos <= cap < MAX_PATH`. Reads from
    // `more` use indices in `skip..mlen`, validated by `wlen` as the pre-NUL region.
    unsafe {
        if add_sep && pos < cap {
            *path.add(pos) = b'\\' as u16;
            pos += 1;
        }
        for j in skip..mlen {
            if pos >= cap {
                break;
            }
            *path.add(pos) = *more.add(j);
            pos += 1;
        }
        *path.add(pos) = 0;
    }
    1
}

/// `shlwapi!PathCombineW(dest, dir, file) -> LPWSTR`. Combines `dir` and `file` into `dest`.
/// If `file` is absolute (starts with `X:` or `\\`) it replaces `dir`; otherwise `dir` is
/// copied to `dest` and `file` is appended with [`path_append_w`]. Returns `dest`.
pub extern "C" fn path_combine_w(dest: *mut u16, dir: *const u16, file: *const u16) -> *mut u16 {
    if dest.is_null() {
        return dest;
    }
    // If `file` is absolute (drive "X:" or UNC "\\"), it replaces the directory entirely.
    let file_abs = if !file.is_null() {
        // SAFETY: the first code unit is always a valid read (NUL-terminated buffer).
        let f0 = unsafe { *file.add(0) };
        if f0 == 0 {
            false
        } else {
            // SAFETY: `f0 != 0` means the NUL is at index >= 1, so index 1 is a valid read.
            let f1 = unsafe { *file.add(1) };
            f1 == b':' as u16 || (f0 == b'\\' as u16 && f1 == b'\\' as u16)
        }
    } else {
        false
    };
    if file_abs {
        copy_wide(dest, file, MAX_PATH);
    } else {
        copy_wide(dest, dir, MAX_PATH);
        if !file.is_null() {
            path_append_w(dest, file);
        }
    }
    dest
}

/// `shlwapi!PathIsRelativeW(path) -> BOOL`. Returns TRUE if `path` is relative (does not
/// start with a drive `X:` or a UNC `\\` prefix), FALSE if it is absolute.
pub extern "C" fn path_is_relative_w(path: *const u16) -> i32 {
    if path.is_null() {
        return 1;
    }
    // SAFETY: the first code unit is always a valid read (NUL-terminated buffer).
    let c0 = unsafe { *path.add(0) };
    if c0 == 0 {
        return 1; // empty string -> relative
    }
    // SAFETY: `c0 != 0` means the NUL is at index >= 1, so index 1 is a valid read.
    let c1 = unsafe { *path.add(1) };
    if c1 == b':' as u16 && is_ascii_alpha16(c0) {
        return 0; // "X:..." -> absolute
    }
    if c0 == b'\\' as u16 && c1 == b'\\' as u16 {
        return 0; // "\\..." UNC -> absolute
    }
    1 // relative
}

// ---------------------------------------------------------------------------
// String comparison
// ---------------------------------------------------------------------------

/// `shlwapi!StrCmpIW(s1, s2) -> int`. Case-insensitive UTF-16 comparison.
pub extern "C" fn str_cmp_i_w(s1: *const u16, s2: *const u16) -> i32 {
    cmp_wide(s1, s2, None, true)
}

/// `shlwapi!StrCmpW(s1, s2) -> int`. Case-sensitive UTF-16 comparison.
pub extern "C" fn str_cmp_w(s1: *const u16, s2: *const u16) -> i32 {
    cmp_wide(s1, s2, None, false)
}

/// `shlwapi!StrCmpNIW(s1, s2, n) -> int`. Case-insensitive UTF-16 comparison of `n` units.
pub extern "C" fn str_cmp_ni_w(s1: *const u16, s2: *const u16, n: i32) -> i32 {
    if n <= 0 {
        return 0;
    }
    cmp_wide(s1, s2, Some(n as usize), true)
}

/// `shlwapi!StrCmpNW(s1, s2, n) -> int`. Case-sensitive UTF-16 comparison of `n` units.
pub extern "C" fn str_cmp_n_w(s1: *const u16, s2: *const u16, n: i32) -> i32 {
    if n <= 0 {
        return 0;
    }
    cmp_wide(s1, s2, Some(n as usize), false)
}

/// `shlwapi!StrCmpIC(s1, s2) -> int`. Case-insensitive ASCII (byte) comparison.
pub extern "C" fn str_cmp_i_c(s1: *const u8, s2: *const u8) -> i32 {
    cmp_cstr(s1, s2, None, true)
}

// ---------------------------------------------------------------------------
// Substring search
// ---------------------------------------------------------------------------

/// Find the first occurrence of `needle` in `hay`, case-insensitively if `ignore_case`,
/// optionally limiting the haystack to its first `max_hay` code units. Returns a pointer
/// into `hay` or null.
fn str_str_w_impl(
    hay: *const u16,
    needle: *const u16,
    max_hay: Option<usize>,
    ignore_case: bool,
) -> *const u16 {
    if hay.is_null() || needle.is_null() {
        return std::ptr::null();
    }
    let nlen = wlen(needle);
    if nlen == 0 {
        return hay; // empty needle matches at the start (Windows behavior)
    }
    let hlen_full = wlen(hay);
    let hlen = max_hay.map_or(hlen_full, |m| hlen_full.min(m));
    if nlen > hlen {
        return std::ptr::null();
    }
    let last_start = hlen - nlen;
    for i in 0..=last_start {
        let mut ok = true;
        for j in 0..nlen {
            // SAFETY: `i` in 0..=last_start and `j` in 0..nlen, so `i + j` in 0..hlen (within
            // the pre-NUL region) and `j` in 0..nlen (within needle's pre-NUL region).
            let (a, b) = unsafe { (*hay.add(i + j), *needle.add(j)) };
            let (la, lb) = if ignore_case {
                (to_lower16(a), to_lower16(b))
            } else {
                (a, b)
            };
            if la != lb {
                ok = false;
                break;
            }
        }
        if ok {
            // SAFETY: `i` in 0..=last_start <= hlen, a valid pointer into `hay`.
            return unsafe { hay.add(i) };
        }
    }
    std::ptr::null()
}

/// `shlwapi!StrStrW(s1, s2) -> LPWSTR`. Case-sensitive substring search.
pub extern "C" fn str_str_w(s1: *const u16, s2: *const u16) -> *const u16 {
    str_str_w_impl(s1, s2, None, false)
}

/// `shlwapi!StrStrIW(s1, s2) -> LPWSTR`. Case-insensitive substring search.
pub extern "C" fn str_str_iw(s1: *const u16, s2: *const u16) -> *const u16 {
    str_str_w_impl(s1, s2, None, true)
}

/// `shlwapi!StrStrNIW(s1, s2, n) -> LPWSTR`. Case-insensitive substring search limited to
/// the first `n` code units of the haystack.
pub extern "C" fn str_str_niw(s1: *const u16, s2: *const u16, n: i32) -> *const u16 {
    if n < 0 {
        return std::ptr::null();
    }
    str_str_w_impl(s1, s2, Some(n as usize), true)
}

/// `shlwapi!StrRStrIW(s1, s2, sub) -> LPWSTR`. Finds the last occurrence of `s2` within the
/// haystack `s1`, searching case-insensitively. `sub` (lpLast) optionally bounds the search
/// to the region `[s1, s1 + (sub - s1))`; null means the whole string.
pub extern "C" fn str_rstr_iw(s1: *const u16, s2: *const u16, sub: *const u16) -> *const u16 {
    if s1.is_null() || s2.is_null() {
        return std::ptr::null();
    }
    let nlen = wlen(s2);
    if nlen == 0 {
        return s1; // empty needle matches at the start
    }
    let hlen_full = wlen(s1);
    // The optional end bound `sub` (lpLast) limits the haystack. If it is not a pointer
    // into `[s1, s1 + hlen_full]` we fall back to the full length (defensive).
    let hlen = if !sub.is_null() {
        let off_bytes = (sub as usize).wrapping_sub(s1 as usize);
        (off_bytes / 2).min(hlen_full)
    } else {
        hlen_full
    };
    if nlen > hlen {
        return std::ptr::null();
    }
    let last_start = hlen - nlen;
    for i in (0..=last_start).rev() {
        let mut ok = true;
        for j in 0..nlen {
            // SAFETY: `i` in 0..=last_start and `j` in 0..nlen, so `i + j` in 0..hlen and
            // `j` in 0..nlen (within the pre-NUL regions of `s1` and `s2`).
            let (a, b) = unsafe { (*s1.add(i + j), *s2.add(j)) };
            if to_lower16(a) != to_lower16(b) {
                ok = false;
                break;
            }
        }
        if ok {
            // SAFETY: `i` in 0..=last_start <= hlen, a valid pointer into `s1`.
            return unsafe { s1.add(i) };
        }
    }
    std::ptr::null()
}

// ---------------------------------------------------------------------------
// Formatted print (no-op)
// ---------------------------------------------------------------------------

/// `shlwapi!wnsprintfW(buf, count, fmt, ...) -> int`. Returns 0 and writes a NUL (formatting
/// is not implemented; the variadic args are not consumed).
pub extern "C" fn wnsprintf_w(buf: *mut u16, count: i32, _fmt: *const u16) -> i32 {
    if !buf.is_null() && count > 0 {
        // SAFETY: `count > 0` guarantees at least one writable u16.
        unsafe { *buf = 0 };
    }
    0
}

/// `shlwapi!wnsprintfA(buf, count, fmt, ...) -> int`. ASCII twin of [`wnsprintf_w`].
pub extern "C" fn wnsprintf_a(buf: *mut u8, count: i32, _fmt: *const u8) -> i32 {
    if !buf.is_null() && count > 0 {
        // SAFETY: `count > 0` guarantees at least one writable byte.
        unsafe { *buf = 0 };
    }
    0
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full list of `shlwapi.dll` exports implemented here, with the metadata the PE loader
/// needs to build ABI thunks. Each `dll` is `"shlwapi.dll"`.
pub fn shlwapi_exports() -> Vec<ExportSpec> {
    macro_rules! lw {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "shlwapi.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        lw!("PathFindFileNameW", path_find_file_name_w, 1),
        lw!("PathFindFileNameA", path_find_file_name_a, 1),
        lw!("PathFindExtensionW", path_find_extension_w, 1),
        lw!("PathRemoveFileSpecW", path_remove_file_spec_w, 1),
        lw!("PathAppendW", path_append_w, 2),
        lw!("PathCombineW", path_combine_w, 3),
        lw!("PathIsRelativeW", path_is_relative_w, 1),
        lw!("StrCmpIW", str_cmp_i_w, 2),
        lw!("StrCmpW", str_cmp_w, 2),
        lw!("StrCmpNIW", str_cmp_ni_w, 3),
        lw!("StrCmpNW", str_cmp_n_w, 3),
        lw!("StrCmpIC", str_cmp_i_c, 2),
        lw!("StrStrW", str_str_w, 2),
        lw!("StrStrIW", str_str_iw, 2),
        lw!("StrRStrIW", str_rstr_iw, 3),
        lw!("wnsprintfW", wnsprintf_w, 3),
        lw!("wnsprintfA", wnsprintf_a, 3),
        lw!("StrStrNIW", str_str_niw, 3),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a NUL-terminated UTF-16 buffer from a Rust string.
    fn wbuf(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// Decode the NUL-terminated UTF-16 buffer at `p` into a Rust `String` (lossy).
    fn wstr(p: *const u16) -> String {
        let n = wlen(p);
        // SAFETY: `wlen` counted the pre-NUL units; reading them is in bounds.
        let slice = unsafe { std::slice::from_raw_parts(p, n) };
        String::from_utf16_lossy(slice)
    }

    #[test]
    fn path_find_file_name_w_finds_last_component() {
        let p = wbuf("C:\\dir\\file.txt");
        let r = path_find_file_name_w(p.as_ptr());
        assert_eq!(wstr(r), "file.txt");

        let bare = wbuf("file.txt");
        assert_eq!(wstr(path_find_file_name_w(bare.as_ptr())), "file.txt");
    }

    #[test]
    fn path_find_file_name_a_finds_last_component() {
        let p = b"C:\\dir\\file.txt\0";
        let r = path_find_file_name_a(p.as_ptr());
        // SAFETY: the returned pointer is a NUL-terminated C string within `p`.
        let got = unsafe { std::ffi::CStr::from_ptr(r as *const i8) };
        assert_eq!(got.to_str().unwrap(), "file.txt");
    }

    #[test]
    fn path_find_extension_w_finds_dot() {
        let p = wbuf("file.txt");
        assert_eq!(wstr(path_find_extension_w(p.as_ptr())), ".txt");

        let none = wbuf("noext");
        assert_eq!(wstr(path_find_extension_w(none.as_ptr())), "");

        // A dot inside a directory component is not an extension.
        let dir = wbuf("C:\\my.dir\\file");
        assert_eq!(wstr(path_find_extension_w(dir.as_ptr())), "");
    }

    #[test]
    fn path_remove_file_spec_w_truncates_at_separator() {
        let mut p = wbuf("C:\\dir\\file.txt");
        assert_eq!(path_remove_file_spec_w(p.as_mut_ptr()), 1);
        assert_eq!(wstr(p.as_ptr()), "C:\\dir");

        // No separator -> unchanged, returns FALSE.
        let mut bare = wbuf("file.txt");
        assert_eq!(path_remove_file_spec_w(bare.as_mut_ptr()), 0);
        assert_eq!(wstr(bare.as_ptr()), "file.txt");
    }

    #[test]
    fn path_append_w_adds_separator() {
        let mut p = vec![0u16; MAX_PATH];
        let dir = wbuf("C:\\dir");
        for (i, &c) in dir.iter().enumerate() {
            p[i] = c;
        }
        let more = wbuf("file.txt");
        assert_eq!(path_append_w(p.as_mut_ptr(), more.as_ptr()), 1);
        assert_eq!(wstr(p.as_ptr()), "C:\\dir\\file.txt");
    }

    #[test]
    fn path_append_w_skips_double_separator() {
        let mut p = vec![0u16; MAX_PATH];
        let dir = wbuf("C:\\dir\\");
        for (i, &c) in dir.iter().enumerate() {
            p[i] = c;
        }
        let more = wbuf("\\file.txt");
        assert_eq!(path_append_w(p.as_mut_ptr(), more.as_ptr()), 1);
        assert_eq!(wstr(p.as_ptr()), "C:\\dir\\file.txt");
    }

    #[test]
    fn path_combine_w_dir_and_file() {
        let mut dest = vec![0u16; MAX_PATH];
        let dir = wbuf("C:\\dir");
        let file = wbuf("file.txt");
        let r = path_combine_w(dest.as_mut_ptr(), dir.as_ptr(), file.as_ptr());
        assert_eq!(r as *const u16, dest.as_ptr());
        assert_eq!(wstr(dest.as_ptr()), "C:\\dir\\file.txt");
    }

    #[test]
    fn path_combine_w_absolute_file_replaces_dir() {
        let mut dest = vec![0u16; MAX_PATH];
        let dir = wbuf("C:\\dir");
        let file = wbuf("D:\\other.txt");
        path_combine_w(dest.as_mut_ptr(), dir.as_ptr(), file.as_ptr());
        assert_eq!(wstr(dest.as_ptr()), "D:\\other.txt");
    }

    #[test]
    fn path_is_relative_w_drive_is_absolute() {
        assert_eq!(path_is_relative_w(wbuf("C:\\windows").as_ptr()), 0);
        assert_eq!(path_is_relative_w(wbuf("\\\\server\\share").as_ptr()), 0);
        assert_eq!(path_is_relative_w(wbuf("rel\\path").as_ptr()), 1);
        assert_eq!(path_is_relative_w(wbuf("").as_ptr()), 1);
    }

    #[test]
    fn str_cmp_i_w_case_insensitive_equal() {
        assert_eq!(
            str_cmp_i_w(wbuf("Hello").as_ptr(), wbuf("HELLO").as_ptr()),
            0
        );
        assert_eq!(
            str_cmp_i_w(wbuf("hello").as_ptr(), wbuf("hello").as_ptr()),
            0
        );
    }

    #[test]
    fn str_cmp_w_case_sensitive_differs() {
        assert!(str_cmp_w(wbuf("abc").as_ptr(), wbuf("abd").as_ptr()) < 0);
        assert!(str_cmp_w(wbuf("abd").as_ptr(), wbuf("abc").as_ptr()) > 0);
        assert_eq!(str_cmp_w(wbuf("abc").as_ptr(), wbuf("abc").as_ptr()), 0);
    }

    #[test]
    fn str_cmp_n_w_limits_length() {
        assert_eq!(
            str_cmp_n_w(wbuf("abcX").as_ptr(), wbuf("abcY").as_ptr(), 3),
            0
        );
        assert!(str_cmp_n_w(wbuf("abcX").as_ptr(), wbuf("abcY").as_ptr(), 4) < 0);
    }

    #[test]
    fn str_cmp_i_c_ascii_case_insensitive() {
        assert_eq!(
            str_cmp_i_c(
                c"Hello".as_ptr() as *const u8,
                c"HELLO".as_ptr() as *const u8
            ),
            0
        );
        assert!(str_cmp_i_c(c"abc".as_ptr() as *const u8, c"abd".as_ptr() as *const u8) < 0);
    }

    #[test]
    fn str_str_w_finds_substring() {
        let h = wbuf("hello world");
        let n = wbuf("world");
        let r = str_str_w(h.as_ptr(), n.as_ptr());
        assert!(!r.is_null());
        assert_eq!(wstr(r), "world");

        assert!(str_str_w(h.as_ptr(), wbuf("missing").as_ptr()).is_null());
    }

    #[test]
    fn str_str_iw_case_insensitive() {
        let h = wbuf("Hello World");
        let r = str_str_iw(h.as_ptr(), wbuf("WORLD").as_ptr());
        assert!(!r.is_null());
        assert_eq!(wstr(r), "World");
    }

    #[test]
    fn str_rstr_iw_finds_last_occurrence() {
        let h = wbuf("abcabcX");
        let r = str_rstr_iw(h.as_ptr(), wbuf("ABC").as_ptr(), std::ptr::null());
        assert!(!r.is_null());
        assert_eq!(wstr(r), "abcX");
    }

    #[test]
    fn str_str_niw_limited_haystack() {
        let h = wbuf("abc world xyz");
        // Limiting the haystack to 3 chars ("abc") means "world" is not found.
        assert!(str_str_niw(h.as_ptr(), wbuf("world").as_ptr(), 3).is_null());
        // A wider limit includes "world".
        let r = str_str_niw(h.as_ptr(), wbuf("world").as_ptr(), 10);
        assert!(!r.is_null());
        assert_eq!(wstr(r), "world xyz");
    }

    #[test]
    fn wnsprintf_returns_zero_and_null_terminates() {
        let mut buf = [0u16; 16];
        assert_eq!(wnsprintf_w(buf.as_mut_ptr(), 16, std::ptr::null()), 0);
        assert_eq!(buf[0], 0);
        let mut abuf = [0u8; 16];
        assert_eq!(wnsprintf_a(abuf.as_mut_ptr(), 16, std::ptr::null()), 0);
        assert_eq!(abuf[0], 0);
    }

    #[test]
    fn export_table_is_complete() {
        let exports = shlwapi_exports();
        let names: Vec<&str> = exports.iter().map(|e| e.sym).collect();
        assert!(names.contains(&"PathFindFileNameW"));
        assert!(names.contains(&"PathCombineW"));
        assert!(names.contains(&"StrCmpIW"));
        assert!(names.contains(&"StrStrW"));
        assert!(names.contains(&"wnsprintfW"));
        assert!(exports.iter().all(|e| e.dll == "shlwapi.dll"));
        assert_eq!(exports.len(), 18);
    }
}
