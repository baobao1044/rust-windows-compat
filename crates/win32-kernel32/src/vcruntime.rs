//! VCRUNTIME140.dll + MSVCP140.dll — MSVC C++ runtime exports.
//!
//! VCRUNTIME140 implements C runtime intrinsics (memchr, memcmp, setjmp, etc.)
//! and SEH support (__C_specific_handler). MSVCP140 implements the C++ standard
//! library (std::ostream, std::locale, etc.). We delegate the C string/memory
//! functions to libc and no-op the C++ vtable methods — the game's bundled
//! DLLs (PhysX, lua) import these, but the game's own code path may not call
//! all of them.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_int, c_void};

// ---------------------------------------------------------------------------
// VCRUNTIME140.dll — C runtime intrinsics
// ---------------------------------------------------------------------------

/// `VCRUNTIME140!memchr(ptr, c, n) -> void*`. Delegates to libc memchr.
pub extern "C" fn vcr_memchr(ptr: *const c_void, c: i32, n: usize) -> *mut c_void {
    // SAFETY: libc memchr is safe with valid ptr+n.
    unsafe { libc::memchr(ptr, c, n) as *mut c_void }
}

/// `VCRUNTIME140!memcmp(a, b, n) -> int`. Delegates to libc memcmp.
pub extern "C" fn vcr_memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    // SAFETY: libc memcmp with valid pointers.
    unsafe { libc::memcmp(a, b, n) }
}

/// `VCRUNTIME140!strchr(s, c) -> char*`. Delegates to libc strchr.
pub extern "C" fn vcr_strchr(s: *const u8, c: c_int) -> *mut u8 {
    // SAFETY: libc strchr with a NUL-terminated string.
    unsafe { libc::strchr(s as *const i8, c) as *mut u8 }
}

/// `VCRUNTIME140!strrchr(s, c) -> char*`. Delegates to libc strrchr.
pub extern "C" fn vcr_strrchr(s: *const u8, c: c_int) -> *mut u8 {
    // SAFETY: libc strrchr with a NUL-terminated string.
    unsafe { libc::strrchr(s as *const i8, c) as *mut u8 }
}

/// `VCRUNTIME140!strstr(haystack, needle) -> char*`. Delegates to libc strstr.
pub extern "C" fn vcr_strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    // SAFETY: libc strstr with NUL-terminated strings.
    unsafe { libc::strstr(haystack as *const i8, needle as *const i8) as *mut u8 }
}

/// `VCRUNTIME140!strlen(s) -> size_t`. Delegates to libc strlen.
pub extern "C" fn vcr_strlen(s: *const u8) -> usize {
    // SAFETY: libc strlen with a NUL-terminated string.
    unsafe { libc::strlen(s as *const i8) }
}

/// `VCRUNTIME140!__C_specific_handler(...) -> EXCEPTION_DISPOSITION`.
/// Minimal stub: return ExceptionContinueSearch (0).
pub extern "C" fn vcr_c_specific_handler() -> i32 {
    0 // ExceptionContinueSearch
}

/// `VCRUNTIME140!__std_exception_copy(src, dst) -> void`. No-op.
pub extern "C" fn vcr_std_exception_copy(_src: *const c_void, _dst: *mut c_void) {}

/// `VCRUNTIME140!__std_exception_destroy(ptr) -> void`. No-op.
pub extern "C" fn vcr_std_exception_destroy(_ptr: *mut c_void) {}

/// `VCRUNTIME140!__std_type_info_destroy_list(ptr) -> void`. No-op.
pub extern "C" fn vcr_std_type_info_destroy_list(_ptr: *mut c_void) {}

/// `VCRUNTIME140!longjmp(env, val) -> noreturn`. Not implemented (would need
/// to restore the guest's stack pointer). For now, call libc::_exit.
pub extern "C" fn vcr_longjmp(_env: *mut c_void, _val: c_int) -> ! {
    log::warn!("vcruntime: longjmp called — not implemented, exiting");
    // SAFETY: _exit never returns.
    unsafe { libc::_exit(1) }
}

/// `VCRUNTIME140!__intrinsic_setjmp(env) -> int`. Return 0 (first call).
pub extern "C" fn vcr_intrinsic_setjmp(_env: *mut c_void) -> c_int {
    0
}

/// `VCRUNTIME140!_CxxThrowException(ptr, info) -> noreturn`. Not implemented.
pub extern "C" fn vcr_cxx_throw_exception(_ptr: *const c_void, _info: *const c_void) -> ! {
    log::warn!("vcruntime: _CxxThrowException called — not implemented, exiting");
    unsafe { libc::_exit(1) }
}

/// `VCRUNTIME140!memcpy(dst, src, n) -> void*`. Delegates to libc memcpy.
pub extern "C" fn vcr_memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: libc memcpy with valid pointers.
    unsafe { libc::memcpy(dst, src, n) }
}

/// `VCRUNTIME140!memset(dst, c, n) -> void*`. Delegates to libc memset.
pub extern "C" fn vcr_memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // SAFETY: libc memset with valid pointer.
    unsafe { libc::memset(dst, c, n) }
}

/// `VCRUNTIME140!memmove(dst, src, n) -> void*`. Delegates to libc memmove.
pub extern "C" fn vcr_memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // SAFETY: libc memmove with valid pointers.
    unsafe { libc::memmove(dst, src, n) }
}

/// `VCRUNTIME140!_purecall() -> int`. Pure virtual function call — abort.
pub extern "C" fn vcr_purecall() -> c_int {
    log::error!("vcruntime: pure virtual function call");
    unsafe {
        libc::abort();
    }
}

/// `VCRUNTIME140!__security_check_cookie(cookie) -> void`. No-op.
pub extern "C" fn vcr_security_check_cookie(_cookie: usize) {}

/// `VCRUNTIME140!__guard_check_icall_fptr(ptr) -> void`. No-op (CFG).
pub extern "C" fn vcr_guard_check_icall(_ptr: *const c_void) {}

/// `VCRUNTIME140!__guard_dispatch_icall_fptr(ptr) -> void`. No-op (CFG).
pub extern "C" fn vcr_guard_dispatch_icall(_ptr: *const c_void) {}

// ---------------------------------------------------------------------------
// MSVCP140.dll — C++ stdlib (all no-ops — the mangled C++ vtable methods)
// ---------------------------------------------------------------------------

/// `MSVCP140!?_Xout_of_range@std@@YAXPEBD@Z` — std::_Xout_of_range. No-op.
pub extern "C" fn msvcp_xout_of_range(_msg: *const u8) {}

/// `MSVCP140!?_Xinvalid_argument@std@@YAXPEBD@Z` — std::_Xinvalid_argument. No-op.
pub extern "C" fn msvcp_xinvalid_argument(_msg: *const u8) {}

/// `MSVCP140!?_Xlength_error@std@@YAXPEBD@Z` — std::_Xlength_error. No-op.
pub extern "C" fn msvcp_xlength_error(_msg: *const u8) {}

/// `MSVCP140!?_Xruntime_error@std@@YAXPEBD@Z` — std::_Xruntime_error. No-op.
pub extern "C" fn msvcp_xruntime_error(_msg: *const u8) {}

/// `MSVCP140!?_Xbad_alloc@std@@YAXXZ` — std::_Xbad_alloc. No-op.
pub extern "C" fn msvcp_xbad_alloc() {}

/// `MSVCP140!?_Xoverflow_error@std@@YAXPEBD@Z` — std::_Xoverflow_error. No-op.
pub extern "C" fn msvcp_xoverflow_error(_msg: *const u8) {}

// ---------------------------------------------------------------------------
// Export registration
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct ExportSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: *const c_void,
    pub n_args: u8,
    pub noreturn: bool,
}

pub fn vcruntime_exports() -> Vec<ExportSpec> {
    fn e(dll: &'static str, sym: &'static str, f: *const c_void, n: u8, nr: bool) -> ExportSpec {
        ExportSpec {
            dll,
            sym,
            ptr: f,
            n_args: n,
            noreturn: nr,
        }
    }

    vec![
        // VCRUNTIME140.dll
        e(
            "vcruntime140.dll",
            "memchr",
            vcr_memchr as *const c_void,
            3,
            false,
        ),
        e(
            "vcruntime140.dll",
            "memcmp",
            vcr_memcmp as *const c_void,
            3,
            false,
        ),
        e(
            "vcruntime140.dll",
            "strchr",
            vcr_strchr as *const c_void,
            2,
            false,
        ),
        e(
            "vcruntime140.dll",
            "strrchr",
            vcr_strrchr as *const c_void,
            2,
            false,
        ),
        e(
            "vcruntime140.dll",
            "strstr",
            vcr_strstr as *const c_void,
            2,
            false,
        ),
        e(
            "vcruntime140.dll",
            "strlen",
            vcr_strlen as *const c_void,
            1,
            false,
        ),
        e(
            "vcruntime140.dll",
            "memcpy",
            vcr_memcpy as *const c_void,
            3,
            false,
        ),
        e(
            "vcruntime140.dll",
            "memset",
            vcr_memset as *const c_void,
            3,
            false,
        ),
        e(
            "vcruntime140.dll",
            "memmove",
            vcr_memmove as *const c_void,
            3,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__C_specific_handler",
            vcr_c_specific_handler as *const c_void,
            4,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__std_exception_copy",
            vcr_std_exception_copy as *const c_void,
            2,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__std_exception_destroy",
            vcr_std_exception_destroy as *const c_void,
            1,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__std_type_info_destroy_list",
            vcr_std_type_info_destroy_list as *const c_void,
            1,
            false,
        ),
        e(
            "vcruntime140.dll",
            "longjmp",
            vcr_longjmp as *const c_void,
            2,
            true,
        ),
        e(
            "vcruntime140.dll",
            "__intrinsic_setjmp",
            vcr_intrinsic_setjmp as *const c_void,
            1,
            false,
        ),
        e(
            "vcruntime140.dll",
            "_CxxThrowException",
            vcr_cxx_throw_exception as *const c_void,
            2,
            true,
        ),
        e(
            "vcruntime140.dll",
            "_purecall",
            vcr_purecall as *const c_void,
            0,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__security_check_cookie",
            vcr_security_check_cookie as *const c_void,
            1,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__guard_check_icall_fptr",
            vcr_guard_check_icall as *const c_void,
            1,
            false,
        ),
        e(
            "vcruntime140.dll",
            "__guard_dispatch_icall_fptr",
            vcr_guard_dispatch_icall as *const c_void,
            1,
            false,
        ),
        // MSVCP140.dll exception helpers
        e(
            "msvcp140.dll",
            "?_Xout_of_range@std@@YAXPEBD@Z",
            msvcp_xout_of_range as *const c_void,
            1,
            false,
        ),
        e(
            "msvcp140.dll",
            "?_Xinvalid_argument@std@@YAXPEBD@Z",
            msvcp_xinvalid_argument as *const c_void,
            1,
            false,
        ),
        e(
            "msvcp140.dll",
            "?_Xlength_error@std@@YAXPEBD@Z",
            msvcp_xlength_error as *const c_void,
            1,
            false,
        ),
        e(
            "msvcp140.dll",
            "?_Xruntime_error@std@@YAXPEBD@Z",
            msvcp_xruntime_error as *const c_void,
            1,
            false,
        ),
        e(
            "msvcp140.dll",
            "?_Xbad_alloc@std@@YAXXZ",
            msvcp_xbad_alloc as *const c_void,
            0,
            false,
        ),
        e(
            "msvcp140.dll",
            "?_Xoverflow_error@std@@YAXPEBD@Z",
            msvcp_xoverflow_error as *const c_void,
            1,
            false,
        ),
    ]
}
