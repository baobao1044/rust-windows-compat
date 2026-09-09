//! ole32.dll — COM initialization and instance creation stubs.
//!
//! DirectX games and many anti-cheat DLLs call `CoInitializeEx` at startup
//! to initialize the COM apartment. If it returns an error, the game bails
//! out. We return `S_OK` (already initialized — our COM vtables are set up
//! by the PE loader's thunk layer, so there's no real apartment to
//! initialize). `CoCreateInstance` returns `CLASS_NOT_AVAILABLE` for
//! unknown CLSIDs — a real implementation would need to dispatch through
//! our D3D11/D3D12/DXGI COM layers, which the PE's import-level exports
//! (`D3D11CreateDeviceAndSwapChain`, `CreateDXGIFactory`) already cover.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_int, c_void};

/// `S_OK` (0) — COM success.
const S_OK: c_int = 0;
/// `S_FALSE` (1) — COM "already initialized with a different concurrency model".
const S_FALSE: c_int = 1;
/// `REGDB_E_CLASSNOTREG` (0x80040154) — CLSID not registered.
const REGDB_E_CLASSNOTREG: c_int = 0x8004_0154u32 as c_int;
/// `COINIT_MULTITHREADED` = 0x0 (the most common value passed by D3D games).
const COINIT_MULTITHREADED: u32 = 0x0;

// ---------------------------------------------------------------------------
// CoInitialize / CoInitializeEx
// ---------------------------------------------------------------------------

/// `ole32!CoInitializeEx(reserved, coInit) -> HRESULT`. Returns S_OK — our COM
/// objects are always "initialized" because the PE loader sets up the vtables.
pub extern "C" fn co_initialize_ex(_reserved: *mut c_void, _co_init: u32) -> c_int {
    S_OK
}

/// `ole32!CoInitialize(reserved) -> HRESULT`. Legacy single-threaded variant.
pub extern "C" fn co_initialize(_reserved: *mut c_void) -> c_int {
    S_OK
}

/// `ole32!CoUninitialize() -> void`. No-op — no per-apartment state to clean up.
pub extern "C" fn co_uninitialize() {}

// ---------------------------------------------------------------------------
// CoCreateInstance
// ---------------------------------------------------------------------------

/// `ole32!CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv) -> HRESULT`.
/// Returns `REGDB_E_CLASSNOTREG` — we don't maintain a CLSID registry. Games
/// that use D3D11/12 import the factory functions directly
/// (`D3D11CreateDeviceAndSwapChain`, `CreateDXGIFactory`), not through
/// `CoCreateInstance`. This stub lets the PE's import resolve and the fallback
/// path run.
pub extern "C" fn co_create_instance(
    _rclsid: *const u8,
    _p_unk_outer: *mut c_void,
    _cls_context: u32,
    _riid: *const u8,
    _ppv: *mut *mut c_void,
) -> c_int {
    REGDB_E_CLASSNOTREG
}

// ---------------------------------------------------------------------------
// Misc ole32 stubs
// ---------------------------------------------------------------------------

/// `ole32!CoGetMalloc(which, ppMalloc) -> HRESULT`. Returns E_NOTIMPL.
pub extern "C" fn co_get_malloc(_which: u32, _pp_malloc: *mut *mut c_void) -> c_int {
    0x8000_4001u32 as c_int // E_NOTIMPL
}

/// `ole32!StringFromGUID2(rguid, lpsz, cch) -> int`. Returns 0 (failed).
pub extern "C" fn string_from_guid2(_rguid: *const u8, _lpsz: *mut u16, _cch: c_int) -> c_int {
    0
}

/// `ole32!CLSIDFromString(lpsz, pclsid) -> HRESULT`. Returns E_NOTIMPL.
pub extern "C" fn clsid_from_string(_lpsz: *const u16, _pclsid: *mut u8) -> c_int {
    0x8000_4001u32 as c_int // E_NOTIMPL
}

/// `ole32!CoTaskMemAlloc(cb) -> void*`. Delegates to malloc.
pub extern "C" fn co_task_mem_alloc(cb: usize) -> *mut c_void {
    // SAFETY: libc malloc is safe to call from any context.
    unsafe { libc::malloc(cb) }
}

/// `ole32!CoTaskMemFree(pv) -> void`. Delegates to free (NULL-safe).
pub extern "C" fn co_task_mem_free(pv: *mut c_void) {
    // SAFETY: libc free is NULL-safe.
    unsafe { libc::free(pv) }
}

/// `ole32!CoTaskMemRealloc(pv, cb) -> void*`. Delegates to realloc.
pub extern "C" fn co_task_mem_realloc(pv: *mut c_void, cb: usize) -> *mut c_void {
    // SAFETY: libc realloc handles NULL pv (acts as malloc).
    unsafe { libc::realloc(pv, cb) }
}

/// `ole32!CoAddRefServerProcess() -> ULONG`. No-op returning 1.
pub extern "C" fn co_add_ref_server_process() -> u32 {
    1
}

/// `ole32!CoReleaseServerProcess() -> ULONG`. No-op returning 0.
pub extern "C" fn co_release_server_process() -> u32 {
    0
}

/// `ole32!CoWaitForMultipleHandles(...) -> HRESULT`. Returns S_OK after a no-op.
pub extern "C" fn co_wait_for_multiple_handles(
    _flags: u32,
    _timeout_ms: u32,
    _handle_count: u32,
    _handles: *const *mut c_void,
    _signaled_index: *mut u32,
) -> c_int {
    S_OK
}

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

pub fn ole32_exports() -> Vec<ExportSpec> {
    macro_rules! o {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "ole32.dll",
                sym: $sym,
                ptr: $f as *const c_void,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        o!("CoInitialize", co_initialize, 1),
        o!("CoInitializeEx", co_initialize_ex, 2),
        o!("CoUninitialize", co_uninitialize, 0),
        o!("CoCreateInstance", co_create_instance, 5),
        o!("CoGetMalloc", co_get_malloc, 2),
        o!("StringFromGUID2", string_from_guid2, 3),
        o!("CLSIDFromString", clsid_from_string, 2),
        o!("CoTaskMemAlloc", co_task_mem_alloc, 1),
        o!("CoTaskMemFree", co_task_mem_free, 1),
        o!("CoTaskMemRealloc", co_task_mem_realloc, 2),
        o!("CoAddRefServerProcess", co_add_ref_server_process, 0),
        o!("CoReleaseServerProcess", co_release_server_process, 0),
        o!("CoWaitForMultipleHandles", co_wait_for_multiple_handles, 5),
    ]
}
