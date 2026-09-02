//! COM vtable layer for D3D12 (workstream M8b).
//!
//! This crate wraps the existing Rust-native D3D12-over-Vulkan translation
//! (`nigg-d3d12`, `nigg-dxgi`) in COM objects a Windows PE can drive through real
//! vtables. It is the D3D12 twin of `nigg-d3d11-com`: the object layout, the
//! shared `IUnknown` methods, the thunk-install hook, and the import-level
//! export registry are all identical in shape.
//!
//! # The problem this solves
//!
//! A PE that links `d3d12.dll` calls `D3D12CreateDevice` through the Import
//! Address Table (an import → IAT → Win64->SysV thunk → our Rust impl). That call
//! hands back an `ID3D12Device*` COM interface pointer. The PE then calls device
//! methods through the object's vtable:
//!
//! ```text
//! mov rax, [device]        ; load vtable pointer (first field of the object)
//! mov rax, [rax + offset]  ; load the method function pointer
//! mov rcx, device          ; `this` (Windows x64 arg1)
//! ; ...more args in RDX/R8/R9 + stack...
//! call rax                 ; Windows x64 ABI call through the vtable slot
//! ```
//!
//! The function pointers in the vtable MUST be Win64-ABI, but our Rust method
//! implementations are System V ABI. So every vtable slot holds a **Win64->SysV
//! thunk** — exactly what the PE loader's `ThunkArena` produces. To avoid a
//! workspace dependency cycle (this crate must not depend on the loader), the
//! loader passes a thunk-creation callback into [`install_vtables`]; this crate
//! uses it to allocate the per-slot thunks at load time, before the arena is
//! sealed (flipped to `PROT_EXEC`).
//!
//! # COM object layout
//!
//! [`ComObject<T>`] is `#[repr(C)]` with the vtable pointer first (so `*obj` is
//! the vtable pointer, matching the COM contract), a refcount, a type-erased
//! drop function, then the wrapped Rust object `inner`. The first three fields
//! form a [`ComHeader`] that the shared `IUnknown` methods operate on, so one
//! set of `QueryInterface`/`AddRef`/`Release` thunks is reused across every
//! interface vtable.
//!
//! # Vtable layout (M8b)
//!
//! Each interface vtable is a `#[repr(C)]` struct of function pointers. The slot
//! order is the order declared in the corresponding `*Vtbl` struct in
//! [`methods`]; it is a **minimal, documented** layout (IUnknown + only the
//! methods a clear-colour sample needs), not the full Windows vtable. The
//! hand-written D3D12 sample fixture calls methods by these exact byte offsets,
//! so the layout is internally consistent. Full Windows-vtable-order fidelity
//! (so real D3D12 PEs index the right slots) is deferred to a later milestone.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block has a
//! SAFETY comment.

#![deny(unsafe_op_in_unsafe_fn)]
// The COM vtable structs, inner wrappers, and no-op stubs model the full M8b
// method surface even when only a subset is exercised by the clear-colour
// sample (e.g. SetPipelineState/DrawInstanced are wired but the clear path does
// not set a PSO); keeping them avoids surprising `dead_code` churn as more
// methods light up in later milestones.
#![allow(dead_code)]

mod imp;
mod methods;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use std::os::raw::c_void;

pub use methods::{
    ComVtables, Id3d12CommandAllocatorVtbl, Id3d12CommandQueueVtbl, Id3d12DescriptorHeapVtbl,
    Id3d12DeviceVtbl, Id3d12GraphicsCommandListVtbl, Id3d12PipelineStateVtbl, Id3d12ResourceVtbl,
    Id3d12RootSignatureVtbl,
};

// ---------------------------------------------------------------------------
// HRESULT
// ---------------------------------------------------------------------------

/// `S_OK` — success.
pub const S_OK: i32 = 0;
/// `E_NOTIMPL` — method not implemented (this milestone's stubs).
pub const E_NOTIMPL: i32 = 0x8000_4001u32 as i32;
/// `E_INVALIDARG` — bad argument.
pub const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
/// `E_FAIL` — unspecified failure.
pub const E_FAIL: i32 = 0x8000_4005u32 as i32;
/// `E_NOINTERFACE` — `QueryInterface` asked for an unsupported IID.
pub const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;

// ---------------------------------------------------------------------------
// COM object
// ---------------------------------------------------------------------------

/// The fixed prefix of every [`ComObject<T>`]: the vtable pointer, the
/// refcount, and the type-erased drop function. Casting any COM object pointer
/// to `*mut ComHeader` lets the shared `IUnknown` methods manipulate the
/// refcount and (on `Release` to zero) invoke the drop function without
/// knowing the concrete `T`.
#[repr(C)]
struct ComHeader {
    vtable: *const c_void,
    refcount: AtomicU32,
    drop_fn: unsafe fn(*mut c_void),
}

/// A COM object: vtable pointer first (COM contract), refcount, type-erased
/// drop function, then the wrapped Rust object `inner`. The PE only ever
/// dereferences `*obj` (the vtable pointer); the remaining fields are private
/// Rust state.
#[repr(C)]
pub struct ComObject<T> {
    vtable: *const c_void,
    refcount: AtomicU32,
    drop_fn: unsafe fn(*mut c_void),
    inner: T,
}

impl<T> ComObject<T> {
    /// Allocate a heap COM object wrapping `inner`, with its vtable pointer set
    /// to `vtable` and refcount 1. Returns the COM interface pointer (the
    /// address of the object) the PE receives.
    pub(crate) fn into_raw(vtable: *const c_void, inner: T) -> *mut c_void {
        let obj = ComObject {
            vtable,
            refcount: AtomicU32::new(1),
            drop_fn: drop_impl::<T>,
            inner,
        };
        // SAFETY: `Box::new` allocates on the heap; `into_raw` yields the raw
        // address and suppresses the destructor (the caller owns it via Release).
        Box::into_raw(Box::new(obj)) as *mut c_void
    }
}

/// Type-erased destructor for a [`ComObject<T>`]: reconstruct the `Box` from
/// the raw pointer and drop it, freeing the allocation and dropping `inner`.
unsafe fn drop_impl<T>(p: *mut c_void) {
    // SAFETY: `p` came from `ComObject::<T>::into_raw` (i.e. `Box::into_raw`);
    // reconstructing and dropping the `Box` is sound and happens exactly once.
    drop(unsafe { Box::from_raw(p as *mut ComObject<T>) });
}

/// Borrow the `inner` field immutably from a COM `this` pointer.
///
/// # Safety
/// `this` must be a valid `*mut ComObject<T>` allocated by [`ComObject::into_raw`].
pub(crate) unsafe fn inner<'a, T>(this: *mut c_void) -> &'a T {
    // SAFETY: caller upholds that `this` is a live `*mut ComObject<T>`.
    unsafe { &(*(this as *const ComObject<T>)).inner }
}

/// Borrow the `inner` field mutably from a COM `this` pointer.
///
/// # Safety
/// `this` must be a valid `*mut ComObject<T>` allocated by [`ComObject::into_raw`]
/// and not aliasing any other borrow.
pub(crate) unsafe fn inner_mut<'a, T>(this: *mut c_void) -> &'a mut T {
    // SAFETY: caller upholds that `this` is a live, unaliased `*mut ComObject<T>`.
    unsafe { &mut (*(this as *mut ComObject<T>)).inner }
}

// ---------------------------------------------------------------------------
// Shared IUnknown methods (one set of thunks, reused in every vtable)
// ---------------------------------------------------------------------------

/// `IUnknown::QueryInterface` — not implemented for M8b (returns `E_NOINTERFACE`
/// and nulls the out-pointer). The clear-colour sample never calls it.
unsafe extern "C" fn com_query_interface(
    _this: *mut c_void,
    _riid: *const u8,
    ppv: *mut *mut c_void,
) -> i32 {
    if !ppv.is_null() {
        // SAFETY: `ppv` is a valid writable out-pointer per the COM contract.
        unsafe { *ppv = std::ptr::null_mut() };
    }
    E_NOINTERFACE
}

/// `IUnknown::AddRef` — atomically increment the refcount and return the new
/// value. Works for every interface because all COM objects share the
/// [`ComHeader`] prefix.
unsafe extern "C" fn com_add_ref(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a live COM object; casting to `*mut ComHeader` is sound
    // because `ComObject<T>` starts with the `ComHeader` fields (`#[repr(C)]`).
    let h = this as *mut ComHeader;
    let prev = unsafe { (*h).refcount.fetch_add(1, Ordering::Relaxed) };
    prev + 1
}

/// `IUnknown::Release` — atomically decrement the refcount; on reaching zero,
/// invoke the type-erased drop function (which frees the object and drops the
/// wrapped Rust object). Returns the new refcount.
unsafe extern "C" fn com_release(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a live COM object; the `ComHeader` prefix is valid.
    let h = this as *mut ComHeader;
    let prev = unsafe { (*h).refcount.fetch_sub(1, Ordering::Relaxed) };
    let new = prev - 1;
    if new == 0 {
        // SAFETY: refcount hit zero; no other references exist, so invoking the
        // type-erased drop (which `Box::from_raw`s and drops) is sound and
        // happens exactly once.
        unsafe { ((*h).drop_fn)(this) };
    }
    new
}

// ---------------------------------------------------------------------------
// Global vtable registry (single-load assumption)
// ---------------------------------------------------------------------------

/// The pre-built vtables, installed once at PE load time. `nigg-loader` runs a
/// single PE per process, so one global is sufficient; the vtable thunks it
/// points at stay valid for as long as the loader's `ThunkArena` (owned by the
/// `PeImage`) is alive, i.e. the whole PE run.
static VTABLES: OnceLock<ComVtables> = OnceLock::new();

/// Install the COM vtables by allocating a Win64->SysV thunk for every vtable
/// slot via `make_thunk`, then leaking the vtable structs (stable addresses
/// for the PE's lifetime). Must be called before the thunk arena is sealed and
/// before any PE code runs. Calling twice is a no-op (the first install wins).
///
/// `make_thunk(target, n_args)` must return the address of a Win64->SysV
/// trampoline for the System V `extern "C"` function `target` taking `n_args`
/// integer/pointer arguments.
pub fn install_vtables(make_thunk: &mut dyn FnMut(*const c_void, u8) -> *const c_void) {
    if VTABLES.get().is_some() {
        return;
    }
    let vtables = ComVtables::build(make_thunk);
    // OnceLock::set fails only if already set; we checked above, so this always
    // succeeds. The leaked vtable structs inside `vtables` live forever (process
    // lifetime), which is what we want.
    let _ = VTABLES.set(vtables);
}

/// The installed vtables. Panics if [`install_vtables`] was not called first.
pub(crate) fn vtables() -> &'static ComVtables {
    VTABLES
        .get()
        .expect("nigg-d3d12-com: vtables not installed; call install_vtables at load time")
}

// ---------------------------------------------------------------------------
// Import-level export specs (registered by the PE loader)
// ---------------------------------------------------------------------------

/// One import-level D3D12 export the PE loader registers in its `ImplTable`:
/// `(dll, symbol)` plus the System V implementation address and argument count
/// (so the loader can wrap it in a Win64->SysV thunk).
pub struct ComExportSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub target: *const c_void,
    pub n_args: u8,
}

// SAFETY: `ComExportSpec` holds only `'static str` keys, a raw function address
// (immutable, valid for the process lifetime), and a `u8`. It is constructed
// once into a `static` and never mutated; sharing it across threads is sound.
unsafe impl Send for ComExportSpec {}
unsafe impl Sync for ComExportSpec {}

/// The D3D12 import-level exports (`D3D12CreateDevice`, ...). The PE loader
/// iterates these and registers a thunk for each, exactly like its kernel32/
/// user32 exports and the D3D11/DXGI COM exports.
pub fn com_export_specs() -> &'static [ComExportSpec] {
    imp::EXPORT_SPECS
}
