//! Import-level D3D12 export: the function a PE links against
//! (`D3D12CreateDevice`). The PE loader registers a Win64->SysV thunk for it
//! (exactly like its kernel32 exports and the D3D11/DXGI COM exports), so a PE
//! `call [IAT slot]` lands here in System V ABI.
//!
//! This function creates the D3D12 device COM object (filling its vtable with
//! the pre-allocated thunks from the global registry) and hands the interface
//! pointer back to the PE.

#![allow(clippy::missing_safety_doc)]

use std::os::raw::c_void;

use crate::methods::DeviceInner;
use crate::{vtables, ComExportSpec, ComObject, E_FAIL, E_INVALIDARG, S_OK};

/// `D3D12CreateDevice(pAdapter, MinimumFeatureLevel, riid, ppDevice)` — 4 args
/// (System V after the thunk).
///
/// Creates the shared Vulkan context (via a DXGI factory, the same path the
/// DXGI swap-chain and D3D11 layer use), wraps it in a native
/// `nigg_d3d12::Device`, then wraps that in a COM object whose vtable slots are
/// pre-allocated thunks, and returns the `ID3D12Device*` interface pointer to
/// the PE. `pAdapter` is ignored (we always use the default physical device);
/// `MinimumFeatureLevel` is accepted but not honoured (the device always
/// targets the highest available).
unsafe extern "C" fn d3d12_create_device(
    _p_adapter: *mut c_void,
    _min_feature_level: u32,
    _riid: *const u8,
    pp_device: *mut *mut c_void,
) -> i32 {
    if pp_device.is_null() {
        return E_INVALIDARG;
    }
    // Bring up the shared Vulkan context the same way the DXGI swap-chain and
    // D3D11 layer do: a fresh `Factory` owns the instance/device/queue, and we
    // clone its `Arc<VkCtx>` into the D3D12 device.
    let factory = match nigg_dxgi::Factory::new() {
        Ok(f) => f,
        Err(e) => {
            log::error!("d3d12-com: D3D12CreateDevice: factory: {e}");
            return E_FAIL;
        }
    };
    let device = match nigg_d3d12::Device::new(factory.ctx().clone()) {
        Ok(d) => d,
        Err(e) => {
            log::error!("d3d12-com: D3D12CreateDevice: device: {e}");
            return E_FAIL;
        }
    };
    let vt = vtables();
    // SAFETY: freshly built COM object; the vtable holds the pre-allocated
    // Win64->SysV thunks.
    let ptr = ComObject::into_raw(vt.device as *const c_void, DeviceInner { device });
    // SAFETY: `pp_device` was validated non-null above.
    unsafe { *pp_device = ptr };
    S_OK
}

/// The D3D12 import-level exports the PE loader registers.
pub(crate) static EXPORT_SPECS: &[ComExportSpec] = &[ComExportSpec {
    dll: "d3d12.dll",
    sym: "D3D12CreateDevice",
    target: d3d12_create_device as *const c_void,
    n_args: 4,
}];
