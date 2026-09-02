//! Import-level D3D11/DXGI exports: the functions a PE links against
//! (`D3D11CreateDeviceAndSwapChain`, `CreateDXGIFactory`, ...). The PE loader
//! registers a Win64->SysV thunk for each (exactly like its kernel32 exports),
//! so a PE `call [IAT slot]` lands here in System V ABI.
//!
//! These functions create the COM objects (filling their vtables with the
//! pre-allocated thunks from the global registry) and hand the interface
//! pointers back to the PE.

#![allow(clippy::missing_safety_doc)]

use std::os::raw::c_void;
use std::sync::Arc;

use crate::methods::{
    map_format, ContextInner, DeviceInner, FactoryInner, SwapChainDescWin, SwapChainInner,
};
use crate::{vtables, ComExportSpec, ComObject, E_FAIL, E_INVALIDARG, S_OK};

/// `D3D11CreateDeviceAndSwapChain` — 12 args (System V after the thunk).
///
/// Creates a DXGI factory + swap chain + D3D11 device + immediate context, all
/// backed by the shared Vulkan context, wraps each in a COM object whose
/// vtable slots are pre-allocated thunks, and returns the three interface
/// pointers to the PE.
unsafe extern "C" fn d3d11_create_device_and_swap_chain(
    _adapter: *mut c_void,
    _driver_type: u32,
    _software: *mut c_void,
    _flags: u32,
    _pfeature_levels: *const u32,
    _feature_levels: u32,
    _sdk_version: u32,
    pswap_desc: *const SwapChainDescWin,
    ppswapchain: *mut *mut c_void,
    ppdevice: *mut *mut c_void,
    _pfeature_level: *mut u32,
    ppimmediate_context: *mut *mut c_void,
) -> i32 {
    if pswap_desc.is_null()
        || ppswapchain.is_null()
        || ppdevice.is_null()
        || ppimmediate_context.is_null()
    {
        return E_INVALIDARG;
    }
    // SAFETY: `pswap_desc` is a valid `DXGI_SWAP_CHAIN_DESC` provided by the PE.
    let desc_win = unsafe { &*pswap_desc };

    let factory = match nigg_dxgi::Factory::new() {
        Ok(f) => f,
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDeviceAndSwapChain: factory: {e}");
            return E_FAIL;
        }
    };
    let sc_desc = nigg_dxgi::SwapChainDesc {
        width: desc_win.width.max(1),
        height: desc_win.height.max(1),
        format: map_format(desc_win.format),
        buffer_count: desc_win.buffer_count.max(2),
    };
    let swapchain = match factory.create_swap_chain(None, sc_desc) {
        Ok(s) => s,
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDeviceAndSwapChain: swap chain: {e}");
            return E_FAIL;
        }
    };

    let device = match nigg_d3d11::Device::new(&swapchain) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDeviceAndSwapChain: device: {e}");
            return E_FAIL;
        }
    };
    let context = match nigg_d3d11::DeviceContext::new(device.clone()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDeviceAndSwapChain: context: {e}");
            return E_FAIL;
        }
    };

    let vt = vtables();
    // Build the context COM first so the device can store its pointer as the
    // immediate context handed out by `GetImmediateContext`.
    // SAFETY: freshly built COM objects; vtables are the pre-allocated thunks.
    let context_com =
        ComObject::into_raw(vt.context as *const c_void, ContextInner { ctx: context });
    let device_com = ComObject::into_raw(
        vt.device as *const c_void,
        DeviceInner {
            device,
            immediate_ctx: context_com,
        },
    );
    let swapchain_com =
        ComObject::into_raw(vt.swapchain as *const c_void, SwapChainInner { swapchain });

    // SAFETY: the four out-pointers were validated non-null above.
    unsafe {
        *ppswapchain = swapchain_com;
        *ppdevice = device_com;
        *ppimmediate_context = context_com;
    }
    S_OK
}

/// `D3D11CreateDevice` — 10 args (no swap chain). Builds a headless device +
/// immediate context (the sample uses the swap-chain variant, but this is
/// wired for completeness).
unsafe extern "C" fn d3d11_create_device(
    _adapter: *mut c_void,
    _driver_type: u32,
    _software: *mut c_void,
    _flags: u32,
    _pfeature_levels: *const u32,
    _feature_levels: u32,
    _sdk_version: u32,
    ppdevice: *mut *mut c_void,
    _pfeature_level: *mut u32,
    ppimmediate_context: *mut *mut c_void,
) -> i32 {
    if ppdevice.is_null() || ppimmediate_context.is_null() {
        return E_INVALIDARG;
    }
    let factory = match nigg_dxgi::Factory::new() {
        Ok(f) => f,
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDevice: factory: {e}");
            return E_FAIL;
        }
    };
    let device = match nigg_d3d11::Device::from_ctx(factory.ctx().clone()) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDevice: device: {e}");
            return E_FAIL;
        }
    };
    let context = match nigg_d3d11::DeviceContext::new(device.clone()) {
        Ok(c) => c,
        Err(e) => {
            log::error!("d3d11-com: D3D11CreateDevice: context: {e}");
            return E_FAIL;
        }
    };
    let vt = vtables();
    // SAFETY: freshly built COM objects.
    let context_com =
        ComObject::into_raw(vt.context as *const c_void, ContextInner { ctx: context });
    let device_com = ComObject::into_raw(
        vt.device as *const c_void,
        DeviceInner {
            device,
            immediate_ctx: context_com,
        },
    );
    // SAFETY: out-pointers validated non-null above.
    unsafe {
        *ppdevice = device_com;
        *ppimmediate_context = context_com;
    }
    S_OK
}

/// Build an `IDXGIFactory*` COM object backed by a fresh DXGI factory.
unsafe fn create_factory_impl(pp: *mut *mut c_void) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    let factory = match nigg_dxgi::Factory::new() {
        Ok(f) => f,
        Err(e) => {
            log::error!("d3d11-com: CreateDXGIFactory: {e}");
            return E_FAIL;
        }
    };
    let vt = vtables();
    // SAFETY: freshly built COM object with the pre-allocated factory vtable.
    let ptr = ComObject::into_raw(vt.factory as *const c_void, FactoryInner { factory });
    // SAFETY: `pp` validated non-null above.
    unsafe { *pp = ptr };
    S_OK
}

/// `CreateDXGIFactory(REFIID, void**)`.
unsafe extern "C" fn create_dxgi_factory(_riid: *const u8, pp: *mut *mut c_void) -> i32 {
    unsafe { create_factory_impl(pp) }
}

/// `CreateDXGIFactory1(REFIID, void**)`.
unsafe extern "C" fn create_dxgi_factory1(_riid: *const u8, pp: *mut *mut c_void) -> i32 {
    unsafe { create_factory_impl(pp) }
}

/// `CreateDXGIFactory2(UINT Flags, REFIID, void**)`.
unsafe extern "C" fn create_dxgi_factory2(
    _flags: u32,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    unsafe { create_factory_impl(pp) }
}

/// The D3D11/DXGI import-level exports the PE loader registers.
pub(crate) static EXPORT_SPECS: &[ComExportSpec] = &[
    ComExportSpec {
        dll: "d3d11.dll",
        sym: "D3D11CreateDeviceAndSwapChain",
        target: d3d11_create_device_and_swap_chain as *const c_void,
        n_args: 12,
    },
    ComExportSpec {
        dll: "d3d11.dll",
        sym: "D3D11CreateDevice",
        target: d3d11_create_device as *const c_void,
        n_args: 10,
    },
    ComExportSpec {
        dll: "dxgi.dll",
        sym: "CreateDXGIFactory",
        target: create_dxgi_factory as *const c_void,
        n_args: 2,
    },
    ComExportSpec {
        dll: "dxgi.dll",
        sym: "CreateDXGIFactory1",
        target: create_dxgi_factory1 as *const c_void,
        n_args: 2,
    },
    ComExportSpec {
        dll: "dxgi.dll",
        sym: "CreateDXGIFactory2",
        target: create_dxgi_factory2 as *const c_void,
        n_args: 3,
    },
];
