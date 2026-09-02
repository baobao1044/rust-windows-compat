//! M7a D3D11 sample PE fixture.
//!
//! A minimal `#![no_std]`/`#![no_main]` Windows program that imports only
//! `d3d11.dll`, `dxgi.dll`, and `kernel32.dll` (via `raw-dylib` + a custom entry
//! point, so there is no CRT import surface), and:
//!
//! 1. Calls `D3D11CreateDeviceAndSwapChain` to create a device, swap chain,
//!    and immediate context (COM objects whose vtable slots are the loader's
//!    Win64->SysV thunks).
//! 2. `IDXGISwapChain::GetBuffer(0, ...)` → back-buffer texture.
//! 3. `ID3D11Device::CreateRenderTargetView(backbuffer, ...)` → RTV.
//! 4. `ID3D11DeviceContext::OMSetRenderTargets(1, &rtv, null)`.
//! 5. `ID3D11DeviceContext::ClearRenderTargetView(rtv, &color)` (solid red).
//! 6. `ID3D11DeviceContext::Flush()`.
//! 7. `IDXGISwapChain::Present(0, 0)`.
//! 8. `ExitProcess(0)`.
//!
//! The COM vtable structs below mirror the slot order declared in
//! `nigg-d3d11-com` (`crates/d3d11-com/src/methods.rs`); the byte offsets the
//! generated code indexes are therefore consistent with the loader's thunks.
//! Because this builds for `x86_64-pc-windows-gnu`, `extern "C"` IS the
//! Windows x64 ABI (RCX/RDX/R8/R9 + stack), so a method call through the vtable
//! lands in the loader's Win64->SysV thunk exactly as a real PE would issue it.
//!
//! COM object pointers are kept as `*mut u8` (the loader hands them out that
//! way); a tiny helper reads the vtable pointer (the object's first field) and
//! casts it to the right `*Vtbl` so each call indexes the correct slot.

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::ptr;

/// `S_OK`.
const S_OK: i32 = 0;
/// `DXGI_FORMAT_B8G8R8A8_UNORM` numeric value (87).
const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
/// `D3D_DRIVER_TYPE_HARDWARE` (1).
const D3D_DRIVER_TYPE_HARDWARE: u32 = 1;

// ---------------------------------------------------------------------------
// raw-dylib imports (the only symbols this PE imports)
// ---------------------------------------------------------------------------

#[link(name = "d3d11", kind = "raw-dylib")]
unsafe extern "C" {
    fn D3D11CreateDeviceAndSwapChain(
        adapter: *mut u8,
        driver_type: u32,
        software: *mut u8,
        flags: u32,
        pfeature_levels: *const u32,
        feature_levels: u32,
        sdk_version: u32,
        pswap_desc: *const SwapChainDesc,
        ppswapchain: *mut *mut u8,
        ppdevice: *mut *mut u8,
        pfeature_level: *mut u32,
        ppimmediate_context: *mut *mut u8,
    ) -> i32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn ExitProcess(code: u32) -> !;
}

// ---------------------------------------------------------------------------
// COM interface + vtable definitions (slot order mirrors nigg-d3d11-com)
// ---------------------------------------------------------------------------

/// Minimal `DXGI_SWAP_CHAIN_DESC` matching `nigg_d3d11_com::SwapChainDescWin`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SwapChainDesc {
    width: u32,
    height: u32,
    format: u32,
    buffer_count: u32,
    hwnd: u64,
}

/// `IDXGISwapChain` vtable: IUnknown + Present, GetBuffer, GetDesc, ResizeBuffers.
#[repr(C)]
struct IdxgiSwapChainVtbl {
    query_interface: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    add_ref: unsafe extern "C" fn(*mut u8) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> u32,
    present: unsafe extern "C" fn(*mut u8, u32, u32) -> i32,
    get_buffer: unsafe extern "C" fn(*mut u8, u32, *const u8, *mut *mut u8) -> i32,
    get_desc: unsafe extern "C" fn(*mut u8, *mut SwapChainDesc) -> i32,
    resize_buffers: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32, u32) -> i32,
}

/// `ID3D11Device` vtable (slot order mirrors nigg-d3d11-com).
#[repr(C)]
struct Id3d11DeviceVtbl {
    query_interface: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    add_ref: unsafe extern "C" fn(*mut u8) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> u32,
    create_texture_2d: unsafe extern "C" fn(*mut u8, *const u8, *const u8, *mut *mut u8) -> i32,
    create_render_target_view: unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *mut *mut u8) -> i32,
    create_vertex_shader: unsafe extern "C" fn(*mut u8, *const u8, usize, *mut u8, *mut *mut u8) -> i32,
    create_pixel_shader: unsafe extern "C" fn(*mut u8, *const u8, usize, *mut u8, *mut *mut u8) -> i32,
    create_buffer: unsafe extern "C" fn(*mut u8, *const u8, *const u8, *mut *mut u8) -> i32,
    create_input_layout: unsafe extern "C" fn(*mut u8, *const u8, u32, *const u8, usize, *mut *mut u8) -> i32,
    create_rasterizer_state: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    create_blend_state: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    create_depth_stencil_state: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    create_depth_stencil_view: unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *mut *mut u8) -> i32,
    create_sampler_state: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    get_immediate_context: unsafe extern "C" fn(*mut u8, *mut *mut u8),
}

/// `ID3D11DeviceContext` vtable (slot order mirrors nigg-d3d11-com).
#[repr(C)]
struct Id3d11DeviceContextVtbl {
    query_interface: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    add_ref: unsafe extern "C" fn(*mut u8) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> u32,
    om_set_render_targets: unsafe extern "C" fn(*mut u8, u32, *const *mut u8, *mut u8),
    clear_render_target_view: unsafe extern "C" fn(*mut u8, *mut u8, *const f32),
    vs_set_shader: unsafe extern "C" fn(*mut u8, *mut u8, *const *mut u8, u32),
    ps_set_shader: unsafe extern "C" fn(*mut u8, *mut u8, *const *mut u8, u32),
    vs_set_constant_buffers: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8),
    ps_set_constant_buffers: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8),
    vs_set_shader_resources: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8),
    ps_set_shader_resources: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8),
    vs_set_samplers: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8),
    ps_set_samplers: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8),
    ia_set_vertex_buffers: unsafe extern "C" fn(*mut u8, u32, u32, *const *mut u8, *const u64, *const u32),
    ia_set_index_buffer: unsafe extern "C" fn(*mut u8, *mut u8, u32, u32),
    ia_set_input_layout: unsafe extern "C" fn(*mut u8, *mut u8),
    ia_set_primitive_topology: unsafe extern "C" fn(*mut u8, u32),
    update_subresource: unsafe extern "C" fn(*mut u8, *mut u8, u32, *const u8, *const u8, u32, u32),
    draw: unsafe extern "C" fn(*mut u8, u32, u32),
    draw_indexed: unsafe extern "C" fn(*mut u8, u32, u32, i32),
    map: unsafe extern "C" fn(*mut u8, *mut u8, u32, u32, u32, *mut u8) -> i32,
    unmap: unsafe extern "C" fn(*mut u8, *mut u8, u32),
    flush: unsafe extern "C" fn(*mut u8),
}

/// Read a COM object's vtable pointer (its first field) and cast it to `&Vtbl`.
unsafe fn vtable<Vtbl>(obj: *mut u8) -> &'static Vtbl {
    // SAFETY: `obj` is a valid COM object; its first field is the vtable pointer
    // (an 8-byte address). Dereferencing it reads a stable, leaked vtable struct.
    unsafe { &*(*(obj as *const *const u8) as *const Vtbl) }
}

// ---------------------------------------------------------------------------
// Entry point (no CRT)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No panic path in the sample; loop if reached.
    loop {}
}

// The precompiled `core` (shipped by rustup, built with `panic=unwind`) carries
// `.pdata` referencing `rust_eh_personality`. Our `#[panic_handler]` loops
// instead of unwinding, so the personality function is never called at runtime
// — it only needs to exist to satisfy the linker. Provide a no-op stub.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn mainCRTStartup() {
    let exit = unsafe { try_run() };
    unsafe { ExitProcess(exit as u32) };
}

/// The whole D3D11 clear+present sequence. Returns 0 on success, a nonzero
/// sentinel on any failure (so a broken path is visible, not silent).
unsafe fn try_run() -> i32 {
    // Swap-chain desc for a 640x480 headless B8G8R8A8 surface, 2 back buffers.
    let desc = SwapChainDesc {
        width: 640,
        height: 480,
        format: DXGI_FORMAT_B8G8R8A8_UNORM,
        buffer_count: 2,
        hwnd: 0,
    };

    let mut swapchain: *mut u8 = ptr::null_mut();
    let mut device: *mut u8 = ptr::null_mut();
    let mut context: *mut u8 = ptr::null_mut();

    // 1. Create the device + swap chain + immediate context.
    let hr = unsafe {
        D3D11CreateDeviceAndSwapChain(
            ptr::null_mut(), // pAdapter (default)
            D3D_DRIVER_TYPE_HARDWARE,
            ptr::null_mut(), // Software
            0,               // Flags
            ptr::null(),     // pFeatureLevels (default)
            0,               // FeatureLevels
            0,               // SDKVersion
            &desc,           // pSwapChainDesc
            &mut swapchain,  // ppSwapChain
            &mut device,     // ppDevice
            ptr::null_mut(), // pFeatureLevel
            &mut context,    // ppImmediateContext
        )
    };
    if hr != S_OK {
        return 1;
    }

    // 2. GetBuffer(0) → back-buffer texture.
    let mut backbuffer: *mut u8 = ptr::null_mut();
    let iid: [u8; 16] = [0; 16];
    let hr = unsafe {
        let vt = vtable::<IdxgiSwapChainVtbl>(swapchain);
        (vt.get_buffer)(swapchain, 0, iid.as_ptr(), &mut backbuffer)
    };
    if hr != S_OK {
        return 2;
    }

    // 3. CreateRenderTargetView(backbuffer) → RTV.
    let mut rtv: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d11DeviceVtbl>(device);
        (vt.create_render_target_view)(device, backbuffer, ptr::null(), &mut rtv)
    };
    if hr != S_OK {
        return 3;
    }

    // 4. OMSetRenderTargets(1, &rtv, null).
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        let views: [*mut u8; 1] = [rtv];
        (vt.om_set_render_targets)(context, 1, views.as_ptr(), ptr::null_mut());
    }

    // 5. ClearRenderTargetView(rtv, [1,0,0,1]) — solid red.
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        let color: [f32; 4] = [1.0, 0.0, 0.0, 1.0];
        (vt.clear_render_target_view)(context, rtv, color.as_ptr());
    }

    // 6. Flush() — submit the recorded clear command buffer.
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        (vt.flush)(context);
    }

    // 7. Present(0, 0).
    unsafe {
        let vt = vtable::<IdxgiSwapChainVtbl>(swapchain);
        let _ = (vt.present)(swapchain, 0, 0);
    }

    // 8. Success — ExitProcess(0) follows in mainCRTStartup.
    0
}
