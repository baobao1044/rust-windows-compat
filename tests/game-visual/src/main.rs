//! "Game visual" D3D11 PE — a game fixture combining:
//!
//! 1. System-integrity checks (anti-cheat simulation)
//! 2. D3D11 render pipeline (clear + present)
//! 3. Clean exit
//!
//! Each failure returns a distinct sentinel so a CLI test can assert which
//! leg failed. All checks passed → exit 0.

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::ptr;

const S_OK: i32 = 0;
const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
const D3D_DRIVER_TYPE_HARDWARE: u32 = 1;

// Anti-cheat sentinels.
const FAIL_IS_DEBUGGER: i32 = 100;
const FAIL_REMOTE_DEBUGGER: i32 = 101;
const FAIL_SNAPSHOT: i32 = 102;
const FAIL_SECURE_BOOT: i32 = 103;
// D3D sentinels (1..n) get offset by 110 so pre-D3D/post-D3D don't collide.
const D3D_HR_OFFSET: i32 = 110;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn ExitProcess(code: u32) -> !;
    fn IsDebuggerPresent() -> i32;
    fn CheckRemoteDebuggerPresent(h: *mut u8, pb: *mut i32) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut u8;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "C" {
    fn NtQuerySystemInformation(
        info_class: u32,
        info: *mut u8,
        info_len: u32,
        ret_len: *mut u32,
    ) -> i32;
}

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

#[repr(C)]
#[derive(Clone, Copy)]
struct SwapChainDesc {
    width: u32,
    height: u32,
    format: u32,
    buffer_count: u32,
    hwnd: u64,
}

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

unsafe fn vtable<Vtbl>(obj: *mut u8) -> &'static Vtbl {
    unsafe { &*(*(obj as *const *const u8) as *const Vtbl) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn mainCRTStartup() {
    let exit = unsafe { try_run() };
    unsafe { ExitProcess(exit as u32) };
}

/// `SystemSecureBootInformation` = 161 from NT.
const SYSTEM_SECURE_BOOT_INFORMATION: u32 = 161;
/// `TH32CS_SNAPMODULE` = 0x8.
const TH32CS_SNAPMODULE: u32 = 0x8;

unsafe fn try_run() -> i32 {
    // --- 1. System integrity checks (anti-cheat simulation) ---

    if unsafe { IsDebuggerPresent() } != 0 {
        return FAIL_IS_DEBUGGER;
    }

    let mut remote_dbg = 0i32;
    let _ = unsafe { CheckRemoteDebuggerPresent(ptr::null_mut(), &mut remote_dbg) };
    if remote_dbg != 0 {
        return FAIL_REMOTE_DEBUGGER;
    }

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0) };
    if snap.is_null() {
        return FAIL_SNAPSHOT;
    }

    // NtQuerySystemInformation(SystemSecureBootInformation) — the low 32-bit
    // `SecureBootEnabled` field is filled as 1 by our virtual platform.
    let mut secure_boot_info = [0u8; 4];
    let mut ret_len = 0u32;
    let rc = unsafe {
        NtQuerySystemInformation(
            SYSTEM_SECURE_BOOT_INFORMATION,
            secure_boot_info.as_mut_ptr(),
            4,
            &mut ret_len,
        )
    };
    if rc != 0 {
        return FAIL_SECURE_BOOT;
    }
    if u32::from_le_bytes(secure_boot_info) == 0 {
        return FAIL_SECURE_BOOT;
    }

    // --- 2. D3D11 render pipeline ---
    let d3d_h = unsafe { run_d3d11() };
    if d3d_h != S_OK {
        return D3D_HR_OFFSET + d3d_h;
    }

    0
}

unsafe fn run_d3d11() -> i32 {
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

    let hr = unsafe {
        D3D11CreateDeviceAndSwapChain(
            ptr::null_mut(),
            D3D_DRIVER_TYPE_HARDWARE,
            ptr::null_mut(),
            0,
            ptr::null(),
            0,
            0,
            &desc,
            &mut swapchain,
            &mut device,
            ptr::null_mut(),
            &mut context,
        )
    };
    if hr != S_OK {
        return 1;
    }

    // GetBuffer(0) → backbuffer
    let mut backbuffer: *mut u8 = ptr::null_mut();
    let iid: [u8; 16] = [0; 16];
    let hr = unsafe {
        let vt = vtable::<IdxgiSwapChainVtbl>(swapchain);
        (vt.get_buffer)(swapchain, 0, iid.as_ptr(), &mut backbuffer)
    };
    if hr != S_OK {
        return 2;
    }

    // CreateRenderTargetView
    let mut rtv: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d11DeviceVtbl>(device);
        (vt.create_render_target_view)(device, backbuffer, ptr::null(), &mut rtv)
    };
    if hr != S_OK {
        return 3;
    }

    // OMSetRenderTargets
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        let views: [*mut u8; 1] = [rtv];
        (vt.om_set_render_targets)(context, 1, views.as_ptr(), ptr::null_mut());
    }

    // Clear (dark blue)
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        let color: [f32; 4] = [0.15, 0.25, 0.55, 1.0];
        (vt.clear_render_target_view)(context, rtv, color.as_ptr());
    }

    // Flush
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        (vt.flush)(context);
    }

    // Present
    unsafe {
        let vt = vtable::<IdxgiSwapChainVtbl>(swapchain);
        let _ = (vt.present)(swapchain, 0, 0);
    }

    0
}
