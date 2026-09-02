//! M7+ game-window sample PE fixture.
//!
//! A `#![no_std]`/`#![no_main]` Windows program that simulates a real game's
//! startup path: registers a window class, creates a window, initializes D3D11
//! with a swap chain attached to that window's HWND, runs one frame (clear +
//! present), processes the message pump, and exits cleanly.
//!
//! Unlike the d3d11-sample (headless, no window), this exercises the user32
//! windowing API + D3D11 integration end-to-end through nigg-loader:
//!
//! 1. `RegisterClassExW` — register a window class with a simple wndproc.
//! 2. `CreateWindowExW` — create a 640x480 window.
//! 3. `D3D11CreateDeviceAndSwapChain` — create device + swap chain with the HWND.
//! 4. `GetBuffer` → back-buffer texture.
//! 5. `CreateRenderTargetView` → RTV.
//! 6. `OMSetRenderTargets(1, &rtv, null)`.
//! 7. `ClearRenderTargetView(rtv, [0.2, 0.4, 0.8, 1])` — blue background.
//! 8. `Flush()`.
//! 9. `Present(0, 0)`.
//! 10. `PeekMessageW` — check for messages (non-blocking).
//! 11. `ExitProcess(0)`.
//!
//! This validates the HWND → swap chain path and the user32 + D3D11 COM
//! integration in a single PE.

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
/// `CS_HREDRAW | CS_VREDRAW` = 0x0003.
const CS_HREDRAW_OR_VREDRAW: u32 = 0x0003;
/// `WS_OVERLAPPEDWINDOW` = 0x00CF_0000.
const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
/// `WS_VISIBLE` = 0x1000_0000 — we add this so ShowWindow isn't strictly needed.
const WS_VISIBLE: u32 = 0x1000_0000;

// ---------------------------------------------------------------------------
// raw-dylib imports
// ---------------------------------------------------------------------------

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn ExitProcess(code: u32) -> !;
    fn GetTickCount() -> u32;
    fn Sleep(ms: u32);
}

#[link(name = "user32", kind = "raw-dylib")]
unsafe extern "C" {
    fn RegisterClassExW(lpclss: *const WndClassExW) -> u16;
    fn CreateWindowExW(
        ex_style: u32,
        class_name: *const u16,
        window_name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: usize,
        menu: usize,
        instance: usize,
        param: usize,
    ) -> usize;
    fn DefWindowProcW(hwnd: usize, msg: u32, wparam: usize, lparam: usize) -> usize;
    fn PeekMessageW(msg: *mut Msg, hwnd: usize, min: u32, max: u32, remove: u32) -> i32;
    fn PostQuitMessage(code: i32);
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

// ---------------------------------------------------------------------------
// COM vtable definitions (slot order mirrors nigg-d3d11-com)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Win32 structures
// ---------------------------------------------------------------------------

#[repr(C)]
struct WndClassExW {
    cb_size: u32,
    style: u32,
    wnd_proc: unsafe extern "C" fn(usize, u32, usize, usize) -> usize,
    cls_extra: i32,
    wnd_extra: i32,
    instance: usize,
    icon: usize,
    cursor: usize,
    background: usize,
    menu_name: *const u16,
    class_name: *const u16,
    icon_sm: usize,
}

#[repr(C)]
struct Msg {
    hwnd: usize,
    message: u32,
    wparam: usize,
    lparam: usize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
}

/// The window procedure — a no-op that calls DefWindowProcW for everything.
unsafe extern "C" fn wnd_proc(hwnd: usize, msg: u32, wparam: usize, lparam: usize) -> usize {
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

unsafe fn vtable<Vtbl>(obj: *mut u8) -> &'static Vtbl {
    unsafe { &*(*(obj as *const *const u8) as *const Vtbl) }
}

// ---------------------------------------------------------------------------
// Wide string helpers
// ----------------------------------------------------------------@

const fn wstr(s: &[u8]) -> [u16; 32] {
    let mut out = [0u16; 32];
    let mut i = 0;
    let mut j = 0;
    while i + 1 < s.len() && j < 31 {
        out[j] = (s[i] as u16) | ((s[i + 1] as u16) << 8);
        // We assume ASCII — each byte is one char
        out[j] = s[i] as u16;
        i += 1;
        j += 1;
    }
    out
}

/// Encode an ASCII string as a NUL-terminated UTF-16LE array.
const fn wstr_ascii(s: &[u8]) -> [u16; 32] {
    let mut out = [0u16; 32];
    let mut i = 0;
    while i < s.len() && i < 31 {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

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

unsafe fn try_run() -> i32 {
    let class_name = wstr_ascii(b"NiggGameClass");
    let window_name = wstr_ascii(b"Nigg Game Window");

    // 1. Register the window class.
    let wc = WndClassExW {
        cb_size: core::mem::size_of::<WndClassExW>() as u32,
        style: CS_HREDRAW_OR_VREDRAW,
        wnd_proc: wnd_proc,
        cls_extra: 0,
        wnd_extra: 0,
        instance: 0,
        icon: 0,
        cursor: 0,
        background: 0,
        menu_name: ptr::null(),
        class_name: class_name.as_ptr(),
        icon_sm: 0,
    };
    let atom = unsafe { RegisterClassExW(&wc) };
    if atom == 0 {
        return 10;
    }

    // 2. Create the window.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_name.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            0,
            0,
            640,
            480,
            0,
            0,
            0,
            0,
        )
    };
    if hwnd == 0 {
        return 11;
    }

    // 3. Create D3D11 device + swap chain attached to the window.
    let desc = SwapChainDesc {
        width: 640,
        height: 480,
        format: DXGI_FORMAT_B8G8R8A8_UNORM,
        buffer_count: 2,
        hwnd: hwnd as u64,
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

    // 4. GetBuffer(0) → back-buffer texture.
    let mut backbuffer: *mut u8 = ptr::null_mut();
    let iid: [u8; 16] = [0; 16];
    let hr = unsafe {
        let vt = vtable::<IdxgiSwapChainVtbl>(swapchain);
        (vt.get_buffer)(swapchain, 0, iid.as_ptr(), &mut backbuffer)
    };
    if hr != S_OK {
        return 2;
    }

    // 5. CreateRenderTargetView(backbuffer) → RTV.
    let mut rtv: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d11DeviceVtbl>(device);
        (vt.create_render_target_view)(device, backbuffer, ptr::null(), &mut rtv)
    };
    if hr != S_OK {
        return 3;
    }

    // 6. OMSetRenderTargets(1, &rtv, null).
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        let views: [*mut u8; 1] = [rtv];
        (vt.om_set_render_targets)(context, 1, views.as_ptr(), ptr::null_mut());
    }

    // 7. ClearRenderTargetView(rtv, [0.2, 0.4, 0.8, 1]) — blue.
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        let color: [f32; 4] = [0.2, 0.4, 0.8, 1.0];
        (vt.clear_render_target_view)(context, rtv, color.as_ptr());
    }

    // 8. Flush().
    unsafe {
        let vt = vtable::<Id3d11DeviceContextVtbl>(context);
        (vt.flush)(context);
    }

    // 9. Present(0, 0).
    unsafe {
        let vt = vtable::<IdxgiSwapChainVtbl>(swapchain);
        let _ = (vt.present)(swapchain, 0, 0);
    }

    // 10. PeekMessageW — check for messages (non-blocking, PM_REMOVE=1).
    let mut msg: Msg = core::mem::zeroed();
    let _ = unsafe { PeekMessageW(&mut msg, 0, 0, 0xFFFF, 1) };

    // 11. Success.
    0
}
