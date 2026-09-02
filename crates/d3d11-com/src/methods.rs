//! COM vtable structs, wrapped Rust objects, and the `extern "C"` method
//! implementations that delegate to the existing `nigg-d3d11`/`nigg-dxgi`
//! Vulkan translation.
//!
//! Each vtable is a `#[repr(C)]` struct of `*const c_void` slots. The PE
//! reads a slot as an 8-byte function pointer and `call`s it (Win64 ABI); we
//! store a Win64->SysV thunk address in each slot, so the call lands in our
//! System V method. The slot order is the declaration order in the struct;
//! the hand-written D3D11 sample fixture indexes methods by these exact byte
//! offsets, so the layout is internally consistent. `ComVtables::build`
//! allocates a thunk for every slot (via the loader-supplied callback) and
//! leaks the vtable structs so their addresses stay valid for the PE's
//! lifetime.
//!
//! Declaring the slots as `*const c_void` (rather than typed fn pointers)
//! keeps the layout identical to a real COM vtable while avoiding a generic
//! `transmute` (which the compiler cannot size-check for a generic `F`).

#![allow(clippy::too_many_arguments)] // COM method signatures mirror the Windows ABI.

use std::os::raw::c_void;
use std::sync::Arc;

use ash::vk;

use crate::{com_add_ref, inner, inner_mut, vtables, E_FAIL, E_INVALIDARG, E_NOTIMPL, S_OK};

// ---------------------------------------------------------------------------
// DXGI_SWAP_CHAIN_DESC (the minimal subset we read/write)
// ---------------------------------------------------------------------------

/// The minimal `DXGI_SWAP_CHAIN_DESC` the sample fills and our
/// `D3D11CreateDeviceAndSwapChain` reads. `#[repr(C)]` so the layout matches
/// the PE's struct. Only the fields a headless clear need are modelled.
#[repr(C)]
pub(crate) struct SwapChainDescWin {
    pub width: u32,
    pub height: u32,
    /// `DXGI_FORMAT` numeric value (e.g. 87 = `B8G8R8A8_UNORM`).
    pub format: u32,
    pub buffer_count: u32,
    /// OutputWindow (`HWND`); 0 for headless (no real surface yet).
    pub hwnd: u64,
}

/// Map a `DXGI_FORMAT` numeric value to our `nigg_dxgi::DxgiFormat`, defaulting
/// to the most common swap-chain format for anything unrecognised.
pub(crate) fn map_format(f: u32) -> nigg_dxgi::DxgiFormat {
    // DXGI_FORMAT_B8G8R8A8_UNORM = 87, DXGI_FORMAT_B8G8R8A8_UNORM_SRGB = 91.
    match f {
        91 => nigg_dxgi::DxgiFormat::B8G8R8A8UnormSrgb,
        _ => nigg_dxgi::DxgiFormat::B8G8R8A8Unorm,
    }
}

fn dxgi_format_to_vk(f: nigg_dxgi::DxgiFormat) -> vk::Format {
    match f {
        nigg_dxgi::DxgiFormat::B8G8R8A8Unorm => vk::Format::B8G8R8A8_UNORM,
        nigg_dxgi::DxgiFormat::B8G8R8A8UnormSrgb => vk::Format::B8G8R8A8_SRGB,
    }
}

// ---------------------------------------------------------------------------
// Wrapped Rust objects (the `inner` of each COM object)
// ---------------------------------------------------------------------------

pub(crate) struct FactoryInner {
    pub factory: nigg_dxgi::Factory,
}

pub(crate) struct SwapChainInner {
    pub swapchain: nigg_dxgi::SwapChain,
}

pub(crate) struct DeviceInner {
    pub device: Arc<nigg_d3d11::Device>,
    /// The immediate context COM object, created alongside the device and
    /// handed out by `GetImmediateContext`. Lives until the device is freed.
    pub immediate_ctx: *mut c_void,
}

pub(crate) struct ContextInner {
    pub ctx: nigg_d3d11::DeviceContext,
}

/// A 2D texture handle. `owned` is `Some` when created via `CreateTexture2D`
/// (we own the `VkImage`), and `None` when borrowed from a swap-chain back
/// buffer via `GetBuffer` (the swap chain owns the image).
pub(crate) struct Texture2dInner {
    pub image: vk::Image,
    pub format: vk::Format,
    pub width: u32,
    pub height: u32,
    pub owned: Option<Box<nigg_d3d11::Texture2d>>,
}

pub(crate) struct RtvInner {
    pub rtv: nigg_d3d11::RenderTargetView,
}

pub(crate) struct BufferInner {
    pub buffer: nigg_d3d11::Buffer,
}

pub(crate) struct ShaderInner {
    pub shader: nigg_d3d11::Shader,
}

// ---------------------------------------------------------------------------
// Vtable structs (slots are `*const c_void` = 8 bytes, identical to fn ptrs)
// ---------------------------------------------------------------------------

/// `IDXGIFactory` — minimal: IUnknown + `EnumAdapters` + `CreateSwapChain`
/// (both stubbed for M7a; the sample uses `D3D11CreateDeviceAndSwapChain`).
/// Slot order = declaration order.
#[repr(C)]
pub struct IdxgiFactoryVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub enum_adapters: *const c_void,
    pub create_swap_chain: *const c_void,
}

/// `IDXGISwapChain` — IUnknown + `Present`, `GetBuffer`, `GetDesc`,
/// `ResizeBuffers`. Slot order = declaration order.
#[repr(C)]
pub struct IdxgiSwapChainVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub present: *const c_void,
    pub get_buffer: *const c_void,
    pub get_desc: *const c_void,
    pub resize_buffers: *const c_void,
}

/// `ID3D11Device` — IUnknown + the clear-colour/triangle-relevant creators.
/// Slot order = declaration order.
#[repr(C)]
pub struct Id3d11DeviceVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub create_texture_2d: *const c_void,
    pub create_render_target_view: *const c_void,
    pub create_vertex_shader: *const c_void,
    pub create_pixel_shader: *const c_void,
    pub create_buffer: *const c_void,
    pub create_input_layout: *const c_void,
    pub create_rasterizer_state: *const c_void,
    pub create_blend_state: *const c_void,
    pub create_depth_stencil_state: *const c_void,
    pub create_depth_stencil_view: *const c_void,
    pub create_sampler_state: *const c_void,
    pub get_immediate_context: *const c_void,
}

/// `ID3D11DeviceContext` — IUnknown + the clear/triangle methods. Slot order
/// = declaration order.
#[repr(C)]
pub struct Id3d11DeviceContextVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub om_set_render_targets: *const c_void,
    pub clear_render_target_view: *const c_void,
    pub vs_set_shader: *const c_void,
    pub ps_set_shader: *const c_void,
    pub vs_set_constant_buffers: *const c_void,
    pub ps_set_constant_buffers: *const c_void,
    pub vs_set_shader_resources: *const c_void,
    pub ps_set_shader_resources: *const c_void,
    pub vs_set_samplers: *const c_void,
    pub ps_set_samplers: *const c_void,
    pub ia_set_vertex_buffers: *const c_void,
    pub ia_set_index_buffer: *const c_void,
    pub ia_set_input_layout: *const c_void,
    pub ia_set_primitive_topology: *const c_void,
    pub update_subresource: *const c_void,
    pub draw: *const c_void,
    pub draw_indexed: *const c_void,
    pub map: *const c_void,
    pub unmap: *const c_void,
    pub flush: *const c_void,
}

/// Opaque resource vtables (just IUnknown).
macro_rules! iunknown_vtbl {
    ($name:ident) => {
        #[repr(C)]
        pub struct $name {
            pub query_interface: *const c_void,
            pub add_ref: *const c_void,
            pub release: *const c_void,
        }
    };
}

iunknown_vtbl!(Id3d11Texture2dVtbl);
iunknown_vtbl!(Id3d11RenderTargetViewVtbl);
iunknown_vtbl!(Id3d11BufferVtbl);
iunknown_vtbl!(Id3d11VertexShaderVtbl);
iunknown_vtbl!(Id3d11PixelShaderVtbl);

// ---------------------------------------------------------------------------
// IDXGISwapChain methods
// ---------------------------------------------------------------------------

extern "C" fn swapchain_present(this: *mut c_void, sync: u32, _flags: u32) -> i32 {
    // SAFETY: `this` is a live `*mut ComObject<SwapChainInner>` per the COM contract.
    unsafe {
        let sc = inner_mut::<SwapChainInner>(this);
        // Present is best-effort for M7a: the clear already happened (recorded +
        // flushed by the context); a present error must not abort the sample.
        if let Err(e) = sc.swapchain.present(sync) {
            log::warn!("d3d11-com: Present failed (ignored): {e}");
        }
    }
    S_OK
}

extern "C" fn swapchain_get_buffer(
    this: *mut c_void,
    index: u32,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `this` is a live swap-chain COM object; `pp` is a valid out-pointer.
    unsafe {
        let sc = inner::<SwapChainInner>(this);
        let image = match sc.swapchain.get_buffer(index as usize) {
            Ok(i) => i,
            Err(e) => {
                log::warn!("d3d11-com: GetBuffer({index}) failed: {e}");
                return E_FAIL;
            }
        };
        let desc = sc.swapchain.desc();
        let format = dxgi_format_to_vk(desc.format);
        let tex = Texture2dInner {
            image,
            format,
            width: desc.width,
            height: desc.height,
            owned: None,
        };
        let ptr = crate::ComObject::into_raw(vtables().texture2d as *const c_void, tex);
        *pp = ptr;
        S_OK
    }
}

extern "C" fn swapchain_get_desc(this: *mut c_void, pdesc: *mut SwapChainDescWin) -> i32 {
    if pdesc.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `this` is a live swap-chain COM object; `pdesc` is a valid out-pointer.
    unsafe {
        let sc = inner::<SwapChainInner>(this);
        let desc = sc.swapchain.desc();
        let format_num = match desc.format {
            nigg_dxgi::DxgiFormat::B8G8R8A8Unorm => 87,
            nigg_dxgi::DxgiFormat::B8G8R8A8UnormSrgb => 91,
        };
        *pdesc = SwapChainDescWin {
            width: desc.width,
            height: desc.height,
            format: format_num,
            buffer_count: desc.buffer_count,
            hwnd: 0,
        };
    }
    S_OK
}

extern "C" fn swapchain_resize_buffers(
    this: *mut c_void,
    _buf_count: u32,
    width: u32,
    height: u32,
    _format: u32,
    _flags: u32,
) -> i32 {
    // SAFETY: `this` is a live swap-chain COM object.
    unsafe {
        let sc = inner_mut::<SwapChainInner>(this);
        if let Err(e) = sc.swapchain.resize_buffers(width, height) {
            log::warn!("d3d11-com: ResizeBuffers failed (ignored): {e}");
        }
    }
    S_OK
}

// ---------------------------------------------------------------------------
// ID3D11Device methods
// ---------------------------------------------------------------------------

extern "C" fn device_create_render_target_view(
    this: *mut c_void,
    presource: *mut c_void,
    _pdesc: *const c_void,
    ppview: *mut *mut c_void,
) -> i32 {
    if ppview.is_null() || presource.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `presource` is an `ID3D11Texture2D*` COM object we created (via
    // `GetBuffer` or `CreateTexture2D`); `this` is a live device COM object.
    unsafe {
        let tex = inner::<Texture2dInner>(presource);
        let dev = inner::<DeviceInner>(this);
        match dev
            .device
            .create_render_target_view_from_image(tex.image, tex.format, tex.width, tex.height)
        {
            Ok(rtv) => {
                let ptr =
                    crate::ComObject::into_raw(vtables().rtv as *const c_void, RtvInner { rtv });
                *ppview = ptr;
                S_OK
            }
            Err(e) => {
                log::warn!("d3d11-com: CreateRenderTargetView failed: {e}");
                E_FAIL
            }
        }
    }
}

extern "C" fn device_get_immediate_context(this: *mut c_void, ppcontext: *mut *mut c_void) {
    if ppcontext.is_null() {
        return;
    }
    // SAFETY: `this` is a live device COM object; `immediate_ctx` is the context
    // COM object allocated alongside it; `ppcontext` is a valid out-pointer.
    unsafe {
        let dev = inner::<DeviceInner>(this);
        let ctx = dev.immediate_ctx;
        // Hand out the shared immediate context, AddRef'd so the PE's Release balances.
        com_add_ref(ctx);
        *ppcontext = ctx;
    }
}

// Stubs for the remaining ID3D11Device creators the clear sample does not call.
// They return E_NOTIMPL so a caller can detect the gap; the M7a sample never
// invokes them. Plain safe `extern "C" fn` (no unsafe operations).
extern "C" fn stub_create4(
    _this: *mut c_void,
    _a: *const c_void,
    _b: *const c_void,
    _c: *mut *mut c_void,
) -> i32 {
    E_NOTIMPL
}

extern "C" fn stub_create_shader(
    _this: *mut c_void,
    _a: *const u8,
    _b: usize,
    _c: *mut c_void,
    _d: *mut *mut c_void,
) -> i32 {
    E_NOTIMPL
}

extern "C" fn stub_create_input_layout(
    _this: *mut c_void,
    _a: *const c_void,
    _b: u32,
    _c: *const u8,
    _d: usize,
    _e: *mut *mut c_void,
) -> i32 {
    E_NOTIMPL
}

extern "C" fn stub_create_state(
    _this: *mut c_void,
    _a: *const c_void,
    _b: *mut *mut c_void,
) -> i32 {
    E_NOTIMPL
}

extern "C" fn stub_create_dsv(
    _this: *mut c_void,
    _a: *mut c_void,
    _b: *const c_void,
    _c: *mut *mut c_void,
) -> i32 {
    E_NOTIMPL
}

// ---------------------------------------------------------------------------
// ID3D11DeviceContext methods
// ---------------------------------------------------------------------------

extern "C" fn context_om_set_render_targets(
    this: *mut c_void,
    num_views: u32,
    ppviews: *const *mut c_void,
    _pdepth: *mut c_void,
) {
    if num_views == 0 || ppviews.is_null() {
        return;
    }
    // SAFETY: `ppviews` points to `num_views` interface pointers.
    let rtv_ptr = unsafe { *ppviews };
    if rtv_ptr.is_null() {
        return;
    }
    // SAFETY: `rtv_ptr` is a live RTV COM object; `this` is a live context.
    unsafe {
        let rtv = inner::<RtvInner>(rtv_ptr);
        let ctx = inner_mut::<ContextInner>(this);
        if let Err(e) = ctx.ctx.om_set_render_targets(&rtv.rtv) {
            log::warn!("d3d11-com: OMSetRenderTargets failed: {e}");
        }
    }
}

extern "C" fn context_clear_render_target_view(
    this: *mut c_void,
    prtview: *mut c_void,
    color: *const f32,
) {
    if prtview.is_null() {
        return;
    }
    // Default to opaque black if the caller passed no colour pointer.
    let col: [f32; 4] = if color.is_null() {
        [0.0, 0.0, 0.0, 1.0]
    } else {
        // SAFETY: `color` points to a 4-float array per the D3D11 contract.
        unsafe { *(color as *const [f32; 4]) }
    };
    // SAFETY: `prtview` is a live RTV COM object; `this` is a live context.
    unsafe {
        let rtv = inner::<RtvInner>(prtview);
        let ctx = inner_mut::<ContextInner>(this);
        if let Err(e) = ctx.ctx.clear_render_target_view(&rtv.rtv, col) {
            log::warn!("d3d11-com: ClearRenderTargetView failed: {e}");
        }
    }
}

extern "C" fn context_flush(this: *mut c_void) {
    // SAFETY: `this` is a live context COM object.
    unsafe {
        let ctx = inner_mut::<ContextInner>(this);
        if let Err(e) = ctx.ctx.flush() {
            log::warn!("d3d11-com: Flush failed: {e}");
        }
    }
}

// No-op stubs for the context setters/draws the clear sample does not call.
// These are `void` in D3D11; a no-op keeps callers happy. Plain safe fns.
extern "C" fn noop0(_this: *mut c_void) {}
extern "C" fn noop1(_this: *mut c_void, _a: u32) {}
extern "C" fn noop2(_this: *mut c_void, _a: u32, _b: u32) {}
extern "C" fn noop3(_this: *mut c_void, _a: u32, _b: u32, _c: i32) {}
extern "C" fn noop_set_ptrs(_this: *mut c_void, _a: u32, _b: u32, _c: *const *mut c_void) {}
extern "C" fn noop_set_shader(
    _this: *mut c_void,
    _a: *mut c_void,
    _b: *const *mut c_void,
    _c: u32,
) {
}
extern "C" fn noop_ia_vertex_buffers(
    _this: *mut c_void,
    _a: u32,
    _b: u32,
    _c: *const *mut c_void,
    _d: *const u64,
    _e: *const u32,
) {
}
extern "C" fn noop_ia_index_buffer(_this: *mut c_void, _a: *mut c_void, _b: u32, _c: u32) {}
extern "C" fn noop_ia_input_layout(_this: *mut c_void, _a: *mut c_void) {}
extern "C" fn noop_update(
    _this: *mut c_void,
    _a: *mut c_void,
    _b: u32,
    _c: *const c_void,
    _d: *const c_void,
    _e: u32,
    _f: u32,
) {
}
extern "C" fn noop_map(
    _this: *mut c_void,
    _a: *mut c_void,
    _b: u32,
    _c: u32,
    _d: u32,
    _e: *mut c_void,
) -> i32 {
    E_NOTIMPL
}

extern "C" fn factory_enum_adapters(_this: *mut c_void, _index: u32, _pp: *mut *mut c_void) -> i32 {
    E_NOTIMPL
}

extern "C" fn factory_create_swap_chain(
    _this: *mut c_void,
    _adapter: *mut c_void,
    _desc: *const SwapChainDescWin,
    _pp: *mut *mut c_void,
) -> i32 {
    E_NOTIMPL
}

// ---------------------------------------------------------------------------
// ComVtables: pre-built, leaked vtables
// ---------------------------------------------------------------------------

/// The set of pre-built COM vtables. Each field is the address of a leaked
/// `*Vtbl` struct whose slots hold Win64->SysV thunk pointers. Stored in the
/// process-global registry at PE load time and read by the import-level
/// functions and by `GetImmediateContext`.
pub struct ComVtables {
    pub factory: *const IdxgiFactoryVtbl,
    pub swapchain: *const IdxgiSwapChainVtbl,
    pub device: *const Id3d11DeviceVtbl,
    pub context: *const Id3d11DeviceContextVtbl,
    pub texture2d: *const Id3d11Texture2dVtbl,
    pub rtv: *const Id3d11RenderTargetViewVtbl,
    pub buffer: *const Id3d11BufferVtbl,
    pub vertex_shader: *const Id3d11VertexShaderVtbl,
    pub pixel_shader: *const Id3d11PixelShaderVtbl,
}

// SAFETY: `ComVtables` holds only raw addresses of leaked vtable structs and
// thunk pointers. All are immutable and valid for the process lifetime; the
// registry is read-only after `install_vtables`. The COM objects themselves
// are not `Sync`, but the vtable registry (this struct) is never mutated after
// install, so sharing it across threads is sound.
unsafe impl Send for ComVtables {}
unsafe impl Sync for ComVtables {}

impl ComVtables {
    /// Allocate a thunk for every vtable slot, fill the vtable structs, and
    /// leak them (stable addresses for the PE's lifetime). `make_thunk(target,
    /// n_args)` returns a Win64->SysV trampoline for the System V `extern "C"`
    /// function `target` taking `n_args` integer/pointer arguments.
    pub(crate) fn build(make_thunk: &mut dyn FnMut(*const c_void, u8) -> *const c_void) -> Self {
        // Shared IUnknown thunks (reused in every vtable's first three slots).
        let qi = make_thunk(crate::com_query_interface as *const c_void, 3);
        let ar = make_thunk(crate::com_add_ref as *const c_void, 1);
        let rl = make_thunk(crate::com_release as *const c_void, 1);

        let mut mk = |target: *const c_void, n: u8| -> *const c_void { make_thunk(target, n) };

        let factory = Box::into_raw(Box::new(IdxgiFactoryVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            enum_adapters: mk(factory_enum_adapters as *const c_void, 3),
            create_swap_chain: mk(factory_create_swap_chain as *const c_void, 4),
        })) as *const IdxgiFactoryVtbl;

        let swapchain = Box::into_raw(Box::new(IdxgiSwapChainVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            present: mk(swapchain_present as *const c_void, 3),
            get_buffer: mk(swapchain_get_buffer as *const c_void, 4),
            get_desc: mk(swapchain_get_desc as *const c_void, 2),
            resize_buffers: mk(swapchain_resize_buffers as *const c_void, 6),
        })) as *const IdxgiSwapChainVtbl;

        let device = Box::into_raw(Box::new(Id3d11DeviceVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            create_texture_2d: mk(stub_create4 as *const c_void, 4),
            create_render_target_view: mk(device_create_render_target_view as *const c_void, 4),
            create_vertex_shader: mk(stub_create_shader as *const c_void, 5),
            create_pixel_shader: mk(stub_create_shader as *const c_void, 5),
            create_buffer: mk(stub_create4 as *const c_void, 4),
            create_input_layout: mk(stub_create_input_layout as *const c_void, 5),
            create_rasterizer_state: mk(stub_create_state as *const c_void, 3),
            create_blend_state: mk(stub_create_state as *const c_void, 3),
            create_depth_stencil_state: mk(stub_create_state as *const c_void, 3),
            create_depth_stencil_view: mk(stub_create_dsv as *const c_void, 4),
            create_sampler_state: mk(stub_create_state as *const c_void, 3),
            get_immediate_context: mk(device_get_immediate_context as *const c_void, 2),
        })) as *const Id3d11DeviceVtbl;

        let context = Box::into_raw(Box::new(Id3d11DeviceContextVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            om_set_render_targets: mk(context_om_set_render_targets as *const c_void, 4),
            clear_render_target_view: mk(context_clear_render_target_view as *const c_void, 3),
            vs_set_shader: mk(noop_set_shader as *const c_void, 4),
            ps_set_shader: mk(noop_set_shader as *const c_void, 4),
            vs_set_constant_buffers: mk(noop_set_ptrs as *const c_void, 4),
            ps_set_constant_buffers: mk(noop_set_ptrs as *const c_void, 4),
            vs_set_shader_resources: mk(noop_set_ptrs as *const c_void, 4),
            ps_set_shader_resources: mk(noop_set_ptrs as *const c_void, 4),
            vs_set_samplers: mk(noop_set_ptrs as *const c_void, 4),
            ps_set_samplers: mk(noop_set_ptrs as *const c_void, 4),
            ia_set_vertex_buffers: mk(noop_ia_vertex_buffers as *const c_void, 5),
            ia_set_index_buffer: mk(noop_ia_index_buffer as *const c_void, 4),
            ia_set_input_layout: mk(noop_ia_input_layout as *const c_void, 2),
            ia_set_primitive_topology: mk(noop1 as *const c_void, 2),
            update_subresource: mk(noop_update as *const c_void, 7),
            draw: mk(noop2 as *const c_void, 3),
            draw_indexed: mk(noop3 as *const c_void, 4),
            map: mk(noop_map as *const c_void, 6),
            unmap: mk(noop2 as *const c_void, 3),
            flush: mk(context_flush as *const c_void, 1),
        })) as *const Id3d11DeviceContextVtbl;

        let texture2d = Box::into_raw(Box::new(Id3d11Texture2dVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11Texture2dVtbl;
        let rtv = Box::into_raw(Box::new(Id3d11RenderTargetViewVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11RenderTargetViewVtbl;
        let buffer = Box::into_raw(Box::new(Id3d11BufferVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11BufferVtbl;
        let vertex_shader = Box::into_raw(Box::new(Id3d11VertexShaderVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11VertexShaderVtbl;
        let pixel_shader = Box::into_raw(Box::new(Id3d11PixelShaderVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11PixelShaderVtbl;

        ComVtables {
            factory,
            swapchain,
            device,
            context,
            texture2d,
            rtv,
            buffer,
            vertex_shader,
            pixel_shader,
        }
    }
}
