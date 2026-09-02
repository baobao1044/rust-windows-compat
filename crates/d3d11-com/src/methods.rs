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

/// An input layout: the owned copy of the D3D11 input-element descriptions.
/// The native pipeline currently hardcodes a single `float2` position binding
/// (matching the triangle sample), so the stored layout is kept for correctness
/// and future milestones but is not yet consumed by the draw path.
pub(crate) struct InputLayoutInner {
    pub elements: Vec<InputElementDesc>,
}

/// Opaque state objects (rasterizer/blend/depth-stencil/sampler/view). The
/// triangle sample never sets any of them (the native draw uses defaults), so
/// they are pure IUnknown shells: the PE can create and `Release` them, which
/// is enough to drive the D3D11 API surface end-to-end.
pub(crate) struct RasterizerStateInner;
pub(crate) struct BlendStateInner;
pub(crate) struct DepthStencilStateInner;
pub(crate) struct DepthStencilViewInner;
pub(crate) struct SamplerStateInner;

// ---------------------------------------------------------------------------
// Windows-side D3D11 description structs (the `#[repr(C)]` layouts a PE fills)
// ---------------------------------------------------------------------------

/// `D3D11_BUFFER_DESC` subset. Only `ByteWidth` and `BindFlags` are read; the
/// remaining fields are accepted and ignored for M7b.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct D3d11BufferDescWin {
    pub byte_width: u32,
    pub usage: u32,
    pub bind_flags: u32,
    pub cpu_access_flags: u32,
    pub misc_flags: u32,
    pub structure_byte_stride: u32,
}

/// `D3D11_SUBRESOURCE_DATA`: the host pointer + pitches for initial data.
#[repr(C)]
pub(crate) struct D3d11SubresourceDataWin {
    pub p_sys_mem: *const c_void,
    pub sys_mem_pitch: u32,
    pub sys_mem_slice_pitch: u32,
}

/// `D3D11_INPUT_ELEMENT_DESC` as the PE lays it out. `SemanticName` is a
/// NUL-terminated C string borrowed from the PE; we copy it into an owned
/// [`InputElementDesc`] so the layout outlives the call.
#[repr(C)]
#[derive(Clone)]
pub(crate) struct D3d11InputElementDescWin {
    pub semantic_name: *const u8,
    pub semantic_index: u32,
    pub format: u32,
    pub input_slot: u32,
    pub aligned_byte_offset: u32,
    pub input_slot_class: u32,
    pub instance_data_step_rate: u32,
}

/// Owned copy of a single input-element description (the semantic name is an
/// owned `String`, so it does not dangle after the PE call returns).
#[derive(Clone)]
pub(crate) struct InputElementDesc {
    pub semantic_name: String,
    pub semantic_index: u32,
    pub format: u32,
    pub input_slot: u32,
    pub aligned_byte_offset: u32,
    pub input_slot_class: u32,
    pub instance_data_step_rate: u32,
}

/// `D3D11_BIND_VERTEX_BUFFER` (0x1), `...INDEX_BUFFER` (0x2),
/// `...CONSTANT_BUFFER` (0x4).
fn map_bind_flags(flags: u32) -> nigg_d3d11::BufferUsage {
    if flags & 0x4 != 0 {
        nigg_d3d11::BufferUsage::Constant
    } else if flags & 0x2 != 0 {
        nigg_d3d11::BufferUsage::Index
    } else {
        nigg_d3d11::BufferUsage::Vertex
    }
}

/// `D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST` = 4. The native pipeline hardcodes
/// `TRIANGLE_LIST`, so any non-triangle topology is logged and still drawn as
/// triangles (M7b only exercises the triangle-list path).
fn map_topology(topology: u32) {
    if topology != 4 {
        log::warn!("d3d11-com: IASetPrimitiveTopology({topology}) — only TRIANGLELIST (4) is honoured by the native pipeline; drawing as triangles");
    }
}

/// Reinterpret a SPIR-V byte blob as the little-endian `u32` word stream the
/// native `create_shader` expects. Returns `None` if the length is not a
/// whole number of words.
///
/// # Safety
/// `bytes` must be a valid SPIR-V bytecode pointer of `len` readable bytes,
/// exactly as the PE hands it to `CreateVertexShader`/`CreatePixelShader`.
//
// `is_multiple_of` (clippy's suggestion) was stabilised in Rust 1.87, but the
// workspace MSRV is 1.75, so the manual `%` check is kept.
#[allow(clippy::manual_is_multiple_of)]
unsafe fn spirv_bytes_to_words(bytes: *const u8, len: usize) -> Option<Vec<u32>> {
    if len == 0 || len % 4 != 0 || bytes.is_null() {
        return None;
    }
    // SAFETY: caller upholds that `bytes..bytes+len` is valid for reading.
    let slice = unsafe { std::slice::from_raw_parts(bytes, len) };
    let n = len / 4;
    let mut words = Vec::with_capacity(n);
    for i in 0..n {
        let b = &slice[i * 4..i * 4 + 4];
        words.push(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    }
    Some(words)
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
iunknown_vtbl!(Id3d11InputLayoutVtbl);
// Generic IUnknown vtable shared by the opaque state objects
// (rasterizer/blend/depth-stencil-state/depth-stencil-view/sampler). They are
// pure shells the PE can create and `Release`; the shared IUnknown thunks
// suffice because `Release` operates on the `ComHeader` prefix.
iunknown_vtbl!(Id3d11StateVtbl);

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

// ---------------------------------------------------------------------------
// ID3D11Device creators (triangle path)
// ---------------------------------------------------------------------------

/// `ID3D11Device::CreateVertexShader(pShaderBytecode, BytecodeLength,
/// pClassLinkage, ppVertexShader)`. Builds a `VkShaderModule` from the SPIR-V
/// bytecode via the native `Device::create_shader(Vertex)`, wraps it in a
/// `ComObject<ShaderInner>` with the vertex-shader vtable, and returns the
/// interface pointer. `pClassLinkage` is ignored (no class linkage in M7b).
extern "C" fn device_create_vertex_shader(
    this: *mut c_void,
    p_shader_bytecode: *const u8,
    bytecode_length: usize,
    _p_class_linkage: *mut c_void,
    pp_vertex_shader: *mut *mut c_void,
) -> i32 {
    if pp_vertex_shader.is_null() || p_shader_bytecode.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_shader_bytecode` is a SPIR-V byte blob of `bytecode_length`
    // readable bytes per the D3D11 contract; `this` is a live device COM object.
    let words = unsafe { spirv_bytes_to_words(p_shader_bytecode, bytecode_length) };
    let words = match words {
        Some(w) => w,
        None => {
            log::warn!("d3d11-com: CreateVertexShader: invalid bytecode length {bytecode_length}");
            return E_INVALIDARG;
        }
    };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev
        .device
        .create_shader(&words, nigg_d3d11::ShaderStage::Vertex)
    {
        Ok(shader) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().vertex_shader as *const c_void,
                ShaderInner { shader },
            );
            // SAFETY: `pp_vertex_shader` is a valid out-pointer per the contract.
            unsafe { *pp_vertex_shader = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d11-com: CreateVertexShader failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D11Device::CreatePixelShader` — the pixel-stage twin of
/// [`device_create_vertex_shader`].
extern "C" fn device_create_pixel_shader(
    this: *mut c_void,
    p_shader_bytecode: *const u8,
    bytecode_length: usize,
    _p_class_linkage: *mut c_void,
    pp_pixel_shader: *mut *mut c_void,
) -> i32 {
    if pp_pixel_shader.is_null() || p_shader_bytecode.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_shader_bytecode` is a SPIR-V byte blob of `bytecode_length`
    // readable bytes per the D3D11 contract; `this` is a live device COM object.
    let words = unsafe { spirv_bytes_to_words(p_shader_bytecode, bytecode_length) };
    let words = match words {
        Some(w) => w,
        None => {
            log::warn!("d3d11-com: CreatePixelShader: invalid bytecode length {bytecode_length}");
            return E_INVALIDARG;
        }
    };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev
        .device
        .create_shader(&words, nigg_d3d11::ShaderStage::Pixel)
    {
        Ok(shader) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().pixel_shader as *const c_void,
                ShaderInner { shader },
            );
            // SAFETY: `pp_pixel_shader` is a valid out-pointer per the contract.
            unsafe { *pp_pixel_shader = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d11-com: CreatePixelShader failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D11Device::CreateBuffer(pDesc, pInitialData, ppBuffer)`. Reads the
/// Windows `D3D11_BUFFER_DESC` (ByteWidth + BindFlags), maps the bind flags to
/// a `BufferUsage`, optionally copies the initial data from the
/// `D3D11_SUBRESOURCE_DATA` host pointer, and delegates to the native
/// `Device::create_buffer`.
extern "C" fn device_create_buffer(
    this: *mut c_void,
    p_desc: *const D3d11BufferDescWin,
    p_initial_data: *const D3d11SubresourceDataWin,
    pp_buffer: *mut *mut c_void,
) -> i32 {
    if pp_buffer.is_null() || p_desc.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_desc` is a valid `D3D11_BUFFER_DESC` provided by the PE; `this`
    // is a live device COM object. `p_initial_data` may be null (no init data).
    let (desc_win, initial) = unsafe {
        let desc = &*p_desc;
        let initial = if p_initial_data.is_null() {
            None
        } else {
            // SAFETY: `p_initial_data` is a valid `D3D11_SUBRESOURCE_DATA` per
            // the contract; `p_sys_mem` points to `byte_width` readable bytes.
            let data = &*p_initial_data;
            if data.p_sys_mem.is_null() {
                None
            } else {
                Some(std::slice::from_raw_parts(
                    data.p_sys_mem as *const u8,
                    desc.byte_width as usize,
                ))
            }
        };
        (desc, initial)
    };
    let native_desc = nigg_d3d11::BufferDesc {
        size: desc_win.byte_width as u64,
        usage: map_bind_flags(desc_win.bind_flags),
    };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev.device.create_buffer(native_desc, initial) {
        Ok(buffer) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().buffer as *const c_void,
                BufferInner { buffer },
            );
            // SAFETY: `pp_buffer` is a valid out-pointer per the contract.
            unsafe { *pp_buffer = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d11-com: CreateBuffer failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D11Device::CreateInputLayout(pInputElementDescs, NumElements,
/// pShaderBytecode, BytecodeLength, ppInputLayout)`. Copies the input-element
/// descriptions (owning the semantic-name strings) into a
/// `ComObject<InputLayoutInner>`. The native pipeline currently hardcodes the
/// `float2 POSITION` vertex binding, so the layout is stored for correctness
/// but not yet consumed by the draw path.
extern "C" fn device_create_input_layout(
    this: *mut c_void,
    p_input_element_descs: *const D3d11InputElementDescWin,
    num_elements: u32,
    _p_shader_bytecode: *const u8,
    _bytecode_length: usize,
    pp_input_layout: *mut *mut c_void,
) -> i32 {
    if pp_input_layout.is_null() {
        return E_INVALIDARG;
    }
    if p_input_element_descs.is_null() && num_elements != 0 {
        return E_INVALIDARG;
    }
    // SAFETY: `p_input_element_descs` points to `num_elements` valid
    // `D3D11_INPUT_ELEMENT_DESC` structs per the contract.
    let descs: Vec<D3d11InputElementDescWin> = if num_elements == 0 {
        Vec::new()
    } else {
        // SAFETY: `p_input_element_descs` points to `num_elements` valid structs
        // per the D3D11 contract; copying them into an owned Vec keeps them
        // valid beyond the (borrowed) PE-side lifetime.
        unsafe { std::slice::from_raw_parts(p_input_element_descs, num_elements as usize).to_vec() }
    };
    let mut elements = Vec::with_capacity(descs.len());
    for d in descs {
        // SAFETY: `semantic_name` is a NUL-terminated C string per the contract.
        let name = if d.semantic_name.is_null() {
            String::new()
        } else {
            unsafe { c_str_to_string(d.semantic_name) }
        };
        elements.push(InputElementDesc {
            semantic_name: name,
            semantic_index: d.semantic_index,
            format: d.format,
            input_slot: d.input_slot,
            aligned_byte_offset: d.aligned_byte_offset,
            input_slot_class: d.input_slot_class,
            instance_data_step_rate: d.instance_data_step_rate,
        });
    }
    // `this` is only used to validate the device is live; the layout does not
    // need device resources. Keep the borrow to mirror the other creators.
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let _ = unsafe { inner::<DeviceInner>(this) };
    let ptr = crate::ComObject::into_raw(
        vtables().input_layout as *const c_void,
        InputLayoutInner { elements },
    );
    // SAFETY: `pp_input_layout` is a valid out-pointer per the contract.
    unsafe { *pp_input_layout = ptr };
    S_OK
}

/// Copy a NUL-terminated C string into an owned `String`.
///
/// # Safety
/// `p` must point to a valid NUL-terminated UTF-8 byte string.
unsafe fn c_str_to_string(p: *const u8) -> String {
    // SAFETY: `p` is a valid NUL-terminated C string; the loop reads up to the
    // NUL, which is within the allocation per the contract.
    let len = unsafe {
        let mut n = 0usize;
        while *p.add(n) != 0 {
            n += 1;
        }
        n
    };
    // SAFETY: `p..p+len` are valid, non-NUL bytes; copying them into a String
    // via the byte slice is sound.
    let bytes = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// `ID3D11Device::CreateRasterizerState(pDesc, ppRasterizerState)` — stores the
/// desc opaquely and returns a shell `ComObject`. The native draw uses defaults.
extern "C" fn device_create_rasterizer_state(
    _this: *mut c_void,
    _p_desc: *const c_void,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: freshly built COM object with the shared state vtable.
    let ptr = crate::ComObject::into_raw(vtables().state as *const c_void, RasterizerStateInner);
    // SAFETY: `pp` is a valid out-pointer per the contract.
    unsafe { *pp = ptr };
    S_OK
}

/// `ID3D11Device::CreateBlendState` — shell `ComObject` (see
/// [`device_create_rasterizer_state`]).
extern "C" fn device_create_blend_state(
    _this: *mut c_void,
    _p_desc: *const c_void,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    let ptr = crate::ComObject::into_raw(vtables().state as *const c_void, BlendStateInner);
    // SAFETY: `pp` is a valid out-pointer per the contract.
    unsafe { *pp = ptr };
    S_OK
}

/// `ID3D11Device::CreateDepthStencilState` — shell `ComObject`.
extern "C" fn device_create_depth_stencil_state(
    _this: *mut c_void,
    _p_desc: *const c_void,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    let ptr = crate::ComObject::into_raw(vtables().state as *const c_void, DepthStencilStateInner);
    // SAFETY: `pp` is a valid out-pointer per the contract.
    unsafe { *pp = ptr };
    S_OK
}

/// `ID3D11Device::CreateDepthStencilView(pResource, pDesc, ppDepthStencilView)`
/// — shell `ComObject`. The triangle sample uses no depth/stencil.
extern "C" fn device_create_depth_stencil_view(
    _this: *mut c_void,
    _p_resource: *mut c_void,
    _p_desc: *const c_void,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    let ptr = crate::ComObject::into_raw(vtables().state as *const c_void, DepthStencilViewInner);
    // SAFETY: `pp` is a valid out-pointer per the contract.
    unsafe { *pp = ptr };
    S_OK
}

/// `ID3D11Device::CreateSamplerState` — shell `ComObject`.
extern "C" fn device_create_sampler_state(
    _this: *mut c_void,
    _p_desc: *const c_void,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    let ptr = crate::ComObject::into_raw(vtables().state as *const c_void, SamplerStateInner);
    // SAFETY: `pp` is a valid out-pointer per the contract.
    unsafe { *pp = ptr };
    S_OK
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

// ---------------------------------------------------------------------------
// ID3D11DeviceContext methods (triangle path)
// ---------------------------------------------------------------------------

/// `ID3D11DeviceContext::VSSetShader(pVertexShader, ppClassInstances, ...)`.
/// Extracts the native `Shader` from the COM object and binds it on the
/// context. The class-instance arguments are ignored (M7b has none).
extern "C" fn context_vs_set_shader(
    this: *mut c_void,
    p_vertex_shader: *mut c_void,
    _pp_class_instances: *const *mut c_void,
    _num_class_instances: u32,
) {
    if p_vertex_shader.is_null() {
        return;
    }
    // SAFETY: `p_vertex_shader` is a live vertex-shader COM object; `this` is a
    // live context COM object.
    unsafe {
        let shader = inner::<ShaderInner>(p_vertex_shader);
        let ctx = inner_mut::<ContextInner>(this);
        ctx.ctx.vs_set_shader(&shader.shader);
    }
}

/// `ID3D11DeviceContext::PSSetShader` — the pixel-stage twin of
/// [`context_vs_set_shader`].
extern "C" fn context_ps_set_shader(
    this: *mut c_void,
    p_pixel_shader: *mut c_void,
    _pp_class_instances: *const *mut c_void,
    _num_class_instances: u32,
) {
    if p_pixel_shader.is_null() {
        return;
    }
    // SAFETY: `p_pixel_shader` is a live pixel-shader COM object; `this` is a
    // live context COM object.
    unsafe {
        let shader = inner::<ShaderInner>(p_pixel_shader);
        let ctx = inner_mut::<ContextInner>(this);
        ctx.ctx.ps_set_shader(&shader.shader);
    }
}

/// `ID3D11DeviceContext::IASetVertexBuffers(StartSlot, NumBuffers,
/// ppVertexBuffers, pStrides, pOffsets)`. Binds the first vertex buffer (slot
/// 0) to the native context. Only slot 0 is honoured by the native pipeline;
/// additional buffers are accepted and ignored.
extern "C" fn context_ia_set_vertex_buffers(
    this: *mut c_void,
    _start_slot: u32,
    num_buffers: u32,
    pp_vertex_buffers: *const *mut c_void,
    _p_strides: *const u64,
    p_offsets: *const u32,
) {
    if num_buffers == 0 || pp_vertex_buffers.is_null() {
        return;
    }
    // SAFETY: `pp_vertex_buffers` points to `num_buffers` interface pointers.
    let vb_ptr = unsafe { *pp_vertex_buffers };
    if vb_ptr.is_null() {
        return;
    }
    let offset = if p_offsets.is_null() {
        0
    } else {
        // SAFETY: `p_offsets` points to `num_buffers` u32 offsets per the contract.
        unsafe { *p_offsets as u64 }
    };
    // SAFETY: `vb_ptr` is a live buffer COM object; `this` is a live context.
    unsafe {
        let buf = inner::<BufferInner>(vb_ptr);
        let ctx = inner_mut::<ContextInner>(this);
        ctx.ctx.ia_set_vertex_buffers(&buf.buffer, offset);
    }
}

/// `ID3D11DeviceContext::IASetInputLayout(pInputLayout)`. The native pipeline
/// hardcodes the `float2 POSITION` binding, so the layout is accepted but not
/// consumed; storing it would require a context-side field the native API does
/// not expose yet.
extern "C" fn context_ia_set_input_layout(_this: *mut c_void, _p_input_layout: *mut c_void) {
    // Accepted; the native pipeline builds the vertex input from the bound
    // vertex buffer's stride (hardcoded 2*f32) at pipeline-creation time.
}

/// `ID3D11DeviceContext::IASetPrimitiveTopology(Topology)`. Maps the D3D11
/// topology to the native pipeline (which hardcodes `TRIANGLE_LIST`); only
/// `D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST` (4) is honoured.
extern "C" fn context_ia_set_primitive_topology(_this: *mut c_void, topology: u32) {
    map_topology(topology);
}

/// `ID3D11DeviceContext::Draw(VertexCount, StartVertexLocation)`. Delegates to
/// the native `DeviceContext::draw` with default rasterizer state (the
/// triangle sample sets no custom rasterizer state).
extern "C" fn context_draw(this: *mut c_void, vertex_count: u32, start_vertex: u32) {
    let _ = start_vertex;
    // SAFETY: `this` is a live context COM object.
    let ctx = unsafe { inner_mut::<ContextInner>(this) };
    if let Err(e) = ctx
        .ctx
        .draw(vertex_count, nigg_d3d11::RasterizerDesc::default())
    {
        log::warn!("d3d11-com: Draw failed: {e}");
    }
}

/// `ID3D11DeviceContext::DrawIndexed(IndexCount, StartIndex, VertexOffset)`.
/// Delegates to the native `DeviceContext::draw_indexed`.
extern "C" fn context_draw_indexed(
    this: *mut c_void,
    index_count: u32,
    start_index: u32,
    vertex_offset: i32,
) {
    let _ = start_index;
    // SAFETY: `this` is a live context COM object.
    let ctx = unsafe { inner_mut::<ContextInner>(this) };
    if let Err(e) = ctx.ctx.draw_indexed(
        index_count,
        vertex_offset,
        nigg_d3d11::RasterizerDesc::default(),
    ) {
        log::warn!("d3d11-com: DrawIndexed failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// No-op stubs for the remaining context setters the triangle sample does not
// call. These are `void` in D3D11; a no-op keeps callers happy. Plain safe fns.
// ---------------------------------------------------------------------------

/// `*SetConstantBuffers` / `*SetShaderResources` / `*SetSamplers` — the
/// triangle sample binds no constant buffers, shader resources, or samplers,
/// so these are accepted and ignored.
extern "C" fn noop_set_ptrs(_this: *mut c_void, _a: u32, _b: u32, _c: *const *mut c_void) {}

/// `IASetIndexBuffer` — the triangle draws non-indexed (`Draw(3, 0)`), so the
/// index buffer setter is accepted and ignored.
extern "C" fn noop_ia_index_buffer(_this: *mut c_void, _a: *mut c_void, _b: u32, _c: u32) {}

/// `UpdateSubresource(pDst, DstSubresource, pDstBox, pSrcData, SrcRowPitch,
/// SrcDepthPitch)` — uploads data to a constant buffer. The triangle sample
/// uses no constant buffers, so this is accepted and ignored.
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

/// `Map` — returns `E_NOTIMPL` (the triangle uses no dynamic resources).
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

/// `Unmap` — a void no-op (the triangle uses no dynamic resources).
extern "C" fn noop_unmap(_this: *mut c_void, _a: *mut c_void, _b: u32) {}

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
    pub input_layout: *const Id3d11InputLayoutVtbl,
    pub state: *const Id3d11StateVtbl,
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
            create_vertex_shader: mk(device_create_vertex_shader as *const c_void, 5),
            create_pixel_shader: mk(device_create_pixel_shader as *const c_void, 5),
            create_buffer: mk(device_create_buffer as *const c_void, 4),
            create_input_layout: mk(device_create_input_layout as *const c_void, 6),
            create_rasterizer_state: mk(device_create_rasterizer_state as *const c_void, 3),
            create_blend_state: mk(device_create_blend_state as *const c_void, 3),
            create_depth_stencil_state: mk(device_create_depth_stencil_state as *const c_void, 3),
            create_depth_stencil_view: mk(device_create_depth_stencil_view as *const c_void, 4),
            create_sampler_state: mk(device_create_sampler_state as *const c_void, 3),
            get_immediate_context: mk(device_get_immediate_context as *const c_void, 2),
        })) as *const Id3d11DeviceVtbl;

        let context = Box::into_raw(Box::new(Id3d11DeviceContextVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            om_set_render_targets: mk(context_om_set_render_targets as *const c_void, 4),
            clear_render_target_view: mk(context_clear_render_target_view as *const c_void, 3),
            vs_set_shader: mk(context_vs_set_shader as *const c_void, 4),
            ps_set_shader: mk(context_ps_set_shader as *const c_void, 4),
            vs_set_constant_buffers: mk(noop_set_ptrs as *const c_void, 4),
            ps_set_constant_buffers: mk(noop_set_ptrs as *const c_void, 4),
            vs_set_shader_resources: mk(noop_set_ptrs as *const c_void, 4),
            ps_set_shader_resources: mk(noop_set_ptrs as *const c_void, 4),
            vs_set_samplers: mk(noop_set_ptrs as *const c_void, 4),
            ps_set_samplers: mk(noop_set_ptrs as *const c_void, 4),
            ia_set_vertex_buffers: mk(context_ia_set_vertex_buffers as *const c_void, 6),
            ia_set_index_buffer: mk(noop_ia_index_buffer as *const c_void, 4),
            ia_set_input_layout: mk(context_ia_set_input_layout as *const c_void, 2),
            ia_set_primitive_topology: mk(context_ia_set_primitive_topology as *const c_void, 2),
            update_subresource: mk(noop_update as *const c_void, 7),
            draw: mk(context_draw as *const c_void, 3),
            draw_indexed: mk(context_draw_indexed as *const c_void, 4),
            map: mk(noop_map as *const c_void, 6),
            unmap: mk(noop_unmap as *const c_void, 3),
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
        let input_layout = Box::into_raw(Box::new(Id3d11InputLayoutVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11InputLayoutVtbl;
        let state = Box::into_raw(Box::new(Id3d11StateVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d11StateVtbl;

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
            input_layout,
            state,
        }
    }
}
