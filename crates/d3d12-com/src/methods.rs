//! COM vtable structs, wrapped Rust objects, and the `extern "C"` method
//! implementations that delegate to the existing `nigg-d3d12`/`nigg-dxgi`
//! Vulkan translation.
//!
//! Each vtable is a `#[repr(C)]` struct of `*const c_void` slots. The PE reads
//! a slot as an 8-byte function pointer and `call`s it (Win64 ABI); we store a
//! Win64->SysV thunk address in each slot, so the call lands in our System V
//! method. The slot order is the declaration order in the struct; the
//! hand-written D3D12 sample fixture indexes methods by these exact byte
//! offsets, so the layout is internally consistent. `ComVtables::build`
//! allocates a thunk for every slot (via the loader-supplied callback) and
//! leaks the vtable structs so their addresses stay valid for the PE's
//! lifetime.
//!
//! Declaring the slots as `*const c_void` (rather than typed fn pointers)
//! keeps the layout identical to a real COM vtable while avoiding a generic
//! `transmute` (which the compiler cannot size-check for a generic `F`).
//!
//! # CPU descriptor handle convention (M8b)
//!
//! Real D3D12 obtains a heap's first descriptor handle via
//! `ID3D12DescriptorHeap::GetCPUDescriptorHandleForHeapStart` (a per-heap base
//! pointer the app offsets by `GetDescriptorHandleIncrementSize`). The M8b
//! heap vtable is just `IUnknown` for now, so this crate uses an internally
//! consistent, minimal encoding instead: the CPU descriptor handle a PE passes
//! to `CreateRenderTargetView` / `SetRenderTargets` / `ClearRenderTargetView`
//! is the **descriptor heap COM object's interface pointer** (cast to `u64`),
//! and the descriptor index is `0` (the clear-screen sample uses a single RTV
//! at slot 0). The COM method casts the handle back to the heap COM object,
//! borrows its `DescriptorHeap` inner, and operates on slot 0. This is a
//! documented simplification; full heap-handle arithmetic is deferred.

#![allow(clippy::too_many_arguments)] // COM method signatures mirror the Windows ABI.

use std::os::raw::c_void;
use std::sync::Arc;

use crate::{inner, inner_mut, vtables, E_FAIL, E_INVALIDARG, S_OK};

// ---------------------------------------------------------------------------
// Windows-side D3D12 description structs (the `#[repr(C)]` layouts a PE fills)
// ---------------------------------------------------------------------------

/// `D3D12_COMMAND_QUEUE_DESC` subset. Only `Type` (the command list type) is
/// read; the remaining fields are accepted for layout parity.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CommandQueueDescWin {
    /// `D3D12_COMMAND_LIST_TYPE` (0 = DIRECT).
    pub list_type: u32,
    pub priority: i32,
    pub flags: u32,
    pub node_mask: u32,
}

/// `D3D12_DESCRIPTOR_HEAP_DESC` subset. `Type` and `NumDescriptors` are read;
/// the remaining fields are accepted for layout parity.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct DescriptorHeapDescWin {
    /// `D3D12_DESCRIPTOR_HEAP_TYPE` (2 = RTV).
    pub heap_type: u32,
    pub num_descriptors: u32,
    pub flags: u32,
    pub node_mask: u32,
}

/// `D3D12_HEAP_PROPERTIES` subset. Only `Type` (the heap type) is read; the
/// remaining fields are accepted for layout parity.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct HeapPropertiesWin {
    /// `D3D12_HEAP_TYPE` (0 = DEFAULT, 1 = UPLOAD, 2 = READBACK).
    pub heap_type: u32,
    pub cpu_page_property: u32,
    pub memory_pool_preference: u32,
    pub creation_node_mask: u32,
    pub visible_node_mask: u32,
}

/// `D3D12_RESOURCE_DESC` subset, laid out to match the real struct's field
/// order/offsets. Only the texture-relevant fields are read.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ResourceDescWin {
    /// `D3D12_RESOURCE_DIMENSION` (2 = TEXTURE2D).
    pub dimension: u32,
    pub alignment: u64,
    pub width: u64,
    pub height: u32,
    pub depth_or_array_size: u16,
    pub mip_levels: u16,
    /// `DXGI_FORMAT` numeric value (e.g. 87 = `B8G8R8A8_UNORM`).
    pub format: u32,
    pub sample_count: u32,
    pub sample_quality: u32,
    pub layout: u32,
    pub flags: u32,
}

/// `D3D12_RESOURCE_BARRIER` (transition variant) as the PE lays it out. The
/// clear-screen sample only issues `TRANSITION` barriers (`barrier_type == 0`).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ResourceBarrierWin {
    /// `D3D12_RESOURCE_BARRIER_TYPE` (0 = TRANSITION).
    pub barrier_type: u32,
    pub flags: u32,
    /// `ID3D12Resource*` being transitioned.
    pub p_resource: *mut c_void,
    pub subresource: u32,
    /// `D3D12_RESOURCE_STATES` before.
    pub state_before: u32,
    /// `D3D12_RESOURCE_STATES` after.
    pub state_after: u32,
}

// ---------------------------------------------------------------------------
// Enum mapping (Windows numeric values -> nigg-d3d12 enums)
// ---------------------------------------------------------------------------

/// Map a `D3D12_COMMAND_LIST_TYPE` numeric value to our enum.
fn map_list_type(t: u32) -> nigg_d3d12::CommandListType {
    match t {
        1 => nigg_d3d12::CommandListType::Compute,
        2 => nigg_d3d12::CommandListType::Copy,
        // 0 (DIRECT) and 3 (BUNDLE) both use the graphics queue in M8.
        _ => nigg_d3d12::CommandListType::Direct,
    }
}

/// Map a `D3D12_DESCRIPTOR_HEAP_TYPE` numeric value to our enum.
fn map_heap_type(t: u32) -> nigg_d3d12::DescriptorHeapType {
    match t {
        0 => nigg_d3d12::DescriptorHeapType::CbvSrvUav,
        1 => nigg_d3d12::DescriptorHeapType::Sampler,
        3 => nigg_d3d12::DescriptorHeapType::Dsv,
        // 2 (RTV) and anything unknown default to RTV (the clear-screen case).
        _ => nigg_d3d12::DescriptorHeapType::Rtv,
    }
}

/// Map a `D3D12_HEAP_TYPE` numeric value to our `HeapType`.
fn map_heap_type_props(t: u32) -> nigg_d3d12::HeapType {
    match t {
        1 => nigg_d3d12::HeapType::Upload,
        2 => nigg_d3d12::HeapType::Readback,
        // 0 (DEFAULT) and 3 (CUSTOM) both use device-local memory in M8.
        _ => nigg_d3d12::HeapType::Default,
    }
}

/// Map a `D3D12_RESOURCE_DIMENSION` numeric value to our enum.
fn map_dimension(d: u32) -> nigg_d3d12::ResourceDimension {
    match d {
        0 => nigg_d3d12::ResourceDimension::Buffer,
        1 => nigg_d3d12::ResourceDimension::Texture1d,
        3 => nigg_d3d12::ResourceDimension::Texture3d,
        // 2 (TEXTURE2D) and anything unknown default to 2D (the render-target case).
        _ => nigg_d3d12::ResourceDimension::Texture2d,
    }
}

/// Map a `D3D12_RESOURCE_STATES` numeric value to our enum. Only the discrete
/// states the clear-screen sample touches are honoured; anything else collapses
/// to `GenericRead` (a safe read-compatible fallback).
fn map_state(s: u32) -> nigg_d3d12::ResourceStates {
    match s {
        0 => nigg_d3d12::ResourceStates::Common,
        0x4 => nigg_d3d12::ResourceStates::RenderTarget,
        0x400 => nigg_d3d12::ResourceStates::CopyDest,
        0x800 => nigg_d3d12::ResourceStates::CopySource,
        _ => nigg_d3d12::ResourceStates::GenericRead,
    }
}

/// Map a `DXGI_FORMAT` numeric value to our `nigg_dxgi::DxgiFormat`, defaulting
/// to the most common render-target format for anything unrecognised.
pub(crate) fn map_format(f: u32) -> nigg_dxgi::DxgiFormat {
    // DXGI_FORMAT_B8G8R8A8_UNORM = 87, DXGI_FORMAT_B8G8R8A8_UNORM_SRGB = 91.
    match f {
        91 => nigg_dxgi::DxgiFormat::B8G8R8A8UnormSrgb,
        _ => nigg_dxgi::DxgiFormat::B8G8R8A8Unorm,
    }
}

// ---------------------------------------------------------------------------
// Wrapped Rust objects (the `inner` of each COM object)
// ---------------------------------------------------------------------------

pub(crate) struct DeviceInner {
    pub device: nigg_d3d12::Device,
}

pub(crate) struct CommandQueueInner {
    pub queue: nigg_d3d12::CommandQueue,
}

/// Holds the `Arc<CommandAllocator>` so the pool outlives any command lists
/// built from it (the PE keeps the allocator alive for the device's lifetime).
pub(crate) struct AllocatorInner {
    pub allocator: Arc<nigg_d3d12::CommandAllocator>,
}

pub(crate) struct CommandListInner {
    pub list: nigg_d3d12::GraphicsCommandList,
}

pub(crate) struct DescriptorHeapInner {
    pub heap: nigg_d3d12::DescriptorHeap,
}

pub(crate) struct ResourceInner {
    pub resource: nigg_d3d12::Resource,
}

/// `ID3D12PipelineState` inner. The M8b device vtable does not expose
/// `CreatePipelineState`, so this is never constructed by the clear-screen
/// sample; `SetPipelineState` is still wired so the surface is real for later
/// milestones.
pub(crate) struct PipelineStateInner {
    pub pso: nigg_d3d12::PipelineState,
}

/// `ID3D12RootSignature` inner. Same status as [`PipelineStateInner`]: not
/// constructible in M8b, kept for API parity.
pub(crate) struct RootSignatureInner {
    pub root: nigg_d3d12::RootSignature,
}

// ---------------------------------------------------------------------------
// Vtable structs (slots are `*const c_void` = 8 bytes, identical to fn ptrs)
// ---------------------------------------------------------------------------

/// `ID3D12Device` — IUnknown + the clear-colour-relevant creators. Slot order
/// = declaration order.
#[repr(C)]
pub struct Id3d12DeviceVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub create_command_queue: *const c_void,
    pub create_command_allocator: *const c_void,
    pub create_command_list: *const c_void,
    pub create_descriptor_heap: *const c_void,
    pub create_render_target_view: *const c_void,
    pub create_committed_resource: *const c_void,
    pub get_descriptor_handle_increment_size: *const c_void,
}

/// `ID3D12CommandQueue` — IUnknown + `ExecuteCommandLists`. Slot order =
/// declaration order.
#[repr(C)]
pub struct Id3d12CommandQueueVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub execute_command_lists: *const c_void,
}

/// `ID3D12GraphicsCommandList` — IUnknown + the clear/draw methods. Slot order
/// = declaration order.
#[repr(C)]
pub struct Id3d12GraphicsCommandListVtbl {
    pub query_interface: *const c_void,
    pub add_ref: *const c_void,
    pub release: *const c_void,
    pub close: *const c_void,
    pub set_pipeline_state: *const c_void,
    pub set_render_targets: *const c_void,
    pub clear_render_target_view: *const c_void,
    pub resource_barrier: *const c_void,
    pub draw_instanced: *const c_void,
}

/// Opaque resource/state vtables (just IUnknown). The PE can create and
/// `Release` these; the shared IUnknown thunks suffice because `Release`
/// operates on the `ComHeader` prefix.
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

iunknown_vtbl!(Id3d12CommandAllocatorVtbl);
iunknown_vtbl!(Id3d12DescriptorHeapVtbl);
iunknown_vtbl!(Id3d12ResourceVtbl);
iunknown_vtbl!(Id3d12PipelineStateVtbl);
iunknown_vtbl!(Id3d12RootSignatureVtbl);

// ---------------------------------------------------------------------------
// ID3D12Device methods
// ---------------------------------------------------------------------------

/// `ID3D12Device::CreateCommandQueue(pDesc, riid, ppCommandQueue)`. Reads the
/// command list type from the desc, builds a native `CommandQueue` (the shared
/// graphics queue), and wraps it in a COM object with the command-queue vtable.
extern "C" fn device_create_command_queue(
    this: *mut c_void,
    p_desc: *const CommandQueueDescWin,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() || p_desc.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_desc` is a valid `D3D12_COMMAND_QUEUE_DESC` provided by the PE.
    let list_type = unsafe { (*p_desc).list_type };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev.device.create_command_queue(map_list_type(list_type)) {
        Ok(queue) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().command_queue as *const c_void,
                CommandQueueInner { queue },
            );
            // SAFETY: `pp` is a valid out-pointer per the contract.
            unsafe { *pp = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d12-com: CreateCommandQueue failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D12Device::CreateCommandAllocator(Type, riid, ppAllocator)`. Builds a
/// native `CommandAllocator` (a `VkCommandPool`) and wraps it (as an `Arc`) in a
/// COM object with the allocator vtable.
extern "C" fn device_create_command_allocator(
    this: *mut c_void,
    list_type: u32,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev
        .device
        .create_command_allocator(map_list_type(list_type))
    {
        Ok(allocator) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().command_allocator as *const c_void,
                AllocatorInner { allocator },
            );
            // SAFETY: `pp` is a valid out-pointer per the contract.
            unsafe { *pp = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d12-com: CreateCommandAllocator failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D12Device::CreateCommandList(NodeMask, Type, pAllocator, pInitialState,
/// riid, ppCommandList)`. Extracts the native allocator from the
/// `ID3D12CommandAllocator*` COM object (cloning its `Arc`), allocates a primary
/// command buffer from its pool, begins recording, and wraps it in a COM object
/// with the command-list vtable. `pInitialState` is ignored (no PSO needed for
/// a clear).
extern "C" fn device_create_command_list(
    this: *mut c_void,
    _node_mask: u32,
    list_type: u32,
    p_allocator: *mut c_void,
    _p_initial_state: *mut c_void,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() || p_allocator.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_allocator` is a live `ID3D12CommandAllocator*` COM object we
    // created via `CreateCommandAllocator`; cloning its `Arc` keeps the pool
    // alive for the command buffer's lifetime.
    let allocator = unsafe { inner::<AllocatorInner>(p_allocator).allocator.clone() };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev
        .device
        .create_command_list(allocator, map_list_type(list_type))
    {
        Ok(list) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().command_list as *const c_void,
                CommandListInner { list },
            );
            // SAFETY: `pp` is a valid out-pointer per the contract.
            unsafe { *pp = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d12-com: CreateCommandList failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D12Device::CreateDescriptorHeap(pDesc, riid, ppHeap)`. Reads the heap
/// type and descriptor count, builds a native `DescriptorHeap`, and wraps it.
extern "C" fn device_create_descriptor_heap(
    this: *mut c_void,
    p_desc: *const DescriptorHeapDescWin,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() || p_desc.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_desc` is a valid `D3D12_DESCRIPTOR_HEAP_DESC` provided by the PE.
    let (heap_type, count) = unsafe { ((*p_desc).heap_type, (*p_desc).num_descriptors) };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev
        .device
        .create_descriptor_heap(map_heap_type(heap_type), count)
    {
        Ok(heap) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().descriptor_heap as *const c_void,
                DescriptorHeapInner { heap },
            );
            // SAFETY: `pp` is a valid out-pointer per the contract.
            unsafe { *pp = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d12-com: CreateDescriptorHeap failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D12Device::CreateRenderTargetView(pResource, pDesc, CpuDescriptor)`.
/// Per the M8b CPU-descriptor-handle convention (see the module docs),
/// `cpu_handle` is the descriptor heap COM object's interface pointer; the RTV
/// is stored at slot 0 of that heap. `pDesc` is ignored (the view is inferred
/// from the resource).
extern "C" fn device_create_render_target_view(
    this: *mut c_void,
    p_resource: *mut c_void,
    _p_desc: *const c_void,
    cpu_handle: u64,
) {
    if p_resource.is_null() || cpu_handle == 0 {
        return;
    }
    // SAFETY: `this` is a live device COM object; `p_resource` is a live
    // `ID3D12Resource*` COM object we created via `CreateCommittedResource`;
    // `cpu_handle` is the descriptor heap COM object's pointer (see module docs).
    unsafe {
        let dev = inner::<DeviceInner>(this);
        let res = inner::<ResourceInner>(p_resource);
        let heap = inner_mut::<DescriptorHeapInner>(cpu_handle as *mut c_void);
        if let Err(e) = dev
            .device
            .create_render_target_view(&res.resource, &mut heap.heap, 0)
        {
            log::warn!("d3d12-com: CreateRenderTargetView failed: {e}");
        }
    }
}

/// `ID3D12Device::CreateCommittedResource(pHeapProperties, HeapFlags, pDesc,
/// InitialResourceState, pOptimizedClearValue, riid, ppvResource)`. Reads the
/// heap type and resource desc, builds a native `Resource` (a `VkImage`/buffer
/// + bound memory), and wraps it in a `ID3D12Resource*` COM object.
extern "C" fn device_create_committed_resource(
    this: *mut c_void,
    p_heap_props: *const HeapPropertiesWin,
    _heap_flags: u32,
    p_desc: *const ResourceDescWin,
    initial_state: u32,
    _p_optimized_clear_value: *mut c_void,
    _riid: *const u8,
    pp: *mut *mut c_void,
) -> i32 {
    if pp.is_null() || p_desc.is_null() || p_heap_props.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: `p_heap_props` and `p_desc` are valid Windows structs provided by
    // the PE per the D3D12 contract.
    let (heap_type_raw, desc_win) = unsafe { ((*p_heap_props).heap_type, &*p_desc) };
    let native_desc = nigg_d3d12::ResourceDesc {
        dimension: map_dimension(desc_win.dimension),
        width: desc_win.width,
        height: desc_win.height,
        depth_or_array_size: desc_win.depth_or_array_size,
        format: map_format(desc_win.format),
        mip_levels: desc_win.mip_levels,
        sample_count: desc_win.sample_count,
        heap_type: map_heap_type_props(heap_type_raw),
    };
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    match dev
        .device
        .create_committed_resource(native_desc, map_state(initial_state))
    {
        Ok(resource) => {
            // SAFETY: freshly built COM object with the pre-allocated vtable.
            let ptr = crate::ComObject::into_raw(
                vtables().resource as *const c_void,
                ResourceInner { resource },
            );
            // SAFETY: `pp` is a valid out-pointer per the contract.
            unsafe { *pp = ptr };
            S_OK
        }
        Err(e) => {
            log::warn!("d3d12-com: CreateCommittedResource failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D12Device::GetDescriptorHandleIncrementSize(DescriptorHeapType)`. The
/// translation layer indexes a `Vec`, so the per-slot stride is `1`.
extern "C" fn device_get_descriptor_handle_increment_size(
    this: *mut c_void,
    heap_type: u32,
) -> u32 {
    // SAFETY: `this` is a live device COM object allocated by `into_raw`.
    let dev = unsafe { inner::<DeviceInner>(this) };
    dev.device
        .get_descriptor_handle_increment_size(map_heap_type(heap_type))
}

// ---------------------------------------------------------------------------
// ID3D12CommandQueue methods
// ---------------------------------------------------------------------------

/// `ID3D12CommandQueue::ExecuteCommandLists(NumCommandLists, ppCommandLists)`.
/// Decodes each `ID3D12CommandList*` COM object to its native
/// `GraphicsCommandList`, collects the references, and submits them on the
/// shared graphics queue (which synchronously waits on a fence before returning).
extern "C" fn queue_execute_command_lists(
    this: *mut c_void,
    num_lists: u32,
    pp_lists: *const *mut c_void,
) {
    if num_lists == 0 || pp_lists.is_null() {
        return;
    }
    // SAFETY: `this` is a live command-queue COM object allocated by `into_raw`.
    let queue = unsafe { inner::<CommandQueueInner>(this) };
    let mut lists: Vec<&nigg_d3d12::GraphicsCommandList> = Vec::with_capacity(num_lists as usize);
    for i in 0..num_lists as usize {
        // SAFETY: `pp_lists` points to `num_lists` interface pointers per the
        // D3D12 contract; each is a live `ID3D12GraphicsCommandList*` we created.
        let ptr = unsafe { *pp_lists.add(i) };
        if ptr.is_null() {
            continue;
        }
        // SAFETY: `ptr` is a live command-list COM object allocated by `into_raw`.
        let list = unsafe { inner::<CommandListInner>(ptr) };
        lists.push(&list.list);
    }
    if let Err(e) = queue.queue.execute_command_lists(&lists) {
        log::warn!("d3d12-com: ExecuteCommandLists failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// ID3D12GraphicsCommandList methods
// ---------------------------------------------------------------------------

/// `ID3D12GraphicsCommandList::Close()`. Ends command buffer recording so the
/// list is ready to execute on a command queue.
extern "C" fn cmdlist_close(this: *mut c_void) -> i32 {
    // SAFETY: `this` is a live command-list COM object allocated by `into_raw`.
    let list = unsafe { inner_mut::<CommandListInner>(this) };
    match list.list.close() {
        Ok(()) => S_OK,
        Err(e) => {
            log::warn!("d3d12-com: Close failed: {e}");
            E_FAIL
        }
    }
}

/// `ID3D12GraphicsCommandList::SetPipelineState(pso)`. Binds a graphics
/// pipeline. The clear-screen sample never sets a PSO (no `CreatePipelineState`
/// in the M8b device vtable), so this is wired but unexercised by the sample.
extern "C" fn cmdlist_set_pipeline_state(this: *mut c_void, pso: *mut c_void) {
    if pso.is_null() {
        return;
    }
    // SAFETY: `this` is a live command-list COM object; `pso` is a live
    // `ID3D12PipelineState*` COM object (when one exists).
    unsafe {
        let list = inner_mut::<CommandListInner>(this);
        let pso_inner = inner::<PipelineStateInner>(pso);
        list.list.set_pipeline_state(&pso_inner.pso);
    }
}

/// `ID3D12GraphicsCommandList::OMSetRenderTargets(NumRTVs, pHandles, pDSV)`.
/// Per the M8b handle convention, the first RTV handle is the descriptor heap
/// COM object's pointer; the render target is slot 0 of that heap. `pDSV` is
/// ignored (the clear-screen sample uses no depth/stencil).
extern "C" fn cmdlist_set_render_targets(
    this: *mut c_void,
    num_rtvs: u32,
    p_handles: *const u64,
    _p_dsv: u64,
) {
    if num_rtvs == 0 || p_handles.is_null() {
        return;
    }
    // SAFETY: `p_handles` points to `num_rtvs` CPU descriptor handles per the
    // D3D12 contract.
    let first = unsafe { *p_handles };
    if first == 0 {
        return;
    }
    // SAFETY: `this` is a live command-list COM object; `first` is the descriptor
    // heap COM object's pointer (see module docs).
    unsafe {
        let list = inner_mut::<CommandListInner>(this);
        let heap = inner::<DescriptorHeapInner>(first as *mut c_void);
        let handle = nigg_d3d12::CpuDescriptorHandle { index: 0 };
        if let Err(e) = list
            .list
            .set_render_targets(&heap.heap, std::slice::from_ref(&handle))
        {
            log::warn!("d3d12-com: OMSetRenderTargets failed: {e}");
        }
    }
}

/// `ID3D12GraphicsCommandList::ClearRenderTargetView(CpuDescriptor, ColorRGBA,
/// NumRects, pRects)`. Per the M8b handle convention, `rtv_handle` is the
/// descriptor heap COM object's pointer; the clear targets slot 0 of that heap.
extern "C" fn cmdlist_clear_render_target_view(
    this: *mut c_void,
    rtv_handle: u64,
    color: *const f32,
    _num_rects: u32,
    _p_rects: *const c_void,
) {
    if rtv_handle == 0 {
        return;
    }
    // Default to opaque black if the caller passed no colour pointer.
    let col: [f32; 4] = if color.is_null() {
        [0.0, 0.0, 0.0, 1.0]
    } else {
        // SAFETY: `color` points to a 4-float array per the D3D12 contract.
        unsafe { *(color as *const [f32; 4]) }
    };
    // SAFETY: `this` is a live command-list COM object; `rtv_handle` is the
    // descriptor heap COM object's pointer (see module docs).
    unsafe {
        let list = inner_mut::<CommandListInner>(this);
        let heap = inner::<DescriptorHeapInner>(rtv_handle as *mut c_void);
        let handle = nigg_d3d12::CpuDescriptorHandle { index: 0 };
        if let Err(e) = list.list.clear_render_target_view(&heap.heap, handle, col) {
            log::warn!("d3d12-com: ClearRenderTargetView failed: {e}");
        }
    }
}

/// `ID3D12GraphicsCommandList::ResourceBarrier(NumBarriers, pBarriers)`. Each
/// `TRANSITION` barrier is decoded (resource COM object + before/after states)
/// and recorded as a `vkCmdPipelineBarrier`. Barriers are issued one at a time
/// (the sample passes one per call); multiple barriers per call would each
/// record their own pipeline barrier, which is functionally equivalent.
extern "C" fn cmdlist_resource_barrier(
    this: *mut c_void,
    num_barriers: u32,
    p_barriers: *const ResourceBarrierWin,
) {
    if num_barriers == 0 || p_barriers.is_null() {
        return;
    }
    // SAFETY: `this` is a live command-list COM object allocated by `into_raw`.
    let list = unsafe { inner_mut::<CommandListInner>(this) };
    for i in 0..num_barriers as usize {
        // SAFETY: `p_barriers` points to `num_barriers` valid
        // `D3D12_RESOURCE_BARRIER` structs per the contract.
        let b = unsafe { &*p_barriers.add(i) };
        // Only `TRANSITION` barriers (type 0) are modelled in M8.
        if b.barrier_type != 0 || b.p_resource.is_null() {
            continue;
        }
        // SAFETY: `b.p_resource` is a live `ID3D12Resource*` COM object we
        // created via `CreateCommittedResource`; the borrow covers this single
        // `resource_barrier` call (the PE holds the resource alive).
        unsafe {
            let res = inner::<ResourceInner>(b.p_resource);
            let barrier = nigg_d3d12::ResourceBarrier {
                resource: &res.resource,
                state_before: map_state(b.state_before),
                state_after: map_state(b.state_after),
            };
            if let Err(e) = list.list.resource_barrier(std::slice::from_ref(&barrier)) {
                log::warn!("d3d12-com: ResourceBarrier[{i}] failed: {e}");
            }
        }
    }
}

/// `ID3D12GraphicsCommandList::DrawInstanced(VertexCount, InstanceCount,
/// StartVertex, StartInstance)`. Records a non-indexed draw inside a render
/// pass built from the bound render target + pipeline state. The clear-screen
/// sample does not draw, so this is wired but unexercised by the sample.
extern "C" fn cmdlist_draw_instanced(
    this: *mut c_void,
    vertex_count: u32,
    instance_count: u32,
    start_vertex: u32,
    start_instance: u32,
) {
    // SAFETY: `this` is a live command-list COM object allocated by `into_raw`.
    let list = unsafe { inner_mut::<CommandListInner>(this) };
    if let Err(e) =
        list.list
            .draw_instanced(vertex_count, instance_count, start_vertex, start_instance)
    {
        log::warn!("d3d12-com: DrawInstanced failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// ComVtables: pre-built, leaked vtables
// ---------------------------------------------------------------------------

/// The set of pre-built COM vtables. Each field is the address of a leaked
/// `*Vtbl` struct whose slots hold Win64->SysV thunk pointers. Stored in the
/// process-global registry at PE load time and read by the import-level
/// `D3D12CreateDevice` and the per-method implementations.
pub struct ComVtables {
    pub device: *const Id3d12DeviceVtbl,
    pub command_queue: *const Id3d12CommandQueueVtbl,
    pub command_allocator: *const Id3d12CommandAllocatorVtbl,
    pub command_list: *const Id3d12GraphicsCommandListVtbl,
    pub descriptor_heap: *const Id3d12DescriptorHeapVtbl,
    pub resource: *const Id3d12ResourceVtbl,
    pub pipeline_state: *const Id3d12PipelineStateVtbl,
    pub root_signature: *const Id3d12RootSignatureVtbl,
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

        let device = Box::into_raw(Box::new(Id3d12DeviceVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            create_command_queue: mk(device_create_command_queue as *const c_void, 4),
            create_command_allocator: mk(device_create_command_allocator as *const c_void, 4),
            create_command_list: mk(device_create_command_list as *const c_void, 7),
            create_descriptor_heap: mk(device_create_descriptor_heap as *const c_void, 4),
            create_render_target_view: mk(device_create_render_target_view as *const c_void, 4),
            create_committed_resource: mk(device_create_committed_resource as *const c_void, 8),
            get_descriptor_handle_increment_size: mk(
                device_get_descriptor_handle_increment_size as *const c_void,
                2,
            ),
        })) as *const Id3d12DeviceVtbl;

        let command_queue = Box::into_raw(Box::new(Id3d12CommandQueueVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            execute_command_lists: mk(queue_execute_command_lists as *const c_void, 3),
        })) as *const Id3d12CommandQueueVtbl;

        let command_list = Box::into_raw(Box::new(Id3d12GraphicsCommandListVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
            close: mk(cmdlist_close as *const c_void, 1),
            set_pipeline_state: mk(cmdlist_set_pipeline_state as *const c_void, 2),
            set_render_targets: mk(cmdlist_set_render_targets as *const c_void, 4),
            clear_render_target_view: mk(cmdlist_clear_render_target_view as *const c_void, 5),
            resource_barrier: mk(cmdlist_resource_barrier as *const c_void, 3),
            draw_instanced: mk(cmdlist_draw_instanced as *const c_void, 5),
        })) as *const Id3d12GraphicsCommandListVtbl;

        let command_allocator = Box::into_raw(Box::new(Id3d12CommandAllocatorVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d12CommandAllocatorVtbl;
        let descriptor_heap = Box::into_raw(Box::new(Id3d12DescriptorHeapVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d12DescriptorHeapVtbl;
        let resource = Box::into_raw(Box::new(Id3d12ResourceVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d12ResourceVtbl;
        let pipeline_state = Box::into_raw(Box::new(Id3d12PipelineStateVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d12PipelineStateVtbl;
        let root_signature = Box::into_raw(Box::new(Id3d12RootSignatureVtbl {
            query_interface: qi,
            add_ref: ar,
            release: rl,
        })) as *const Id3d12RootSignatureVtbl;

        ComVtables {
            device,
            command_queue,
            command_allocator,
            command_list,
            descriptor_heap,
            resource,
            pipeline_state,
            root_signature,
        }
    }
}
