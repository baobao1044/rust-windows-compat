//! M8b D3D12 sample PE fixture.
//!
//! A minimal `#![no_std]`/`#![no_main]` Windows program that imports only
//! `d3d12.dll` and `kernel32.dll` (via `raw-dylib` + a custom entry point, so
//! there is no CRT import surface), and exercises the D3D12 COM vtable thunk
//! layer end-to-end:
//!
//! 1. `D3D12CreateDevice` -> `ID3D12Device*`.
//! 2. `ID3D12Device::CreateCommandQueue` -> `ID3D12CommandQueue*`.
//! 3. `ID3D12Device::CreateCommandAllocator` -> `ID3D12CommandAllocator*`.
//! 4. `ID3D12Device::CreateCommandList` -> `ID3D12GraphicsCommandList*`.
//! 5. `ID3D12Device::CreateDescriptorHeap` (RTV, 1) -> `ID3D12DescriptorHeap*`.
//! 6. `ID3D12Device::CreateCommittedResource` (640x480 B8G8R8A8 texture) -> `ID3D12Resource*`.
//! 7. `ID3D12Device::CreateRenderTargetView(resource, null, heap_ptr)`.
//! 8. `ID3D12GraphicsCommandList::ResourceBarrier` (COMMON->RENDER_TARGET).
//! 9. `ID3D12GraphicsCommandList::SetRenderTargets(1, &heap_ptr, 0)`.
//! 10. `ID3D12GraphicsCommandList::ClearRenderTargetView(heap_ptr, red, 0, null)`.
//! 11. `ID3D12GraphicsCommandList::ResourceBarrier` (RENDER_TARGET->COMMON).
//! 12. `ID3D12GraphicsCommandList::Close()`.
//! 13. `ID3D12CommandQueue::ExecuteCommandLists(1, &cmdlist)`.
//! 14. `ExitProcess(0)`.
//!
//! The COM vtable structs below mirror the slot order declared in
//! `nigg-d3d12-com` (`crates/d3d12-com/src/methods.rs`). The CPU descriptor
//! handle convention is the heap COM object's interface pointer (cast to u64),
//! as documented in the COM layer.

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::ptr;

const S_OK: i32 = 0;
const DXGI_FORMAT_B8G8R8A8_UNORM: u32 = 87;
const D3D12_RESOURCE_DIMENSION_TEXTURE2D: u32 = 2;
const D3D12_HEAP_TYPE_DEFAULT: u32 = 0;
const D3D12_COMMAND_LIST_TYPE_DIRECT: u32 = 0;
const D3D12_DESCRIPTOR_HEAP_TYPE_RTV: u32 = 2;
const D3D12_RESOURCE_STATE_COMMON: u32 = 0;
const D3D12_RESOURCE_STATE_RENDER_TARGET: u32 = 0x4;
const D3D12_RESOURCE_BARRIER_TYPE_TRANSITION: u32 = 0;

// ---------------------------------------------------------------------------
// raw-dylib imports
// ---------------------------------------------------------------------------

#[link(name = "d3d12", kind = "raw-dylib")]
unsafe extern "C" {
    fn D3D12CreateDevice(
        adapter: *mut u8,
        min_feature_level: u32,
        riid: *const u8,
        pp_device: *mut *mut u8,
    ) -> i32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn ExitProcess(code: u32) -> !;
}

// ---------------------------------------------------------------------------
// Win structs (mirror nigg-d3d12-com)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct CommandQueueDesc {
    list_type: u32,
    priority: i32,
    flags: u32,
    node_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DescriptorHeapDesc {
    heap_type: u32,
    num_descriptors: u32,
    flags: u32,
    node_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HeapProperties {
    heap_type: u32,
    cpu_page_property: u32,
    memory_pool_preference: u32,
    creation_node_mask: u32,
    visible_node_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceDesc {
    dimension: u32,
    alignment: u64,
    width: u64,
    height: u32,
    depth_or_array_size: u16,
    mip_levels: u16,
    format: u32,
    sample_count: u32,
    sample_quality: u32,
    layout: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceBarrier {
    barrier_type: u32,
    flags: u32,
    p_resource: *mut u8,
    subresource: u32,
    state_before: u32,
    state_after: u32,
}

// ---------------------------------------------------------------------------
// COM vtable definitions (slot order mirrors nigg-d3d12-com)
// ---------------------------------------------------------------------------

#[repr(C)]
struct Id3d12DeviceVtbl {
    query_interface: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    add_ref: unsafe extern "C" fn(*mut u8) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> u32,
    create_command_queue: unsafe extern "C" fn(*mut u8, *const CommandQueueDesc, *const u8, *mut *mut u8) -> i32,
    create_command_allocator: unsafe extern "C" fn(*mut u8, u32, *const u8, *mut *mut u8) -> i32,
    create_command_list: unsafe extern "C" fn(*mut u8, u32, u32, *mut u8, *mut u8, *const u8, *mut *mut u8) -> i32,
    create_descriptor_heap: unsafe extern "C" fn(*mut u8, *const DescriptorHeapDesc, *const u8, *mut *mut u8) -> i32,
    create_render_target_view: unsafe extern "C" fn(*mut u8, *mut u8, *const u8, u64),
    create_committed_resource: unsafe extern "C" fn(*mut u8, *const HeapProperties, u32, *const ResourceDesc, u32, *mut u8, *const u8, *mut *mut u8) -> i32,
    get_descriptor_handle_increment_size: unsafe extern "C" fn(*mut u8, u32) -> u32,
}

#[repr(C)]
struct Id3d12CommandQueueVtbl {
    query_interface: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    add_ref: unsafe extern "C" fn(*mut u8) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> u32,
    execute_command_lists: unsafe extern "C" fn(*mut u8, u32, *const *mut u8),
}

#[repr(C)]
struct Id3d12GraphicsCommandListVtbl {
    query_interface: unsafe extern "C" fn(*mut u8, *const u8, *mut *mut u8) -> i32,
    add_ref: unsafe extern "C" fn(*mut u8) -> u32,
    release: unsafe extern "C" fn(*mut u8) -> u32,
    close: unsafe extern "C" fn(*mut u8) -> i32,
    set_pipeline_state: unsafe extern "C" fn(*mut u8, *mut u8),
    set_render_targets: unsafe extern "C" fn(*mut u8, u32, *const u64, u64),
    clear_render_target_view: unsafe extern "C" fn(*mut u8, u64, *const f32, u32, *const u8),
    resource_barrier: unsafe extern "C" fn(*mut u8, u32, *const ResourceBarrier),
    draw_instanced: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32),
}

unsafe fn vtable<Vtbl>(obj: *mut u8) -> &'static Vtbl {
    unsafe { &*(*(obj as *const *const u8) as *const Vtbl) }
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
    let iid: [u8; 16] = [0; 16];

    // 1. D3D12CreateDevice -> ID3D12Device*.
    let mut device: *mut u8 = ptr::null_mut();
    let hr = unsafe { D3D12CreateDevice(ptr::null_mut(), 0, iid.as_ptr(), &mut device) };
    if hr != S_OK {
        return 1;
    }

    // 2. CreateCommandQueue -> ID3D12CommandQueue*.
    let queue_desc = CommandQueueDesc {
        list_type: D3D12_COMMAND_LIST_TYPE_DIRECT,
        priority: 0,
        flags: 0,
        node_mask: 0,
    };
    let mut queue: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d12DeviceVtbl>(device);
        (vt.create_command_queue)(device, &queue_desc, iid.as_ptr(), &mut queue)
    };
    if hr != S_OK {
        return 2;
    }

    // 3. CreateCommandAllocator -> ID3D12CommandAllocator*.
    let mut allocator: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d12DeviceVtbl>(device);
        (vt.create_command_allocator)(device, D3D12_COMMAND_LIST_TYPE_DIRECT, iid.as_ptr(), &mut allocator)
    };
    if hr != S_OK {
        return 3;
    }

    // 4. CreateCommandList -> ID3D12GraphicsCommandList*.
    let mut cmdlist: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d12DeviceVtbl>(device);
        (vt.create_command_list)(device, 0, D3D12_COMMAND_LIST_TYPE_DIRECT, allocator, ptr::null_mut(), iid.as_ptr(), &mut cmdlist)
    };
    if hr != S_OK {
        return 4;
    }

    // 5. CreateDescriptorHeap (RTV, 1) -> ID3D12DescriptorHeap*.
    let heap_desc = DescriptorHeapDesc {
        heap_type: D3D12_DESCRIPTOR_HEAP_TYPE_RTV,
        num_descriptors: 1,
        flags: 0,
        node_mask: 0,
    };
    let mut rtv_heap: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d12DeviceVtbl>(device);
        (vt.create_descriptor_heap)(device, &heap_desc, iid.as_ptr(), &mut rtv_heap)
    };
    if hr != S_OK {
        return 5;
    }

    // 6. CreateCommittedResource (640x480 B8G8R8A8 texture2D) -> ID3D12Resource*.
    let heap_props = HeapProperties {
        heap_type: D3D12_HEAP_TYPE_DEFAULT,
        cpu_page_property: 0,
        memory_pool_preference: 0,
        creation_node_mask: 0,
        visible_node_mask: 0,
    };
    let resource_desc = ResourceDesc {
        dimension: D3D12_RESOURCE_DIMENSION_TEXTURE2D,
        alignment: 0,
        width: 640,
        height: 480,
        depth_or_array_size: 1,
        mip_levels: 1,
        format: DXGI_FORMAT_B8G8R8A8_UNORM,
        sample_count: 1,
        sample_quality: 0,
        layout: 0,
        flags: 0,
    };
    let mut resource: *mut u8 = ptr::null_mut();
    let hr = unsafe {
        let vt = vtable::<Id3d12DeviceVtbl>(device);
        (vt.create_committed_resource)(
            device,
            &heap_props,
            0,
            &resource_desc,
            D3D12_RESOURCE_STATE_COMMON,
            ptr::null_mut(),
            iid.as_ptr(),
            &mut resource,
        )
    };
    if hr != S_OK {
        return 6;
    }

    // 7. CreateRenderTargetView(resource, null, rtv_heap_ptr_as_u64).
    unsafe {
        let vt = vtable::<Id3d12DeviceVtbl>(device);
        (vt.create_render_target_view)(device, resource, ptr::null(), rtv_heap as u64);
    }

    let rtv_handle = rtv_heap as u64;

    // 8. ResourceBarrier (COMMON -> RENDER_TARGET).
    let barrier_to_rt = ResourceBarrier {
        barrier_type: D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
        flags: 0,
        p_resource: resource,
        subresource: 0,
        state_before: D3D12_RESOURCE_STATE_COMMON,
        state_after: D3D12_RESOURCE_STATE_RENDER_TARGET,
    };
    unsafe {
        let vt = vtable::<Id3d12GraphicsCommandListVtbl>(cmdlist);
        (vt.resource_barrier)(cmdlist, 1, &barrier_to_rt);
    }

    // 9. SetRenderTargets(1, &rtv_handle, 0).
    unsafe {
        let vt = vtable::<Id3d12GraphicsCommandListVtbl>(cmdlist);
        (vt.set_render_targets)(cmdlist, 1, &rtv_handle, 0);
    }

    // 10. ClearRenderTargetView(rtv_handle, [1,0,0,1], 0, null) — solid red.
    unsafe {
        let vt = vtable::<Id3d12GraphicsCommandListVtbl>(cmdlist);
        let color: [f32; 4] = [1.0, 0.0, 0.0, 1.0];
        (vt.clear_render_target_view)(cmdlist, rtv_handle, color.as_ptr(), 0, ptr::null());
    }

    // 11. ResourceBarrier (RENDER_TARGET -> COMMON).
    let barrier_to_common = ResourceBarrier {
        barrier_type: D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
        flags: 0,
        p_resource: resource,
        subresource: 0,
        state_before: D3D12_RESOURCE_STATE_RENDER_TARGET,
        state_after: D3D12_RESOURCE_STATE_COMMON,
    };
    unsafe {
        let vt = vtable::<Id3d12GraphicsCommandListVtbl>(cmdlist);
        (vt.resource_barrier)(cmdlist, 1, &barrier_to_common);
    }

    // 12. Close().
    let hr = unsafe {
        let vt = vtable::<Id3d12GraphicsCommandListVtbl>(cmdlist);
        (vt.close)(cmdlist)
    };
    if hr != S_OK {
        return 7;
    }

    // 13. ExecuteCommandLists(1, &cmdlist).
    unsafe {
        let vt = vtable::<Id3d12CommandQueueVtbl>(queue);
        let lists: [*mut u8; 1] = [cmdlist];
        (vt.execute_command_lists)(queue, 1, lists.as_ptr());
    }

    // 14. Success.
    0
}
