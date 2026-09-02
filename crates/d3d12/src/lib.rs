//! Direct3D 12 → Vulkan translation (milestone M8).
//!
//! This crate implements the smallest subset of the D3D12 device/command-list API
//! needed to clear a render target to a solid colour, translated onto Vulkan via
//! [`ash`] using the shared [`nigg_dxgi::VkCtx`] (the same logical device the DXGI
//! swap chain and the D3D11 layer drive).
//!
//! # Mapping
//!
//! | D3D12                          | Vulkan                                                |
//! |--------------------------------|-------------------------------------------------------|
//! | `ID3D12Device`                 | wraps [`nigg_dxgi::VkCtx`] (logical device + queue)   |
//! | `CreateCommittedResource`      | `vkCreateImage`/`vkCreateBuffer` + memory alloc/bind  |
//! | `CreateRenderTargetView`       | `vkCreateImageView` stored in a [`DescriptorHeap`]    |
//! | `CreateRootSignature`          | `vkCreatePipelineLayout` (empty for M8)               |
//! | `CreatePipelineState`          | `vkCreateRenderPass` + `vkCreateGraphicsPipelines`     |
//! | `ID3D12CommandAllocator`       | `vkCreateCommandPool`                                 |
//! | `ID3D12GraphicsCommandList`   | one `vk::CommandBuffer` allocated from the pool        |
//! | `ID3D12CommandQueue`           | the shared `vk::Queue` (+ a fence per `Execute`)      |
//! | `ID3D12DescriptorHeap`         | a `Vec` of owned `VkImageView`/`VkBufferView` handles  |
//! | `ResourceBarrier`              | `vkCmdPipelineBarrier` (image/buffer memory barrier)  |
//! | `ClearRenderTargetView`        | `vkCmdClearColorImage` (layout-managed)               |
//! | `SetRenderTargets` + `DrawInstanced` | render pass + `vkCmdDraw` inside it            |
//! | `ExecuteCommandLists`         | `vkQueueSubmit` + `vkWaitForFences` (synchronous)     |
//!
//! D3D12 is a low-level, explicit API: the app records command lists on an
//! allocator, closes them, and submits them on a command queue. This layer keeps
//! that shape — the [`GraphicsCommandList`] records into a real `VkCommandBuffer`,
//! [`CommandQueue::execute_command_lists`] submits and (for the M8 simplification)
//! synchronously waits on a fence before returning.
//!
//! All `unsafe` blocks carry a SAFETY comment explaining the invariant upheld.

#![deny(unsafe_op_in_unsafe_fn)]
// Several structs model the broader D3D12 surface (e.g. CBV/SRV/UAV descriptor
// heaps, the image/format fields of a bound render target) that the M8
// clear-screen sample does not yet exercise. Keeping them avoids surprising
// `dead_code` churn as more of the API lights up in later milestones.
#![allow(dead_code)]

use std::sync::Arc;

use ash::vk;
use nigg_dxgi::VkCtx;

// ===========================================================================
// Errors
// ===========================================================================

/// A D3D12-over-Vulkan error.
#[derive(Debug, thiserror::Error)]
pub enum D3d12Error {
    /// A Vulkan call returned a non-success result.
    #[error("vulkan: {0}")]
    Vulkan(String),
    /// A D3D12-level precondition was violated.
    #[error("invalid argument: {0}")]
    Invalid(String),
    /// No render target was set before a draw.
    #[error("no render target bound")]
    NoRenderTarget,
    /// No pipeline state was set before a draw.
    #[error("no pipeline state bound")]
    NoPipeline,
    /// A descriptor heap index was out of range.
    #[error("descriptor index {0} out of range (count={1})")]
    DescriptorIndexOutOfRange(usize, usize),
    /// An operation was attempted on a resource that does not support it (e.g.
    /// mapping a device-local image).
    #[error("resource does not support the requested operation: {0}")]
    Unsupported(String),
}

fn vk_err(e: vk::Result) -> D3d12Error {
    D3d12Error::Vulkan(e.to_string())
}

impl From<nigg_dxgi::DxgiError> for D3d12Error {
    fn from(e: nigg_dxgi::DxgiError) -> Self {
        match e {
            nigg_dxgi::DxgiError::Vulkan(s) => D3d12Error::Vulkan(s),
            nigg_dxgi::DxgiError::MissingExtension(n) => D3d12Error::Vulkan(n.to_string()),
            nigg_dxgi::DxgiError::NoSurface => D3d12Error::Vulkan("no surface available".into()),
            nigg_dxgi::DxgiError::BufferIndexOutOfRange(i, c) => {
                D3d12Error::Invalid(format!("buffer index {i} out of range (count={c})"))
            }
        }
    }
}

// ===========================================================================
// Resource descriptions (D3D12-shaped structs)
// ===========================================================================

/// `D3D12_RESOURCE_DIMENSION` subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDimension {
    /// A flat byte buffer (`D3D12_RESOURCE_DIMENSION_BUFFER`).
    Buffer,
    /// A 1D texture.
    Texture1d,
    /// A 2D texture (the common render-target case).
    Texture2d,
    /// A 3D texture.
    Texture3d,
}

/// `D3D12_HEAP_TYPE` subset — selects the memory property flags for a committed
/// resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapType {
    /// `D3D12_HEAP_TYPE_DEFAULT` — device-local memory (fast GPU access, not
    /// host-mappable).
    Default,
    /// `D3D12_HEAP_TYPE_UPLOAD` — host-visible, host-coherent (for CPU→GPU uploads).
    Upload,
    /// `D3D12_HEAP_TYPE_READBACK` — host-visible, host-cached (for GPU→CPU reads).
    Readback,
}

impl HeapType {
    fn vk_memory_flags(self) -> vk::MemoryPropertyFlags {
        match self {
            HeapType::Default => vk::MemoryPropertyFlags::DEVICE_LOCAL,
            HeapType::Upload => {
                vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT
            }
            HeapType::Readback => {
                vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_CACHED
            }
        }
    }
}

/// `D3D12_RESOURCE_STATES` subset. D3D12 states are explicit; the translation
/// layer maps each to a `VkImageLayout`/access mask for `ResourceBarrier`. We
/// model only the discrete states the clear-screen sample touches (D3D12 states
/// are bitflags in the real API, but a single before/after state per barrier is
/// all M8 needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceStates {
    /// `D3D12_RESOURCE_STATE_COMMON` — a generic read-compatible state.
    Common,
    /// `D3D12_RESOURCE_STATE_PRESENT` — the swap-chain presentation layout.
    Present,
    /// `D3D12_RESOURCE_STATE_RENDER_TARGET` — colour attachment write.
    RenderTarget,
    /// `D3D12_RESOURCE_STATE_COPY_DEST` — destination of a copy/clear.
    CopyDest,
    /// `D3D12_RESOURCE_STATE_COPY_SOURCE` — source of a copy.
    CopySource,
    /// `D3D12_RESOURCE_STATE_GENERIC_READ` — any read access.
    GenericRead,
    /// The initial state of a freshly created resource (maps to `UNDEFINED`).
    Undefined,
}

impl ResourceStates {
    /// The Vulkan image layout this D3D12 state maps to.
    fn vk_image_layout(self) -> vk::ImageLayout {
        match self {
            ResourceStates::Common | ResourceStates::GenericRead => vk::ImageLayout::GENERAL,
            ResourceStates::Present => vk::ImageLayout::PRESENT_SRC_KHR,
            ResourceStates::RenderTarget => vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL,
            ResourceStates::CopyDest => vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            ResourceStates::CopySource => vk::ImageLayout::TRANSFER_SRC_OPTIMAL,
            ResourceStates::Undefined => vk::ImageLayout::UNDEFINED,
        }
    }

    /// The Vulkan buffer layout this D3D12 state maps to (Vulkan has only
    /// `UNDEFINED`/`GENERAL`/`SHARED` for buffers; we collapse to `GENERAL`).
    fn vk_buffer_layout(self) -> vk::ImageLayout {
        match self {
            ResourceStates::Undefined => vk::ImageLayout::UNDEFINED,
            _ => vk::ImageLayout::GENERAL,
        }
    }

    /// The source access mask for a barrier entering this state (conservative:
    /// the operations that must complete before the new state's writes).
    fn src_access(self) -> vk::AccessFlags {
        match self {
            ResourceStates::Common | ResourceStates::Undefined => vk::AccessFlags::empty(),
            ResourceStates::Present => vk::AccessFlags::MEMORY_READ,
            ResourceStates::RenderTarget => {
                vk::AccessFlags::COLOR_ATTACHMENT_READ | vk::AccessFlags::COLOR_ATTACHMENT_WRITE
            }
            ResourceStates::CopyDest => vk::AccessFlags::TRANSFER_WRITE,
            ResourceStates::CopySource | ResourceStates::GenericRead => {
                vk::AccessFlags::TRANSFER_READ
            }
        }
    }

    /// The destination access mask for a barrier entering this state.
    fn dst_access(self) -> vk::AccessFlags {
        match self {
            ResourceStates::Common | ResourceStates::Present | ResourceStates::Undefined => {
                vk::AccessFlags::MEMORY_READ
            }
            ResourceStates::RenderTarget => {
                vk::AccessFlags::COLOR_ATTACHMENT_READ | vk::AccessFlags::COLOR_ATTACHMENT_WRITE
            }
            ResourceStates::CopyDest => vk::AccessFlags::TRANSFER_WRITE,
            ResourceStates::CopySource | ResourceStates::GenericRead => {
                vk::AccessFlags::TRANSFER_READ
            }
        }
    }

    /// The source pipeline stage that produces this state.
    fn src_stage(self) -> vk::PipelineStageFlags {
        match self {
            ResourceStates::Common | ResourceStates::Undefined | ResourceStates::Present => {
                vk::PipelineStageFlags::BOTTOM_OF_PIPE
            }
            ResourceStates::RenderTarget => vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT,
            ResourceStates::CopyDest | ResourceStates::CopySource | ResourceStates::GenericRead => {
                vk::PipelineStageFlags::TRANSFER
            }
        }
    }

    /// The destination pipeline stage that consumes this state.
    fn dst_stage(self) -> vk::PipelineStageFlags {
        match self {
            ResourceStates::Common | ResourceStates::Undefined | ResourceStates::Present => {
                vk::PipelineStageFlags::TOP_OF_PIPE
            }
            ResourceStates::RenderTarget => vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT,
            ResourceStates::CopyDest | ResourceStates::CopySource | ResourceStates::GenericRead => {
                vk::PipelineStageFlags::TRANSFER
            }
        }
    }
}

/// `D3D12_RESOURCE_DESC` subset.
#[derive(Debug, Clone, Copy)]
pub struct ResourceDesc {
    /// Buffer vs. texture dimension.
    pub dimension: ResourceDimension,
    /// Width in pixels (textures) or bytes (buffers).
    pub width: u64,
    /// Height in pixels (0 for buffers/1D).
    pub height: u32,
    /// Depth (3D) or array layers (1D/2D). 1 for the common 2D case.
    pub depth_or_array_size: u16,
    /// Surface format (textures). Ignored for buffers.
    pub format: nigg_dxgi::DxgiFormat,
    /// Mip level count (1 for the common case).
    pub mip_levels: u16,
    /// Sample count (1 for the common non-MSAA case).
    pub sample_count: u32,
    /// Memory heap type (Default = device-local, Upload/Readback = host-visible).
    pub heap_type: HeapType,
}

impl ResourceDesc {
    /// A 2D render-target texture at `w x h` in the given format, device-local.
    pub fn render_target_2d(width: u32, height: u32, format: nigg_dxgi::DxgiFormat) -> Self {
        Self {
            dimension: ResourceDimension::Texture2d,
            width: width as u64,
            height,
            depth_or_array_size: 1,
            format,
            mip_levels: 1,
            sample_count: 1,
            heap_type: HeapType::Default,
        }
    }

    /// An upload buffer of `size` bytes (host-visible, host-coherent).
    pub fn upload_buffer(size: u64) -> Self {
        Self {
            dimension: ResourceDimension::Buffer,
            width: size,
            height: 0,
            depth_or_array_size: 1,
            format: nigg_dxgi::DxgiFormat::B8G8R8A8Unorm,
            mip_levels: 1,
            sample_count: 1,
            heap_type: HeapType::Upload,
        }
    }
}

// ===========================================================================
// Resources
// ===========================================================================

/// The Vulkan-side kind of a [`Resource`]: either an image or a buffer, each with
/// its bound device memory.
enum ResourceInner {
    Image {
        image: vk::Image,
        memory: vk::DeviceMemory,
        format: vk::Format,
        extent: vk::Extent3D,
        /// Whether the bound memory is host-mappable.
        host_visible: bool,
    },
    Buffer {
        buffer: vk::Buffer,
        memory: vk::DeviceMemory,
        size: u64,
        /// Whether the bound memory is host-mappable.
        host_visible: bool,
    },
}

/// `ID3D12Resource` — a committed resource: a `VkImage` or `VkBuffer` plus its
/// bound device memory. Created by [`Device::create_committed_resource`].
pub struct Resource {
    ctx: Arc<VkCtx>,
    inner: ResourceInner,
    desc: ResourceDesc,
    /// Tracks whether the resource is currently mapped (for `unmap`).
    mapped: bool,
}

impl Resource {
    /// Borrow the resource description.
    pub fn desc(&self) -> ResourceDesc {
        self.desc
    }

    /// Is this resource a buffer?
    pub fn is_buffer(&self) -> bool {
        matches!(self.inner, ResourceInner::Buffer { .. })
    }

    /// The Vulkan image handle, or null for buffers.
    pub fn image_handle(&self) -> vk::Image {
        match self.inner {
            ResourceInner::Image { image, .. } => image,
            ResourceInner::Buffer { .. } => vk::Image::null(),
        }
    }

    /// The Vulkan buffer handle, or null for images.
    pub fn buffer_handle(&self) -> vk::Buffer {
        match self.inner {
            ResourceInner::Buffer { buffer, .. } => buffer,
            ResourceInner::Image { .. } => vk::Buffer::null(),
        }
    }

    /// The image's format (or `UNDEFINED` for buffers).
    pub fn format(&self) -> vk::Format {
        match self.inner {
            ResourceInner::Image { format, .. } => format,
            ResourceInner::Buffer { .. } => vk::Format::UNDEFINED,
        }
    }

    /// The image's extent (or a zero extent for buffers).
    pub fn extent(&self) -> vk::Extent3D {
        match self.inner {
            ResourceInner::Image { extent, .. } => extent,
            ResourceInner::Buffer { .. } => vk::Extent3D::default(),
        }
    }

    /// `Map(subresource)` — map the resource's memory for CPU access. Only
    /// host-visible (Upload/Readback) resources can be mapped; device-local
    /// images return [`D3d12Error::Unsupported`]. Returns a raw pointer to the
    /// mapped region. The caller must pair this with [`unmap`].
    ///
    /// [`unmap`]: Self::unmap
    pub fn map(&mut self) -> Result<*mut u8, D3d12Error> {
        if self.mapped {
            return Err(D3d12Error::Invalid("resource already mapped".into()));
        }
        let (memory, size, host_visible) = match &self.inner {
            ResourceInner::Buffer {
                memory,
                size,
                host_visible,
                ..
            } => (*memory, *size, *host_visible),
            ResourceInner::Image {
                memory,
                host_visible,
                ..
            } => (*memory, 0, *host_visible),
        };
        if !host_visible {
            return Err(D3d12Error::Unsupported(
                "resource memory is not host-visible".into(),
            ));
        }
        let ptr = unsafe {
            // SAFETY: `memory` is HOST_VISIBLE and exclusively owned by this
            // resource; `vkMapMemory` with offset 0 and size WHOLE_SIZE maps the
            // entire allocation. The device is valid (owned by `ctx`).
            self.ctx
                .device
                .map_memory(memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
        }
        .map_err(vk_err)?;
        self.mapped = true;
        // `size` is 0 for images (whole-size map) and the buffer size for buffers.
        let _ = size;
        Ok(ptr as *mut u8)
    }

    /// `Unmap(subresource)` — unmap a previously mapped resource.
    pub fn unmap(&mut self) -> Result<(), D3d12Error> {
        if !self.mapped {
            return Ok(());
        }
        let memory = match &self.inner {
            ResourceInner::Buffer { memory, .. } => *memory,
            ResourceInner::Image { memory, .. } => *memory,
        };
        unsafe {
            // SAFETY: `memory` is currently mapped (we checked `mapped`); unmap is
            // safe exactly once per map.
            self.ctx.device.unmap_memory(memory);
        }
        self.mapped = false;
        Ok(())
    }
}

impl Drop for Resource {
    fn drop(&mut self) {
        // If still mapped, unmap before freeing memory.
        if self.mapped {
            let memory = match &self.inner {
                ResourceInner::Buffer { memory, .. } => *memory,
                ResourceInner::Image { memory, .. } => *memory,
            };
            unsafe {
                // SAFETY: `memory` is mapped (we only set `mapped` after a successful
                // map); unmap is safe.
                self.ctx.device.unmap_memory(memory);
            }
            self.mapped = false;
        }
        unsafe {
            // SAFETY: the image/buffer and its memory were created from `ctx.device`
            // and bound together; each is destroyed exactly once here.
            match &self.inner {
                ResourceInner::Image { image, memory, .. } => {
                    self.ctx.device.destroy_image(*image, None);
                    self.ctx.device.free_memory(*memory, None);
                }
                ResourceInner::Buffer { buffer, memory, .. } => {
                    self.ctx.device.destroy_buffer(*buffer, None);
                    self.ctx.device.free_memory(*memory, None);
                }
            }
        }
    }
}

// ===========================================================================
// Descriptor heaps + handles
// ===========================================================================

/// `D3D12_DESCRIPTOR_HEAP_TYPE` — which kind of descriptor a heap holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorHeapType {
    /// Render-target views (`D3D12_DESCRIPTOR_HEAP_TYPE_RTV`). CPU-only (not
    /// shader-visible).
    Rtv,
    /// Depth-stencil views (`D3D12_DESCRIPTOR_HEAP_TYPE_DSV`). CPU-only.
    Dsv,
    /// Constant-buffer / shader-resource / unordered-access views
    /// (`D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV`). Shader-visible.
    CbvSrvUav,
    /// Samplers (`D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER`). Shader-visible.
    Sampler,
}

/// A single descriptor stored in a [`DescriptorHeap`]. Owns the underlying
/// `VkImageView`/`VkBufferView`, destroyed when the heap drops or the slot is
/// overwritten.
#[derive(Debug)]
enum Descriptor {
    /// A render-target view (image view + the image it views, for clearing).
    Rtv {
        view: vk::ImageView,
        image: vk::Image,
        format: vk::Format,
        extent: vk::Extent2D,
    },
    /// A shader-resource / unordered-access view over an image.
    Image {
        view: vk::ImageView,
        image: vk::Image,
        format: vk::Format,
    },
    /// A constant-buffer / shader-resource / unordered-access view over a buffer.
    Buffer {
        view: vk::BufferView,
        buffer: vk::Buffer,
    },
    /// An empty/unused slot.
    Empty,
}

impl Descriptor {
    /// The owned Vulkan view handle (image or buffer view), or null if empty.
    fn view_handle(&self) -> vk::ImageView {
        match self {
            Descriptor::Rtv { view, .. } | Descriptor::Image { view, .. } => *view,
            Descriptor::Buffer { .. } | Descriptor::Empty => vk::ImageView::null(),
        }
    }

    fn buffer_view_handle(&self) -> vk::BufferView {
        match self {
            Descriptor::Buffer { view, .. } => *view,
            _ => vk::BufferView::null(),
        }
    }

    /// Destroy any owned view against `device`, releasing the slot.
    ///
    /// # Safety
    /// `device` must be the `VkDevice` the stored view was created from, and the
    /// slot must not be concurrently referenced by the GPU.
    unsafe fn destroy(&mut self, device: &ash::Device) {
        unsafe {
            // SAFETY: see the function-level safety contract; each view is
            // destroyed at most once (the slot is then emptied below).
            match self {
                Descriptor::Rtv { view, .. } | Descriptor::Image { view, .. } => {
                    if *view != vk::ImageView::null() {
                        device.destroy_image_view(*view, None);
                    }
                }
                Descriptor::Buffer { view, .. } => {
                    if *view != vk::BufferView::null() {
                        device.destroy_buffer_view(*view, None);
                    }
                }
                Descriptor::Empty => {}
            }
        }
        *self = Descriptor::Empty;
    }
}

/// `D3D12_CPU_DESCRIPTOR_HANDLE` — an opaque handle into a descriptor heap. In
/// D3D12 this is a raw pointer incremented by the descriptor increment size; the
/// translation layer models it as a heap-relative index (the increment size is
/// therefore `1` slot, see [`Device::get_descriptor_handle_increment_size`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuDescriptorHandle {
    /// The slot index within the owning heap.
    pub index: u32,
}

impl CpuDescriptorHandle {
    /// Offset this handle by `n` slots (D3D12 `ptr + n * incrementSize`).
    pub fn offset(self, n: u32) -> Self {
        Self {
            index: self.index + n,
        }
    }
}

/// `D3D12_GPU_DESCRIPTOR_HANDLE` — the shader-visible analogue of
/// [`CpuDescriptorHandle`]. Only meaningful for shader-visible heaps
/// (CBV_SRV_UAV / Sampler).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GpuDescriptorHandle {
    pub index: u32,
}

impl GpuDescriptorHandle {
    /// Offset this handle by `n` slots.
    pub fn offset(self, n: u32) -> Self {
        Self {
            index: self.index + n,
        }
    }
}

/// `ID3D12DescriptorHeap` — a fixed-capacity array of descriptors. Each slot
/// owns a `VkImageView`/`VkBufferView` created by a `Create*View` call. RTV/DSV
/// heaps are CPU-only (no GPU handle); CBV_SRV_UAV/Sampler heaps are
/// shader-visible (the GPU handle is the same index space).
pub struct DescriptorHeap {
    ctx: Arc<VkCtx>,
    heap_type: DescriptorHeapType,
    /// Whether the heap is shader-visible (has a GPU handle).
    shader_visible: bool,
    descriptors: Vec<Descriptor>,
}

impl DescriptorHeap {
    /// The heap type.
    pub fn heap_type(&self) -> DescriptorHeapType {
        self.heap_type
    }

    /// Whether this heap is shader-visible.
    pub fn shader_visible(&self) -> bool {
        self.shader_visible
    }

    /// Number of descriptor slots in the heap.
    pub fn capacity(&self) -> usize {
        self.descriptors.len()
    }

    /// `GetCPUDescriptorHandleForHeapStart()` — the CPU handle of slot 0.
    pub fn cpu_descriptor_start(&self) -> CpuDescriptorHandle {
        CpuDescriptorHandle { index: 0 }
    }

    /// `GetGPUDescriptorHandleForHeapStart()` — the GPU handle of slot 0. Only
    /// valid for shader-visible heaps (returns the zero handle otherwise).
    pub fn gpu_descriptor_start(&self) -> GpuDescriptorHandle {
        GpuDescriptorHandle { index: 0 }
    }

    /// Borrow the descriptor at `handle` (must be in range).
    fn descriptor(&self, handle: CpuDescriptorHandle) -> Result<&Descriptor, D3d12Error> {
        self.descriptors
            .get(handle.index as usize)
            .ok_or(D3d12Error::DescriptorIndexOutOfRange(
                handle.index as usize,
                self.descriptors.len(),
            ))
    }

    /// Mutably borrow the slot at `index` (must be in range).
    fn slot_mut(&mut self, index: u32) -> Result<&mut Descriptor, D3d12Error> {
        let len = self.descriptors.len();
        self.descriptors
            .get_mut(index as usize)
            .ok_or(D3d12Error::DescriptorIndexOutOfRange(index as usize, len))
    }
}

impl Drop for DescriptorHeap {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: every descriptor in the heap was created from `ctx.device`; we
            // destroy each owned view exactly once and the heap owns no other Vulkan
            // resources.
            for slot in &mut self.descriptors {
                slot.destroy(&self.ctx.device);
            }
        }
    }
}

// ===========================================================================
// Root signature + pipeline state
// ===========================================================================

/// `ID3D12RootSignature` — the shader binding layout. Backed by a
/// `VkPipelineLayout`. The M8 minimal root signature is empty (no descriptor
/// set layouts, no push constants); the PSO borrows this layout at build time.
pub struct RootSignature {
    ctx: Arc<VkCtx>,
    layout: vk::PipelineLayout,
}

impl RootSignature {
    /// The underlying Vulkan pipeline layout (borrowed by the PSO at build time).
    pub fn layout(&self) -> vk::PipelineLayout {
        self.layout
    }
}

impl Drop for RootSignature {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `layout` was created from `ctx.device` and destroyed once.
            self.ctx.device.destroy_pipeline_layout(self.layout, None);
        }
    }
}

/// `D3D12_PRIMITIVE_TOPOLOGY` subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrimitiveTopology {
    PointList,
    LineList,
    LineStrip,
    #[default]
    TriangleList,
    TriangleStrip,
}

impl PrimitiveTopology {
    fn vk(self) -> vk::PrimitiveTopology {
        match self {
            PrimitiveTopology::PointList => vk::PrimitiveTopology::POINT_LIST,
            PrimitiveTopology::LineList => vk::PrimitiveTopology::LINE_LIST,
            PrimitiveTopology::LineStrip => vk::PrimitiveTopology::LINE_STRIP,
            PrimitiveTopology::TriangleList => vk::PrimitiveTopology::TRIANGLE_LIST,
            PrimitiveTopology::TriangleStrip => vk::PrimitiveTopology::TRIANGLE_STRIP,
        }
    }
}

/// `D3D12_FILL_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FillMode {
    #[default]
    Solid,
    Wireframe,
}

/// `D3D12_CULL_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CullMode {
    #[default]
    None,
    Front,
    Back,
}

impl CullMode {
    fn vk(self) -> vk::CullModeFlags {
        match self {
            CullMode::None => vk::CullModeFlags::NONE,
            CullMode::Front => vk::CullModeFlags::FRONT,
            CullMode::Back => vk::CullModeFlags::BACK,
        }
    }
}

/// `D3D12_RASTERIZER_DESC` subset.
#[derive(Debug, Clone, Copy)]
pub struct RasterizerDesc {
    pub fill_mode: FillMode,
    pub cull_mode: CullMode,
    pub front_counter_clockwise: bool,
}

impl Default for RasterizerDesc {
    fn default() -> Self {
        Self {
            fill_mode: FillMode::Solid,
            cull_mode: CullMode::None,
            front_counter_clockwise: false,
        }
    }
}

/// `D3D12_BLEND_DESC` subset. M8 renders opaque geometry, so blending is off.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlendDesc {
    pub alpha_to_coverage_enable: bool,
    pub independent_blend_enable: bool,
}

/// `D3D12_SAMPLE_DESC`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SampleDesc {
    pub count: u32,
    pub quality: u32,
}

impl SampleDesc {
    fn vk_samples(self) -> vk::SampleCountFlags {
        match self.count {
            1 => vk::SampleCountFlags::TYPE_1,
            2 => vk::SampleCountFlags::TYPE_2,
            4 => vk::SampleCountFlags::TYPE_4,
            8 => vk::SampleCountFlags::TYPE_8,
            16 => vk::SampleCountFlags::TYPE_16,
            32 => vk::SampleCountFlags::TYPE_32,
            64 => vk::SampleCountFlags::TYPE_64,
            _ => vk::SampleCountFlags::TYPE_1,
        }
    }
}

/// `D3D12_INPUT_CLASSIFICATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexInputRate {
    Vertex,
    Instance,
}

impl VertexInputRate {
    fn vk(self) -> vk::VertexInputRate {
        match self {
            VertexInputRate::Vertex => vk::VertexInputRate::VERTEX,
            VertexInputRate::Instance => vk::VertexInputRate::INSTANCE,
        }
    }
}

/// A vertex-input binding description (`D3D12_INPUT_ELEMENT_DESC` grouping).
#[derive(Debug, Clone, Copy)]
pub struct VertexInputBinding {
    pub binding: u32,
    pub stride: u32,
    pub input_rate: VertexInputRate,
}

/// A single vertex attribute (`D3D12_INPUT_ELEMENT_DESC`).
#[derive(Debug, Clone, Copy)]
pub struct VertexInputAttribute {
    pub location: u32,
    pub binding: u32,
    pub format: vk::Format,
    pub offset: u32,
}

/// `D3D12_GRAPHICS_PIPELINE_STATE_DESC` subset. The shaders are supplied as
/// SPIR-V `u32` word streams (as produced by `nigg_hlsl_compiler::compile`); the
/// device builds and the PSO owns the resulting `VkShaderModule`s.
pub struct PipelineStateDesc {
    /// Optional root signature to borrow the pipeline layout from. If `None`, the
    /// PSO builds and owns an empty pipeline layout.
    pub root_signature: Option<vk::PipelineLayout>,
    /// Vertex shader SPIR-V words (required for a draw).
    pub vs_spirv: Option<Vec<u32>>,
    /// Pixel shader SPIR-V words (optional).
    pub ps_spirv: Option<Vec<u32>>,
    /// Render-target format (must match the bound render target).
    pub render_target_format: nigg_dxgi::DxgiFormat,
    /// Primitive topology.
    pub topology: PrimitiveTopology,
    /// Rasterizer state.
    pub rasterizer: RasterizerDesc,
    /// Blend state (off for M8).
    pub blend: BlendDesc,
    /// Sample state (typically 1/0).
    pub sample_desc: SampleDesc,
    /// Vertex-input bindings (empty for vertex-index-generated geometry).
    pub vertex_bindings: Vec<VertexInputBinding>,
    /// Vertex-input attributes.
    pub vertex_attributes: Vec<VertexInputAttribute>,
}

impl std::fmt::Debug for PipelineStateDesc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineStateDesc")
            .field("root_signature", &self.root_signature)
            .field("vs_spirv_len", &self.vs_spirv.as_ref().map(Vec::len))
            .field("ps_spirv_len", &self.ps_spirv.as_ref().map(Vec::len))
            .field("render_target_format", &self.render_target_format)
            .field("topology", &self.topology)
            .field("rasterizer", &self.rasterizer)
            .field("blend", &self.blend)
            .field("sample_desc", &self.sample_desc)
            .field("vertex_bindings", &self.vertex_bindings)
            .field("vertex_attributes", &self.vertex_attributes)
            .finish()
    }
}

impl Default for PipelineStateDesc {
    fn default() -> Self {
        Self {
            root_signature: None,
            vs_spirv: None,
            ps_spirv: None,
            render_target_format: nigg_dxgi::DxgiFormat::B8G8R8A8Unorm,
            topology: PrimitiveTopology::TriangleList,
            rasterizer: RasterizerDesc::default(),
            blend: BlendDesc::default(),
            sample_desc: SampleDesc::default(),
            vertex_bindings: Vec::new(),
            vertex_attributes: Vec::new(),
        }
    }
}

/// `ID3D12PipelineState` — a complete graphics pipeline. Owns the
/// `VkPipeline`, its `VkRenderPass`, and (when it built its own) the
/// `VkPipelineLayout`; plus the `VkShaderModule`s used to build it.
pub struct PipelineState {
    ctx: Arc<VkCtx>,
    pipeline: vk::Pipeline,
    render_pass: vk::RenderPass,
    /// The layout bound into the pipeline. Destroyed on drop iff `owns_layout`.
    layout: vk::PipelineLayout,
    owns_layout: bool,
    modules: Vec<vk::ShaderModule>,
}

impl PipelineState {
    /// The Vulkan pipeline handle (borrowed by the command list at draw time).
    pub fn pipeline(&self) -> vk::Pipeline {
        self.pipeline
    }

    /// The Vulkan render pass (compatible with the bound render target).
    pub fn render_pass(&self) -> vk::RenderPass {
        self.render_pass
    }
}

impl Drop for PipelineState {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: all handles were created from `ctx.device`; each is destroyed
            // exactly once here. The pipeline is destroyed before its layout/render
            // pass/modules (Vulkan allows destroying the layout/render pass after
            // pipeline creation as long as the pipeline is destroyed first).
            self.ctx.device.destroy_pipeline(self.pipeline, None);
            self.ctx.device.destroy_render_pass(self.render_pass, None);
            if self.owns_layout {
                self.ctx.device.destroy_pipeline_layout(self.layout, None);
            }
            for m in &self.modules {
                self.ctx.device.destroy_shader_module(*m, None);
            }
        }
    }
}

// ===========================================================================
// Command allocator + command list
// ===========================================================================

/// `ID3D12CommandAllocator` — owns a `VkCommandPool` that backs one or more
/// command lists. Resetting the allocator recycles the pool's command buffers.
pub struct CommandAllocator {
    ctx: Arc<VkCtx>,
    pool: vk::CommandPool,
}

impl CommandAllocator {
    /// The Vulkan command pool (used by the device to allocate command lists).
    fn pool(&self) -> vk::CommandPool {
        self.pool
    }

    /// `Reset()` — reset the allocator, recycling all command buffers allocated
    /// from its pool. The caller must guarantee no GPU work is pending on any
    /// command list built from this allocator.
    pub fn reset(&self) -> Result<(), D3d12Error> {
        unsafe {
            // SAFETY: `pool` is valid and owned by this allocator; the caller
            // guarantees no pending GPU work references it (M8 executes
            // synchronously, so the prior execute has completed).
            self.ctx
                .device
                .reset_command_pool(self.pool, vk::CommandPoolResetFlags::empty())
        }
        .map_err(vk_err)
    }
}

impl Drop for CommandAllocator {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `pool` was created from `ctx.device`; destroying it frees all
            // command buffers allocated from it. Command lists built from this
            // allocator hold an `Arc<CommandAllocator>`, so this only runs once all
            // such lists are dropped.
            self.ctx.device.destroy_command_pool(self.pool, None);
        }
    }
}

/// A render target bound to the command list via `set_render_targets`.
#[derive(Clone, Copy)]
struct BoundTarget {
    view: vk::ImageView,
    image: vk::Image,
    format: vk::Format,
    extent: vk::Extent2D,
}

/// A pipeline bound to the command list via `set_pipeline_state`.
#[derive(Clone, Copy)]
struct BoundPipeline {
    pipeline: vk::Pipeline,
    render_pass: vk::RenderPass,
}

/// `ID3D12GraphicsCommandList` — records commands into a `VkCommandBuffer`
/// allocated from a [`CommandAllocator`]. D3D12 command lists are created in the
/// open (recording) state; [`close`] ends recording. Holds an `Arc` to its
/// allocator so the underlying pool outlives the command buffer.
///
/// [`close`]: Self::close
pub struct GraphicsCommandList {
    ctx: Arc<VkCtx>,
    /// Keeps the allocator (and its pool) alive for the command buffer's lifetime.
    _allocator: Arc<CommandAllocator>,
    command_buffer: vk::CommandBuffer,
    /// The render target set by `set_render_targets` (borrowed handle).
    target: Option<BoundTarget>,
    /// The pipeline set by `set_pipeline_state` (borrowed handle).
    pipeline: Option<BoundPipeline>,
    /// Recorded viewport (for the draw path).
    viewport: Option<vk::Viewport>,
    /// Recorded scissor (for the draw path).
    scissor: Option<vk::Rect2D>,
    /// True while the command buffer is in the recording state.
    recording: bool,
    /// True once `close` has been called.
    closed: bool,
}

impl GraphicsCommandList {
    /// Borrow the underlying Vulkan command buffer (for queue submission).
    pub fn command_buffer(&self) -> vk::CommandBuffer {
        self.command_buffer
    }

    /// Whether the list is closed (ready to execute).
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// `Close()` — end command buffer recording. After this the list is ready to
    /// execute on a command queue.
    pub fn close(&mut self) -> Result<(), D3d12Error> {
        if self.closed {
            return Ok(());
        }
        if !self.recording {
            return Err(D3d12Error::Invalid(
                "close called on a command list that was never recording".into(),
            ));
        }
        unsafe {
            // SAFETY: `command_buffer` is in the recording state (we began it on
            // creation or on `reset`).
            self.ctx
                .device
                .end_command_buffer(self.command_buffer)
                .map_err(vk_err)?;
        }
        self.recording = false;
        self.closed = true;
        Ok(())
    }

    /// `Reset(allocator, initial_pso)` — recycle the command list for a new
    /// recording. Frees the old command buffer back to `allocator`'s pool and
    /// allocates a fresh one in the open state. The bound target/pipeline are
    /// cleared. M8 resets to the same allocator.
    pub fn reset(&mut self, allocator: Arc<CommandAllocator>) -> Result<(), D3d12Error> {
        // The previous command buffer must not be pending (M8 executes
        // synchronously, so it has completed).
        unsafe {
            // SAFETY: the command buffer is not pending (synchronous execute) and
            // belongs to the old allocator's pool; freeing it there is safe.
            self.ctx.device.free_command_buffers(
                self._allocator.pool(),
                std::slice::from_ref(&self.command_buffer),
            );
        }
        self._allocator = allocator;
        let alloc_info = vk::CommandBufferAllocateInfo::default()
            .command_pool(self._allocator.pool())
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(1);
        self.command_buffer = unsafe {
            // SAFETY: the allocator's pool is valid and owned.
            self.ctx.device.allocate_command_buffers(&alloc_info)
        }
        .map_err(vk_err)?
        .pop()
        .ok_or_else(|| D3d12Error::Vulkan("command buffer allocation returned none".into()))?;
        let begin_info = vk::CommandBufferBeginInfo::default()
            .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
        unsafe {
            // SAFETY: the freshly allocated command buffer is not in the recording
            // state.
            self.ctx
                .device
                .begin_command_buffer(self.command_buffer, &begin_info)
        }
        .map_err(vk_err)?;
        self.target = None;
        self.pipeline = None;
        self.viewport = None;
        self.scissor = None;
        self.recording = true;
        self.closed = false;
        Ok(())
    }

    /// `SetPipelineState(pso)` — bind a graphics pipeline. The pipeline's render
    /// pass is remembered for the draw-time framebuffer.
    pub fn set_pipeline_state(&mut self, pso: &PipelineState) {
        self.pipeline = Some(BoundPipeline {
            pipeline: pso.pipeline(),
            render_pass: pso.render_pass(),
        });
    }

    /// `OMSetRenderTargets` — bind one or more render targets. M8 supports a
    /// single colour target (the first handle). The target view is borrowed from
    /// `heap` and remembered for the draw path.
    pub fn set_render_targets(
        &mut self,
        heap: &DescriptorHeap,
        handles: &[CpuDescriptorHandle],
    ) -> Result<(), D3d12Error> {
        let first = handles.first().ok_or(D3d12Error::Invalid(
            "set_render_targets needs at least one handle".into(),
        ))?;
        let desc = heap.descriptor(*first)?;
        match desc {
            Descriptor::Rtv {
                view,
                image,
                format,
                extent,
            } => {
                self.target = Some(BoundTarget {
                    view: *view,
                    image: *image,
                    format: *format,
                    extent: *extent,
                });
            }
            other => {
                return Err(D3d12Error::Invalid(format!(
                    "descriptor at index {} is not an RTV (got {:?})",
                    first.index, other
                )));
            }
        }
        Ok(())
    }

    /// `ClearRenderTargetView(rtv, color, rects)` — record a `vkCmdClearColorImage`
    /// for the render target referenced by `handle`. The image is transitioned to
    /// `TRANSFER_DST_OPTIMAL` for the clear and back to `COLOR_ATTACHMENT_OPTIMAL`
    /// (the D3D12 `RENDER_TARGET` state) afterwards, so a subsequent
    /// `RENDER_TARGET → PRESENT` barrier is well-formed.
    ///
    /// `UNDEFINED` is used as the old layout of the first transition: a clear
    /// discards prior contents, so this is valid regardless of the image's actual
    /// current layout (matching the D3D11 translation's clear path).
    pub fn clear_render_target_view(
        &mut self,
        heap: &DescriptorHeap,
        handle: CpuDescriptorHandle,
        color: [f32; 4],
    ) -> Result<(), D3d12Error> {
        self.require_recording()?;
        let desc = heap.descriptor(handle)?;
        let (image, format) = match desc {
            Descriptor::Rtv { image, format, .. } => (*image, *format),
            other => {
                return Err(D3d12Error::Invalid(format!(
                    "clear_render_target_view expects an RTV descriptor (got {:?})",
                    other
                )));
            }
        };
        let _ = format; // format is implied by the image; not needed for the clear call.
        let clear_color = vk::ClearColorValue { float32: color };
        let subresource = vk::ImageSubresourceRange::default()
            .aspect_mask(vk::ImageAspectFlags::COLOR)
            .level_count(1)
            .layer_count(1);
        let device = &self.ctx.device;
        let cmd = self.command_buffer;
        let barrier_to_dst = vk::ImageMemoryBarrier::default()
            .old_layout(vk::ImageLayout::UNDEFINED)
            .new_layout(vk::ImageLayout::TRANSFER_DST_OPTIMAL)
            .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
            .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
            .image(image)
            .subresource_range(subresource)
            .src_access_mask(vk::AccessFlags::empty())
            .dst_access_mask(vk::AccessFlags::TRANSFER_WRITE);
        let barrier_to_color = vk::ImageMemoryBarrier::default()
            .old_layout(vk::ImageLayout::TRANSFER_DST_OPTIMAL)
            .new_layout(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL)
            .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
            .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
            .image(image)
            .subresource_range(subresource)
            .src_access_mask(vk::AccessFlags::TRANSFER_WRITE)
            .dst_access_mask(
                vk::AccessFlags::COLOR_ATTACHMENT_READ | vk::AccessFlags::COLOR_ATTACHMENT_WRITE,
            );
        unsafe {
            // SAFETY: `image` is valid; the barrier transitions it UNDEFINED→
            // TRANSFER_DST (old contents discarded, which a clear permits).
            device.cmd_pipeline_barrier(
                cmd,
                vk::PipelineStageFlags::TOP_OF_PIPE,
                vk::PipelineStageFlags::TRANSFER,
                vk::DependencyFlags::empty(),
                &[],
                &[],
                std::slice::from_ref(&barrier_to_dst),
            );
            // SAFETY: image is now in TRANSFER_DST_OPTIMAL, the layout the clear
            // requires; `subresource` covers the single mip/layer.
            device.cmd_clear_color_image(
                cmd,
                image,
                vk::ImageLayout::TRANSFER_DST_OPTIMAL,
                &clear_color,
                std::slice::from_ref(&subresource),
            );
            // SAFETY: transition back to COLOR_ATTACHMENT_OPTIMAL, the layout the
            // render-target state and a subsequent RENDER_TARGET→PRESENT barrier
            // expect.
            device.cmd_pipeline_barrier(
                cmd,
                vk::PipelineStageFlags::TRANSFER,
                vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT,
                vk::DependencyFlags::empty(),
                &[],
                &[],
                std::slice::from_ref(&barrier_to_color),
            );
        }
        Ok(())
    }

    /// `RSSetViewports` — set the viewport(s) used by the draw path. M8 records
    /// a single viewport.
    pub fn set_viewport(&mut self, viewport: vk::Viewport) -> Result<(), D3d12Error> {
        self.require_recording()?;
        self.viewport = Some(viewport);
        unsafe {
            // SAFETY: `command_buffer` is recording; `viewport` is a valid viewport
            // state set dynamically (the PSO has viewport count 1).
            self.ctx.device.cmd_set_viewport(
                self.command_buffer,
                0,
                std::slice::from_ref(&viewport),
            );
        }
        Ok(())
    }

    /// `RSSetScissorRects` — set the scissor rect(s) used by the draw path.
    pub fn set_scissor_rect(&mut self, scissor: vk::Rect2D) -> Result<(), D3d12Error> {
        self.require_recording()?;
        self.scissor = Some(scissor);
        unsafe {
            // SAFETY: `command_buffer` is recording; `scissor` is a valid scissor.
            self.ctx
                .device
                .cmd_set_scissor(self.command_buffer, 0, std::slice::from_ref(&scissor));
        }
        Ok(())
    }

    /// `ResourceBarrier` — record one or more image/buffer memory barriers. The
    /// app declares the before/after D3D12 states; the translation layer maps them
    /// to `VkImageLayout`/`VkBufferLayout` and access/stage masks. The caller is
    /// responsible for declaring a `state_before` that matches the resource's
    /// actual current state (the standard D3D12 contract).
    pub fn resource_barrier(&mut self, barriers: &[ResourceBarrier<'_>]) -> Result<(), D3d12Error> {
        self.require_recording()?;
        if barriers.is_empty() {
            return Ok(());
        }
        let device = &self.ctx.device;
        let cmd = self.command_buffer;
        // Collect image + buffer barriers separately so we issue at most two
        // `cmd_pipeline_barrier` calls (one per type), each with all of its kind.
        let mut image_barriers: Vec<vk::ImageMemoryBarrier<'_>> = Vec::new();
        let mut buffer_barriers: Vec<vk::BufferMemoryBarrier<'_>> = Vec::new();
        let mut src_stages_img = vk::PipelineStageFlags::empty();
        let mut dst_stages_img = vk::PipelineStageFlags::empty();
        let mut src_stages_buf = vk::PipelineStageFlags::empty();
        let mut dst_stages_buf = vk::PipelineStageFlags::empty();
        let color_aspect = vk::ImageAspectFlags::COLOR;
        for b in barriers {
            match &b.resource.inner {
                ResourceInner::Image { image, .. } => {
                    let range = vk::ImageSubresourceRange::default()
                        .aspect_mask(color_aspect)
                        .level_count(b.resource.desc.mip_levels as u32)
                        .layer_count(b.resource.desc.depth_or_array_size as u32);
                    image_barriers.push(
                        vk::ImageMemoryBarrier::default()
                            .old_layout(b.state_before.vk_image_layout())
                            .new_layout(b.state_after.vk_image_layout())
                            .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                            .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                            .image(*image)
                            .subresource_range(range)
                            .src_access_mask(b.state_before.src_access())
                            .dst_access_mask(b.state_after.dst_access()),
                    );
                    src_stages_img |= b.state_before.src_stage();
                    dst_stages_img |= b.state_after.dst_stage();
                }
                ResourceInner::Buffer { buffer, .. } => {
                    buffer_barriers.push(
                        vk::BufferMemoryBarrier::default()
                            .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                            .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
                            .buffer(*buffer)
                            .offset(0)
                            .size(vk::WHOLE_SIZE)
                            .src_access_mask(b.state_before.src_access())
                            .dst_access_mask(b.state_after.dst_access()),
                    );
                    src_stages_buf |= b.state_before.src_stage();
                    dst_stages_buf |= b.state_after.dst_stage();
                    let _ = b.state_before.vk_buffer_layout();
                }
            }
        }
        unsafe {
            // SAFETY: each barrier references a valid image/buffer owned by the
            // referenced `Resource`; the declared before-states match the app's
            // tracked state (the D3D12 contract). The stage masks are the union of
            // the per-barrier source/destination stages.
            if !image_barriers.is_empty() {
                device.cmd_pipeline_barrier(
                    cmd,
                    if src_stages_img.is_empty() {
                        vk::PipelineStageFlags::TOP_OF_PIPE
                    } else {
                        src_stages_img
                    },
                    if dst_stages_img.is_empty() {
                        vk::PipelineStageFlags::BOTTOM_OF_PIPE
                    } else {
                        dst_stages_img
                    },
                    vk::DependencyFlags::empty(),
                    &[],
                    &[],
                    &image_barriers,
                );
            }
            if !buffer_barriers.is_empty() {
                device.cmd_pipeline_barrier(
                    cmd,
                    if src_stages_buf.is_empty() {
                        vk::PipelineStageFlags::TOP_OF_PIPE
                    } else {
                        src_stages_buf
                    },
                    if dst_stages_buf.is_empty() {
                        vk::PipelineStageFlags::BOTTOM_OF_PIPE
                    } else {
                        dst_stages_buf
                    },
                    vk::DependencyFlags::empty(),
                    &[],
                    &buffer_barriers,
                    &[],
                );
            }
        }
        Ok(())
    }

    /// `DrawInstanced(vertex_count, instance_count, start_vertex, start_instance)`
    /// — record a non-indexed draw inside a render pass built from the bound
    /// render target + pipeline state. A transient framebuffer is created for the
    /// draw and destroyed immediately afterwards.
    pub fn draw_instanced(
        &mut self,
        vertex_count: u32,
        instance_count: u32,
        start_vertex: u32,
        start_instance: u32,
    ) -> Result<(), D3d12Error> {
        self.require_recording()?;
        let target = self.target.ok_or(D3d12Error::NoRenderTarget)?;
        let pipeline = self.pipeline.ok_or(D3d12Error::NoPipeline)?;
        let device = &self.ctx.device;
        let cmd = self.command_buffer;

        // Build a transient framebuffer compatible with the PSO's render pass and
        // the bound target view. Destroyed at the end of the draw.
        let attachments = [target.view];
        let fb_info = vk::FramebufferCreateInfo::default()
            .render_pass(pipeline.render_pass)
            .attachments(&attachments)
            .width(target.extent.width)
            .height(target.extent.height)
            .layers(1);
        let framebuffer = unsafe {
            // SAFETY: `pipeline.render_pass` is compatible with `target.view` (both
            // were built from the same colour format); the extent matches the
            // target image.
            device.create_framebuffer(&fb_info, None)
        }
        .map_err(vk_err)?;
        // RAII guard so the framebuffer is destroyed even on the early-return paths.
        let fb_guard = FramebufferGuard {
            device,
            framebuffer,
        };

        let clear = [vk::ClearValue {
            color: vk::ClearColorValue {
                float32: [0.0, 0.0, 0.0, 0.0],
            },
        }];
        let begin = vk::RenderPassBeginInfo::default()
            .render_pass(pipeline.render_pass)
            .framebuffer(framebuffer)
            .render_area(vk::Rect2D {
                offset: vk::Offset2D { x: 0, y: 0 },
                extent: target.extent,
            })
            .clear_values(&clear);
        unsafe {
            // SAFETY: `pipeline.render_pass` and `framebuffer` are compatible (built
            // from the same colour attachment); begin the pass inline.
            device.cmd_begin_render_pass(cmd, &begin, vk::SubpassContents::INLINE);
            // SAFETY: bind the bound graphics pipeline.
            device.cmd_bind_pipeline(cmd, vk::PipelineBindPoint::GRAPHICS, pipeline.pipeline);
            // SAFETY: valid bound pipeline; D3D12 DrawInstanced maps directly to
            // vkCmdDraw(vertex_count, instance_count, start_vertex, start_instance).
            device.cmd_draw(
                cmd,
                vertex_count,
                instance_count,
                start_vertex,
                start_instance,
            );
            // SAFETY: a matching begin_render_pass was recorded above.
            device.cmd_end_render_pass(cmd);
        }
        // Destroy the transient framebuffer now that the pass has ended.
        drop(fb_guard);
        Ok(())
    }

    fn require_recording(&self) -> Result<(), D3d12Error> {
        if self.closed {
            return Err(D3d12Error::Invalid(
                "command used on a closed command list".into(),
            ));
        }
        if !self.recording {
            return Err(D3d12Error::Invalid(
                "command list is not in the recording state".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for GraphicsCommandList {
    fn drop(&mut self) {
        // If still recording, end the command buffer so it can be freed cleanly.
        if self.recording && !self.closed {
            unsafe {
                // SAFETY: the command buffer is in the recording state; ending it is
                // required before it can be freed back to the pool. The result is
                // ignored on drop (best-effort teardown).
                let _ = self.ctx.device.end_command_buffer(self.command_buffer);
            }
            self.recording = false;
            self.closed = true;
        }
        unsafe {
            // SAFETY: `command_buffer` was allocated from the allocator's pool (kept
            // alive by `_allocator`); freeing it back there is safe. We never free it
            // while pending because M8 executes synchronously.
            self.ctx.device.free_command_buffers(
                self._allocator.pool(),
                std::slice::from_ref(&self.command_buffer),
            );
        }
    }
}

/// A single resource barrier for [`GraphicsCommandList::resource_barrier`].
/// Borrows the resource and declares the before/after D3D12 states.
#[derive(Clone, Copy)]
pub struct ResourceBarrier<'a> {
    pub resource: &'a Resource,
    pub state_before: ResourceStates,
    pub state_after: ResourceStates,
}

/// RAII guard that destroys a transient framebuffer on drop.
struct FramebufferGuard<'a> {
    device: &'a ash::Device,
    framebuffer: vk::Framebuffer,
}

impl Drop for FramebufferGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `framebuffer` was created from `device` and is destroyed once.
            self.device.destroy_framebuffer(self.framebuffer, None);
        }
    }
}

// ===========================================================================
// Command queue
// ===========================================================================

/// `ID3D12CommandQueue` — submits command lists to the GPU. Backed by the shared
/// graphics `VkQueue`. M8 executes synchronously: each `execute_command_lists`
/// submits the command buffers and waits on a fence before returning.
pub struct CommandQueue {
    ctx: Arc<VkCtx>,
    queue: vk::Queue,
}

impl CommandQueue {
    /// Borrow the underlying Vulkan queue.
    pub fn queue(&self) -> vk::Queue {
        self.queue
    }

    /// `ExecuteCommandLists(lists)` — submit the given closed command lists to the
    /// queue and synchronously wait for them to complete (M8 simplification; a real
    /// D3D12 app would signal a fence and wait later). All lists must be closed.
    pub fn execute_command_lists(&self, lists: &[&GraphicsCommandList]) -> Result<(), D3d12Error> {
        if lists.is_empty() {
            return Ok(());
        }
        let mut command_buffers = Vec::with_capacity(lists.len());
        for list in lists {
            if !list.closed() {
                return Err(D3d12Error::Invalid(
                    "execute_command_lists: a command list is not closed".into(),
                ));
            }
            command_buffers.push(list.command_buffer());
        }
        let submit_info = vk::SubmitInfo::default().command_buffers(&command_buffers);
        let fence = unsafe {
            // SAFETY: `ctx.device` is valid; trivial create info.
            self.ctx
                .device
                .create_fence(&vk::FenceCreateInfo::default(), None)
        }
        .map_err(vk_err)?;
        let result = unsafe {
            // SAFETY: the command buffers are recorded, complete and not pending
            // (synchronous execution guarantees the prior execute finished); the
            // queue is the graphics queue.
            self.ctx
                .device
                .queue_submit(self.queue, std::slice::from_ref(&submit_info), fence)
        };
        if let Err(e) = result {
            unsafe {
                // SAFETY: `fence` was created above and was not signalled (submit
                // failed); destroy it before propagating.
                self.ctx.device.destroy_fence(fence, None);
            }
            return Err(vk_err(e));
        }
        unsafe {
            // SAFETY: `fence` was signalled by the submit above.
            let wait =
                self.ctx
                    .device
                    .wait_for_fences(std::slice::from_ref(&fence), true, u64::MAX);
            self.ctx.device.destroy_fence(fence, None);
            wait.map_err(vk_err)?;
        }
        Ok(())
    }
}

// ===========================================================================
// ID3D12Device
// ===========================================================================

/// `ID3D12Device` — wraps the shared Vulkan logical device + graphics queue.
pub struct Device {
    ctx: Arc<VkCtx>,
}

impl Device {
    /// Create a D3D12 device over a bare [`VkCtx`] (the same context the DXGI
    /// swap chain and D3D11 layer use).
    pub fn new(ctx: Arc<VkCtx>) -> Result<Self, D3d12Error> {
        Ok(Self { ctx })
    }

    /// Borrow the shared Vulkan context.
    pub fn ctx(&self) -> &Arc<VkCtx> {
        &self.ctx
    }

    /// `CreateCommandQueue` — return the shared graphics `VkQueue` wrapped as a
    /// [`CommandQueue`]. M8 uses a single queue (the graphics queue from
    /// [`VkCtx`]); `queue_type` is accepted for API parity but only `Direct` is
    /// honoured.
    pub fn create_command_queue(
        &self,
        _queue_type: CommandListType,
    ) -> Result<CommandQueue, D3d12Error> {
        Ok(CommandQueue {
            ctx: self.ctx.clone(),
            queue: self.ctx.graphics_queue,
        })
    }

    /// `CreateCommandAllocator` — create a `VkCommandPool` for the graphics queue
    /// family.
    pub fn create_command_allocator(
        &self,
        _list_type: CommandListType,
    ) -> Result<Arc<CommandAllocator>, D3d12Error> {
        let pool_info = vk::CommandPoolCreateInfo::default()
            .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER)
            .queue_family_index(self.ctx.selected.graphics_family);
        let pool = unsafe {
            // SAFETY: `ctx.device` is valid; the queue family index was validated at
            // VkCtx creation. RESET_COMMAND_BUFFER lets command lists be re-recorded.
            self.ctx.device.create_command_pool(&pool_info, None)
        }
        .map_err(vk_err)?;
        Ok(Arc::new(CommandAllocator {
            ctx: self.ctx.clone(),
            pool,
        }))
    }

    /// `CreateCommandList(allocator, type, pso)` — allocate a primary command
    /// buffer from `allocator`'s pool and begin recording (D3D12 command lists
    /// are created in the open state). The list holds an `Arc` to `allocator` so
    /// the pool outlives the command buffer.
    pub fn create_command_list(
        &self,
        allocator: Arc<CommandAllocator>,
        _list_type: CommandListType,
    ) -> Result<GraphicsCommandList, D3d12Error> {
        let alloc_info = vk::CommandBufferAllocateInfo::default()
            .command_pool(allocator.pool())
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(1);
        let command_buffer = unsafe {
            // SAFETY: `allocator.pool()` is a valid command pool.
            self.ctx.device.allocate_command_buffers(&alloc_info)
        }
        .map_err(vk_err)?
        .pop()
        .ok_or_else(|| D3d12Error::Vulkan("command buffer allocation returned none".into()))?;
        let begin_info = vk::CommandBufferBeginInfo::default()
            .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
        unsafe {
            // SAFETY: the freshly allocated command buffer is not in the recording
            // state.
            self.ctx
                .device
                .begin_command_buffer(command_buffer, &begin_info)
        }
        .map_err(vk_err)?;
        Ok(GraphicsCommandList {
            ctx: self.ctx.clone(),
            _allocator: allocator,
            command_buffer,
            target: None,
            pipeline: None,
            viewport: None,
            scissor: None,
            recording: true,
            closed: false,
        })
    }

    /// `CreateDescriptorHeap(type, count)` — allocate a descriptor heap with
    /// `count` empty slots.
    pub fn create_descriptor_heap(
        &self,
        heap_type: DescriptorHeapType,
        count: u32,
    ) -> Result<DescriptorHeap, D3d12Error> {
        let shader_visible = matches!(
            heap_type,
            DescriptorHeapType::CbvSrvUav | DescriptorHeapType::Sampler
        );
        let descriptors = (0..count).map(|_| Descriptor::Empty).collect();
        Ok(DescriptorHeap {
            ctx: self.ctx.clone(),
            heap_type,
            shader_visible,
            descriptors,
        })
    }

    /// `GetDescriptorHandleIncrementSize(type)` — the per-slot stride for handle
    /// arithmetic. The translation layer indexes a `Vec`, so the stride is `1`.
    pub fn get_descriptor_handle_increment_size(&self, _heap_type: DescriptorHeapType) -> u32 {
        1
    }

    /// `GetCPUDescriptorHandleForHeapStart`-style helper: the CPU handle of slot
    /// `index` in `heap`.
    pub fn get_cpu_descriptor_handle(
        &self,
        heap: &DescriptorHeap,
        index: u32,
    ) -> Result<CpuDescriptorHandle, D3d12Error> {
        if (index as usize) >= heap.capacity() {
            return Err(D3d12Error::DescriptorIndexOutOfRange(
                index as usize,
                heap.capacity(),
            ));
        }
        Ok(CpuDescriptorHandle { index })
    }

    /// `GetGPUDescriptorHandleForHeapStart`-style helper: the GPU handle of slot
    /// `index` in a shader-visible `heap`.
    pub fn get_gpu_descriptor_handle(
        &self,
        heap: &DescriptorHeap,
        index: u32,
    ) -> Result<GpuDescriptorHandle, D3d12Error> {
        if !heap.shader_visible() {
            return Err(D3d12Error::Invalid(
                "GPU descriptor handle requested for a non-shader-visible heap".into(),
            ));
        }
        if (index as usize) >= heap.capacity() {
            return Err(D3d12Error::DescriptorIndexOutOfRange(
                index as usize,
                heap.capacity(),
            ));
        }
        Ok(GpuDescriptorHandle { index })
    }

    /// `CreateRenderTargetView(resource, desc, cpu_descriptor)` — create a
    /// `VkImageView` over `resource` (a 2D colour image) and store it in `heap` at
    /// `index`, replacing any prior descriptor there.
    pub fn create_render_target_view(
        &self,
        resource: &Resource,
        heap: &mut DescriptorHeap,
        index: u32,
    ) -> Result<(), D3d12Error> {
        if heap.heap_type() != DescriptorHeapType::Rtv {
            return Err(D3d12Error::Invalid(format!(
                "create_render_target_view needs an RTV heap (got {:?})",
                heap.heap_type()
            )));
        }
        let (image, format, extent) = match &resource.inner {
            ResourceInner::Image {
                image,
                format,
                extent,
                ..
            } => (*image, *format, *extent),
            ResourceInner::Buffer { .. } => {
                return Err(D3d12Error::Invalid(
                    "create_render_target_view needs an image resource".into(),
                ));
            }
        };
        let subresource = vk::ImageSubresourceRange::default()
            .aspect_mask(vk::ImageAspectFlags::COLOR)
            .level_count(1)
            .layer_count(1);
        let create_info = vk::ImageViewCreateInfo::default()
            .image(image)
            .view_type(vk::ImageViewType::TYPE_2D)
            .format(format)
            .subresource_range(subresource);
        let view = unsafe {
            // SAFETY: `image` is valid (owned by `resource`) and `create_info`
            // describes a valid 2D colour view of it.
            self.ctx.device.create_image_view(&create_info, None)
        }
        .map_err(vk_err)?;
        let slot = heap.slot_mut(index)?;
        unsafe {
            // SAFETY: destroying the previous occupant (if any) before overwriting it
            // prevents leaking the old view; `device` is the creating device.
            slot.destroy(&self.ctx.device);
        }
        *slot = Descriptor::Rtv {
            view,
            image,
            format,
            extent: vk::Extent2D {
                width: extent.width,
                height: extent.height,
            },
        };
        Ok(())
    }

    /// `CreateCommittedResource(desc, initial_state)` — create a `VkImage` or
    /// `VkBuffer` plus bound device memory. Images are created device-local;
    /// buffers honour `desc.heap_type` (Default/Upload/Readback). The Vulkan
    /// image always starts in `UNDEFINED` layout; the app barriers into the
    /// `initial_state` as needed.
    pub fn create_committed_resource(
        &self,
        desc: ResourceDesc,
        _initial_state: ResourceStates,
    ) -> Result<Resource, D3d12Error> {
        match desc.dimension {
            ResourceDimension::Buffer => self.create_committed_buffer(desc),
            ResourceDimension::Texture1d
            | ResourceDimension::Texture2d
            | ResourceDimension::Texture3d => self.create_committed_image(desc),
        }
    }

    fn create_committed_image(&self, desc: ResourceDesc) -> Result<Resource, D3d12Error> {
        let image_type = match desc.dimension {
            ResourceDimension::Texture1d => vk::ImageType::TYPE_1D,
            ResourceDimension::Texture2d => vk::ImageType::TYPE_2D,
            ResourceDimension::Texture3d => vk::ImageType::TYPE_3D,
            ResourceDimension::Buffer => unreachable!("buffer handled elsewhere"),
        };
        let depth = if desc.dimension == ResourceDimension::Texture3d {
            desc.depth_or_array_size as u32
        } else {
            1
        };
        let array_layers = if desc.dimension == ResourceDimension::Texture3d {
            1
        } else {
            desc.depth_or_array_size as u32
        };
        let usage = vk::ImageUsageFlags::COLOR_ATTACHMENT | vk::ImageUsageFlags::TRANSFER_DST;
        let create_info = vk::ImageCreateInfo::default()
            .image_type(image_type)
            .format(desc.format.vk_format())
            .extent(vk::Extent3D {
                width: desc.width as u32,
                height: desc.height,
                depth,
            })
            .mip_levels(desc.mip_levels as u32)
            .array_layers(array_layers)
            .samples(vk::SampleCountFlags::from_raw(desc.sample_count))
            .tiling(vk::ImageTiling::OPTIMAL)
            .usage(usage)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::UNDEFINED);
        let image = unsafe {
            // SAFETY: `ctx.device` is valid; `create_info` describes a valid image.
            self.ctx.device.create_image(&create_info, None)
        }
        .map_err(vk_err)?;
        let reqs = unsafe {
            // SAFETY: `image` is a valid VkImage just created.
            self.ctx.device.get_image_memory_requirements(image)
        };
        let mem_type = self
            .ctx
            .find_memory_type(reqs.memory_type_bits, desc.heap_type.vk_memory_flags())
            .map_err(D3d12Error::from)?;
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(reqs.size)
            .memory_type_index(mem_type);
        let memory = unsafe {
            // SAFETY: memory type chosen from the image's requirements.
            self.ctx.device.allocate_memory(&alloc_info, None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: `memory` was allocated for this image; offset 0 is the only
            // binding.
            self.ctx
                .device
                .bind_image_memory(image, memory, 0)
                .map_err(vk_err)?;
        }
        // Images are device-local in M8, so never host-visible.
        Ok(Resource {
            ctx: self.ctx.clone(),
            inner: ResourceInner::Image {
                image,
                memory,
                format: desc.format.vk_format(),
                extent: vk::Extent3D {
                    width: desc.width as u32,
                    height: desc.height,
                    depth,
                },
                host_visible: false,
            },
            desc,
            mapped: false,
        })
    }

    fn create_committed_buffer(&self, desc: ResourceDesc) -> Result<Resource, D3d12Error> {
        let size = desc.width;
        if size == 0 {
            return Err(D3d12Error::Invalid("buffer size must be > 0".into()));
        }
        let create_info = vk::BufferCreateInfo::default()
            .size(size)
            .usage(
                vk::BufferUsageFlags::VERTEX_BUFFER
                    | vk::BufferUsageFlags::INDEX_BUFFER
                    | vk::BufferUsageFlags::UNIFORM_BUFFER
                    | vk::BufferUsageFlags::TRANSFER_SRC
                    | vk::BufferUsageFlags::TRANSFER_DST,
            )
            .sharing_mode(vk::SharingMode::EXCLUSIVE);
        let buffer = unsafe {
            // SAFETY: `ctx.device` is valid; `create_info` is a valid buffer spec.
            self.ctx.device.create_buffer(&create_info, None)
        }
        .map_err(vk_err)?;
        let reqs = unsafe {
            // SAFETY: `buffer` is a valid VkBuffer just created.
            self.ctx.device.get_buffer_memory_requirements(buffer)
        };
        let mem_type = self
            .ctx
            .find_memory_type(reqs.memory_type_bits, desc.heap_type.vk_memory_flags())
            .map_err(D3d12Error::from)?;
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(reqs.size)
            .memory_type_index(mem_type);
        let memory = unsafe {
            // SAFETY: memory type chosen from the buffer's requirements.
            self.ctx.device.allocate_memory(&alloc_info, None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: `memory` was allocated for this buffer; offset 0 is the only
            // binding.
            self.ctx
                .device
                .bind_buffer_memory(buffer, memory, 0)
                .map_err(vk_err)?;
        }
        let host_visible = matches!(desc.heap_type, HeapType::Upload | HeapType::Readback);
        Ok(Resource {
            ctx: self.ctx.clone(),
            inner: ResourceInner::Buffer {
                buffer,
                memory,
                size,
                host_visible,
            },
            desc,
            mapped: false,
        })
    }

    /// `CreateRootSignature` — create an empty `VkPipelineLayout` (no descriptor
    /// set layouts, no push constants). Sufficient for the M8 clear-screen
    /// sample and for shaders that take no root arguments.
    pub fn create_root_signature(&self) -> Result<RootSignature, D3d12Error> {
        let layout_info = vk::PipelineLayoutCreateInfo::default();
        let layout = unsafe {
            // SAFETY: valid device + empty layout (no descriptor sets/push constants).
            self.ctx.device.create_pipeline_layout(&layout_info, None)
        }
        .map_err(vk_err)?;
        Ok(RootSignature {
            ctx: self.ctx.clone(),
            layout,
        })
    }

    /// `CreateGraphicsPipelineState(desc)` — build a `VkRenderPass` (from the
    /// PSO's render-target format) and a `VkGraphicsPipeline`, owning the shader
    /// modules. If `desc.root_signature` is `Some`, its layout is borrowed (not
    // destroyed by the PSO); otherwise an empty layout is created and owned.
    pub fn create_pipeline_state(
        &self,
        desc: &PipelineStateDesc,
    ) -> Result<PipelineState, D3d12Error> {
        let format = desc.render_target_format.vk_format();
        let render_pass = make_render_pass(&self.ctx.device, format)?;

        // Build shader modules for the supplied SPIR-V.
        let mut modules: Vec<vk::ShaderModule> = Vec::new();
        let mut stages: Vec<vk::PipelineShaderStageCreateInfo<'_>> = Vec::new();
        let entry_name = c"main";
        if let Some(vs) = &desc.vs_spirv {
            let module = self.create_shader_module(vs)?;
            stages.push(
                vk::PipelineShaderStageCreateInfo::default()
                    .stage(vk::ShaderStageFlags::VERTEX)
                    .module(module)
                    .name(entry_name),
            );
            modules.push(module);
        }
        if let Some(ps) = &desc.ps_spirv {
            let module = self.create_shader_module(ps)?;
            stages.push(
                vk::PipelineShaderStageCreateInfo::default()
                    .stage(vk::ShaderStageFlags::FRAGMENT)
                    .module(module)
                    .name(entry_name),
            );
            modules.push(module);
        }

        // Convert the PSO's vertex-input descriptions into vk structs that live for
        // the duration of pipeline creation.
        let vk_bindings: Vec<vk::VertexInputBindingDescription> = desc
            .vertex_bindings
            .iter()
            .map(|b| vk::VertexInputBindingDescription {
                binding: b.binding,
                stride: b.stride,
                input_rate: b.input_rate.vk(),
            })
            .collect();
        let vk_attributes: Vec<vk::VertexInputAttributeDescription> = desc
            .vertex_attributes
            .iter()
            .map(|a| vk::VertexInputAttributeDescription {
                location: a.location,
                binding: a.binding,
                format: a.format,
                offset: a.offset,
            })
            .collect();
        let vertex_input = vk::PipelineVertexInputStateCreateInfo::default()
            .vertex_binding_descriptions(&vk_bindings)
            .vertex_attribute_descriptions(&vk_attributes);

        let input_assembly =
            vk::PipelineInputAssemblyStateCreateInfo::default().topology(desc.topology.vk());

        // Static viewport/scissor state: the PSO declares one viewport/scissor; the
        // command list sets the actual values dynamically (Vulkan dynamic state).
        let viewport_state = vk::PipelineViewportStateCreateInfo::default()
            .viewport_count(1)
            .scissor_count(1);

        let raster_state = vk::PipelineRasterizationStateCreateInfo::default()
            .depth_clamp_enable(false)
            .rasterizer_discard_enable(false)
            .polygon_mode(if desc.rasterizer.fill_mode == FillMode::Wireframe {
                vk::PolygonMode::LINE
            } else {
                vk::PolygonMode::FILL
            })
            .cull_mode(desc.rasterizer.cull_mode.vk())
            .front_face(if desc.rasterizer.front_counter_clockwise {
                vk::FrontFace::COUNTER_CLOCKWISE
            } else {
                vk::FrontFace::CLOCKWISE
            })
            .line_width(1.0);

        let multisample = vk::PipelineMultisampleStateCreateInfo::default()
            .rasterization_samples(desc.sample_desc.vk_samples());

        let blend_attachment = vk::PipelineColorBlendAttachmentState::default()
            .blend_enable(false)
            .color_write_mask(vk::ColorComponentFlags::RGBA);
        let blend_state = vk::PipelineColorBlendStateCreateInfo::default()
            .attachments(std::slice::from_ref(&blend_attachment));

        // Decide on the pipeline layout: borrow the root signature's, or build an
        // empty owned one.
        let (layout, owns_layout) = match desc.root_signature {
            Some(provided) => (provided, false),
            None => {
                let layout_info = vk::PipelineLayoutCreateInfo::default();
                let layout = unsafe {
                    // SAFETY: valid device + empty layout.
                    self.ctx.device.create_pipeline_layout(&layout_info, None)
                }
                .map_err(vk_err)?;
                (layout, true)
            }
        };

        let create_info = vk::GraphicsPipelineCreateInfo::default()
            .stages(&stages)
            .vertex_input_state(&vertex_input)
            .input_assembly_state(&input_assembly)
            .viewport_state(&viewport_state)
            .rasterization_state(&raster_state)
            .multisample_state(&multisample)
            .color_blend_state(&blend_state)
            .layout(layout)
            .render_pass(render_pass)
            .subpass(0);

        let result = unsafe {
            // SAFETY: all state structs are valid and reference the freshly built
            // shader modules; the render pass matches the PSO's render-target format.
            self.ctx.device.create_graphics_pipelines(
                vk::PipelineCache::null(),
                std::slice::from_ref(&create_info),
                None,
            )
        };
        let pipeline = match result {
            Ok(pipelines) => pipelines.into_iter().next().ok_or_else(|| {
                D3d12Error::Vulkan("pipeline creation returned no pipelines".into())
            })?,
            Err((_pipelines, err)) => {
                // Teardown the per-attempt resources before propagating.
                unsafe {
                    // SAFETY: `render_pass`, the owned `layout` (if any) and the
                    // shader modules were created above and must not leak on failure.
                    self.ctx.device.destroy_render_pass(render_pass, None);
                    if owns_layout {
                        self.ctx.device.destroy_pipeline_layout(layout, None);
                    }
                    for m in &modules {
                        self.ctx.device.destroy_shader_module(*m, None);
                    }
                }
                return Err(vk_err(err));
            }
        };

        Ok(PipelineState {
            ctx: self.ctx.clone(),
            pipeline,
            render_pass,
            layout,
            owns_layout,
            modules,
        })
    }

    /// Build a `VkShaderModule` from a SPIR-V word stream.
    fn create_shader_module(&self, spirv: &[u32]) -> Result<vk::ShaderModule, D3d12Error> {
        let create_info = vk::ShaderModuleCreateInfo::default().code(spirv);
        unsafe {
            // SAFETY: `spirv` is a valid SPIR-V word stream; `ctx.device` is valid.
            self.ctx.device.create_shader_module(&create_info, None)
        }
        .map_err(vk_err)
    }
}

/// `D3D12_COMMAND_LIST_TYPE` subset. Only `Direct` (graphics) is exercised by
/// M8; the others are accepted for API parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandListType {
    /// `D3D12_COMMAND_LIST_TYPE_DIRECT` — the graphics queue.
    Direct,
    /// `D3D12_COMMAND_LIST_TYPE_COMPUTE` — a compute queue (not wired in M8).
    Compute,
    /// `D3D12_COMMAND_LIST_TYPE_COPY` — a copy queue (not wired in M8).
    Copy,
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Build a render pass with one colour attachment matching `format`, using
/// `CLEAR`/`STORE` load/store and `COLOR_ATTACHMENT_OPTIMAL` layouts (matching
/// the clear path's final layout).
fn make_render_pass(
    device: &ash::Device,
    format: vk::Format,
) -> Result<vk::RenderPass, D3d12Error> {
    let attachment = vk::AttachmentDescription::default()
        .format(format)
        .samples(vk::SampleCountFlags::TYPE_1)
        .load_op(vk::AttachmentLoadOp::CLEAR)
        .store_op(vk::AttachmentStoreOp::STORE)
        .stencil_load_op(vk::AttachmentLoadOp::DONT_CARE)
        .stencil_store_op(vk::AttachmentStoreOp::DONT_CARE)
        .initial_layout(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL)
        .final_layout(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL);
    let color_ref = vk::AttachmentReference::default()
        .attachment(0)
        .layout(vk::ImageLayout::COLOR_ATTACHMENT_OPTIMAL);
    let subpass = vk::SubpassDescription::default()
        .pipeline_bind_point(vk::PipelineBindPoint::GRAPHICS)
        .color_attachments(std::slice::from_ref(&color_ref));
    let create_info = vk::RenderPassCreateInfo::default()
        .attachments(std::slice::from_ref(&attachment))
        .subpasses(std::slice::from_ref(&subpass));
    unsafe {
        // SAFETY: `device` is valid; `create_info` describes a valid single-attachment
        // render pass.
        device.create_render_pass(&create_info, None)
    }
    .map_err(vk_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bring up a Vulkan context, or skip the test if no Vulkan is available.
    fn make_ctx() -> Option<Arc<VkCtx>> {
        match nigg_dxgi::Factory::new() {
            Ok(f) => Some(f.ctx().clone()),
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                None
            }
        }
    }

    /// Device creation must succeed over a bare VkCtx.
    #[test]
    fn device_creation_succeeds() {
        let Some(ctx) = make_ctx() else {
            return;
        };
        let device = Device::new(ctx).expect("device creation");
        assert_ne!(device.ctx().device.handle(), vk::Device::null());
    }

    /// A command allocator + command list + queue must be constructible and the
    /// list must start in the recording state.
    #[test]
    fn command_list_starts_recording() {
        let Some(ctx) = make_ctx() else {
            return;
        };
        let device = Device::new(ctx).expect("device");
        let allocator = device
            .create_command_allocator(CommandListType::Direct)
            .expect("allocator");
        let queue = device
            .create_command_queue(CommandListType::Direct)
            .expect("queue");
        assert_ne!(queue.queue(), vk::Queue::null());
        let mut list = device
            .create_command_list(allocator, CommandListType::Direct)
            .expect("command list");
        assert!(!list.closed());
        list.close().expect("close");
        assert!(list.closed());
    }

    /// The clear-screen acceptance path: build a render-target resource + RTV
    /// heap, record a barrier + clear + barrier, close, execute on the queue.
    #[test]
    fn clear_screen_records_and_executes() {
        let Some(ctx) = make_ctx() else {
            return;
        };
        let device = Device::new(ctx).expect("device");
        let allocator = device
            .create_command_allocator(CommandListType::Direct)
            .expect("allocator");
        let queue = device
            .create_command_queue(CommandListType::Direct)
            .expect("queue");
        let mut list = device
            .create_command_list(allocator, CommandListType::Direct)
            .expect("command list");

        // Render target resource + RTV heap + RTV at slot 0.
        let resource = device
            .create_committed_resource(
                ResourceDesc::render_target_2d(64, 64, nigg_dxgi::DxgiFormat::B8G8R8A8Unorm),
                ResourceStates::Common,
            )
            .expect("committed resource");
        let mut heap = device
            .create_descriptor_heap(DescriptorHeapType::Rtv, 1)
            .expect("rtv heap");
        device
            .create_render_target_view(&resource, &mut heap, 0)
            .expect("rtv");
        let handle = device.get_cpu_descriptor_handle(&heap, 0).expect("handle");

        // Record: COMMON -> RENDER_TARGET, clear, RENDER_TARGET -> COMMON.
        let barrier_in = ResourceBarrier {
            resource: &resource,
            state_before: ResourceStates::Common,
            state_after: ResourceStates::RenderTarget,
        };
        list.resource_barrier(std::slice::from_ref(&barrier_in))
            .expect("barrier in");
        list.clear_render_target_view(&heap, handle, [0.2, 0.4, 0.8, 1.0])
            .expect("clear");
        let barrier_out = ResourceBarrier {
            resource: &resource,
            state_before: ResourceStates::RenderTarget,
            state_after: ResourceStates::Common,
        };
        list.resource_barrier(std::slice::from_ref(&barrier_out))
            .expect("barrier out");
        list.close().expect("close");

        queue.execute_command_lists(&[&list]).expect("execute");
    }

    /// An upload buffer must be mappable and unmappable.
    #[test]
    fn upload_buffer_maps_and_unmaps() {
        let Some(ctx) = make_ctx() else {
            return;
        };
        let device = Device::new(ctx).expect("device");
        let mut resource = device
            .create_committed_resource(
                ResourceDesc::upload_buffer(256),
                ResourceStates::GenericRead,
            )
            .expect("buffer");
        assert!(resource.is_buffer());
        let ptr = resource.map().expect("map");
        // Write a byte so the mapped region is real.
        unsafe {
            // SAFETY: `ptr` is a valid mapped pointer to >= 256 bytes.
            *ptr = 0xAB;
        }
        resource.unmap().expect("unmap");
        // Mapping again after unmap must succeed.
        let _ = resource.map().expect("map again");
        resource.unmap().expect("unmap again");
    }

    /// A device-local image must refuse to map.
    #[test]
    fn device_local_image_refuses_map() {
        let Some(ctx) = make_ctx() else {
            return;
        };
        let device = Device::new(ctx).expect("device");
        let mut resource = device
            .create_committed_resource(
                ResourceDesc::render_target_2d(8, 8, nigg_dxgi::DxgiFormat::B8G8R8A8Unorm),
                ResourceStates::Common,
            )
            .expect("image");
        let err = resource
            .map()
            .expect_err("device-local image should not map");
        assert!(matches!(err, D3d12Error::Unsupported(_)));
    }
}
