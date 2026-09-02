//! Minimal Direct3D 11 → Vulkan translation (workstream M6b).
//!
//! This crate implements the smallest subset of the D3D11 device/context API needed
//! to clear a render target to a solid colour and (stretch goal) draw a triangle,
//! all translated onto Vulkan via [`ash`] using the shared [`nigg_dxgi::VkCtx`].
//!
//! # Mapping
//!
//! | D3D11                       | Vulkan                                            |
//! |-----------------------------|---------------------------------------------------|
//! | `ID3D11Device`              | wraps [`VkCtx`] (logical device + graphics queue) |
//! | `CreateTexture2D`           | `vkCreateImage` + memory alloc/bind               |
//! | `CreateRenderTargetView`    | `vkCreateImageView`                               |
//! | `CreateVertexShader`/`...PixelShader` | `vkCreateShaderModule` from SPIR-V     |
//! | `CreateBuffer`              | `vkCreateBuffer` + memory alloc/bind             |
//! | `ID3D11DeviceContext`       | one primary command buffer + a render pass        |
//! | `OMSetRenderTargets`        | `vkCreateFramebuffer` (lazily)                    |
//! | `ClearRenderTargetView`     | `vkCmdClear{Color}Image` (layout-managed)         |
//! | `VSSetShader`/`PSSetShader` | recorded; bound at pipeline build time           |
//! | `IASetVertexBuffers`/...`IndexBuffer` | recorded; bound at pipeline build time |
//! | `Draw`/`DrawIndexed`         | `vkCmdDraw{Indexed}` inside a render pass         |
//! | `Flush`                     | `vkQueueSubmit` the primary command buffer        |
//!
//! The immediate context records a single primary command buffer per frame and
//! flushes it to the queue on [`DeviceContext::flush`]. Clear is recorded as a
//! `vkCmdClearColorImage`; the draw path wraps everything in a render pass.
//!
//! All `unsafe` blocks carry a SAFETY comment explaining the invariant upheld.

use std::sync::Arc;

use ash::vk;
use nigg_dxgi::VkCtx;

/// A D3D11/D3D11-over-Vulkan error.
#[derive(Debug, thiserror::Error)]
pub enum D3d11Error {
    /// A Vulkan call returned a non-success result.
    #[error("vulkan: {0}")]
    Vulkan(String),
    /// A D3D11-level precondition was violated.
    #[error("invalid argument: {0}")]
    Invalid(String),
    /// No render target was set before a draw/clear.
    #[error("no render target bound")]
    NoRenderTarget,
    /// No pipeline (VS+PS) was built before a draw.
    #[error("no pipeline bound; set both vertex and pixel shaders")]
    NoPipeline,
}

fn vk_err(e: vk::Result) -> D3d11Error {
    D3d11Error::Vulkan(e.to_string())
}

impl From<nigg_dxgi::DxgiError> for D3d11Error {
    fn from(e: nigg_dxgi::DxgiError) -> Self {
        match e {
            nigg_dxgi::DxgiError::Vulkan(s) => D3d11Error::Vulkan(s),
            nigg_dxgi::DxgiError::MissingExtension(n) => D3d11Error::Vulkan(n.to_string()),
            nigg_dxgi::DxgiError::NoSurface => D3d11Error::Vulkan("no surface available".into()),
            nigg_dxgi::DxgiError::BufferIndexOutOfRange(i, c) => {
                D3d11Error::Invalid(format!("buffer index {i} out of range (count={c})"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Resource descriptions (D3D11-shaped structs, mostly defaults)
// ---------------------------------------------------------------------------

/// `D3D11_TEXTURE2D_DESC` subset. Only what the translation layer needs.
#[derive(Debug, Clone, Copy)]
pub struct Texture2dDesc {
    pub width: u32,
    pub height: u32,
    pub format: nigg_dxgi::DxgiFormat,
    /// True when this texture is used as a render target.
    pub render_target: bool,
}

impl Texture2dDesc {
    /// A render-target texture at `w x h`.
    pub fn render_target(width: u32, height: u32, format: nigg_dxgi::DxgiFormat) -> Self {
        Self {
            width,
            height,
            format,
            render_target: true,
        }
    }

    fn vk_format(self) -> vk::Format {
        self.format.vk_format()
    }
}

/// `D3D11_BUFFER_DESC` subset, tagged by in D3D11 by the bind flag.
#[derive(Debug, Clone, Copy)]
pub struct BufferDesc {
    pub size: u64,
    pub usage: BufferUsage,
}

/// The D3D11 bind-flag analog for a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferUsage {
    /// `D3D11_BIND_VERTEX_BUFFER`.
    Vertex,
    /// `D3D11_BIND_INDEX_BUFFER`.
    Index,
    /// `D3D11_BIND_CONSTANT_BUFFER` (a uniform buffer).
    Constant,
}

impl BufferUsage {
    fn vk_usage(self) -> vk::BufferUsageFlags {
        match self {
            BufferUsage::Vertex => vk::BufferUsageFlags::VERTEX_BUFFER,
            BufferUsage::Index => vk::BufferUsageFlags::INDEX_BUFFER,
            BufferUsage::Constant => vk::BufferUsageFlags::UNIFORM_BUFFER,
        }
    }
}

/// `D3D11_RASTERIZER_DESC` — a thin default-constructible struct. The translation
/// layer honours `fill_mode`/`cull_mode`/`front_counter_clockwise` at pipeline
/// build time; the rest are accepted and ignored for M6b.
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

/// `D3D11_FILL_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillMode {
    Solid,
    Wireframe,
}

/// `D3D11_CULL_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CullMode {
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

/// `D3D11_BLEND_DESC` — kept as a default-constructible struct. M6b renders opaque
/// geometry, so blending is off; the struct exists so callers can write D3D11 code
/// that sets it and the field is not silently dropped.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlendDesc {
    pub alpha_to_coverage_enable: bool,
    pub independent_blend_enable: bool,
}

/// `D3D11_DEPTH_STENCIL_DESC` — default (depth/stencil disabled) for M6b.
#[derive(Debug, Clone, Copy, Default)]
pub struct DepthStencilDesc {
    pub depth_enable: bool,
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// A 2D texture: a Vulkan `VkImage` + bound memory.
pub struct Texture2d {
    ctx: Arc<VkCtx>,
    image: vk::Image,
    memory: vk::DeviceMemory,
    desc: Texture2dDesc,
}

impl Texture2d {
    fn vk_format(&self) -> vk::Format {
        self.desc.vk_format()
    }
}

impl Drop for Texture2d {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `image` and `memory` were created from `ctx.device` and bound
            // together; both are valid and destroyed exactly once here.
            self.ctx.device.destroy_image(self.image, None);
            self.ctx.device.free_memory(self.memory, None);
        }
    }
}

/// A render-target view: a `VkImageView` over a [`Texture2d`] (or swap-chain image).
pub struct RenderTargetView {
    ctx: Arc<VkCtx>,
    view: vk::ImageView,
    /// The underlying image (needed to record `vkCmdClearColorImage`).
    image: vk::Image,
    format: vk::Format,
    extent: vk::Extent2D,
}

impl Drop for RenderTargetView {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `view` was created from `ctx.device` and is destroyed once here.
            self.ctx.device.destroy_image_view(self.view, None);
        }
    }
}

/// A vertex or pixel shader: a `VkShaderModule` built from SPIR-V words.
pub struct Shader {
    ctx: Arc<VkCtx>,
    module: vk::ShaderModule,
    stage: ShaderStage,
}

/// Which stage a [`Shader`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaderStage {
    Vertex,
    Pixel,
}

/// The D3D11 index type (`DXGI_FORMAT_R16_UINT` / `R32_UINT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexType {
    UInt16,
    UInt32,
}

impl IndexType {
    fn vk(self) -> vk::IndexType {
        match self {
            IndexType::UInt16 => vk::IndexType::UINT16,
            IndexType::UInt32 => vk::IndexType::UINT32,
        }
    }
}

impl ShaderStage {
    /// The Vulkan shader-stage flag this stage maps to.
    pub fn vk_flags(self) -> vk::ShaderStageFlags {
        match self {
            ShaderStage::Vertex => vk::ShaderStageFlags::VERTEX,
            ShaderStage::Pixel => vk::ShaderStageFlags::FRAGMENT,
        }
    }
}

impl Drop for Shader {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `module` was created from `ctx.device` and is destroyed once.
            self.ctx.device.destroy_shader_module(self.module, None);
        }
    }
}

/// A vertex/index/constant buffer: a `VkBuffer` + bound memory.
pub struct Buffer {
    ctx: Arc<VkCtx>,
    buffer: vk::Buffer,
    memory: vk::DeviceMemory,
    size: u64,
    usage: BufferUsage,
}

impl Buffer {
    /// The Vulkan buffer handle (for binding into a command buffer).
    pub fn handle(&self) -> vk::Buffer {
        self.buffer
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The buffer's D3D11 usage class.
    pub fn usage(&self) -> BufferUsage {
        self.usage
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `buffer` and `memory` were created from `ctx.device` and bound
            // together; both destroyed exactly once here.
            self.ctx.device.destroy_buffer(self.buffer, None);
            self.ctx.device.free_memory(self.memory, None);
        }
    }
}

// ---------------------------------------------------------------------------
// ID3D11Device
// ---------------------------------------------------------------------------

/// `ID3D11Device` — wraps the shared Vulkan logical device + queue. Owns one
/// command pool for the immediate context.
pub struct Device {
    ctx: Arc<VkCtx>,
    command_pool: vk::CommandPool,
}

impl Device {
    /// Create a D3D11 device over the given swap chain's Vulkan context.
    pub fn new(swapchain: &nigg_dxgi::SwapChain) -> Result<Self, D3d11Error> {
        Self::from_ctx(swapchain.ctx().clone())
    }

    /// Create a D3D11 device over a bare [`VkCtx`] (useful for tests that do not
    /// need a swap chain).
    pub fn from_ctx(ctx: Arc<VkCtx>) -> Result<Self, D3d11Error> {
        let pool_info = vk::CommandPoolCreateInfo::default()
            .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER)
            .queue_family_index(ctx.selected.graphics_family);
        let command_pool = unsafe {
            // SAFETY: `ctx.device` is valid; the queue family index was validated at
            // VkCtx creation. RESET_COMMAND_BUFFER lets the immediate context re-record
            // the primary buffer each frame.
            ctx.device.create_command_pool(&pool_info, None)
        }
        .map_err(vk_err)?;
        Ok(Self { ctx, command_pool })
    }

    /// Borrow the shared Vulkan context.
    pub fn ctx(&self) -> &Arc<VkCtx> {
        &self.ctx
    }

    /// Borrow the immediate-context command pool.
    pub fn command_pool(&self) -> vk::CommandPool {
        self.command_pool
    }

    /// `CreateTexture2D` → `vkCreateImage` + memory alloc/bind.
    pub fn create_texture_2d(&self, desc: Texture2dDesc) -> Result<Texture2d, D3d11Error> {
        let mut usage = vk::ImageUsageFlags::TRANSFER_DST;
        if desc.render_target {
            usage |= vk::ImageUsageFlags::COLOR_ATTACHMENT;
        }
        let create_info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .format(desc.vk_format())
            .extent(vk::Extent3D {
                width: desc.width,
                height: desc.height,
                depth: 1,
            })
            .mip_levels(1)
            .array_layers(1)
            .samples(vk::SampleCountFlags::TYPE_1)
            .tiling(vk::ImageTiling::OPTIMAL)
            .usage(usage)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::UNDEFINED);
        let image = unsafe {
            // SAFETY: `ctx.device` is valid; `create_info` describes a valid 2D image.
            self.ctx.device.create_image(&create_info, None)
        }
        .map_err(vk_err)?;
        let reqs = unsafe {
            // SAFETY: `image` is a valid VkImage just created.
            self.ctx.device.get_image_memory_requirements(image)
        };
        let mem_type = self
            .ctx
            .find_memory_type(reqs.memory_type_bits, vk::MemoryPropertyFlags::DEVICE_LOCAL)
            .map_err(D3d11Error::from)?;
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(reqs.size)
            .memory_type_index(mem_type);
        let memory = unsafe {
            // SAFETY: memory type chosen from the image's requirements.
            self.ctx.device.allocate_memory(&alloc_info, None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: `memory` allocated for this image; offset 0 is the only binding.
            self.ctx
                .device
                .bind_image_memory(image, memory, 0)
                .map_err(vk_err)?;
        }
        Ok(Texture2d {
            ctx: self.ctx.clone(),
            image,
            memory,
            desc,
        })
    }

    /// `CreateRenderTargetView` → `vkCreateImageView`.
    ///
    /// Accepts either a [`Texture2d`] (owned image) or a swap-chain back-buffer index.
    pub fn create_render_target_view_from_texture(
        &self,
        texture: &Texture2d,
    ) -> Result<RenderTargetView, D3d11Error> {
        self.create_rtv(
            texture.image,
            texture.vk_format(),
            texture.desc.width,
            texture.desc.height,
        )
    }

    /// `CreateRenderTargetView` over a swap-chain back buffer (`GetBuffer`).
    pub fn create_render_target_view_from_image(
        &self,
        image: vk::Image,
        format: vk::Format,
        width: u32,
        height: u32,
    ) -> Result<RenderTargetView, D3d11Error> {
        self.create_rtv(image, format, width, height)
    }

    fn create_rtv(
        &self,
        image: vk::Image,
        format: vk::Format,
        width: u32,
        height: u32,
    ) -> Result<RenderTargetView, D3d11Error> {
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
            // SAFETY: `image` is valid (owned by the texture or swap chain) and
            // `create_info` describes a valid 2D colour view of it.
            self.ctx.device.create_image_view(&create_info, None)
        }
        .map_err(vk_err)?;
        Ok(RenderTargetView {
            ctx: self.ctx.clone(),
            view,
            image,
            format,
            extent: vk::Extent2D { width, height },
        })
    }

    /// `CreateVertexShader` / `CreatePixelShader` — build a `VkShaderModule` from
    /// SPIR-V words. `spirv` is the little-endian `u32` word stream (as produced by
    /// `nigg_hlsl_compiler::compile`).
    pub fn create_shader(&self, spirv: &[u32], stage: ShaderStage) -> Result<Shader, D3d11Error> {
        let create_info = vk::ShaderModuleCreateInfo::default().code(spirv);
        let module = unsafe {
            // SAFETY: `spirv` is a valid SPIR-V word stream; `ctx.device` is valid.
            self.ctx.device.create_shader_module(&create_info, None)
        }
        .map_err(vk_err)?;
        Ok(Shader {
            ctx: self.ctx.clone(),
            module,
            stage,
        })
    }

    /// `CreateBuffer` → `vkCreateBuffer` + memory alloc/bind. `initial_data` (if
    /// provided) is host-copied in via a staging buffer so the result lives in
    /// device-local memory.
    pub fn create_buffer(
        &self,
        desc: BufferDesc,
        initial_data: Option<&[u8]>,
    ) -> Result<Buffer, D3d11Error> {
        if let Some(data) = initial_data {
            if data.len() as u64 > desc.size {
                return Err(D3d11Error::Invalid(format!(
                    "initial_data ({} bytes) larger than buffer size ({})",
                    data.len(),
                    desc.size
                )));
            }
        }
        let create_info = vk::BufferCreateInfo::default()
            .size(desc.size)
            .usage(desc.usage.vk_usage())
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
        // Prefer HOST_VISIBLE for constant buffers (mapped updates); device-local
        // otherwise. For staging-host-visible we also need HOST_COHERENT.
        let props = if desc.usage == BufferUsage::Constant {
            vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT
        } else {
            vk::MemoryPropertyFlags::DEVICE_LOCAL
        };
        let mem_type = self
            .ctx
            .find_memory_type(reqs.memory_type_bits, props)
            .map_err(D3d11Error::from)?;
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(reqs.size)
            .memory_type_index(mem_type);
        let memory = unsafe {
            // SAFETY: memory type chosen from the buffer's requirements.
            self.ctx.device.allocate_memory(&alloc_info, None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: `memory` allocated for this buffer; offset 0 is the only binding.
            self.ctx
                .device
                .bind_buffer_memory(buffer, memory, 0)
                .map_err(vk_err)?;
        }

        if let Some(data) = initial_data {
            if desc.usage == BufferUsage::Constant {
                // HOST_VISIBLE: map and copy directly.
                unsafe {
                    // SAFETY: `memory` is HOST_VISIBLE/HOST_COHERENT and exclusively
                    // owned by this buffer; `desc.size` >= data.len().
                    let ptr = self
                        .ctx
                        .device
                        .map_memory(memory, 0, desc.size, vk::MemoryMapFlags::empty())
                        .map_err(vk_err)?;
                    // SAFETY: the mapped region is `desc.size` bytes of valid write
                    // space; we copy `data.len()` (<= desc.size) bytes in.
                    std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
                    self.ctx.device.unmap_memory(memory);
                }
            } else {
                // Device-local: upload via a transient staging buffer + a one-shot
                // command buffer on the graphics queue.
                self.upload_to_device_local(buffer, memory, desc.size, data)?;
            }
        }

        Ok(Buffer {
            ctx: self.ctx.clone(),
            buffer,
            memory,
            size: desc.size,
            usage: desc.usage,
        })
    }

    /// Allocate and record a one-shot command buffer, run `f` with it, then submit +
    /// wait. Used for staging uploads.
    fn one_shot<R>(
        &self,
        f: impl FnOnce(vk::CommandBuffer) -> Result<R, D3d11Error>,
    ) -> Result<R, D3d11Error> {
        let alloc_info = vk::CommandBufferAllocateInfo::default()
            .command_pool(self.command_pool)
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(1);
        let cmd = unsafe {
            // SAFETY: `command_pool` is valid and owned by this device.
            self.ctx.device.allocate_command_buffers(&alloc_info)
        }
        .map_err(vk_err)?
        .pop()
        .ok_or_else(|| D3d11Error::Vulkan("command buffer allocation returned none".into()))?;
        let begin_info = vk::CommandBufferBeginInfo::default()
            .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
        unsafe {
            // SAFETY: `cmd` is freshly allocated and not in the recording state.
            self.ctx
                .device
                .begin_command_buffer(cmd, &begin_info)
                .map_err(vk_err)?;
        }
        let result = f(cmd)?;
        unsafe {
            // SAFETY: `cmd` is in the recording state (we began it above).
            self.ctx.device.end_command_buffer(cmd).map_err(vk_err)?;
        }
        let submit_info = vk::SubmitInfo::default().command_buffers(std::slice::from_ref(&cmd));
        let fence = unsafe {
            // SAFETY: `ctx.device` is valid; trivial create info.
            self.ctx
                .device
                .create_fence(&vk::FenceCreateInfo::default(), None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: `cmd` is recorded and complete; the queue is the graphics queue.
            self.ctx
                .device
                .queue_submit(
                    self.ctx.graphics_queue,
                    std::slice::from_ref(&submit_info),
                    fence,
                )
                .map_err(vk_err)?;
            // SAFETY: `fence` was signalled by the submit above.
            self.ctx
                .device
                .wait_for_fences(std::slice::from_ref(&fence), true, u64::MAX)
                .map_err(vk_err)?;
            self.ctx.device.destroy_fence(fence, None);
            // SAFETY: `cmd` came from `command_pool`; safe to free back to it.
            self.ctx
                .device
                .free_command_buffers(self.command_pool, std::slice::from_ref(&cmd));
        }
        Ok(result)
    }

    /// Upload `data` to a device-local `VkBuffer` via a host-visible staging buffer.
    fn upload_to_device_local(
        &self,
        dst: vk::Buffer,
        _dst_memory: vk::DeviceMemory,
        dst_size: u64,
        data: &[u8],
    ) -> Result<(), D3d11Error> {
        let staging_info = vk::BufferCreateInfo::default()
            .size(dst_size)
            .usage(vk::BufferUsageFlags::TRANSFER_SRC)
            .sharing_mode(vk::SharingMode::EXCLUSIVE);
        let staging = unsafe {
            // SAFETY: valid device + valid create info.
            self.ctx.device.create_buffer(&staging_info, None)
        }
        .map_err(vk_err)?;
        let reqs = unsafe {
            // SAFETY: `staging` is a valid VkBuffer.
            self.ctx.device.get_buffer_memory_requirements(staging)
        };
        let mem_type = self
            .ctx
            .find_memory_type(
                reqs.memory_type_bits,
                vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT,
            )
            .map_err(D3d11Error::from)?;
        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(reqs.size)
            .memory_type_index(mem_type);
        let staging_mem = unsafe {
            // SAFETY: memory type chosen from the staging buffer's requirements.
            self.ctx.device.allocate_memory(&alloc_info, None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: `staging_mem` allocated for `staging`; offset 0.
            self.ctx
                .device
                .bind_buffer_memory(staging, staging_mem, 0)
                .map_err(vk_err)?;
            let ptr = self
                .ctx
                .device
                .map_memory(staging_mem, 0, dst_size, vk::MemoryMapFlags::empty())
                .map_err(vk_err)?;
            // SAFETY: mapped region is `dst_size` bytes (>= data.len()); copy in.
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
            self.ctx.device.unmap_memory(staging_mem);
        }

        self.one_shot(|cmd| {
            let copy = vk::BufferCopy {
                src_offset: 0,
                dst_offset: 0,
                size: dst_size,
            };
            unsafe {
                // SAFETY: `staging` and `dst` are valid buffers; `copy` describes a
                // whole-buffer copy within bounds.
                self.ctx
                    .device
                    .cmd_copy_buffer(cmd, staging, dst, std::slice::from_ref(&copy));
            }
            Ok(())
        })?;

        unsafe {
            // SAFETY: staging buffer/memory were used only for the upload and are
            // destroyed exactly once here.
            self.ctx.device.destroy_buffer(staging, None);
            self.ctx.device.free_memory(staging_mem, None);
        }
        Ok(())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `command_pool` was created from `ctx.device` and owns all
            // command buffers allocated from it; destroying it frees them. All
            // resources created via this device are dropped before this runs (their
            // owners hold their own refs to VkCtx, but the handles themselves are
            // destroyed by those owners' Drop).
            self.ctx
                .device
                .destroy_command_pool(self.command_pool, None);
        }
    }
}

// ---------------------------------------------------------------------------
// ID3D11DeviceContext (immediate)
// ---------------------------------------------------------------------------

/// A bound render target + its framebuffer, created lazily when a target is set.
struct BoundTarget {
    extent: vk::Extent2D,
    framebuffer: vk::Framebuffer,
    render_pass: vk::RenderPass,
}

impl BoundTarget {
    fn destroy(&mut self, device: &ash::Device) {
        unsafe {
            // SAFETY: both handles created from `device` and destroyed exactly once.
            device.destroy_framebuffer(self.framebuffer, None);
            device.destroy_render_pass(self.render_pass, None);
        }
    }
}

/// `ID3D11DeviceContext` — the immediate context. Records one primary command
/// buffer per frame and submits it on [`flush`].
pub struct DeviceContext {
    device: Arc<Device>,
    command_buffer: vk::CommandBuffer,
    /// Set by `OMSetRenderTargets`. Lazily builds a render pass + framebuffer.
    target: Option<BoundTarget>,
    /// Bound shaders (set by VSSetShader/PSSetShader). Cleared on flush.
    vs: Option<vk::ShaderModule>,
    ps: Option<vk::ShaderModule>,
    /// Bound vertex/index buffers (recorded; consumed at pipeline build).
    vertex_buffer: Option<vk::Buffer>,
    vertex_offset: u64,
    index_buffer: Option<vk::Buffer>,
    index_offset: u64,
    index_type: vk::IndexType,
    /// Whether a draw was recorded since the last flush.
    drew: bool,
    /// True once `begin_command_buffer` has been called on the current frame.
    recording: bool,
}

impl DeviceContext {
    /// Create the immediate context for `device`, allocating its primary command
    /// buffer from the device's command pool.
    pub fn new(device: Arc<Device>) -> Result<Self, D3d11Error> {
        let alloc_info = vk::CommandBufferAllocateInfo::default()
            .command_pool(device.command_pool())
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(1);
        let command_buffer = unsafe {
            // SAFETY: `command_pool` is valid and owned by `device`.
            device.ctx().device.allocate_command_buffers(&alloc_info)
        }
        .map_err(vk_err)?
        .pop()
        .ok_or_else(|| D3d11Error::Vulkan("command buffer allocation returned none".into()))?;
        Ok(Self {
            device,
            command_buffer,
            target: None,
            vs: None,
            ps: None,
            vertex_buffer: None,
            vertex_offset: 0,
            index_buffer: None,
            index_offset: 0,
            index_type: vk::IndexType::UINT16,
            drew: false,
            recording: false,
        })
    }

    /// Borrow the owning device.
    pub fn device(&self) -> &Arc<Device> {
        &self.device
    }

    /// Borrow the raw command buffer (for swap-chain acquire fences, etc.).
    pub fn command_buffer(&self) -> vk::CommandBuffer {
        self.command_buffer
    }

    fn begin_recording(&mut self) -> Result<(), D3d11Error> {
        if self.recording {
            return Ok(());
        }
        let begin_info = vk::CommandBufferBeginInfo::default()
            .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
        unsafe {
            // SAFETY: the primary command buffer is not currently recording; we reset
            // it each frame.
            self.device
                .ctx()
                .device
                .begin_command_buffer(self.command_buffer, &begin_info)
        }
        .map_err(vk_err)?;
        self.recording = true;
        Ok(())
    }

    /// `OMSetRenderTargets(rtvs)` — set the colour render target. Lazily builds a
    /// render pass + framebuffer for the target's format/extent.
    pub fn om_set_render_targets(&mut self, rtv: &RenderTargetView) -> Result<(), D3d11Error> {
        self.begin_recording()?;
        // Tear down any previous target binding.
        if let Some(mut t) = self.target.take() {
            t.destroy(&self.device.ctx().device);
        }
        let device = &self.device.ctx().device;
        let render_pass = make_render_pass(device, rtv.format)?;
        let attachments = [rtv.view];
        let fb_info = vk::FramebufferCreateInfo::default()
            .render_pass(render_pass)
            .attachments(&attachments)
            .width(rtv.extent.width)
            .height(rtv.extent.height)
            .layers(1);
        let framebuffer = unsafe {
            // SAFETY: `render_pass` matches the image view's format; `attachments`
            // holds the single valid colour view.
            device.create_framebuffer(&fb_info, None)
        }
        .map_err(vk_err)?;
        self.target = Some(BoundTarget {
            extent: rtv.extent,
            framebuffer,
            render_pass,
        });
        // Invalidate a cached pipeline (its render pass may no longer match).
        self.clear_pipeline();
        Ok(())
    }

    /// `ClearRenderTargetView(rtv, color)` — record a `vkCmdClearColorImage`. The
    /// image is transitioned to `TRANSFER_DST_OPTIMAL` and back to
    /// `COLOR_ATTACHMENT_OPTIMAL` around the clear so the layout is consistent with
    /// the subsequent render pass.
    pub fn clear_render_target_view(
        &mut self,
        rtv: &RenderTargetView,
        color: [f32; 4],
    ) -> Result<(), D3d11Error> {
        self.begin_recording()?;
        let image = rtv.image;
        let clear_color = vk::ClearColorValue { float32: color };
        let subresource = vk::ImageSubresourceRange::default()
            .aspect_mask(vk::ImageAspectFlags::COLOR)
            .level_count(1)
            .layer_count(1);
        let device = &self.device.ctx().device;
        let cmd = self.command_buffer;
        // v1.0 image barriers (no extension / version requirement).
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
            // SAFETY: `image` is valid; barrier transitions it UNDEFINED→TRANSFER_DST.
            device.cmd_pipeline_barrier(
                cmd,
                vk::PipelineStageFlags::TOP_OF_PIPE,
                vk::PipelineStageFlags::TRANSFER,
                vk::DependencyFlags::empty(),
                &[],
                &[],
                std::slice::from_ref(&barrier_to_dst),
            );
            // SAFETY: image is now in TRANSFER_DST_OPTIMAL, the layout the clear needs.
            device.cmd_clear_color_image(
                cmd,
                image,
                vk::ImageLayout::TRANSFER_DST_OPTIMAL,
                &clear_color,
                std::slice::from_ref(&subresource),
            );
            // SAFETY: transition back to the layout the render pass expects.
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

    /// `VSSetShader` — bind a vertex shader module (used at pipeline build time).
    pub fn vs_set_shader(&mut self, shader: &Shader) {
        if shader.stage != ShaderStage::Vertex {
            return;
        }
        self.vs = Some(shader.module);
        self.clear_pipeline();
    }

    /// `PSSetShader` — bind a pixel shader module.
    pub fn ps_set_shader(&mut self, shader: &Shader) {
        if shader.stage != ShaderStage::Pixel {
            return;
        }
        self.ps = Some(shader.module);
        self.clear_pipeline();
    }

    /// `IASetVertexBuffers` — bind a vertex buffer for the next draw.
    pub fn ia_set_vertex_buffers(&mut self, buffer: &Buffer, offset: u64) {
        if buffer.usage() != BufferUsage::Vertex {
            return;
        }
        self.vertex_buffer = Some(buffer.handle());
        self.vertex_offset = offset;
    }

    /// `IASetIndexBuffer` — bind an index buffer for the next indexed draw.
    pub fn ia_set_index_buffer(&mut self, buffer: &Buffer, offset: u64, index_type: IndexType) {
        if buffer.usage() != BufferUsage::Index {
            return;
        }
        self.index_buffer = Some(buffer.handle());
        self.index_offset = offset;
        self.index_type = index_type.vk();
    }

    /// `Draw(vertex_count)` — record a non-indexed draw inside a render pass. Builds
    /// and binds the graphics pipeline on demand.
    pub fn draw(
        &mut self,
        vertex_count: u32,
        rasterizer: RasterizerDesc,
    ) -> Result<(), D3d11Error> {
        self.draw_internal(vertex_count, 0, 0, None, rasterizer)
    }

    /// `DrawIndexed` — record an indexed draw.
    pub fn draw_indexed(
        &mut self,
        index_count: u32,
        vertex_offset: i32,
        rasterizer: RasterizerDesc,
    ) -> Result<(), D3d11Error> {
        self.draw_internal(
            index_count,
            vertex_offset,
            0,
            Some(self.index_type),
            rasterizer,
        )
    }

    fn draw_internal(
        &mut self,
        count: u32,
        vertex_offset: i32,
        first: u32,
        index_type: Option<vk::IndexType>,
        rasterizer: RasterizerDesc,
    ) -> Result<(), D3d11Error> {
        self.begin_recording()?;
        let target = self.target.as_ref().ok_or(D3d11Error::NoRenderTarget)?;
        let vs = self.vs.ok_or(D3d11Error::NoPipeline)?;
        let ps = self.ps.ok_or(D3d11Error::NoPipeline)?;

        let device = &self.device.ctx().device;
        let cmd = self.command_buffer;

        // Build (or reuse) the pipeline. The pipeline is rebuilt each draw for
        // simplicity in M6b; a real implementation would cache it. We build a fresh
        // pipeline + layout + render pass per draw and tear them down at flush.
        let pipeline = build_pipeline(
            device,
            target.render_pass,
            vs,
            ps,
            target.extent,
            rasterizer,
            self.vertex_buffer,
        )?;
        let pipeline_guard = PipelineGuard { device, pipeline };

        let clear = [vk::ClearValue {
            color: vk::ClearColorValue {
                float32: [0.0, 0.0, 0.0, 0.0],
            },
        }];
        let begin = vk::RenderPassBeginInfo::default()
            .render_pass(target.render_pass)
            .framebuffer(target.framebuffer)
            .render_area(vk::Rect2D {
                offset: vk::Offset2D { x: 0, y: 0 },
                extent: target.extent,
            })
            .clear_values(&clear);
        unsafe {
            // SAFETY: `target.render_pass`/`framebuffer` are compatible (built from
            // the same colour attachment); begin recording the pass.
            device.cmd_begin_render_pass(cmd, &begin, vk::SubpassContents::INLINE);
            // SAFETY: bind the freshly-built graphics pipeline.
            device.cmd_bind_pipeline(
                cmd,
                vk::PipelineBindPoint::GRAPHICS,
                pipeline_guard.pipeline,
            );
            if let Some(vb) = self.vertex_buffer {
                let offsets = [self.vertex_offset];
                // SAFETY: `vb` is a valid vertex buffer; offsets match the binding.
                device.cmd_bind_vertex_buffers(cmd, 0, std::slice::from_ref(&vb), &offsets);
            }
            match index_type {
                Some(it) => {
                    if let Some(ib) = self.index_buffer {
                        // SAFETY: `ib` is a valid index buffer; `it` matches its data.
                        device.cmd_bind_index_buffer(cmd, ib, self.index_offset, it);
                        // SAFETY: valid bound pipeline + index buffer.
                        device.cmd_draw_indexed(cmd, count, 1, first, vertex_offset, 0);
                    }
                }
                None => {
                    // SAFETY: valid bound pipeline.
                    device.cmd_draw(cmd, count, 1, first, 0);
                }
            }
            // SAFETY: a matching begin_render_pass was recorded above.
            device.cmd_end_render_pass(cmd);
        }
        self.drew = true;
        // Pipeline + layout destroyed by the guard when it goes out of scope below.
        drop(pipeline_guard);
        Ok(())
    }

    /// `Flush` — submit the recorded command buffer to the graphics queue and wait
    /// for it to complete (synchronous flush, simplest correct M6b semantics).
    pub fn flush(&mut self) -> Result<(), D3d11Error> {
        if !self.recording {
            return Ok(());
        }
        let device = &self.device.ctx().device;
        unsafe {
            // SAFETY: `command_buffer` is in the recording state.
            device
                .end_command_buffer(self.command_buffer)
                .map_err(vk_err)?;
        }
        let submit_info =
            vk::SubmitInfo::default().command_buffers(std::slice::from_ref(&self.command_buffer));
        let fence = unsafe {
            // SAFETY: valid device + trivial create info.
            device.create_fence(&vk::FenceCreateInfo::default(), None)
        }
        .map_err(vk_err)?;
        unsafe {
            // SAFETY: the command buffer is recorded and complete; the graphics queue
            // is valid.
            device
                .queue_submit(
                    self.device.ctx().graphics_queue,
                    std::slice::from_ref(&submit_info),
                    fence,
                )
                .map_err(vk_err)?;
            // SAFETY: `fence` was signalled by the submit above.
            device
                .wait_for_fences(std::slice::from_ref(&fence), true, u64::MAX)
                .map_err(vk_err)?;
            device.destroy_fence(fence, None);
        }
        // Reset for the next frame.
        unsafe {
            // SAFETY: the command buffer is not in a pending state (we waited on the
            // fence) and the pool was created with RESET_COMMAND_BUFFER.
            device
                .reset_command_buffer(self.command_buffer, vk::CommandBufferResetFlags::empty())
                .map_err(vk_err)?;
        }
        self.recording = false;
        self.drew = false;
        self.clear_pipeline();
        Ok(())
    }

    fn clear_pipeline(&mut self) {
        // No persistent pipeline is stored on the context in M6b; pipelines are
        // built per draw and torn down by the guard. This is a no-op kept for
        // future caching.
    }
}

impl Drop for DeviceContext {
    fn drop(&mut self) {
        if let Some(mut t) = self.target.take() {
            t.destroy(&self.device.ctx().device);
        }
        unsafe {
            // SAFETY: `command_buffer` was allocated from the device's command pool;
            // freeing it back to the pool is safe. We never free it while pending
            // because flush() waits on the fence before returning.
            self.device.ctx().device.free_command_buffers(
                self.device.command_pool(),
                std::slice::from_ref(&self.command_buffer),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// RAII guard that destroys a graphics pipeline + its layout on drop.
struct PipelineGuard<'a> {
    device: &'a ash::Device,
    pipeline: vk::Pipeline,
}

impl Drop for PipelineGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `pipeline` was created from `device` and is destroyed once.
            self.device.destroy_pipeline(self.pipeline, None);
        }
    }
}

/// Build a render pass with one colour attachment matching `format`.
fn make_render_pass(
    device: &ash::Device,
    format: vk::Format,
) -> Result<vk::RenderPass, D3d11Error> {
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

/// Build a graphics pipeline for the current shader/buffer/target state.
fn build_pipeline(
    device: &ash::Device,
    render_pass: vk::RenderPass,
    vs: vk::ShaderModule,
    ps: vk::ShaderModule,
    extent: vk::Extent2D,
    rasterizer: RasterizerDesc,
    vertex_buffer: Option<vk::Buffer>,
) -> Result<vk::Pipeline, D3d11Error> {
    let entry_name = c"main";
    let stages = [
        vk::PipelineShaderStageCreateInfo::default()
            .stage(vk::ShaderStageFlags::VERTEX)
            .module(vs)
            .name(entry_name),
        vk::PipelineShaderStageCreateInfo::default()
            .stage(vk::ShaderStageFlags::FRAGMENT)
            .module(ps)
            .name(entry_name),
    ];

    // Vertex input: a single binding carrying 2 floats of position when a vertex
    // buffer is bound; no vertex input otherwise. The binding/attribute live for the
    // whole function so the borrowed `vi` stays valid through pipeline creation.
    let binding = vk::VertexInputBindingDescription {
        binding: 0,
        stride: 2 * std::mem::size_of::<f32>() as u32,
        input_rate: vk::VertexInputRate::VERTEX,
    };
    let attribute = vk::VertexInputAttributeDescription {
        location: 0,
        binding: 0,
        format: vk::Format::R32G32_SFLOAT,
        offset: 0,
    };
    let input_assembly = vk::PipelineInputAssemblyStateCreateInfo::default()
        .topology(vk::PrimitiveTopology::TRIANGLE_LIST);
    let vertex_input = if vertex_buffer.is_some() {
        vk::PipelineVertexInputStateCreateInfo::default()
            .vertex_binding_descriptions(std::slice::from_ref(&binding))
            .vertex_attribute_descriptions(std::slice::from_ref(&attribute))
    } else {
        vk::PipelineVertexInputStateCreateInfo::default()
    };

    let viewport = vk::Viewport {
        x: 0.0,
        y: 0.0,
        width: extent.width as f32,
        height: extent.height as f32,
        min_depth: 0.0,
        max_depth: 1.0,
    };
    let scissor = vk::Rect2D {
        offset: vk::Offset2D { x: 0, y: 0 },
        extent,
    };
    let viewport_state = vk::PipelineViewportStateCreateInfo::default()
        .viewport_count(1)
        .viewports(std::slice::from_ref(&viewport))
        .scissor_count(1)
        .scissors(std::slice::from_ref(&scissor));

    let raster_state = vk::PipelineRasterizationStateCreateInfo::default()
        .depth_clamp_enable(false)
        .rasterizer_discard_enable(false)
        .polygon_mode(if rasterizer.fill_mode == FillMode::Wireframe {
            vk::PolygonMode::LINE
        } else {
            vk::PolygonMode::FILL
        })
        .cull_mode(rasterizer.cull_mode.vk())
        .front_face(if rasterizer.front_counter_clockwise {
            vk::FrontFace::COUNTER_CLOCKWISE
        } else {
            vk::FrontFace::CLOCKWISE
        })
        .line_width(1.0);

    let multisample = vk::PipelineMultisampleStateCreateInfo::default()
        .rasterization_samples(vk::SampleCountFlags::TYPE_1);

    let blend_attachment = vk::PipelineColorBlendAttachmentState::default()
        .blend_enable(false)
        .color_write_mask(vk::ColorComponentFlags::RGBA);
    let blend_state = vk::PipelineColorBlendStateCreateInfo::default()
        .attachments(std::slice::from_ref(&blend_attachment));

    let layout_info = vk::PipelineLayoutCreateInfo::default();
    let layout = unsafe {
        // SAFETY: valid device + empty layout (no descriptor sets/push constants).
        device.create_pipeline_layout(&layout_info, None)
    }
    .map_err(vk_err)?;

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
        // SAFETY: all state structs are valid and reference the bound shaders; the
        // render pass matches the bound framebuffer's format.
        device.create_graphics_pipelines(
            vk::PipelineCache::null(),
            std::slice::from_ref(&create_info),
            None,
        )
    };
    let pipeline = match result {
        Ok(pipelines) => pipelines
            .into_iter()
            .next()
            .ok_or_else(|| D3d11Error::Vulkan("pipeline creation returned no pipelines".into()))?,
        Err((_pipelines, err)) => {
            unsafe {
                // SAFETY: `layout` was created above; destroy it on failure.
                device.destroy_pipeline_layout(layout, None);
            }
            return Err(vk_err(err));
        }
    };
    unsafe {
        // SAFETY: `layout` is no longer needed after pipeline creation (no descriptor
        // sets reference it in M6b); destroy it now.
        device.destroy_pipeline_layout(layout, None);
    }
    Ok(pipeline)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a factory/device pair, build a texture + RTV, and assert the device
    /// and context objects are non-trivial. Guards Vulkan availability.
    fn make_factory() -> Option<Arc<VkCtx>> {
        match nigg_dxgi::Factory::new() {
            Ok(f) => Some(f.ctx().clone()),
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                None
            }
        }
    }

    /// Device creation must produce a valid command pool.
    #[test]
    fn device_creation_yields_command_pool() {
        let Some(ctx) = make_factory() else {
            return;
        };
        let device = Device::from_ctx(ctx).expect("device creation");
        assert_ne!(device.command_pool(), vk::CommandPool::null());
    }

    /// Buffer creation must allocate a non-null VkBuffer with the requested size.
    #[test]
    fn buffer_creation_allocates_and_binds() {
        let Some(ctx) = make_factory() else {
            return;
        };
        let device = Device::from_ctx(ctx).expect("device creation");
        let data: [f32; 3] = [0.0, 0.5, 1.0];
        let bytes = bytemuck_cast(&data);
        let buffer = device
            .create_buffer(
                BufferDesc {
                    size: bytes.len() as u64,
                    usage: BufferUsage::Vertex,
                },
                Some(&bytes),
            )
            .expect("buffer creation");
        assert_ne!(buffer.handle(), vk::Buffer::null());
        assert_eq!(buffer.size(), bytes.len() as u64);
    }

    /// A clear-colour command must record and submit without error. This is the core
    /// M6b acceptance path: build swap chain → RTV → clear → flush.
    #[test]
    fn clear_color_records_and_submits() {
        let factory = match nigg_dxgi::Factory::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                return;
            }
        };
        let sc = factory
            .create_swap_chain(None, nigg_dxgi::SwapChainDesc::default())
            .expect("swap chain");
        let device = Arc::new(Device::new(&sc).expect("device"));
        let mut ctx = DeviceContext::new(device.clone()).expect("context");

        let image = sc.get_buffer(0).expect("buffer 0");
        let desc = sc.desc();
        let format = match desc.format {
            nigg_dxgi::DxgiFormat::B8G8R8A8Unorm => vk::Format::B8G8R8A8_UNORM,
            nigg_dxgi::DxgiFormat::B8G8R8A8UnormSrgb => vk::Format::B8G8R8A8_SRGB,
        };
        let rtv = device
            .create_render_target_view_from_image(image, format, desc.width, desc.height)
            .expect("rtv");
        ctx.om_set_render_targets(&rtv).expect("set render target");
        ctx.clear_render_target_view(&rtv, [1.0, 0.0, 0.0, 1.0])
            .expect("clear");
        ctx.flush().expect("flush");
    }

    /// Little-endian byte view of a `&[T: Copy]` for buffer uploads in tests.
    fn bytemuck_cast<T: Copy>(slice: &[T]) -> Vec<u8> {
        let len = std::mem::size_of_val(slice);
        let mut out = Vec::with_capacity(len);
        unsafe {
            // SAFETY: `slice` is a valid `&[T]` of `len` bytes; we copy them into a
            // freshly-allocated Vec of the same length.
            std::ptr::copy_nonoverlapping(slice.as_ptr() as *const u8, out.as_mut_ptr(), len);
            out.set_len(len);
        }
        out
    }
}
