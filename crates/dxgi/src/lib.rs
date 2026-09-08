//! Minimal DXGI surface over Vulkan — `IDXGIFactory` + `IDXGISwapChain`.
//!
//! This crate is the host-facing half of the D3D11-over-Vulkan translation layer
//! (workstream M6b). It owns the Vulkan instance, physical/logical device and the
//! graphics queue, and exposes a swap chain backed by a real `VkSwapchainKHR`.
//!
//! Whenever the caller hands in a real window whose WSI backend exposes an
//! `xcb_connection_t*` + XID pair ([`nigg_wsi::RawSurfaceHandle::X11`]), the swap
//! chain presents to a genuine on-screen `VkSurfaceKHR` created with
//! `VK_KHR_xcb_surface` on that window. Otherwise it degrades, in order of
//! preference:
//!
//! - **headless** (`VK_EXT_headless_surface`) — needs no display server at all;
//!   `vkQueuePresentKHR` against a headless surface is defined to succeed (the image
//!   is simply not shown), so the whole clear/present path stays exercisable on a
//!   headless host.
//! - **offscreen** — when even the headless extension is missing, the swap chain
//!   allocates its own colour images and makes `Present` a no-op.
//!
//! Set `NIGG_HEADLESS=1` to force the headless/offscreen fallback even when a real
//! window is available (CI / no-desktop-interference testing).
//!
//! The [`VkCtx`] (shared Vulkan instance/device/queue) is `Arc`-shared with the
//! `nigg-d3d11` crate so the D3D11 device and immediate context drive the same
//! Vulkan device.

mod ctx;

use std::sync::Arc;

use ash::vk;

pub use ctx::{SelectedDevice, VkCtx};

/// A DXGI/D3D11-level error.
#[derive(Debug, thiserror::Error)]
pub enum DxgiError {
    /// A Vulkan call returned a non-success result.
    #[error("vulkan: {0}")]
    Vulkan(String),
    /// The required surface/swapchain extension is not available.
    #[error("missing vulkan extension: {0}")]
    MissingExtension(&'static str),
    /// A WSI window handle was requested but the backend has no surface to offer.
    #[error("no display/surface available for the requested window")]
    NoSurface,
    /// A swap-chain buffer index was out of range.
    #[error("buffer index {0} out of range (count={1})")]
    BufferIndexOutOfRange(usize, usize),
}

/// A DXGI format. Only the subset the translation layer touches is modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DxgiFormat {
    /// 8-bit-per-channel UNORM, BGR ordering — the most common swap-chain format.
    B8G8R8A8Unorm,
    /// 8-bit-per-channel sRGB, BGR ordering.
    B8G8R8A8UnormSrgb,
}

impl DxgiFormat {
    /// The matching Vulkan `VkFormat`.
    pub fn vk_format(self) -> vk::Format {
        match self {
            DxgiFormat::B8G8R8A8Unorm => vk::Format::B8G8R8A8_UNORM,
            DxgiFormat::B8G8R8A8UnormSrgb => vk::Format::B8G8R8A8_SRGB,
        }
    }
}

/// The subset of `DXGI_SWAP_CHAIN_DESC` we honour.
#[derive(Debug, Clone, Copy)]
pub struct SwapChainDesc {
    /// Back-buffer width in pixels.
    pub width: u32,
    /// Back-buffer height in pixels.
    pub height: u32,
    /// Back-buffer format.
    pub format: DxgiFormat,
    /// Number of back buffers (>= 2 for double buffering).
    pub buffer_count: u32,
}

impl Default for SwapChainDesc {
    fn default() -> Self {
        Self {
            width: 640,
            height: 480,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count: 2,
        }
    }
}

/// `IDXGIFactory` — entry point. Backed by a freshly created [`VkCtx`].
pub struct Factory {
    ctx: Arc<VkCtx>,
}

impl Factory {
    /// Create a factory by bringing up a Vulkan instance + device + queue.
    pub fn new() -> Result<Self, DxgiError> {
        let ctx = Arc::new(VkCtx::new()?);
        Ok(Self { ctx })
    }

    /// Borrow the shared Vulkan context (used by D3D11 to build its device).
    pub fn ctx(&self) -> &Arc<VkCtx> {
        &self.ctx
    }

    /// Enumerate the physical devices visible to this factory's instance.
    ///
    /// Returns `(handle, name)` pairs. Useful for the M6b device-enumeration test.
    pub fn enumerate_adapters(&self) -> Result<Vec<(vk::PhysicalDevice, String)>, DxgiError> {
        let physicals = unsafe {
            // SAFETY: `instance` is a valid Vulkan instance owned by `ctx`.
            self.ctx.instance.enumerate_physical_devices()
        }
        .map_err(|e| DxgiError::Vulkan(format!("enumerate physical devices: {e}")))?;
        let mut out = Vec::with_capacity(physicals.len());
        for pd in physicals {
            let props = unsafe {
                // SAFETY: `pd` is a valid physical device enumerated above.
                self.ctx.instance.get_physical_device_properties(pd)
            };
            let name = unsafe {
                // SAFETY: `device_name` is a fixed-size C array of valid bytes per the
                // Vulkan spec; it is NUL-terminated (or we trim at the first NUL).
                let bytes: &[u8] = core::slice::from_raw_parts(
                    props.device_name.as_ptr() as *const u8,
                    props.device_name.len(),
                );
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..end]).into_owned()
            };
            out.push((pd, name));
        }
        Ok(out)
    }

    /// Create a swap chain for `window` using `desc`.
    ///
    /// `window` is optional so the headless path can be exercised without a real
    /// OS window. If `window` resolves to a real [`nigg_wsi::RawSurfaceHandle`] (the
    /// X11 backend hands out its `xcb_connection_t*` + XID), the swap chain presents
    /// to a genuine `VkSurfaceKHR` on that window; if it resolves to
    /// [`nigg_wsi::RawSurfaceHandle::None`] (no display server) it targets a
    /// headless/offscreen surface. Failure of the real-surface bring-up degrades to
    /// headless/offscreen with a warning rather than failing the whole call.
    pub fn create_swap_chain(
        &self,
        window: Option<&nigg_wsi::Window>,
        desc: SwapChainDesc,
    ) -> Result<SwapChain, DxgiError> {
        SwapChain::new(self.ctx.clone(), window, desc)
    }
}

/// The rendering mode the swap chain ended up in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentMode {
    /// A real `VkSwapchainKHR` presenting to a visible host window (X11/XCB
    /// surface).
    Windowed,
    /// A real `VkSwapchainKHR` against a headless `VkSurfaceKHR` (no display).
    Headless,
    /// Offscreen colour images allocated directly; `Present` is a no-op.
    Offscreen,
}

/// `IDXGISwapChain` — a swap chain backed by `VkSwapchainKHR` (windowed or headless)
/// or by directly-allocated colour images (offscreen fallback).
pub struct SwapChain {
    ctx: Arc<VkCtx>,
    desc: SwapChainDesc,
    mode: PresentMode,
    /// The surface, when `mode != Offscreen`. Destroyed on drop.
    surface: vk::SurfaceKHR,
    /// The swapchain, when `mode != Offscreen`. Destroyed on drop.
    swapchain: vk::SwapchainKHR,
    /// Back-buffer images (from the swapchain or directly allocated).
    images: Vec<vk::Image>,
    /// Memory bound to the offscreen images, when `mode == Offscreen`.
    offscreen_memory: Vec<vk::DeviceMemory>,
    current: usize,
}

impl SwapChain {
    fn new(
        ctx: Arc<VkCtx>,
        window: Option<&nigg_wsi::Window>,
        desc: SwapChainDesc,
    ) -> Result<Self, DxgiError> {
        // `NIGG_HEADLESS=1` forces the invisible headless/offscreen path even when a
        // real window is around (used by CI / desktop-interference-free testing).
        let headless_forced =
            std::env::var_os("NIGG_HEADLESS").is_some_and(|v| v == "1" || v == "true");
        let handle = window
            .map(|w| w.raw_surface_handle())
            .unwrap_or(nigg_wsi::RawSurfaceHandle::None);

        // Prefer a real visible window surface, then headless, then offscreen. Any
        // failure of the X11 bring-up degrades (with a warning) instead of failing the
        // call — an invisible-but-working present beats a hard error on misconfigured
        // hosts.
        if let nigg_wsi::RawSurfaceHandle::X11 {
            connection,
            window: window_id,
        } = handle
        {
            if headless_forced {
                log::debug!("NIGG_HEADLESS is set; real window surfaces are disabled");
            } else {
                match Self::new_x11(ctx.clone(), connection, window_id, desc) {
                    Ok(sc) => return Ok(sc),
                    Err(e) => {
                        log::warn!(
                            "presenting to the X11 window failed ({e}); falling back to \
                             headless/offscreen"
                        );
                    }
                }
            }
        }

        if ctx.has_headless_surface {
            Self::new_headless(ctx, desc)
        } else {
            Self::new_offscreen(ctx, desc)
        }
    }

    /// Build a real on-screen surface (`VK_KHR_xcb_surface`) on the X11
    /// connection/window pair handed out by the WSI layer, then bring up the swap
    /// chain on it.
    fn new_x11(
        ctx: Arc<VkCtx>,
        connection: *mut core::ffi::c_void,
        window_id: u32,
        desc: SwapChainDesc,
    ) -> Result<Self, DxgiError> {
        let Some(xcb_ext) = ctx.xcb_surface_ext.as_ref() else {
            return Err(DxgiError::MissingExtension("VK_KHR_xcb_surface"));
        };
        let create_info = vk::XcbSurfaceCreateInfoKHR::default()
            .connection(connection)
            .window(window_id);
        let surface = unsafe {
            // SAFETY: the instance was created with VK_KHR_xcb_surface enabled.
            // `connection` is the `xcb_connection_t*` of the wsi X11 window and
            // `window_id` its XID; the wsi `Window` owns that connection and outlives
            // the surface (and swap chain) built on top of it, so both pointers stay
            // valid for the surface's lifetime. There is no `p_next` chain.
            xcb_ext.create_xcb_surface(&create_info, None)
        }
        .map_err(|e| DxgiError::Vulkan(format!("create xcb surface: {e}")))?;
        Self::new_with_surface(ctx, surface, PresentMode::Windowed, desc)
    }

    fn new_headless(ctx: Arc<VkCtx>, desc: SwapChainDesc) -> Result<Self, DxgiError> {
        let headless_ext = ash::ext::headless_surface::Instance::new(&ctx.entry, &ctx.instance);
        let create_info = vk::HeadlessSurfaceCreateInfoEXT::default();
        let surface = unsafe {
            // SAFETY: the instance was created with VK_EXT_headless_surface enabled;
            // `create_info` is the trivial default with no p_next chain.
            headless_ext.create_headless_surface(&create_info, None)
        }
        .map_err(|e| DxgiError::Vulkan(format!("create headless surface: {e}")))?;
        Self::new_with_surface(ctx, surface, PresentMode::Headless, desc)
    }

    /// Bring up a swap chain targeting the already-created `surface`.
    ///
    /// Takes ownership of `surface`: every error path destroys it before returning,
    /// and success stores it (dropped later by [`SwapChain::destroy_resources`]).
    fn new_with_surface(
        ctx: Arc<VkCtx>,
        surface: vk::SurfaceKHR,
        mode: PresentMode,
        desc: SwapChainDesc,
    ) -> Result<Self, DxgiError> {
        // Verify the graphics queue family can present to this surface. Headless
        // surfaces support present on any queue family per the extension, windows
        // usually cannot be driven from arbitrary families, so we check explicitly so
        // a non-conforming/mismatched setup fails loudly.
        let supported = unsafe {
            // SAFETY: `surface` is a valid VkSurfaceKHR and the physical device is
            // valid; the queue family index is in range.
            ctx.surface_ext.get_physical_device_surface_support(
                ctx.selected.physical_device,
                ctx.selected.graphics_family,
                surface,
            )
        }
        .map_err(|e| {
            // Best-effort surface cleanup before propagating the error.
            unsafe {
                // SAFETY: `surface` is valid and not yet used elsewhere.
                ctx.surface_ext.destroy_surface(surface, None);
            }
            DxgiError::Vulkan(format!("query surface support: {e}"))
        })?;
        if !supported {
            unsafe {
                // SAFETY: surface is valid and unused.
                ctx.surface_ext.destroy_surface(surface, None);
            }
            return Err(DxgiError::Vulkan(
                "graphics queue family does not support present on the surface".into(),
            ));
        }

        // Surface format/extent: a real window reports its client area as
        // `current_extent`; headless surfaces report the requested extent.
        let formats = unsafe {
            // SAFETY: valid physical device + surface.
            ctx.surface_ext
                .get_physical_device_surface_formats(ctx.selected.physical_device, surface)
        }
        .map_err(|e| {
            unsafe {
                // SAFETY: surface is valid.
                ctx.surface_ext.destroy_surface(surface, None);
            }
            DxgiError::Vulkan(format!("query surface formats: {e}"))
        })?;
        let surface_format = formats
            .iter()
            .find(|f| f.format == desc.format.vk_format())
            .copied()
            .unwrap_or_else(|| {
                formats.first().copied().unwrap_or(vk::SurfaceFormatKHR {
                    format: desc.format.vk_format(),
                    color_space: vk::ColorSpaceKHR::SRGB_NONLINEAR,
                })
            });

        let caps = unsafe {
            // SAFETY: valid physical device + surface.
            ctx.surface_ext
                .get_physical_device_surface_capabilities(ctx.selected.physical_device, surface)
        }
        .map_err(|e| {
            unsafe {
                // SAFETY: surface is valid.
                ctx.surface_ext.destroy_surface(surface, None);
            }
            DxgiError::Vulkan(format!("query surface capabilities: {e}"))
        })?;
        let min_image_count = desc.buffer_count.max(caps.min_image_count);
        let extent = clamp_extent(desc.width, desc.height, caps.current_extent);
        let present_mode = vk::PresentModeKHR::FIFO; // always available.

        let create_info = vk::SwapchainCreateInfoKHR::default()
            .surface(surface)
            .min_image_count(min_image_count)
            .image_format(surface_format.format)
            .image_color_space(surface_format.color_space)
            .image_extent(extent)
            .image_array_layers(1)
            .image_usage(vk::ImageUsageFlags::COLOR_ATTACHMENT | vk::ImageUsageFlags::TRANSFER_DST)
            .image_sharing_mode(vk::SharingMode::EXCLUSIVE)
            .pre_transform(vk::SurfaceTransformFlagsKHR::IDENTITY)
            .composite_alpha(vk::CompositeAlphaFlagsKHR::OPAQUE)
            .present_mode(present_mode)
            .clipped(true)
            .image_color_space(surface_format.color_space);

        let swapchain = unsafe {
            // SAFETY: all parameters were validated against surface capabilities;
            // `surface` is valid and supports the graphics queue family.
            ctx.swapchain_ext.create_swapchain(&create_info, None)
        }
        .map_err(|e| {
            unsafe {
                // SAFETY: surface valid; swapchain creation failed so nothing to destroy
                // but the surface.
                ctx.surface_ext.destroy_surface(surface, None);
            }
            DxgiError::Vulkan(format!("create swapchain: {e}"))
        })?;

        let images = unsafe {
            // SAFETY: `swapchain` is a valid VkSwapchainKHR just created.
            ctx.swapchain_ext.get_swapchain_images(swapchain)
        }
        .map_err(|e| {
            unsafe {
                // SAFETY: swapchain valid → destroy it; surface valid → destroy it.
                ctx.swapchain_ext.destroy_swapchain(swapchain, None);
                ctx.surface_ext.destroy_surface(surface, None);
            }
            DxgiError::Vulkan(format!("get swapchain images: {e}"))
        })?;

        Ok(Self {
            ctx,
            desc: SwapChainDesc {
                width: extent.width,
                height: extent.height,
                ..desc
            },
            mode,
            surface,
            swapchain,
            images,
            offscreen_memory: Vec::new(),
            current: 0,
        })
    }

    fn new_offscreen(ctx: Arc<VkCtx>, desc: SwapChainDesc) -> Result<Self, DxgiError> {
        // No surface/swapchain extension: allocate colour images directly.
        let mut images = Vec::with_capacity(desc.buffer_count as usize);
        let mut memories = Vec::with_capacity(desc.buffer_count as usize);
        for _ in 0..desc.buffer_count {
            let create_info = vk::ImageCreateInfo::default()
                .image_type(vk::ImageType::TYPE_2D)
                .format(desc.format.vk_format())
                .extent(vk::Extent3D {
                    width: desc.width,
                    height: desc.height,
                    depth: 1,
                })
                .mip_levels(1)
                .array_layers(1)
                .samples(vk::SampleCountFlags::TYPE_1)
                .tiling(vk::ImageTiling::OPTIMAL)
                .usage(vk::ImageUsageFlags::COLOR_ATTACHMENT | vk::ImageUsageFlags::TRANSFER_DST)
                .sharing_mode(vk::SharingMode::EXCLUSIVE)
                .initial_layout(vk::ImageLayout::UNDEFINED);
            let image = unsafe {
                // SAFETY: `device` is valid; `create_info` describes a valid 2D image.
                ctx.device.create_image(&create_info, None)
            }
            .map_err(|e| DxgiError::Vulkan(format!("create offscreen image: {e}")))?;

            let reqs = unsafe {
                // SAFETY: `image` is a valid VkImage created above.
                ctx.device.get_image_memory_requirements(image)
            };
            let mem_type =
                ctx.find_memory_type(reqs.memory_type_bits, vk::MemoryPropertyFlags::DEVICE_LOCAL)?;
            let alloc_info = vk::MemoryAllocateInfo::default()
                .allocation_size(reqs.size)
                .memory_type_index(mem_type);
            let memory = unsafe {
                // SAFETY: memory type selected from the image's requirements.
                ctx.device.allocate_memory(&alloc_info, None)
            }
            .map_err(|e| DxgiError::Vulkan(format!("allocate offscreen memory: {e}")))?;
            unsafe {
                // SAFETY: `memory` was just allocated for this image; offset 0 is valid
                // because it is the first (only) binding.
                ctx.device
                    .bind_image_memory(image, memory, 0)
                    .map_err(|e| DxgiError::Vulkan(format!("bind offscreen image: {e}")))?;
            }
            images.push(image);
            memories.push(memory);
        }

        Ok(Self {
            ctx,
            desc,
            mode: PresentMode::Offscreen,
            surface: vk::SurfaceKHR::null(),
            swapchain: vk::SwapchainKHR::null(),
            images,
            offscreen_memory: memories,
            current: 0,
        })
    }

    /// The swap-chain descriptor (effective extents after surface clamping).
    pub fn desc(&self) -> SwapChainDesc {
        self.desc
    }

    /// The present mode in use.
    pub fn present_mode(&self) -> PresentMode {
        self.mode
    }

    /// The shared Vulkan context (so D3D11 can build its device off the same VkDevice).
    pub fn ctx(&self) -> &Arc<VkCtx> {
        &self.ctx
    }

    /// Number of back buffers.
    pub fn buffer_count(&self) -> usize {
        self.images.len()
    }

    /// `GetBuffer(index)` — return the back-buffer `VkImage` as a "texture".
    pub fn get_buffer(&self, index: usize) -> Result<vk::Image, DxgiError> {
        self.images
            .get(index)
            .copied()
            .ok_or(DxgiError::BufferIndexOutOfRange(index, self.images.len()))
    }

    /// Borrow all back-buffer images (used by D3D11 to build render-target views).
    pub fn buffers(&self) -> &[vk::Image] {
        &self.images
    }

    /// Acquire the next back buffer for rendering. Returns the image index.
    ///
    /// For the windowed/headless paths this calls `vkAcquireNextImageKHR`
    /// (synchronised with an internal fence). For the offscreen path it round-robins
    /// through the images.
    pub fn acquire_next(&mut self, fence: vk::Fence) -> Result<usize, DxgiError> {
        match self.mode {
            PresentMode::Windowed | PresentMode::Headless => {
                let (_idx, _suboptimal) = unsafe {
                    // SAFETY: `swapchain` is valid; `fence` is a valid fence the caller
                    // will wait on. Using a null semaphore; we gate on the fence.
                    self.ctx.swapchain_ext.acquire_next_image(
                        self.swapchain,
                        u64::MAX,
                        vk::Semaphore::null(),
                        fence,
                    )
                }
                .map_err(|e| DxgiError::Vulkan(format!("acquire next image: {e}")))?;
                self.current = _idx as usize;
                Ok(_idx as usize)
            }
            PresentMode::Offscreen => {
                let idx = self.current % self.images.len();
                self.current = idx;
                Ok(idx)
            }
        }
    }

    /// `Present(sync_interval)` — `vkQueuePresentKHR` for the windowed/headless
    /// paths, a no-op for the offscreen path. `sync_interval` is accepted for API
    /// parity with DXGI but currently maps to FIFO (vsync) present in all cases.
    pub fn present(&mut self, _sync_interval: u32) -> Result<(), DxgiError> {
        if self.mode != PresentMode::Offscreen {
            let index = self.current as u32;
            let present_info = vk::PresentInfoKHR::default()
                .swapchains(std::slice::from_ref(&self.swapchain))
                .image_indices(std::slice::from_ref(&index));
            unsafe {
                // SAFETY: `swapchain` is valid; `current` is a valid image index from a
                // prior acquire; the queue supports present on this surface.
                self.ctx
                    .swapchain_ext
                    .queue_present(self.ctx.graphics_queue, &present_info)
            }
            .map_err(|e| DxgiError::Vulkan(format!("queue present: {e}")))?;
        }
        // Advance the round-robin index for the offscreen path / next presented frame.
        self.current = (self.current + 1) % self.images.len().max(1);
        Ok(())
    }

    /// `ResizeBuffers(width, height)` — recreate the swap chain at a new size.
    ///
    /// Destroys the old swap chain (and offscreen images) and builds a new one. The
    /// format and buffer count are preserved. A windowed swap chain keeps its
    /// (still-valid) `VkSurfaceKHR` and only re-creates the swap chain against it;
    /// headless/offscreen modes rebuild their whole surface/images.
    pub fn resize_buffers(&mut self, width: u32, height: u32) -> Result<(), DxgiError> {
        let desc = SwapChainDesc {
            width,
            height,
            format: self.desc.format,
            buffer_count: self.desc.buffer_count,
        };
        if self.mode == PresentMode::Windowed {
            // The surface belongs to this swap chain and stays valid; re-create only
            // the swap chain against it.
            let surface = self.surface;
            self.surface = vk::SurfaceKHR::null();
            self.destroy_resources();
            let ctx = self.ctx.clone();
            *self = Self::new_with_surface(ctx, surface, PresentMode::Windowed, desc)?;
        } else {
            // Tear down the current resources, keeping the ctx.
            self.destroy_resources();
            let ctx = self.ctx.clone();
            *self = if ctx.has_headless_surface {
                Self::new_headless(ctx, desc)?
            } else {
                Self::new_offscreen(ctx, desc)?
            };
        }
        Ok(())
    }

    fn destroy_resources(&mut self) {
        self.destroy_swapchain_resources();
        unsafe {
            // SAFETY: `surface` was created from `ctx.surface_ext` and is valid until
            // destroyed here; it is destroyed exactly once (nulled right after).
            if self.surface != vk::SurfaceKHR::null() {
                self.ctx.surface_ext.destroy_surface(self.surface, None);
            }
        }
        self.surface = vk::SurfaceKHR::null();
    }

    /// Destroy the swap chain and per-buffer resources, keeping the surface alive.
    fn destroy_swapchain_resources(&mut self) {
        unsafe {
            // SAFETY: all handles below were created from `ctx.device`/swapchain and
            // are valid until destroyed here; each is destroyed exactly once.
            for (image, memory) in self.images.iter().zip(self.offscreen_memory.iter()) {
                if self.mode == PresentMode::Offscreen {
                    self.ctx.device.destroy_image(*image, None);
                    self.ctx.device.free_memory(*memory, None);
                }
            }
            if self.swapchain != vk::SwapchainKHR::null() {
                self.ctx
                    .swapchain_ext
                    .destroy_swapchain(self.swapchain, None);
            }
        }
        self.images.clear();
        self.offscreen_memory.clear();
        self.swapchain = vk::SwapchainKHR::null();
    }
}

impl Drop for SwapChain {
    fn drop(&mut self) {
        self.destroy_resources();
    }
}

/// Clamp a requested extent to the surface's `current_extent`. A `0xFFFF_FFFF`
/// dimension means "use the requested size" (the headless-surface convention).
fn clamp_extent(width: u32, height: u32, current: vk::Extent2D) -> vk::Extent2D {
    let w = if current.width == 0xFFFF_FFFF {
        width
    } else {
        current.width
    };
    let h = if current.height == 0xFFFF_FFFF {
        height
    } else {
        current.height
    };
    vk::Extent2D {
        width: w.max(1),
        height: h.max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The factory must bring up a Vulkan instance + device. We assert the device
    /// handle is non-null (a non-null `VkDevice` implies a non-null `VkInstance`).
    #[test]
    fn factory_creates_vulkan_instance_and_device() {
        let factory = match Factory::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                return;
            }
        };
        let handle = factory.ctx().device.handle();
        assert_ne!(
            handle,
            vk::Device::null(),
            "VkDevice handle must be non-null"
        );
        let inst = factory.ctx().instance.handle();
        assert_ne!(
            inst,
            vk::Instance::null(),
            "VkInstance handle must be non-null"
        );
    }

    /// Device enumeration must find at least one physical device with a name.
    #[test]
    fn enumerate_adapters_finds_at_least_one() {
        let factory = match Factory::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                return;
            }
        };
        let adapters = factory
            .enumerate_adapters()
            .expect("enumerate_adapters should succeed with a valid instance");
        assert!(
            !adapters.is_empty(),
            "at least one physical device expected"
        );
        for (_pd, name) in &adapters {
            assert!(!name.is_empty(), "adapter name should be non-empty");
        }
    }

    /// A headless/offscreen swap chain must be constructible with no window at all,
    /// and must report at least one back buffer.
    #[test]
    fn create_swap_chain_headless() {
        let factory = match Factory::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                return;
            }
        };
        let mut sc = factory
            .create_swap_chain(None, SwapChainDesc::default())
            .expect("swap chain creation should succeed (headless/offscreen)");
        assert!(sc.buffer_count() >= 1);
        let _img = sc.get_buffer(0).expect("buffer 0 must exist");
        // Present must not panic in the offscreen path and must succeed in headless.
        sc.present(0).expect("present should succeed");
    }

    /// On a host with a real X11 display the swap chain built for a wsi `Window` must
    /// present to a visible `VkSurfaceKHR` (mode `Windowed`), not degrade to the
    /// headless path. Skipped on headless hosts (no `DISPLAY`), when `NIGG_HEADLESS`
    /// is forced, and when Vulkan or window construction is unavailable.
    #[test]
    fn create_swap_chain_windowed_on_display() {
        if std::env::var_os("DISPLAY").is_none() {
            eprintln!("skipping: no X11 display available");
            return;
        }
        if std::env::var_os("NIGG_HEADLESS").is_some() {
            eprintln!("skipping: NIGG_HEADLESS forces the headless path");
            return;
        }
        let factory = match Factory::new() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping: no Vulkan available: {e}");
                return;
            }
        };
        let mut window = match nigg_wsi::Window::new("nigg-dxgi-windowed-test", 256, 128) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("skipping: no window available: {e}");
                return;
            }
        };
        let desc = SwapChainDesc {
            width: 256,
            height: 128,
            ..SwapChainDesc::default()
        };
        let mut sc = factory
            .create_swap_chain(Some(&window), desc)
            .expect("windowed swap chain creation should succeed");
        assert_eq!(sc.present_mode(), PresentMode::Windowed);
        assert!(sc.buffer_count() >= 1);
        let img = sc.get_buffer(0).expect("buffer 0 must exist");
        assert_ne!(img, vk::Image::null());
        // One present against the real X11 surface must succeed.
        sc.present(0).expect("present to the window should succeed");
        let _ = window.poll_event();
    }
}
