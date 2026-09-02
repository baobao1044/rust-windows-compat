//! Shared Vulkan context for the DXGI translation layer.
//!
//! [`VkCtx`] owns the Vulkan instance, a physical device, a logical device and the
//! graphics queue that both the DXGI swap chain and the D3D11 device/context build
//! on top of. It is wrapped in [`std::sync::Arc`] by the public API so the swap chain,
//! the D3D11 device and the immediate context can all share a single logical device
//! (the D3D11 contract is one device driving one queue).
//!
//! # Headless operation
//!
//! The WSI layer currently hands back [`RawSurfaceHandle::None`](nigg_wsi::RawSurfaceHandle)
//! from its pure-Rust X11 backend (no `xcb_connection_t*`), so a real `VkSurfaceKHR`
//! cannot be built against an X11 window yet. Instead [`VkCtx`] requests the
//! `VK_EXT_headless_surface` instance extension when it is available; the swap chain
//! then creates a *headless* surface that needs no display server. `vkQueuePresentKHR`
//! against a headless surface is well-defined (the presented images are simply not
//! shown anywhere), which keeps the whole pipeline exercisable on a headless host.

use ash::vk;
use ash::{Entry, Instance};

use crate::DxgiError;

/// A physical-device + graphics-queue pair selected at instance creation time.
#[derive(Debug, Clone, Copy)]
pub struct SelectedDevice {
    pub physical_device: vk::PhysicalDevice,
    pub graphics_family: u32,
}

/// The shared Vulkan instance/device/queue context.
///
/// Owns the `ash` handles and destroys them on drop. The extension wrappers
/// (`khr::surface::Instance`, `khr::swapchain::Device`) are cheap clones that hold
/// only function pointers + the raw handle; they do not own Vulkan resources.
pub struct VkCtx {
    pub entry: Entry,
    pub instance: Instance,
    pub selected: SelectedDevice,
    pub device: ash::Device,
    pub graphics_queue: vk::Queue,
    /// `VK_KHR_surface` instance wrapper (used to destroy any surface, including
    /// headless).
    pub surface_ext: ash::khr::surface::Instance,
    /// `VK_KHR_swapchain` device wrapper (used to create/present the swap chain).
    pub swapchain_ext: ash::khr::swapchain::Device,
    /// `true` when `VK_EXT_headless_surface` was enabled on the instance.
    pub has_headless_surface: bool,
}

impl VkCtx {
    /// Create a Vulkan instance, pick the first physical device exposing a graphics
    /// queue, and create a logical device with one graphics queue plus the
    /// `VK_KHR_swapchain` device extension.
    ///
    /// Requesting `VK_KHR_surface` + (optionally) `VK_EXT_headless_surface` at the
    /// instance level lets a swap chain build a headless surface with no display
    /// server attached.
    pub fn new() -> Result<Self, DxgiError> {
        let entry = unsafe {
            // SAFETY: ash's default `loaded` feature dlopens `libvulkan.so.1`. The host
            // has a Vulkan loader installed (`vulkaninfo` works), so the dlopen is
            // sound. The returned Entry must outlive all Vulkan handles created from
            // it; we store it in VkCtx, which outlives every instance/device handle.
            Entry::load()
        }
        .map_err(|e| DxgiError::Vulkan(format!("load Vulkan loader: {e}")))?;

        // --- enumerate instance extensions to decide which surface path we can take ---
        let instance_exts = unsafe {
            // SAFETY: querying extension properties from the loader is safe; the entry
            // was obtained from the linked Vulkan loader.
            entry.enumerate_instance_extension_properties(None)
        }
        .map_err(|e| DxgiError::Vulkan(format!("enumerate instance extensions: {e}")))?;

        let has_headless_surface = instance_exts
            .iter()
            .any(|ext| ext.extension_name_as_c_str() == Ok(vk::EXT_HEADLESS_SURFACE_NAME));
        let has_khr_surface = instance_exts
            .iter()
            .any(|ext| ext.extension_name_as_c_str() == Ok(vk::KHR_SURFACE_NAME));

        let mut enabled: Vec<&'static std::ffi::CStr> = Vec::new();
        if has_khr_surface {
            enabled.push(vk::KHR_SURFACE_NAME);
        }
        if has_headless_surface {
            enabled.push(vk::EXT_HEADLESS_SURFACE_NAME);
        }
        let enabled_ptrs: Vec<*const std::os::raw::c_char> =
            enabled.iter().map(|n| n.as_ptr()).collect();

        let app_info = vk::ApplicationInfo {
            p_application_name: c"nigg".as_ptr(),
            application_version: 0,
            p_engine_name: c"nigg-dxgi".as_ptr(),
            engine_version: 0,
            api_version: vk::API_VERSION_1_1,
            ..Default::default()
        };
        let create_info = vk::InstanceCreateInfo::default()
            .application_info(&app_info)
            .enabled_extension_names(&enabled_ptrs);

        let instance = unsafe {
            // SAFETY: `create_info` references only stack-local data with the right
            // lifetimes; the extension pointers come from `enabled_ptrs` which outlive
            // this call. The application/engine names are static NUL-terminated C
            // strings.
            entry.create_instance(&create_info, None)
        }
        .map_err(|e| DxgiError::Vulkan(format!("create instance: {e}")))?;

        let surface_ext = ash::khr::surface::Instance::new(&entry, &instance);

        // Pick a physical device with a graphics queue family.
        let physicals = unsafe {
            // SAFETY: `instance` is a valid Vulkan instance.
            instance.enumerate_physical_devices()
        }
        .map_err(|e| DxgiError::Vulkan(format!("enumerate physical devices: {e}")))?;
        let physical_device = *physicals
            .first()
            .ok_or_else(|| DxgiError::Vulkan("no Vulkan physical devices available".into()))?;

        let graphics_family = find_graphics_family(&instance, physical_device)?;

        let queue_priorities = [1.0_f32];
        let queue_create_info = vk::DeviceQueueCreateInfo::default()
            .queue_family_index(graphics_family)
            .queue_priorities(&queue_priorities);

        let device_ext_ptrs: Vec<*const std::os::raw::c_char> = if has_khr_surface {
            vec![vk::KHR_SWAPCHAIN_NAME.as_ptr()]
        } else {
            Vec::new()
        };
        let device_create_info = vk::DeviceCreateInfo::default()
            .queue_create_infos(std::slice::from_ref(&queue_create_info))
            .enabled_extension_names(&device_ext_ptrs);

        let device = unsafe {
            // SAFETY: `physical_device` was enumerated from `instance`; the queue
            // family supports graphics; `VK_KHR_swapchain` is present on the device
            // (the host advertises it) or the slice is empty.
            instance.create_device(physical_device, &device_create_info, None)
        }
        .map_err(|e| DxgiError::Vulkan(format!("create logical device: {e}")))?;

        let graphics_queue = unsafe {
            // SAFETY: the queue family was validated to support graphics; queue index
            // 0 exists for a queue family.
            device.get_device_queue(graphics_family, 0)
        };

        let swapchain_ext = ash::khr::swapchain::Device::new(&instance, &device);

        Ok(Self {
            entry,
            instance,
            selected: SelectedDevice {
                physical_device,
                graphics_family,
            },
            device,
            graphics_queue,
            surface_ext,
            swapchain_ext,
            has_headless_surface,
        })
    }

    /// Pick a memory type satisfying `type_bits` (from a memory requirements query)
    /// that offers all of `properties`.
    pub fn find_memory_type(
        &self,
        type_bits: u32,
        properties: vk::MemoryPropertyFlags,
    ) -> Result<u32, DxgiError> {
        let props = unsafe {
            // SAFETY: `physical_device` is a valid handle enumerated from `instance`.
            self.instance
                .get_physical_device_memory_properties(self.selected.physical_device)
        };
        for i in 0..props.memory_type_count {
            if (type_bits & (1 << i)) != 0
                && props.memory_types[i as usize]
                    .property_flags
                    .contains(properties)
            {
                return Ok(i);
            }
        }
        Err(DxgiError::Vulkan(format!(
            "no memory type matches bits 0x{type_bits:x} with properties {properties:?}"
        )))
    }
}

impl Drop for VkCtx {
    fn drop(&mut self) {
        // Order matters: destroy the device first, then the instance. The extension
        // wrappers hold only function pointers + raw handles and own nothing, so they
        // need no explicit teardown.
        unsafe {
            // SAFETY: `device` owns a valid VkDevice and is dropped exactly once here;
            // no other references to its handles survive after VkCtx drops because all
            // swap-chain/buffer/image handles created from it were already destroyed
            // by their owners before the VkCtx's refcount reached zero.
            self.device.destroy_device(None);
            // SAFETY: `instance` owns a valid VkInstance, destroyed exactly once.
            self.instance.destroy_instance(None);
        }
    }
}

/// Find the first queue family on `physical_device` that supports graphics work.
fn find_graphics_family(
    instance: &Instance,
    physical_device: vk::PhysicalDevice,
) -> Result<u32, DxgiError> {
    let props = unsafe {
        // SAFETY: `physical_device` is a valid handle enumerated from `instance`.
        instance.get_physical_device_queue_family_properties(physical_device)
    };
    for (i, p) in props.iter().enumerate() {
        if p.queue_flags.contains(vk::QueueFlags::GRAPHICS) {
            return Ok(i as u32);
        }
    }
    Err(DxgiError::Vulkan(
        "no graphics queue family on the selected physical device".into(),
    ))
}
