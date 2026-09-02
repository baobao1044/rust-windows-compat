//! M6b acceptance demo: clear-to-colour + (stretch) triangle via DXGI/D3D11 over
//! Vulkan.
//!
//! This is a **Rust-side** demo of the translation layer — not a real PE. It
//! exercises the full path:
//!
//! 1. Open a `wsi::Window` (640x480) if a display is available; otherwise proceed
//!    headless (the swap chain targets a headless Vulkan surface).
//! 2. Create a DXGI factory + swap chain backed by `VkSwapchainKHR`.
//! 3. Create a D3D11 device + immediate context.
//! 4. Build a render-target view over the swap chain's back buffer.
//! 5. Clear to solid red `(1, 0, 0, 1)` via `ClearRenderTargetView`.
//! 6. (Stretch) Compile a trivial HLSL VS+PS via `nigg_hlsl_compiler::compile`,
//!    create a vertex buffer, and draw a green triangle.
//! 7. Present + flush.
//!
//! The demo must NOT hang or panic if there is no display — it creates the Vulkan
//! device and swap chain, attempts the clear, and exits cleanly.

use std::sync::Arc;

use ash::vk;

use nigg_d3d11::{
    BufferDesc, BufferUsage, Device, DeviceContext, IndexType, RasterizerDesc, ShaderStage,
};
use nigg_dxgi::{DxgiFormat, Factory, SwapChainDesc};

fn main() {
    // Logging is optional; init best-effort (no env_logger dep needed for the demo).
    println!("[demo] nigg M6b — clear_triangle (DXGI + D3D11 over Vulkan)");

    // --- 1. Window (optional; headless-safe) ---
    let window = if std::env::var_os("DISPLAY").is_some() {
        match nigg_wsi::Window::new("nigg M6b — clear_triangle", 640, 480) {
            Ok(w) => {
                println!("[demo] opened a 640x480 X11 window");
                Some(w)
            }
            Err(e) => {
                println!("[demo] window creation failed ({e:?}); running headless");
                None
            }
        }
    } else {
        println!("[demo] no DISPLAY; running headless (Vulkan device + headless surface)");
        None
    };

    // --- 2. DXGI factory + swap chain ---
    let factory = Factory::new().expect("create DXGI factory (Vulkan instance + device)");
    println!("[demo] DXGI factory created (Vulkan instance + logical device)");

    let adapters = factory.enumerate_adapters().expect("enumerate adapters");
    for (i, (_pd, name)) in adapters.iter().enumerate() {
        println!("[demo]   adapter {i}: {name}");
    }

    let desc = SwapChainDesc {
        width: 640,
        height: 480,
        format: DxgiFormat::B8G8R8A8Unorm,
        buffer_count: 2,
    };
    let mut swap_chain = factory
        .create_swap_chain(window.as_ref(), desc)
        .expect("create swap chain");
    println!(
        "[demo] swap chain created (mode={:?}, buffers={})",
        swap_chain.present_mode(),
        swap_chain.buffer_count(),
    );

    // --- 3. D3D11 device + immediate context ---
    let device = Arc::new(Device::new(&swap_chain).expect("create D3D11 device"));
    let mut context = DeviceContext::new(device.clone()).expect("create immediate context");
    println!("[demo] D3D11 device + immediate context created");

    // --- 4. Render target view over back buffer 0 ---
    let image = swap_chain.get_buffer(0).expect("get back buffer 0");
    let sc_desc = swap_chain.desc();
    let format = match sc_desc.format {
        DxgiFormat::B8G8R8A8Unorm => vk::Format::B8G8R8A8_UNORM,
        DxgiFormat::B8G8R8A8UnormSrgb => vk::Format::B8G8R8A8_SRGB,
    };
    let rtv = device
        .create_render_target_view_from_image(image, format, sc_desc.width, sc_desc.height)
        .expect("create render target view");
    context
        .om_set_render_targets(&rtv)
        .expect("set render target");
    println!("[demo] render target view bound");

    // --- 5. Clear to solid red ---
    context
        .clear_render_target_view(&rtv, [1.0, 0.0, 0.0, 1.0])
        .expect("clear to red");
    println!("[demo] cleared back buffer to red (1, 0, 0, 1)");

    // --- 6. (Stretch) Draw a green triangle ---
    match draw_triangle(&device, &mut context, sc_desc.width, sc_desc.height) {
        Ok(()) => println!("[demo] drew a green triangle"),
        Err(e) => println!("[demo] triangle draw skipped/failed: {e}"),
    }

    // --- 7. Present + flush ---
    context.flush().expect("flush command buffer");
    swap_chain.present(0).expect("present");
    println!("[demo] flushed + presented — M6b demo complete");

    // Drain one event so the X11 window is visible briefly (best-effort).
    if let Some(mut w) = window {
        let _ = w.poll_event();
    }
}

/// Compile trivial HLSL VS+PS, create a vertex buffer, and draw a green triangle.
fn draw_triangle(
    device: &Arc<Device>,
    context: &mut DeviceContext,
    _width: u32,
    _height: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    // Trivial HLSL: VS takes float2 position, PS outputs solid green.
    let vs_src = "\
struct VSInput {\n\
    float2 pos : POSITION;\n\
};\n\
struct VSOutput {\n\
    float4 pos : SV_Position;\n\
};\n\
VSOutput main(VSInput input) {\n\
    VSOutput o;\n\
    o.pos = float4(input.pos, 0.0, 1.0);\n\
    return o;\n\
}";
    let ps_src = "float4 main() : SV_Target { return float4(0.0, 1.0, 0.0, 1.0); }";

    let vs_spirv = nigg_hlsl_compiler::compile(vs_src, nigg_hlsl_compiler::ShaderStage::Vertex)?;
    let ps_spirv = nigg_hlsl_compiler::compile(ps_src, nigg_hlsl_compiler::ShaderStage::Pixel)?;
    println!(
        "[demo]   compiled HLSL VS ({} words) + PS ({} words)",
        vs_spirv.len(),
        ps_spirv.len()
    );

    let vs = device.create_shader(&vs_spirv, ShaderStage::Vertex)?;
    let ps = device.create_shader(&ps_spirv, ShaderStage::Pixel)?;
    context.vs_set_shader(&vs);
    context.ps_set_shader(&ps);

    // Three vertices: 2 floats each (x, y) in clip space.
    let vertices: [[f32; 2]; 3] = [[-0.5, -0.5], [0.5, -0.5], [0.0, 0.5]];
    let mut bytes = Vec::with_capacity(vertices.len() * 8);
    for v in &vertices {
        bytes.extend_from_slice(&bytemuck_cast(v));
    }
    let vbo = device.create_buffer(
        BufferDesc {
            size: bytes.len() as u64,
            usage: BufferUsage::Vertex,
        },
        Some(&bytes),
    )?;
    context.ia_set_vertex_buffers(&vbo, 0);

    context.draw(3, RasterizerDesc::default())?;
    // Silence unused-import-style lint: IndexType is re-exported for completeness.
    let _ = IndexType::UInt16;
    Ok(())
}

/// Little-endian byte view of a `&[T: Copy]` for buffer uploads.
fn bytemuck_cast<T: Copy>(slice: &[T]) -> Vec<u8> {
    let len = std::mem::size_of_val(slice);
    let mut out = Vec::with_capacity(len);
    // SAFETY: `slice` is a valid `&[T]` of `len` bytes; we copy them into a
    // freshly-allocated Vec of the same length, then set its length.
    unsafe {
        std::ptr::copy_nonoverlapping(slice.as_ptr() as *const u8, out.as_mut_ptr(), len);
        out.set_len(len);
    }
    out
}
