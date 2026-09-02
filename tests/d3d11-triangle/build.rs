//! Build script for the M7b D3D11 triangle sample.
//!
//! Compiles the embedded HLSL vertex/pixel shaders to SPIR-V at build time
//! using the workspace's own `nigg-hlsl-compiler`, writes the little-endian
//! SPIR-V byte blobs to `$OUT_DIR/vs.spv` and `$OUT_DIR/ps.spv`, and exports
//! their paths via `cargo:rustc-env` so `main.rs` can `include_bytes!` them.
//!
//! The sample is a `#![no_std]`/`#![no_main]` program with a custom entry point
//! (`mainCRTStartup`) and no CRT. To avoid a duplicate `mainCRTStartup` from
//! `crt2.o` and an unresolved `WinMain`, we pass `-nostartfiles` +
//! `-nodefaultlibs` to the linker for this bin.

use std::io::Write;
use std::path::PathBuf;

use nigg_hlsl_compiler::{compile, ShaderStage};

/// Vertex shader: maps a `float2 POSITION` to `float4 SV_Position`.
const VS_SOURCE: &str = "\
struct VSInput {
    float2 pos : POSITION;
};
struct VSOutput {
    float4 pos : SV_Position;
};
VSOutput main(VSInput input) {
    VSOutput o;
    o.pos = float4(input.pos, 0.0, 1.0);
    return o;
}
";

/// Pixel shader: outputs a solid green colour.
const PS_SOURCE: &str = "\
float4 main() : SV_Target {
    return float4(0.0, 1.0, 0.0, 1.0);
}
";

/// Write SPIR-V `u32` words to `path` as a little-endian binary stream.
fn write_spv(words: &[u32], path: &std::path::Path) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    let mut buf = Vec::with_capacity(words.len() * 4);
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    f.write_all(&buf)?;
    f.flush()?;
    Ok(())
}

fn main() {
    // The sample has its own `mainCRTStartup` and no `WinMain`; `-nostartfiles`
    // skips `crt2.o` (which defines `mainCRTStartup` and calls `WinMain`). The
    // `rust_eh_personality` symbol referenced by the precompiled `core`'s
    // `.pdata` is provided as a no-op stub in `main.rs` (our panic handler
    // loops, so unwinding never runs).
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));

    // Compile the vertex shader.
    let vs_words = compile(VS_SOURCE, ShaderStage::Vertex).unwrap_or_else(|e| {
        eprintln!("nigg-d3d11-triangle build.rs: VS compile failed: {e}");
        std::process::exit(1);
    });
    let vs_path = out_dir.join("vs.spv");
    write_spv(&vs_words, &vs_path).expect("write vs.spv");
    println!(
        "cargo:rustc-env=VS_SPV_PATH={}",
        vs_path.display()
    );

    // Compile the pixel shader.
    let ps_words = compile(PS_SOURCE, ShaderStage::Pixel).unwrap_or_else(|e| {
        eprintln!("nigg-d3d11-triangle build.rs: PS compile failed: {e}");
        std::process::exit(1);
    });
    let ps_path = out_dir.join("ps.spv");
    write_spv(&ps_words, &ps_path).expect("write ps.spv");
    println!(
        "cargo:rustc-env=PS_SPV_PATH={}",
        ps_path.display()
    );
}
