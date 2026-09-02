//! M6a Feature 4: intrinsics via GLSL.std.450.

#![cfg(test)]

mod common;

use common::*;
use nigg_hlsl_compiler::ShaderStage;

#[test]
fn glsl_std_450_import_present() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { return normalize(pos); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(
        has_ext_inst_import(&words, "GLSL.std.450"),
        "expected OpExtInstImport \"GLSL.std.450\""
    );
}

#[test]
fn dot_intrinsic_compiles() {
    let src = "float4 main(float4 a : SV_Position) : SV_Target { float d = dot(a, a); return float4(d, d, d, d); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_ext_inst_import(&words, "GLSL.std.450"));
    // OpDot is opcode 148.
    assert!(has_op(&words, 148), "expected OpDot");
}

#[test]
fn normalize_intrinsic_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { return normalize(pos); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    eprintln!("normalize first16: {}", first16_hex(&words));
    assert!(has_op(&words, 12), "expected OpExtInst (12) for normalize");
}

#[test]
fn saturate_compiles_as_clamp() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { return saturate(pos); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    // saturate -> GLSL.std.450 FClamp (via OpExtInst opcode 12).
    assert!(has_op(&words, 12), "expected OpExtInst for saturate");
}

#[test]
fn lerp_compiles_as_fmix() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { return lerp(pos, pos, 0.5); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_op(&words, 12), "expected OpExtInst for lerp/FMix");
}

#[test]
fn cross_intrinsic_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float3 c = cross(pos.xyz, pos.xyz); return float4(c, 1.0); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_op(&words, 12), "expected OpExtInst for cross");
}

#[test]
fn transcendental_intrinsics_compile() {
    // A shader exercising several GLSL.std.450 single-operand intrinsics.
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float s = sin(pos.x); float c = cos(pos.y); float r = rsqrt(pos.z); return float4(s, c, r, 1.0); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_ext_inst_import(&words, "GLSL.std.450"));
    assert!(has_op(&words, 12), "expected OpExtInst");
}
