//! M6a Feature 5: vector swizzles and constructors.

#![cfg(test)]

mod common;

use common::*;
use nigg_hlsl_compiler::ShaderStage;

#[test]
fn swizzle_xyz_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float3 v = pos.xyz; return float4(v, 1.0); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    // OpVectorShuffle is opcode 79.
    assert!(has_op(&words, 79), "expected OpVectorShuffle for .xyz");
}

#[test]
fn swizzle_rgba_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { return pos.xxxx; }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_op(&words, 79), "expected OpVectorShuffle for .xxxx");
}

#[test]
fn single_component_extract_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float x = pos.x; return float4(x, x, x, x); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    // OpCompositeExtract is opcode 81, or via shuffle (79); either is acceptable.
    assert!(
        has_op(&words, 81) || has_op(&words, 79),
        "expected OpCompositeExtract (81) or OpVectorShuffle (79) for .x"
    );
}

#[test]
fn broadcast_constructor_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { return float4(1.0); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    // OpCompositeConstruct is opcode 80.
    assert!(
        has_op(&words, 80),
        "expected OpCompositeConstruct for broadcast"
    );
}

#[test]
fn vector_from_components_compiles() {
    let src =
        "float4 main(float4 pos : SV_Position) : SV_Target { return float4(1.0, 2.0, 3.0, 4.0); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_op(&words, 80), "expected OpCompositeConstruct");
}

#[test]
fn chained_swizzle_compiles() {
    // `.xy.x` is a chained swizzle (r-value).
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float f = pos.xy.x; return float4(f, f, f, f); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_op(&words, 79) || has_op(&words, 81));
}
