//! M6a Feature 3: textures and samplers.

#![cfg(test)]

mod common;

use common::*;
use nigg_hlsl_compiler::ShaderStage;

#[test]
fn texture_fixture_compiles() {
    let words = compile_fixture("texture.hlsl", ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC, "SPIR-V magic mismatch");
    eprintln!("texture first16: {}", first16_hex(&words));
    // Must contain OpTypeImage (25), OpTypeSampledImage (26), OpTypeSampler (27).
    assert!(has_type_image(&words), "expected OpTypeImage");
    assert!(
        has_type_sampled_image(&words),
        "expected OpTypeSampledImage"
    );
    assert!(has_type_sampler(&words), "expected OpTypeSampler");
}
