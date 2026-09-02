//! M6a Feature 2: constant buffers (cbuffer).

#![cfg(test)]

mod common;

use common::*;
use nigg_hlsl_compiler::ShaderStage;

#[test]
fn cbuffer_fixture_compiles() {
    let words = compile_fixture("cbuffer.hlsl", ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC, "SPIR-V magic mismatch");
    eprintln!("cbuffer first16: {}", first16_hex(&words));
    // Must contain OpTypeStruct (the cbuffer block type).
    assert!(has_type_struct(&words), "expected OpTypeStruct for cbuffer");
    // Must contain an OpVariable in the Uniform storage class (== 2).
    assert!(
        has_opvariable_storageclass(&words, 2),
        "expected a Uniform-storage OpVariable for the cbuffer"
    );
}
