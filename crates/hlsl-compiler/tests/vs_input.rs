//! M6a Feature 6: vertex-shader struct inputs/outputs.

#![cfg(test)]

mod common;

use common::*;
use nigg_hlsl_compiler::ShaderStage;

#[test]
fn vs_input_fixture_compiles() {
    let words = compile_fixture("vs_input.hlsl", ShaderStage::Vertex);
    assert_eq!(words[0], SPIRV_MAGIC, "SPIR-V magic mismatch");
    eprintln!("vs_input first16: {}", first16_hex(&words));
    // ExecutionModel::Vertex == 0.
    assert!(
        has_entry_point_model(&words, 0),
        "expected OpEntryPoint with Vertex execution model"
    );
    // Struct input/output types.
    assert!(has_type_struct(&words), "expected OpTypeStruct");
    // Both Input (1) and Output (3) storage variables present.
    assert!(
        has_opvariable_storageclass(&words, 1),
        "expected an Input-storage OpVariable"
    );
    assert!(
        has_opvariable_storageclass(&words, 3),
        "expected an Output-storage OpVariable"
    );
}
