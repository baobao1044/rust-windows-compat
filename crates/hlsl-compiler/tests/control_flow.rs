//! M6a Feature 1: control flow (if/else, for loops, locals, assignments).

#![cfg(test)]

mod common;

use common::*;
use nigg_hlsl_compiler::ShaderStage;

#[test]
fn control_flow_fixture_compiles() {
    let words = compile_fixture("control_flow.hlsl", ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC, "SPIR-V magic mismatch");
    eprintln!("control_flow first16: {}", first16_hex(&words));
    // Must contain OpSelectionMerge and OpBranchConditional.
    assert!(
        has_selection_merge(&words),
        "expected OpSelectionMerge in control_flow output"
    );
    assert!(
        has_branch_conditional(&words),
        "expected OpBranchConditional in control_flow output"
    );
}

#[test]
fn control_flow_has_local_variable() {
    let words = compile_fixture("control_flow.hlsl", ShaderStage::Pixel);
    // A Function-storage-class OpVariable for `float x`.
    // StorageClass::Function == 7.
    assert!(
        has_opvariable_storageclass(&words, 7),
        "expected a Function-storage OpVariable for the local"
    );
}

#[test]
fn if_without_else_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { if (pos.x > 0.0) { return float4(1.0,1.0,1.0,1.0); } return float4(0.0,0.0,0.0,1.0); }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_selection_merge(&words));
    assert!(has_branch_conditional(&words));
}

#[test]
fn for_loop_compiles_with_loop_merge() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float4 acc = float4(0.0,0.0,0.0,0.0); for (int i = 0; i < 4; i = i + 1) { acc = acc + float4(1.0); } return acc; }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    eprintln!("for_loop first16: {}", first16_hex(&words));
    assert!(has_loop_merge(&words), "expected OpLoopMerge");
    assert!(
        has_branch_conditional(&words),
        "expected OpBranchConditional"
    );
}

#[test]
fn local_assignment_compiles() {
    let src = "float4 main(float4 pos : SV_Position) : SV_Target { float4 c; c = float4(1.0, 2.0, 3.0, 4.0); return c; }";
    let words = compile(src, ShaderStage::Pixel);
    assert_eq!(words[0], SPIRV_MAGIC);
    assert!(has_opvariable_storageclass(&words, 7));
}
