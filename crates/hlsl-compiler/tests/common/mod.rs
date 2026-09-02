//! Shared helpers for integration tests of the HLSL compiler.

// Each integration test binary only exercises a subset of these helpers, so
// suppress the dead-code warnings for the unused ones.
#![allow(dead_code)]

use nigg_hlsl_compiler::ShaderStage;

/// SPIR-V magic number (little-endian on disk: `03 02 23 07`).
pub const SPIRV_MAGIC: u32 = 0x0723_0203;

pub fn compile(src: &str, stage: ShaderStage) -> Vec<u32> {
    nigg_hlsl_compiler::compile(src, stage).expect("compilation should succeed")
}

pub fn compile_fixture(name: &str, stage: ShaderStage) -> Vec<u32> {
    let src = std::fs::read_to_string(format!("tests/fixtures/shaders/{name}"))
        .expect("fixture should be readable");
    compile(&src, stage)
}

/// First 16 bytes of the assembled SPIR-V as a hex string, for reporting.
pub fn first16_hex(words: &[u32]) -> String {
    let bytes: Vec<u8> = words.iter().take(4).flat_map(|w| w.to_le_bytes()).collect();
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Scan the assembled words for an instruction with the given opcode.
pub fn has_op(words: &[u32], opcode: u32) -> bool {
    let mut i = 5; // skip the 5-word header
    while i < words.len() {
        let first = words[i];
        let word_count = (first >> 16) as usize;
        let op = first & 0xFFFF;
        if op == opcode {
            return true;
        }
        if word_count == 0 {
            return false;
        }
        i += word_count;
    }
    false
}

/// Scan for an OpVariable with the given storage class (the 4th operand of
/// OpVariable is the StorageClass; for a pointer-typed variable the operand
/// after result-type, result-id is the storage class).
pub fn has_opvariable_storageclass(words: &[u32], sc: u32) -> bool {
    const OP_VARIABLE: u32 = 59;
    let mut i = 5; // skip header
    while i < words.len() {
        let first = words[i];
        let word_count = (first >> 16) as usize;
        let op = first & 0xFFFF;
        if op == OP_VARIABLE && word_count >= 4 {
            // operands after (type, id): [StorageClass, (initializer)?]
            let sc_word = words[i + 3];
            if sc_word == sc {
                return true;
            }
        }
        if word_count == 0 {
            return false;
        }
        i += word_count;
    }
    false
}

/// Scan for an OpEntryPoint with the given execution model (operand 0).
pub fn has_entry_point_model(words: &[u32], model: u32) -> bool {
    const OP_ENTRY_POINT: u32 = 15;
    let mut i = 5;
    while i < words.len() {
        let first = words[i];
        let word_count = (first >> 16) as usize;
        let op = first & 0xFFFF;
        if op == OP_ENTRY_POINT && word_count >= 4 && words[i + 1] == model {
            return true;
        }
        if word_count == 0 {
            return false;
        }
        i += word_count;
    }
    false
}

/// Scan for an OpTypeImage instruction (opcode 25).
pub fn has_type_image(words: &[u32]) -> bool {
    has_op(words, 25)
}

/// Scan for an OpTypeSampledImage instruction (opcode 27).
pub fn has_type_sampled_image(words: &[u32]) -> bool {
    has_op(words, 27)
}

/// Scan for an OpTypeSampler instruction (opcode 26).
pub fn has_type_sampler(words: &[u32]) -> bool {
    has_op(words, 26)
}

/// Scan for an OpTypeStruct instruction (opcode 30).
pub fn has_type_struct(words: &[u32]) -> bool {
    has_op(words, 30)
}

/// Scan for an OpSelectionMerge instruction (opcode 247).
pub fn has_selection_merge(words: &[u32]) -> bool {
    has_op(words, 247)
}

/// Scan for an OpLoopMerge instruction (opcode 246).
pub fn has_loop_merge(words: &[u32]) -> bool {
    has_op(words, 246)
}

/// Scan for an OpBranchConditional instruction (opcode 250).
pub fn has_branch_conditional(words: &[u32]) -> bool {
    has_op(words, 250)
}

/// Scan for an OpExtInstImport whose literal string equals the given set.
pub fn has_ext_inst_import(words: &[u32], set: &str) -> bool {
    // OpExtInstImport = 11.
    const OP_EXT_INST_IMPORT: u32 = 11;
    let mut i = 5;
    while i < words.len() {
        let first = words[i];
        let word_count = (first >> 16) as usize;
        let op = first & 0xFFFF;
        if op == OP_EXT_INST_IMPORT && word_count >= 3 {
            // operands: [result_id, LiteralString...]. The string starts at
            // words[i+2] and spans (word_count - 2) words.
            let n = word_count - 2;
            let s = read_literal_string(&words[i + 2..i + 2 + n]);
            if s == set {
                return true;
            }
        }
        if word_count == 0 {
            return false;
        }
        i += word_count;
    }
    false
}

/// Read a null-terminated literal string from a bounded SPIR-V word slice.
fn read_literal_string(words: &[u32]) -> String {
    let mut bytes = Vec::new();
    for w in words {
        for b in w.to_le_bytes() {
            if b == 0 {
                let s = String::from_utf8_lossy(&bytes);
                return s.into_owned();
            }
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}
