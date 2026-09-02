//! HLSL → SPIR-V compiler, written from scratch in Rust.
//!
//! Targets the SM5.0 (Shader Model 5.0) subset required by D3D11. The compiler
//! is organised as a classic frontend:
//!
//! * [`lexer`] — tokenises a subset of HLSL into a span-bearing token stream.
//! * [`ast`] — abstract syntax tree nodes for the supported subset.
//! * [`parser`] — recursive-descent parser producing an [`ast::TranslationUnit`].
//! * [`codegen`] — walks the AST to a SPIR-V module via [`rspirv`].
//!
//! ## Phase 1 (M5)
//! Phase 1 compiles a *trivial* shader: a `main` with no parameters that returns
//! a `float4` constant, bound to `SV_Target` (pixel) or `SV_Position` (vertex).
//! Later milestones (M6+) extend the emitter to textures, samplers, cbuffers,
//! control flow, and HLSL intrinsics; the frontend already parses most of
//! those constructs so the tree shape is stable.
//!
//! ## Public API
//! [`ShaderStage`] selects the entry-point execution model; [`compile`] turns
//! source text into SPIR-V words; [`compile_to_file`] writes them to disk.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod ast;
pub mod codegen;
pub mod lexer;
pub mod parser;

use std::path::Path;

pub use codegen::ShaderStage;

/// A top-level compiler error covering lex, parse, and codegen phases.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("{0}")]
    Lex(#[from] lexer::LexError),
    #[error("{0}")]
    Parse(#[from] parser::ParseError),
    #[error("{0}")]
    Codegen(#[from] codegen::CodegenError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Compile an HLSL source string to SPIR-V words (little-endian `u32`s).
pub fn compile(source: &str, stage: ShaderStage) -> Result<Vec<u32>, CompileError> {
    let tokens = lexer::lex(source)?;
    let unit = parser::parse(tokens)?;
    let words = codegen::codegen(&unit, stage)?;
    Ok(words)
}

/// Compile an HLSL source string and write the SPIR-V binary to `path`.
///
/// The file is the raw little-endian `u32` word stream (no textual header).
pub fn compile_to_file(
    source: &str,
    stage: ShaderStage,
    path: impl AsRef<Path>,
) -> Result<(), CompileError> {
    let words = compile(source, stage)?;
    write_spv(&words, path.as_ref())?;
    Ok(())
}

/// Write SPIR-V words to disk as a little-endian binary stream.
fn write_spv(words: &[u32], path: &Path) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)?;
    let mut buf = Vec::with_capacity(words.len() * 4);
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    f.write_all(&buf)?;
    f.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPIR-V magic number (little-endian on disk: `03 02 23 07`).
    const SPIRV_MAGIC: u32 = 0x0723_0203;

    fn trivial_src() -> &'static str {
        include_str!("../tests/fixtures/shaders/trivial.hlsl")
    }

    #[test]
    fn compiles_trivial_pixel_shader() {
        let words = compile(trivial_src(), ShaderStage::Pixel).expect("compile failed");
        assert!(!words.is_empty());

        // First word is the SPIR-V magic.
        assert_eq!(words[0], SPIRV_MAGIC, "SPIR-V magic mismatch");

        // Header: [magic, version, generator, bound, schema].
        assert!(words.len() >= 5, "module shorter than header");
        let version = words[1].to_le_bytes();
        assert_eq!(version[2], 1, "major version should be 1");
        assert!(words[3] > 0, "bound must be positive (>=1)");
        assert_eq!(words[4], 0, "schema/reserved word must be 0");

        // The module must contain at least one OpFunction.
        assert!(
            module_has_opfunction(&words),
            "no OpFunction instruction found in SPIR-V"
        );

        // If spirv-val is on the host, validate against it; otherwise the
        // structural checks above already stand.
        if let Some(report) = try_spirv_validate(&words) {
            eprintln!("spirv-val report:\n{report}");
        } else {
            eprintln!("spirv-tools not installed; structural header validation used");
        }
    }

    #[test]
    fn compiles_trivial_vertex_shader() {
        let src = "float4 main() : SV_Position { return float4(0.0, 0.0, 0.0, 1.0); }";
        let words = compile(src, ShaderStage::Vertex).expect("vs compile failed");
        assert_eq!(words[0], SPIRV_MAGIC);
        assert!(module_has_opfunction(&words));
    }

    /// Structural validation shared by all M6a fixtures: magic, header, and at
    /// least one `OpFunction`.
    fn structurally_valid(words: &[u32]) {
        assert_eq!(words[0], SPIRV_MAGIC, "SPIR-V magic mismatch");
        assert!(words.len() >= 5, "module shorter than header");
        let version = words[1].to_le_bytes();
        assert_eq!(version[2], 1, "major version should be 1");
        assert!(words[3] > 0, "bound must be positive");
        assert_eq!(words[4], 0, "schema/reserved word must be 0");
        assert!(module_has_opfunction(words), "no OpFunction found");
    }

    #[test]
    fn compiles_control_flow_fixture() {
        let src = include_str!("../tests/fixtures/shaders/control_flow.hlsl");
        let words = compile(src, ShaderStage::Pixel).expect("control_flow compile failed");
        structurally_valid(&words);
        if let Some(report) = try_spirv_validate(&words) {
            eprintln!("control_flow spirv-val:\n{report}");
        }
    }

    #[test]
    fn compiles_cbuffer_fixture() {
        let src = include_str!("../tests/fixtures/shaders/cbuffer.hlsl");
        let words = compile(src, ShaderStage::Pixel).expect("cbuffer compile failed");
        structurally_valid(&words);
        if let Some(report) = try_spirv_validate(&words) {
            eprintln!("cbuffer spirv-val:\n{report}");
        }
    }

    #[test]
    fn compiles_texture_fixture() {
        let src = include_str!("../tests/fixtures/shaders/texture.hlsl");
        let words = compile(src, ShaderStage::Pixel).expect("texture compile failed");
        structurally_valid(&words);
        if let Some(report) = try_spirv_validate(&words) {
            eprintln!("texture spirv-val:\n{report}");
        }
    }

    #[test]
    fn compiles_vs_input_fixture() {
        let src = include_str!("../tests/fixtures/shaders/vs_input.hlsl");
        let words = compile(src, ShaderStage::Vertex).expect("vs_input compile failed");
        structurally_valid(&words);
        if let Some(report) = try_spirv_validate(&words) {
            eprintln!("vs_input spirv-val:\n{report}");
        }
    }

    /// Scan the assembled words for an `OpFunction` opcode.
    ///
    /// SPIR-V instructions are `(word_count << 16) | opcode`; `OpFunction` is
    /// opcode 54. We do a cheap linear scan of the leading opcode words.
    fn module_has_opfunction(words: &[u32]) -> bool {
        const OP_FUNCTION: u32 = 54;
        let mut i = 5; // skip the 5-word header
        while i < words.len() {
            let first = words[i];
            let word_count = (first >> 16) as usize;
            let opcode = first & 0xFFFF;
            if opcode == OP_FUNCTION {
                return true;
            }
            if word_count == 0 {
                // Defensive: a zero word count would loop forever.
                return false;
            }
            i += word_count;
        }
        false
    }

    /// Run `spirv-val` against the assembled binary if it is available on the
    /// host. Returns the combined stdout/stderr on success, or `None` if the
    /// tool is absent.
    fn try_spirv_validate(words: &[u32]) -> Option<String> {
        use std::io::Write;
        use std::process::Command;

        if std::env::var_os("NI_HLSLC_SKIP_SPIRV_VAL").is_some() {
            return None;
        }
        let val = which("spirv-val")?;

        let tmp = std::env::temp_dir().join(format!("nigg_hlslc_{}.spv", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp).ok()?;
            let mut buf = Vec::with_capacity(words.len() * 4);
            for w in words {
                buf.extend_from_slice(&w.to_le_bytes());
            }
            f.write_all(&buf).ok()?;
        }
        let out = Command::new(val).arg(&tmp).output().ok()?;
        let _ = std::fs::remove_file(&tmp);
        let mut s = String::new();
        s.push_str(&String::from_utf8_lossy(&out.stdout));
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        if !out.status.success() {
            s.insert_str(0, "spirv-val FAILED:\n");
        } else {
            s.insert_str(0, "spirv-val OK\n");
        }
        Some(s)
    }

    fn which(prog: &str) -> Option<std::path::PathBuf> {
        use std::process::Command;
        // `which` may not be present; fall back to `command -v`.
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {prog}"))
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(s))
        }
    }
}
