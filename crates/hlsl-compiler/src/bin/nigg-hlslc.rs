// CLI entrypoint: `nigg-hlslc <input.hlsl> -o <output.spv> -s vs|ps` compiles an
// HLSL shader to a SPIR-V binary.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

/// HLSL -> SPIR-V compiler (pure Rust, Phase 1 / M5).
#[derive(Debug, Parser)]
#[command(name = "nigg-hlslc", version, about = "Compile HLSL to SPIR-V")]
struct Cli {
    /// Input HLSL source file.
    input: PathBuf,

    /// Output SPIR-V binary file.
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    /// Shader stage to compile as.
    #[arg(short, long, value_enum, default_value_t = StageArg::Ps)]
    stage: StageArg,
}

/// Command-line shadow of [`nigg_hlsl_compiler::ShaderStage`].
#[derive(Debug, Clone, Copy, ValueEnum)]
enum StageArg {
    /// Vertex shader.
    Vs,
    /// Pixel (fragment) shader.
    Ps,
}

impl From<StageArg> for nigg_hlsl_compiler::ShaderStage {
    fn from(s: StageArg) -> Self {
        match s {
            StageArg::Vs => nigg_hlsl_compiler::ShaderStage::Vertex,
            StageArg::Ps => nigg_hlsl_compiler::ShaderStage::Pixel,
        }
    }
}

fn main() -> ExitCode {
    env_logger::init();
    let cli = Cli::parse();

    let src = match std::fs::read_to_string(&cli.input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nigg-hlslc: cannot read {}: {e}", cli.input.display());
            return ExitCode::from(2);
        }
    };

    match nigg_hlsl_compiler::compile_to_file(&src, cli.stage.into(), &cli.output) {
        Ok(()) => {
            eprintln!(
                "nigg-hlslc: compiled {} -> {} ({})",
                cli.input.display(),
                cli.output.display(),
                stage_label(cli.stage),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("nigg-hlslc: compilation failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn stage_label(s: StageArg) -> &'static str {
    match s {
        StageArg::Vs => "vertex",
        StageArg::Ps => "pixel",
    }
}
