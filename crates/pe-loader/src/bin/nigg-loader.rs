//! CLI entrypoint: `nigg-loader <exe>` loads and runs a Windows PE binary natively.

use clap::Parser;
use nigg_pe_loader::{load, LoadError};

/// Load and run a Windows PE executable natively on Linux.
#[derive(Parser, Debug)]
#[command(
    name = "nigg-loader",
    version,
    about = "Run a Windows PE binary natively on Linux"
)]
struct Cli {
    /// Path to the Windows PE executable to load and run.
    exe: std::path::PathBuf,
}

fn main() {
    // Initialise logging so the loader's `log::` messages (relocations, stubbed imports)
    // are visible when RUST_LOG is set; otherwise keep stderr quiet.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();

    let cli = Cli::parse();
    let image = match load(&cli.exe) {
        Ok(img) => img,
        Err(LoadError::Read(e)) => {
            eprintln!("nigg-loader: cannot read {}: {e}", cli.exe.display());
            std::process::exit(127);
        }
        Err(e) => {
            eprintln!("nigg-loader: failed to load {}: {e}", cli.exe.display());
            std::process::exit(126);
        }
    };

    // Report any imports we couldn't implement, so missing API surface is visible.
    let stubbed = image.stubbed_imports();
    if !stubbed.is_empty() {
        log::warn!("{} imported symbol(s) are stubbed:", stubbed.len());
        for (dll, sym) in &stubbed {
            log::warn!("  {dll}!{sym}");
        }
    }

    match image.run() {
        Ok(code) => {
            log::info!("nigg-loader: {} exited with code {code}", cli.exe.display());
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!(
                "nigg-loader: runtime error while running {}: {e}",
                cli.exe.display()
            );
            std::process::exit(125);
        }
    }
}
