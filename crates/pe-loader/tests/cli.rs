//! End-to-end integration test: spawn the `nigg-loader` CLI binary against the minimal
//! PE fixture written to a temp file and assert it exits with code 42.
//!
//! This exercises the whole stack: PE parsing, section mapping, relocation, the TEB/PEB
//! build, `gs` base setup, the stack trampoline, and the PE entrypoint (`mov eax,42;ret`)
//! — through the real CLI binary, not just the library.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// The `nigg-loader` binary target name (cargo sets this to its build path).
const BIN: &str = env!("CARGO_BIN_EXE_nigg-loader");

/// Write `bytes` to a uniquely-named file under the system temp dir and return its path.
fn write_temp_pe(name: &str, bytes: &[u8]) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "nigg-loader-test-{}-{}.exe",
        name,
        std::process::id()
    ));
    fs::write(&path, bytes).expect("write PE bytes to temp file");
    path
}

#[test]
fn nigg_loader_runs_minimal_fixture_and_exits_42() {
    // Write the minimal PE (entrypoint `mov eax,42; ret`) to a temp file.
    let bytes = nigg_tests_fixtures::minimal_exit_pe();
    let exe_path = write_temp_pe("minimal", &bytes);

    // Run `nigg-loader <exe>` and capture the result.
    let output = Command::new(BIN)
        .arg(&exe_path)
        .output()
        .expect("run nigg-loader");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let _ = fs::remove_file(&exe_path);

    assert_eq!(
        output.status.code(),
        Some(42),
        "nigg-loader must exit 42 for the minimal fixture (got {:?})\n\
         stdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
}

#[test]
fn nigg_loader_reports_usage_with_no_args() {
    let output = Command::new(BIN).output().expect("run nigg-loader");
    // clap exits with code 2 on missing-required-argument errors.
    assert_eq!(output.status.code(), Some(2));
}
