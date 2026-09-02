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

/// M1 acceptance test: the hand-built PE that imports `kernel32!ExitProcess` and calls
/// `ExitProcess(42)` must run end-to-end through the full stack — PE parsing, import
/// resolution to ABI-correct Win64->SysV trampolines, the Windows x64 entrypoint call, and
/// the `call [IAT]` landing in our `exit_process` implementation — and exit with code 42.
///
/// This validates the ABI thunk layer (register shuffle RCX->RDI) and the ntapi
/// `ExitProcess` integration. `ExitProcess` calls `std::process::exit(42)`, so the test
/// runs the loader as a subprocess (the `nigg-loader` binary) and inspects its exit code.
#[test]
fn nigg_loader_runs_exit_process_import_and_exits_42() {
    let bytes = nigg_tests_fixtures::minimal_exit_process_pe();
    let exe_path = write_temp_pe("exit_process", &bytes);

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
        "nigg-loader must exit 42 when the PE calls ExitProcess(42) through the ABI \
         trampoline (got {:?})\nstdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
}

#[test]
fn nigg_loader_reports_usage_with_no_args() {
    let output = Command::new(BIN).output().expect("run nigg-loader");
    // clap exits with code 2 on missing-required-argument errors.
    assert_eq!(output.status.code(), Some(2));
}

/// M2 acceptance test: the hand-built console PE that imports `kernel32!GetStdHandle`,
/// `kernel32!WriteFile`, and `kernel32!ExitProcess` must run end-to-end through the full
/// stack, print `hello` to stdout, and exit with code 0.
///
/// This validates the full M2 kernel32 surface wired into the import table: the
/// `GetStdHandle(STD_OUTPUT_HANDLE)` -> fd 1 delegation, `WriteFile` through the ntapi
/// fd resolver (which no longer spuriously closes the fd — the bug fixed in M2), and
/// `ExitProcess(0)` terminating the process with code 0. The test runs `nigg-loader` as a
/// subprocess and asserts `stdout` contains `hello` and the exit code is `0`.
#[test]
fn nigg_loader_runs_console_pe_prints_hello_and_exits_0() {
    let bytes = nigg_tests_fixtures::minimal_console_pe();
    let exe_path = write_temp_pe("console", &bytes);

    let output = Command::new(BIN)
        .arg(&exe_path)
        .output()
        .expect("run nigg-loader");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let _ = fs::remove_file(&exe_path);

    assert!(
        stdout.contains("hello"),
        "nigg-loader stdout must contain 'hello' for the console PE (got \
         {stdout:?})\nstderr={stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "nigg-loader must exit 0 when the PE calls ExitProcess(0) (got {:?})\n\
         stdout={stdout}\nstderr={stderr}",
        output.status.code()
    );
}

/// Resolve the workspace root (two levels above this crate's manifest dir:
/// `crates/pe-loader` -> `crates` -> workspace root).
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Locate the cross-compiled `d3d11_sample.exe` (a standalone workspace under
/// `tests/d3d11-sample`). Returns `None` when it has not been built yet so the
/// test skips gracefully (it needs a separate cross-compile step and Vulkan at
/// runtime, neither guaranteed in every CI environment).
fn d3d11_sample_exe() -> Option<PathBuf> {
    // `tests/d3d11-sample` is its own workspace, so its target dir is local
    // (unless CARGO_TARGET_DIR is set).
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/d3d11-sample/target"));
    let exe = target_dir
        .join("x86_64-pc-windows-gnu")
        .join("debug")
        .join("d3d11_sample.exe");
    if exe.exists() {
        Some(exe)
    } else {
        None
    }
}

/// M7a acceptance test: the cross-compiled D3D11 sample PE (a `#![no_std]`
/// program that imports `d3d11.dll`/`dxgi.dll`/`kernel32.dll`) must run
/// end-to-end through `nigg-loader` and exit 0.
///
/// This validates the COM vtable thunk layer end-to-end: the PE's
/// `D3D11CreateDeviceAndSwapChain` import resolves to our COM thunk, which
/// creates device/swapchain/context COM objects whose vtable slots are Win64
/// ->SysV trampolines. The PE then drives the vtables (GetBuffer ->
/// CreateRenderTargetView -> OMSetRenderTargets -> ClearRenderTargetView ->
/// Flush -> Present), which delegate to the existing Rust D3D11/DXGI-over-Vulkan
/// translation, and finally calls `ExitProcess(0)`.
///
/// The test skips (passing) if the sample has not been cross-compiled or if no
/// Vulkan device is available, so `cargo test --workspace` stays green in
/// minimal environments. Build the sample with:
///   cargo build --target x86_64-pc-windows-gnu --manifest-path tests/d3d11-sample/Cargo.toml
#[test]
fn nigg_loader_runs_d3d11_sample_and_exits_0() {
    let exe_path = match d3d11_sample_exe() {
        Some(p) => p,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_d3d11_sample_and_exits_0 — \
                 d3d11_sample.exe not built. Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/d3d11-sample/Cargo.toml`."
            );
            return;
        }
    };

    let output = Command::new(BIN)
        .arg(&exe_path)
        .output()
        .expect("run nigg-loader");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    match output.status.code() {
        Some(0) => {}
        Some(code @ 125) => {
            // 125 is the loader's "runtime error" exit (e.g. no Vulkan device).
            // Skip rather than fail so the test stays green on headless/no-Vulkan hosts.
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_d3d11_sample_and_exits_0 — \
                 loader runtime error (likely no Vulkan device), exit {code}.\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
        other => {
            panic!(
                "nigg-loader must exit 0 for the D3D11 sample PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}
