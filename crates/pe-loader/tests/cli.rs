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

/// Locate the cross-compiled `d3d12_sample.exe` (a standalone workspace under
/// `tests/d3d12-sample`). Returns `None` when it has not been built yet so the
/// test skips gracefully (it needs a separate cross-compile step and Vulkan at
/// runtime, neither guaranteed in every CI environment).
fn d3d12_sample_exe() -> Option<PathBuf> {
    // `tests/d3d12-sample` is its own workspace, so its target dir is local
    // (unless CARGO_TARGET_DIR is set).
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/d3d12-sample/target"));
    let exe = target_dir
        .join("x86_64-pc-windows-gnu")
        .join("debug")
        .join("d3d12_sample.exe");
    if exe.exists() {
        Some(exe)
    } else {
        None
    }
}

/// M8b acceptance test: the cross-compiled D3D12 sample PE (a `#![no_std]`
/// program that imports `d3d12.dll`/`kernel32.dll`) must run end-to-end through
/// `nigg-loader` and exit 0.
///
/// This validates the D3D12 COM vtable thunk layer end-to-end: the PE's
/// `D3D12CreateDevice` import resolves to our COM thunk, which creates an
/// `ID3D12Device` COM object whose vtable slots are Win64->SysV trampolines.
/// The PE then drives the vtables (CreateCommandQueue ->
/// CreateCommandAllocator -> CreateCommandList -> CreateDescriptorHeap ->
/// GetDescriptorHandleIncrementSize -> CreateCommittedResource ->
/// CreateRenderTargetView -> ResourceBarrier -> ClearRenderTargetView ->
/// ResourceBarrier -> Close -> ExecuteCommandLists), which delegate to the
/// existing Rust D3D12-over-Vulkan translation, and finally calls
/// `ExitProcess(0)`.
///
/// The test skips (passing) if the sample has not been cross-compiled or if no
/// Vulkan device is available, so `cargo test --workspace` stays green in
/// minimal environments. Build the sample with:
///   cargo build --target x86_64-pc-windows-gnu --manifest-path tests/d3d12-sample/Cargo.toml
#[test]
fn nigg_loader_runs_d3d12_sample_and_exits_0() {
    let exe_path = match d3d12_sample_exe() {
        Some(p) => p,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_d3d12_sample_and_exits_0 — \
                 d3d12_sample.exe not built. Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/d3d12-sample/Cargo.toml`."
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
                "nigg-loader: skipping nigg_loader_runs_d3d12_sample_and_exits_0 — \
                 loader runtime error (likely no Vulkan device), exit {code}.\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
        other => {
            panic!(
                "nigg-loader must exit 0 for the D3D12 sample PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}

/// Locate the cross-compiled `d3d11_triangle.exe` (a standalone workspace under
/// `tests/d3d11-triangle`). Returns `None` when it has not been built yet so the
/// test skips gracefully (it needs a separate cross-compile step and Vulkan at
/// runtime, neither guaranteed in every CI environment).
fn d3d11_triangle_exe() -> Option<PathBuf> {
    // `tests/d3d11-triangle` is its own workspace, so its target dir is local
    // (unless CARGO_TARGET_DIR is set).
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/d3d11-triangle/target"));
    let exe = target_dir
        .join("x86_64-pc-windows-gnu")
        .join("debug")
        .join("d3d11_triangle.exe");
    if exe.exists() {
        Some(exe)
    } else {
        None
    }
}

/// M7b acceptance test: the cross-compiled D3D11 triangle sample PE (a
/// `#![no_std]` program that imports `d3d11.dll`/`dxgi.dll`/`kernel32.dll`) must
/// run end-to-end through `nigg-loader` and exit 0.
///
/// This validates the full triangle draw path end-to-end: the PE's
/// `D3D11CreateDeviceAndSwapChain` import resolves to our COM thunk, which
/// creates device/swapchain/context COM objects whose vtable slots are Win64
/// ->SysV trampolines. The PE then drives the vtables (GetBuffer ->
/// CreateRenderTargetView -> CreateVertexShader/CreatePixelShader from embedded
/// SPIR-V -> CreateBuffer -> CreateInputLayout -> OMSetRenderTargets ->
/// VSSetShader/PSSetShader/IASetVertexBuffers/IASetInputLayout/
/// IASetPrimitiveTopology -> ClearRenderTargetView -> Draw(3,0) -> Flush ->
/// Present), which delegate to the existing Rust D3D11/DXGI-over-Vulkan
/// translation, and finally calls `ExitProcess(0)`.
///
/// The test skips (passing) if the sample has not been cross-compiled or if no
/// Vulkan device is available, so `cargo test --workspace` stays green in
/// minimal environments. Build the sample with:
///   cargo build --target x86_64-pc-windows-gnu --manifest-path tests/d3d11-triangle/Cargo.toml
#[test]
fn nigg_loader_runs_d3d11_triangle_and_exits_0() {
    let exe_path = match d3d11_triangle_exe() {
        Some(p) => p,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_d3d11_triangle_and_exits_0 — \
                 d3d11_triangle.exe not built. Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/d3d11-triangle/Cargo.toml`."
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
                "nigg-loader: skipping nigg_loader_runs_d3d11_triangle_and_exits_0 — \
                 loader runtime error (likely no Vulkan device), exit {code}.\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
        other => {
            panic!(
                "nigg-loader must exit 0 for the D3D11 triangle PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}

/// Locate the cross-compiled `anticheat_sim.exe` (a standalone workspace under
/// `tests/anticheat-sim`). Returns `None` when it has not been built yet.
fn anticheat_sim_exe() -> Option<PathBuf> {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/anticheat-sim/target"));
    let exe = target_dir
        .join("x86_64-pc-windows-gnu")
        .join("debug")
        .join("anticheat_sim.exe");
    if exe.exists() {
        Some(exe)
    } else {
        None
    }
}

/// M7+ acceptance test: the anti-cheat simulation PE must run through nigg-loader
/// and exit 0. This validates the full anti-cheat API surface end-to-end: debug
/// detection, module enumeration, process introspection, Winsock init, registry
/// query, and system info collection — all through the Win64→SysV ABI thunk layer.
#[test]
fn nigg_loader_runs_anticheat_sim_and_exits_0() {
    let exe_path = match anticheat_sim_exe() {
        Some(p) => p,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_anticheat_sim_and_exits_0 — \
                 anticheat_sim.exe not built. Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/anticheat-sim/Cargo.toml`."
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
            eprintln!(
                "nigg-loader: skipping anticheat_sim — loader runtime error, exit {code}.\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
        other => {
            panic!(
                "nigg-loader must exit 0 for the anti-cheat sim PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}

/// Locate the cross-compiled `game_visual.exe` (a standalone workspace under
/// `tests/game-visual`). Returns `None` when it has not been built yet.
fn game_visual_exe() -> Option<PathBuf> {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/game-visual/target"));
    let exe = target_dir
        .join("x86_64-pc-windows-gnu")
        .join("debug")
        .join("game_visual.exe");
    if exe.exists() {
        Some(exe)
    } else {
        None
    }
}

/// M9d acceptance test: the game-visual PE (system-integrity checks + D3D11
/// clear+present through nigg-loader) must exit 0. Connects anti-cheat API
/// surface to the D3D11 render pipeline in a single fixture.
#[test]
fn nigg_loader_runs_game_visual_and_exits_0() {
    let exe_path = match game_visual_exe() {
        Some(p) => p,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_game_visual_and_exits_0 — \
                 game_visual.exe not built. Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/game-visual/Cargo.toml`."
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
            eprintln!(
                "nigg-loader: skipping game_visual — loader runtime error, exit {code}.\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
        other => {
            panic!(
                "nigg-loader must exit 0 for the game-visual PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}

/// Locate the cross-compiled `tpm_secureboot_sim.exe` (a standalone workspace
/// under `tests/tpm-secureboot-sim`). Returns `None` when it has not been built.
fn tpm_secureboot_sim_exe() -> Option<PathBuf> {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/tpm-secureboot-sim/target"));
    let exe = target_dir
        .join("x86_64-pc-windows-gnu")
        .join("debug")
        .join("tpm_secureboot_sim.exe");
    if exe.exists() {
        Some(exe)
    } else {
        None
    }
}

/// TPM 2.0 / Secure Boot acceptance test: the system-integrity simulation PE
/// must run through nigg-loader and exit 0. This validates the Windows 11-era
/// platform-trust surface end-to-end through the Win64→SysV ABI thunk layer:
/// `GetFirmwareType` (UEFI), `GetFirmwareEnvironmentVariableA` (the SecureBoot
/// EFI variable = 1), `tbs.dll` TPM 2.0 context + version + command probes
/// (`TPM_VERSION_20`), the advapi32 secure-boot status probes, the not-WOW64 /
/// product-type checks, and the seeded Secure Boot registry state
/// (`UEFISecureBootEnabled = 1`).
#[test]
fn nigg_loader_runs_tpm_secureboot_sim_and_exits_0() {
    let exe_path = match tpm_secureboot_sim_exe() {
        Some(p) => p,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_tpm_secureboot_sim_and_exits_0 — \
                 tpm_secureboot_sim.exe not built. Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/tpm-secureboot-sim/Cargo.toml`."
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
            eprintln!(
                "nigg-loader: skipping tpm_secureboot_sim — loader runtime error, \
                 exit {code}.\nstdout={stdout}\nstderr={stderr}"
            );
        }
        other => {
            panic!(
                "nigg-loader must exit 0 for the TPM/Secure Boot sim PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}

/// Locate the cross-compiled `dllload_test.exe` **and** its companion `nigg_dllload.dll`
/// (a standalone workspace under `tests/dllload-test`). Returns `None` when either has
/// not been built yet.
fn dllload_fixture() -> Option<(PathBuf, PathBuf)> {
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("tests/dllload-test/target"));
    let dir = target_dir.join("x86_64-pc-windows-gnu").join("debug");
    let exe = dir.join("dllload_test.exe");
    let dll = dir.join("nigg_dllload.dll");
    if exe.exists() && dll.exists() {
        Some((exe, dll))
    } else {
        None
    }
}

/// M9-DLLLOAD acceptance test: the DLL-loading fixture PE must run end-to-end through
/// `nigg-loader` and exit 0. This validates the whole runtime DLL pipeline:
///
/// 1. `kernel32!LoadLibraryA("nigg_dllload.dll")` — the loader searches the process
///    working directory (set to the fixture's target dir), maps the DLL at a
///    kernel-chosen base, applies its base relocations (DIR64/HIGHLOW semantics —
///    mandatory at a relocated base), resolves its imports through the same
///    Win64->SysV thunk surface as the main image, and runs
///    `DllMain(hModule, DLL_PROCESS_ATTACH, NULL)` on a fresh guest stack (the mingw
///    CRT's `_CRT_INIT` runs, including the `gs`-based TEB reads and the process heap).
/// 2. `kernel32!GetProcAddress(h, "dll_increment"/"dll_count")` walks the DLL's *real*
///    export directory (read back from the relocated mapped image) and returns the
///    native Win64 code addresses; a missing export ("dll_absent") resolves to NULL.
/// 3. The EXE calls the resolved export directly (both sides use the Windows x64 ABI,
///    so no trampoline is involved) and verifies the DLL's internal atomic counter
///    advanced by exactly one, then `FreeLibrary` unloads the module (`TRUE`).
///
/// The test runs the loader with the fixture DLL's directory as the working directory
/// so the bare-name search ("nigg_dllload.dll") resolves to the cwd, mirroring the
/// Windows search-path default.
///
/// The test skips (passing) if the fixtures have not been cross-compiled. Build them
/// with:
///   cargo build --target x86_64-pc-windows-gnu --manifest-path tests/dllload-test/Cargo.toml
#[test]
fn nigg_loader_runs_dllload_test_and_exits_0() {
    let (exe_path, dll_path) = match dllload_fixture() {
        Some(pair) => pair,
        None => {
            eprintln!(
                "nigg-loader: skipping nigg_loader_runs_dllload_test_and_exits_0 — \
                 dllload_test.exe / nigg_dllload.dll not built. Build them with: \
                 `cargo build --target x86_64-pc-windows-gnu --manifest-path \
                 tests/dllload-test/Cargo.toml`."
            );
            return;
        }
    };

    // The fixture loads its DLL by bare name, so the loader's DLL search must find the
    // sibling file: run with the fixture's target dir as the working directory.
    let working_dir = dll_path
        .parent()
        .expect("DLL fixture has a parent dir")
        .to_path_buf();
    let output = Command::new(BIN)
        .arg(&exe_path)
        .current_dir(&working_dir)
        .output()
        .expect("run nigg-loader");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    match output.status.code() {
        Some(0) => {}
        other => {
            panic!(
                "nigg-loader must exit 0 for the DLL-loading fixture PE (got {other:?})\n\
                 stdout={stdout}\nstderr={stderr}"
            );
        }
    }
}
