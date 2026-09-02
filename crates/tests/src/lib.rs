//! Test harness for the Nigg compatibility layer.
//!
//! This crate locates the fixture Windows EXEs (built under [`tests/fixtures`] for the
//! `x86_64-pc-windows-gnu` target), validates them as well-formed PE32+ images, and —
//! once the `nigg-pe-loader` (WS-A) lands — drives `nigg-loader` against them and asserts
//! observable behavior (stdout, exit code, argv).
//!
//! # Fixtures
//!
//! Fixtures are tiny Rust console programs compiled for Windows. Build them with:
//!
//! ```text
//! cargo build --target x86_64-pc-windows-gnu -p nigg-tests-fixtures
//! ```
//!
//! The resulting EXEs land under `target/x86_64-pc-windows-gnu/<profile>/<name>.exe`.
//! The default profile is `debug`; override it with the `NIGG_FIXTURE_PROFILE` env var.
//!
//! # Skipping when fixtures are absent
//!
//! Tests that depend on a built fixture call [`require_fixture`], which returns
//! [`Requirement::Missing`] when the EXE has not been cross-compiled yet. The
//! validation tests then call [`Requirement::skip`] to bail out with a clear message,
//! so `cargo test --workspace` stays green even before CI cross-compiles the fixtures.
//!
//! [`tests/fixtures`]: ../../../tests/fixtures/index.html

use std::path::{Path, PathBuf};

/// The Windows GNU target triple the fixtures are cross-compiled for.
pub const WINDOWS_TARGET: &str = "x86_64-pc-windows-gnu";

/// COFF machine value for x86_64 (`IMAGE_FILE_MACHINE_AMD64`).
pub const COFF_MACHINE_X86_64: u16 = 0x8664;

/// The expected PE signature bytes (`"PE\0\0"` read as a little-endian `u32`).
pub const PE_SIGNATURE: u32 = 0x0000_4550;

/// Outcome of looking up a fixture EXE.
///
/// Returned by [`require_fixture`] so callers can decide whether to skip a test
/// gracefully (the fixture is not yet cross-compiled) or proceed to validate/run it.
pub enum Requirement {
    /// The fixture was found at the given path.
    Present(PathBuf),
    /// The fixture was not found. Tests should bail out with a clear skip message.
    Missing(String),
}

/// Resolve the workspace `target/` directory.
///
/// Honors `CARGO_TARGET_DIR` when set; otherwise falls back to `<workspace_root>/target`,
/// where the workspace root is two levels above this crate's manifest directory
/// (`crates/tests` → `crates` → workspace root).
fn target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // crates/tests -> crates -> workspace root
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("target"))
        .unwrap_or_else(|| PathBuf::from("target"))
}

/// The build profile used to locate fixtures: `debug` by default, overridable via
/// `NIGG_FIXTURE_PROFILE` (e.g. `release`).
fn fixture_profile() -> String {
    std::env::var("NIGG_FIXTURE_PROFILE").unwrap_or_else(|_| "debug".to_string())
}

/// Locate a cross-compiled fixture EXE by short name.
///
/// `fixture_path("hello")` resolves to
/// `<target>/x86_64-pc-windows-gnu/<profile>/hello.exe`. This does **not** check
/// existence — use [`require_fixture`] for that in test bodies.
pub fn fixture_path(name: &str) -> PathBuf {
    target_dir()
        .join(WINDOWS_TARGET)
        .join(fixture_profile())
        .join(format!("{name}.exe"))
}

/// Locate a fixture EXE and confirm it exists on disk.
///
/// Returns [`Requirement::Present`] when the EXE is built, or
/// [`Requirement::Missing`] with the attempted path so tests can skip gracefully.
pub fn require_fixture(name: &str) -> Requirement {
    let path = fixture_path(name);
    if path.exists() {
        Requirement::Present(path)
    } else {
        Requirement::Missing(path.display().to_string())
    }
}

/// Read a fixture EXE's bytes, panicking with a clear message if it is absent.
///
/// Intended for tests that have already decided to proceed (i.e. were not skipped via
/// [`require_fixture`]); primarily a convenience for the PE32+ validation tests.
pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = fixture_path(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read fixture {name} at {}: {e}", path.display()))
}

/// Parse `bytes` as a PE image with `goblin` and assert it is a 64-bit PE32+ image for
/// the x86_64 machine, with the `PE\0\0` signature.
///
/// Returns the parsed [`goblin::pe::PE`] so callers can make further assertions.
pub fn assert_pe32_plus_x86_64(bytes: &[u8]) -> goblin::pe::PE<'_> {
    let pe =
        goblin::pe::PE::parse(bytes).unwrap_or_else(|e| panic!("goblin PE::parse failed: {e}"));
    assert!(
        pe.is_64,
        "expected a PE32+ (64-bit) image, got a 32-bit PE image"
    );
    assert_eq!(
        pe.header.coff_header.machine, COFF_MACHINE_X86_64,
        "expected COFF machine == x86_64 (0x8664), got {:#06x}",
        pe.header.coff_header.machine
    );
    assert_eq!(
        pe.header.signature, PE_SIGNATURE,
        "expected PE signature 0x00004550 (\"PE\\0\\0\"), got {:#010x}",
        pe.header.signature
    );
    pe
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cross-compiled `hello.exe` must exist and be a valid PE32+ image for x86_64.
    ///
    /// This is the Phase 1 smoke test: it verifies the fixtures actually cross-compile
    /// to a real Windows executable whose headers are well-formed. If the fixture has
    /// not been built yet (e.g. `cargo test --workspace` run before the cross-compile
    /// step), the test skips with a clear message rather than failing.
    #[test]
    fn hello_exe_is_valid_pe32_plus() {
        let name = "hello";
        match require_fixture(name) {
            Requirement::Present(_) => {}
            Requirement::Missing(attempted) => {
                eprintln!(
                    "nigg-tests: skipping hello_exe_is_valid_pe32_plus — fixture not built \
                     (expected at {attempted}). Build it with: \
                     `cargo build --target x86_64-pc-windows-gnu -p nigg-tests-fixtures`."
                );
                return;
            }
        }

        let bytes = fixture_bytes(name);
        let pe = assert_pe32_plus_x86_64(&bytes);
        // A real console EXE has at least one section and a nonzero entry point RVA.
        assert!(
            !pe.sections.is_empty(),
            "hello.exe has no sections — not a real PE image"
        );
        assert!(pe.entry != 0, "hello.exe entry point RVA is zero");
    }

    /// End-to-end: `nigg-loader hello.exe` should print `hello from windows binary`
    /// and exit 0.
    ///
    /// TODO(WS-A): drive `nigg-loader` (crates/pe-loader) against the cross-compiled
    /// `hello.exe` fixture and assert stdout == "hello from windows binary\n" and exit
    /// code 0. The loader is not implemented yet, so this test is `#[ignore]` until WS-A
    /// lands. Run it explicitly with `cargo test -p nigg-tests -- --ignored
    /// loader_runs_hello_exe` once the loader can run a console EXE.
    #[test]
    #[ignore = "waiting on WS-A (nigg-pe-loader) to run a console EXE"]
    fn loader_runs_hello_exe() {
        let name = "hello";
        if let Requirement::Missing(attempted) = require_fixture(name) {
            eprintln!(
                "nigg-tests: skipping loader_runs_hello_exe — fixture not built (expected at \
                 {attempted}). Build it with: \
                 `cargo build --target x86_64-pc-windows-gnu -p nigg-tests-fixtures`."
            );
            return;
        }
        // TODO(WS-A): spawn `nigg-loader hello.exe`, capture stdout, assert:
        //   stdout == "hello from windows binary\n"
        //   exit code == 0
        unimplemented!("drive nigg-loader against {name}.exe once WS-A lands");
    }

    /// Sanity check for the harness helpers themselves (does not require fixtures).
    #[test]
    fn fixture_path_targets_windows_gnu() {
        let path = fixture_path("hello");
        let expected_suffix = PathBuf::from(WINDOWS_TARGET)
            .join(fixture_profile())
            .join("hello.exe");
        assert!(
            path.ends_with(&expected_suffix),
            "fixture_path(hello) = {} did not end with {}",
            path.display(),
            expected_suffix.display()
        );
    }
}
