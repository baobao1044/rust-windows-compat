//! PE32/PE32+ loader: parse, map sections, apply relocations, resolve imports, build the
//! TEB/PEB, and execute a Windows x64 PE image natively on Linux.
//!
//! The public entry point is [`load`], which returns a [`PeImage`] ready to run with
//! [`PeImage::run`]. The loader:
//!
//! 1. Parses the PE headers and sections with `goblin` (a pure-Rust PE parser — a format
//!    binding, not Windows-compat code).
//! 2. Maps `SizeOfImage` bytes anonymously, copies each section to its RVA, and applies
//!    per-section permissions with `mprotect` (W^X: executable sections are never writable).
//! 3. Applies the base relocation table so absolute addresses match the actual base.
//! 4. Resolves the import directory: known kernel32/ntdll/vcruntime exports get hand-written
//!    Rust implementations backed by Linux syscalls; unknown imports get a logging trap stub.
//! 5. Builds a minimal TEB and PEB so `gs:[...]` reads (the Windows TIB/TEB fields) work.
//! 6. Runs the entrypoint on a fresh stack with the `gs` base set, returning the exit code.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block has a SAFETY comment.

#![deny(unsafe_op_in_unsafe_fn)]

mod imports;
mod mapping;
mod teb;
mod thunk;

use imports::{ImplTable, ResolvedImports};
use mapping::{MapError, MappedImage};
use teb::TebPeb;
use thunk::ThunkArena;

use std::path::Path;

/// Errors loading or running a PE image.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("failed to read PE file: {0}")]
    Read(#[source] std::io::Error),
    #[error("PE parse failed: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("mapping failed: {0}")]
    Map(#[from] MapError),
    #[error("runtime bootstrap failed: {0}")]
    Bootstrap(String),
}

/// A loaded, relocated, import-resolved PE image ready to execute.
pub struct PeImage {
    mapped: MappedImage,
    /// RVA of the entrypoint (relative to `mapped.base`).
    entry_rva: u32,
    imports: ResolvedImports,
    /// The TEB/PEB is kept alive for the lifetime of `PeImage` so the `gs` base stays valid
    /// while (and after) the entrypoint runs.
    _teb_peb: Box<TebPeb>,
    /// The stack allocated for the guest thread. Kept alive alongside the image.
    _stack: nigg_runtime::Stack,
    /// The executable thunk arena holding the Win64->SysV trampolines the IAT points at.
    /// Kept alive for the lifetime of `PeImage` so the trampoline code stays mapped.
    _thunk_arena: ThunkArena,
}

impl PeImage {
    /// The absolute entrypoint address (mapped base + entry RVA).
    pub fn entrypoint(&self) -> *const () {
        // SAFETY: `entry_rva < size` was validated at load time, so the offset stays in
        // the mapping.
        unsafe { self.mapped.base.add(self.entry_rva as usize) as *const () }
    }

    /// Execute the entrypoint on the guest stack with `gs` pointing at the TEB, returning
    /// the process exit code (the value left in `eax`/`rax`).
    pub fn run(&self) -> Result<i32, LoadError> {
        let entry = self.entrypoint();

        // Set the gs base to the TEB so `gs:[...]` reads land in our TEB.
        nigg_runtime::set_thread_gs_base(self._teb_peb.teb_ptr())
            .map_err(|e| LoadError::Bootstrap(e.to_string()))?;

        // Call the entrypoint with the Windows x64 ABI: RCX = PEB pointer, RDX = 0, with a
        // 32-byte shadow space on the guest stack. The entrypoint reads the PEB via
        // `gs:[0x60]` (which we set to point at the PEB) and via the RCX argument. The
        // minimal fixture ignores arguments entirely, so it keeps returning 42 under this
        // convention.
        //
        // SAFETY: `entry` is the resolved, relocated, executable entrypoint; `stack.top()`
        // is a valid, 16-byte-aligned, writable stack pointer with space below it; `peb`
        // is the live PEB pointer kept alive by `self._teb_peb`. All three are held alive
        // by `self` for the duration of the call.
        let code = unsafe {
            nigg_runtime::run_entrypoint_win64(entry, self._stack.top(), self._teb_peb.peb_ptr())
        };
        Ok(code)
    }

    /// Number of imports that were resolved to a real implementation.
    pub fn resolved_import_count(&self) -> usize {
        let trap = imports::trap_stub_addr();
        self.imports
            .resolved
            .iter()
            .filter(|(_, ptr)| **ptr != trap)
            .count()
    }

    /// The (dll, symbol) pairs that got trap stubs because no implementation exists.
    pub fn stubbed_imports(&self) -> Vec<(String, String)> {
        self.imports.stubbed.clone()
    }
}

/// Load and fully prepare a PE image from `path` for execution.
///
/// Reads the file, parses it, maps + relocates it, resolves imports, and builds the
/// TEB/PEB and a guest stack. Returns a [`PeImage`] whose [`PeImage::run`] executes it.
pub fn load(path: &Path) -> Result<PeImage, LoadError> {
    let bytes = std::fs::read(path).map_err(LoadError::Read)?;
    load_bytes(&bytes)
}

/// Load and prepare a PE image from in-memory bytes (used by tests).
pub fn load_bytes(bytes: &[u8]) -> Result<PeImage, LoadError> {
    let pe = goblin::pe::PE::parse(bytes)?;
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| LoadError::Bootstrap("PE has no optional header".to_string()))?;

    // Map sections and apply per-section permissions.
    let mapped = mapping::map_image(bytes, &pe)?;

    // Apply base relocations if the image was loaded at a different base than preferred.
    if let Some(reloc_dir) = opt.data_directories.get_base_relocation_table() {
        mapping::apply_relocations(&mapped, bytes, *reloc_dir)?;
    }

    // Resolve imports and write the IAT. We build ABI-correct Win64->SysV trampolines in
    // an executable arena; the IAT slots point at these trampolines so PE code calling
    // `call [IAT slot]` (Windows x64 ABI) lands in the trampoline, which shuffles the
    // registers to the System V layout and calls the Rust implementation.
    let mut thunk_arena = ThunkArena::with_capacity(32 * 1024)
        .map_err(|e| LoadError::Bootstrap(format!("thunk arena alloc: {e}")))?;
    let table = ImplTable::build(&mut thunk_arena);
    let resolved = imports::resolve(&pe.imports, &table);
    mapping::write_iat(&mapped, &pe.imports, &resolved.resolved);
    // Flip the thunk arena from read/write to read/execute (W^X) before any trampoline is
    // called by the guest.
    thunk_arena
        .finalize()
        .map_err(|e| LoadError::Bootstrap(format!("thunk arena seal: {e}")))?;

    // Build the TEB/PEB. Use the guest stack's bounds for the TIB StackBase/StackLimit so
    // `gs:[0x08]`/`gs:[0x10]` describe the same stack we'll run on.
    let stack =
        nigg_runtime::Stack::new_default().map_err(|e| LoadError::Bootstrap(e.to_string()))?;
    // The stack top is the highest usable address; the limit is one page up from base
    // (above the guard page). We approximate StackLimit as the bottom of the usable region.
    let stack_base = stack.top() as usize;
    let stack_limit = stack_base.saturating_sub(stack_usable());
    let teb_peb = TebPeb::new(stack_base, stack_limit, mapped.base as usize);

    let entry_rva = opt.standard_fields.address_of_entry_point as u32;

    Ok(PeImage {
        mapped,
        entry_rva,
        imports: resolved,
        _teb_peb: teb_peb,
        _stack: stack,
        _thunk_arena: thunk_arena,
    })
}

/// The usable (non-guard) size of the default guest stack, in bytes.
fn stack_usable() -> usize {
    // Mirrors nigg_runtime::Stack's default: 1 MiB usable + 4 KiB guard. We subtract the
    // guard to report the usable span for the TIB StackLimit.
    1 << 20
}

// ---------------------------------------------------------------------------
// Tests live in tests/ below so they can build the fixture.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Load the minimal fixture (a PE whose entrypoint is `mov eax,42; ret`) and run it;
    /// the process exit code must be 42.
    #[test]
    fn load_and_run_minimal_fixture_exits_42() {
        let bytes = nigg_tests_fixtures::minimal_exit_pe();
        let image = load_bytes(&bytes).expect("load minimal fixture");
        let code = image.run().expect("run minimal fixture");
        assert_eq!(
            code, 42,
            "minimal fixture entrypoint must return exit code 42"
        );
    }

    /// Loading reports zero imports for the minimal fixture (it has no import directory).
    #[test]
    fn minimal_fixture_has_no_imports() {
        let bytes = nigg_tests_fixtures::minimal_exit_pe();
        let image = load_bytes(&bytes).expect("load minimal fixture");
        assert!(
            image.stubbed_imports().is_empty(),
            "minimal fixture has no imports"
        );
        assert_eq!(image.resolved_import_count(), 0);
    }
}
