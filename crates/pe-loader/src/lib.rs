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
//! Beyond the main image, [`load_dll`] loads `LoadLibrary`-style DLLs at
//! runtime: the file is mapped at a kernel-chosen base (never colliding with a running
//! image), relocated, import-resolved, initialized with `DllMain(hModule,
//! DLL_PROCESS_ATTACH, NULL)`, and registered in the module list whose `HMODULE`s
//! (image bases) are what `GetProcAddress` resolves exports against.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block has a SAFETY comment.

#![deny(unsafe_op_in_unsafe_fn)]

mod dllmod;
mod imports;
mod mapping;
mod seh;
mod teb;
mod thunk;
mod tls;

pub use dllmod::{free_library, get_proc_address, load_dll};

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
    /// The static-TLS block `TEB.ThreadLocalStoragePointer` refers to. Held here so the
    /// allocation outlives every guest thread-local access; dropping it early would
    /// dangle `gs:[0x58]`.
    _tls_block: Option<tls::TlsBlock>,
    /// TLS callbacks to invoke (with `DLL_PROCESS_ATTACH`) before the entry point.
    tls_callbacks: Vec<*const ()>,
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

        // Run TLS callbacks with DLL_PROCESS_ATTACH before the entry point. Windows
        // does this for every image with an IMAGE_TLS_DIRECTORY; MSVC CRT thread-state
        // init lives here, and so does some of the earliest userland anti-cheat setup,
        // so this has to precede the entry point — never skip it.
        for &cb in &self.tls_callbacks {
            // SAFETY: every callback VA was bounds-checked against the image in
            // `collect_callbacks` and points into the executable code section; the
            // guest stack is fresh and aligned; `h_module` is the live image base.
            unsafe {
                nigg_runtime::run_dll_main_win64(
                    cb,
                    self._stack.top(),
                    self.mapped.base as *mut (),
                    tls::DLL_PROCESS_ATTACH,
                    std::ptr::null_mut(),
                );
            }
        }

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
    // Register the EXE's directory so LoadLibrary can find bundled DLLs
    // (PhysX, lua, assimp, zlib, etc.) that ship alongside the game.
    if let Some(dir) = path.parent() {
        nigg_win32_kernel32::dllload::register_exe_dir(dir.to_path_buf());
    }
    let bytes = std::fs::read(path).map_err(LoadError::Read)?;
    load_bytes(&bytes)
}

/// Load and prepare a PE image from in-memory bytes (used by tests).
pub fn load_bytes(bytes: &[u8]) -> Result<PeImage, LoadError> {
    // Install the kernel32-side `LoadLibrary*`/`GetProcAddress`/`FreeLibrary` bridges so
    // a running PE (and every `LoadLibrary`-loaded DLL) can load further DLLs at
    // runtime. Idempotent: the registration uses `OnceLock`s, so repeated loads
    // (including this one) are no-ops after the first.
    dllmod::register_kernel32_bridge();
    let pe = goblin::pe::PE::parse(bytes)?;
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| LoadError::Bootstrap("PE has no optional header".to_string()))?;

    // Map sections and apply per-section permissions.
    let mapped = mapping::map_image(bytes, &pe)?;

    // Register the actual mapped base so GetModuleHandleW(NULL) returns the
    // correct handle — the game's CRT calls this during init to find itself.
    nigg_win32_kernel32::process::register_exe_base(mapped.base as usize);

    // Apply base relocations if the image was loaded at a different base than preferred.
    if let Some(reloc_dir) = opt.data_directories.get_base_relocation_table() {
        mapping::apply_relocations(&mapped, bytes, &pe, *reloc_dir)?;
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

    // Install the SEH exception-table lookup so `RtlLookupFunctionEntry` (which
    // C++ exception handling, longjmp, and anti-cheat integrity checks call)
    // can find the `RUNTIME_FUNCTION` for any PC inside the image. The exception
    // table is DataDirectory[3] in the optional header; its entries are 12-byte
    // `RUNTIME_FUNCTION` structs (BeginRVA, EndRVA, UnwindRVA), sorted by
    // BeginAddress and non-overlapping.
    if let Some(exc_dir) = opt.data_directories.get_exception_table() {
        let pdata_rva = exc_dir.virtual_address as usize;
        let pdata_size = exc_dir.size as usize;
        if pdata_rva > 0 && pdata_size >= 12 && pdata_rva + pdata_size <= mapped.size {
            let count = pdata_size / 12;
            // SAFETY: `pdata_rva + pdata_size` is within the mapped image
            // (checked above), and the image is mapped RWX/RX at this point.
            let pdata_base = unsafe { mapped.base.add(pdata_rva) } as *const seh::RuntimeFunction;
            // SAFETY: the image stays mapped for the process lifetime (it's the
            // main EXE, owned by the returned PeImage), so the pointer is stable.
            unsafe { seh::install(pdata_base, count, mapped.base as usize, mapped.size) };
            nigg_win32_kernel32::dllload::register_lookup_function_entry(seh_proxy);
            nigg_win32_kernel32::dllload::register_virtual_unwind(virtual_unwind_proxy);
            log::debug!(
                "pe-loader: SEH exception table + virtual unwind installed ({count} RUNTIME_FUNCTION entries at RVA {pdata_rva:#x})"
            );
        }
    }

    // Build the TEB/PEB. Use the guest stack's bounds for the TIB StackBase/StackLimit so
    // `gs:[0x08]`/`gs:[0x10]` describe the same stack we'll run on.
    let stack =
        nigg_runtime::Stack::new_default().map_err(|e| LoadError::Bootstrap(e.to_string()))?;
    // The stack top is the highest usable address; the limit is one page up from base
    // (above the guard page). We approximate StackLimit as the bottom of the usable region.
    let stack_base = stack.top() as usize;
    let stack_limit = stack_base.saturating_sub(stack_usable());
    let mut teb_peb = TebPeb::new(stack_base, stack_limit, mapped.base as usize);

    // Set up static TLS and collect the TLS callbacks, when the image declares a TLS
    // directory. MSVC-linked binaries put CRT thread-state init there and Windows runs
    // it before the entry point, so this has to happen at load time, not on first use.
    let (tls_block, tls_callbacks) = match opt.data_directories.get_tls_table() {
        Some(tls_dir) if tls_dir.virtual_address != 0 => {
            // SAFETY: the image is mapped and relocated by now, and `read_tls_directory`
            // bounds-checks the RVA against the mapping size.
            let parsed = unsafe {
                tls::read_tls_directory(mapped.base, mapped.size, tls_dir.virtual_address)
            };
            match parsed {
                Ok(dir) => {
                    let image_base = mapped.base as u64;
                    // SAFETY: `dir` was parsed from this same mapped image; the index slot
                    // it names lives in a writable data section.
                    let block =
                        unsafe { tls::init_static_tls(mapped.base, mapped.size, image_base, &dir) }
                            .map_err(|e| LoadError::Bootstrap(format!("static TLS setup: {e}")))?;
                    // SAFETY: same image and directory.
                    let cbs = unsafe {
                        tls::collect_callbacks(mapped.base, mapped.size, image_base, &dir)
                    };
                    teb_peb.set_tls_pointer(block.teb_tls_pointer());
                    log::debug!(
                        "pe-loader: static TLS ready ({} bytes, {} callback(s))",
                        dir.block_size(),
                        cbs.len()
                    );
                    (Some(block), cbs)
                }
                Err(e) => {
                    // A malformed TLS directory is not worth failing the load over: an
                    // image that never touches thread-locals still runs fine without it.
                    log::warn!("pe-loader: ignoring unusable TLS directory: {e}");
                    (None, Vec::new())
                }
            }
        }
        _ => (None, Vec::new()),
    };

    let entry_rva = opt.standard_fields.address_of_entry_point as u32;

    Ok(PeImage {
        mapped,
        entry_rva,
        imports: resolved,
        _teb_peb: teb_peb,
        _stack: stack,
        _thunk_arena: thunk_arena,
        _tls_block: tls_block,
        tls_callbacks,
    })
}

/// The usable (non-guard) size of the default guest stack, in bytes.
fn stack_usable() -> usize {
    // Mirrors nigg_runtime::Stack's default: 1 MiB usable + 4 KiB guard. We subtract the
    // guard to report the usable span for the TIB StackLimit.
    1 << 20
}

/// Proxy matching `dllload::LookupFunctionEntryFn`: delegates to `seh::lookup_function_entry`
/// so the kernel32-side `RtlLookupFunctionEntry` stub can reach the PE loader's exception
/// table without a reverse dependency.
fn seh_proxy(pc: u64) -> *const std::os::raw::c_void {
    seh::lookup_function_entry(pc)
}

/// Proxy matching `dllload::VirtualUnwindFn`: delegates to `seh::virtual_unwind`
/// so the kernel32-side `RtlVirtualUnwind` stub can reach the PE loader's
/// unwind implementation without a reverse dependency.
fn virtual_unwind_proxy(
    function_entry: *const std::os::raw::c_void,
    _image_base: usize,
    ctx: *mut std::os::raw::c_void,
    establisher_frame: *mut u64,
) -> u32 {
    // The image_base is stored in the EXC_TABLE global inside seh.rs, so we
    // pass 0 here and let virtual_unwind look it up. Actually, virtual_unwind
    // takes image_base as a parameter — but the bridge passes 0 from kernel32.
    // We need to read the real image_base from the global. Let me check.
    //
    // Actually, the seh::virtual_unwind function takes image_base as a parameter
    // and uses it directly. The bridge passes 0. We need to either:
    // 1. Store image_base in seh.rs and have virtual_unwind use it internally
    // 2. Or pass it through the bridge
    //
    // Option 1 is simpler: modify virtual_unwind to read image_base from the
    // EXC_TABLE global (which already stores it). The parameter becomes unused.
    // But that changes the signature...
    //
    // Simplest: read image_base from the EXC_TABLE global here and pass it.
    let image_base = seh::get_image_base().unwrap_or(0);
    // SAFETY: the caller (kernel32 RtlVirtualUnwind) passes valid pointers from
    // the guest context.
    unsafe {
        seh::virtual_unwind(
            function_entry as *const seh::RuntimeFunction,
            image_base,
            ctx as *mut seh::Context,
            establisher_frame,
        )
    }
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
