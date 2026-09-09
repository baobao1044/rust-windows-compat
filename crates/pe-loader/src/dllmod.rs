//! DLL module registry: loading `LoadLibrary`-style PE DLLs, running `DllMain`, and
//! resolving `GetProcAddress` through each module's export table.
//!
//! A Windows DLL is an ordinary PE image the loader maps at **any** address (the kernel
//! chooses; never `MAP_FIXED` at the preferred base, so a runtime load cannot collide
//! with a running image), relocates, import-resolves exactly like the main image, and
//! finally initializes with `DllMain(hModule, DLL_PROCESS_ATTACH = 1, NULL)` — the same
//! Windows x64 entrypoint convention the EXE loader uses, but with the module handle
//! (the mapped base) in `RCX`, the attach reason in `RDX`, and the reserved context in
//! `R8`. If `DllMain` returns 0 (`FALSE`), the load fails and the mapping is released.
//! On success the module joins the process module list.
//!
//! `HMODULE` is the image base address, matching Windows semantics closely enough for
//! guest code: `GetProcAddress(hModule, name)` walks the module's export directory (read
//! back from the *mapped* image, so relocations have already fixed any absolute data)
//! and returns `base + export RVA` — the real Win64 code address of the export. No ABI
//! trampoline is needed for the return value: the DLL is a native Windows image whose
//! exports already use the Windows x64 ABI, just like the raw-dylib imports guest code
//! links against.
//!
//! This module also owns the registration bridge into `nigg-win32-kernel32::dllload`:
//! `kernel32` must not depend on `nigg-pe-loader` (that would be a reverse crate
//! dependency), so the loader sets function pointers (`dllload::register`) that let the
//! kernel32-side `LoadLibraryA`/`GetProcAddress`/`FreeLibrary` exports call back into
//! this module.

use std::collections::HashMap;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::imports::ImplTable;
use crate::mapping::{apply_relocations, map_image_anywhere, write_iat, MappedImage};
use crate::thunk::ThunkArena;
use crate::LoadError;

/// `IMAGE_FILE_DLL` COFF characteristic: the file is a DLL, not an EXE.
const IMAGE_FILE_DLL: u16 = 0x2000;

/// Cap for reading NUL-terminated strings out of guest memory (export names are short;
/// the cap only bounds a malformed image's damage).
const MAX_NAME_LEN: usize = 4096;

/// The global process module list, holding every `LoadLibrary`-loaded DLL.
static MODULES: Mutex<Vec<Arc<LoadedModule>>> = Mutex::new(Vec::new());

/// A fully loaded, initialized Windows DLL module.
///
/// `h_module` is the mapped image base (`HMODULE`); the export table was parsed from the
/// mapped image at load time; the `Stack` is the stack `DllMain(DLL_PROCESS_ATTACH)` ran
/// on (kept mapped for later thread-attach notifications). The mapped image, the guest
/// stack, the thunk arena, and everything they own stay alive until [`free_library`]
/// drops the module.
pub struct LoadedModule {
    /// The module handle: the mapped image base address.
    pub h_module: *mut c_void,
    /// Canonicalized filesystem path the DLL was loaded from.
    pub module_path: String,
    /// Lowercased file name (with extension), for name-matched diagnostics.
    pub module_name: String,
    /// The DLL's export directory, parsed from the mapped image.
    pub exports: ExportTable,
    /// The mapped, relocated, import-resolved image itself.
    image: MappedImage,
    /// The stack `DllMain(DLL_PROCESS_ATTACH)` ran on.
    _stack: nigg_runtime::Stack,
    /// The Win64->SysV trampoline arena backing the DLL's own IAT.
    _thunk_arena: ThunkArena,
}

// SAFETY: a `LoadedModule` owns only raw memory mappings (image, guest stack, thunk
// arena) and plain data; the mappings carry no thread state and all registry access is
// serialized behind `MODULES`' mutex (export lookups keep only a `&` view into the
// mapped image — concurrent reads of the constant code/data pages are benign). So the
// value can live in shared state.
unsafe impl Send for LoadedModule {}
unsafe impl Sync for LoadedModule {}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        // Release the mapped image. The guest stack and thunk arena inside have their
        // own `Drop` impls that run after this.
        //
        // SAFETY: `self.image.base..self.image.size` is exactly the anonymous mapping
        // created at load time and this module owns it until now; it is unmapped exactly
        // once (the value is consumed by the registry on the success path, or unmapped
        // on the failure path before the struct is ever registered).
        unsafe {
            libc::munmap(self.image.base as *mut libc::c_void, self.image.size);
        }
    }
}

/// The parsed export directory of a loaded module.
pub struct ExportTable {
    /// Export name -> function RVA. Names are kept as raw bytes so PE name bytes (ASCII,
    /// but not guaranteed UTF-8) match guest lookups byte-for-byte.
    names: HashMap<Vec<u8>, u32>,
    /// The exported-functions array (indexed by `ordinal - ordinal_base`).
    function_rvas: Vec<u32>,
    /// The default export ordinal base for `function_rvas` indexing.
    ordinal_base: u32,
    /// `(rva, size)` span of the export directory, used to detect forwarder exports.
    export_dir: ExportDirSpan,
}

/// The `(rva, size)` span of the export directory in the image.
#[derive(Clone, Copy)]
struct ExportDirSpan {
    rva: u32,
    size: u32,
}

impl ExportTable {
    /// The function RVA for an export by ordinal (`MAKEINTRESOURCE` case), or `None`
    /// when out of range.
    fn function_rva_by_ordinal(&self, ordinal: u32) -> Option<u32> {
        let idx = ordinal.checked_sub(self.ordinal_base)?;
        self.function_rvas.get(idx as usize).copied()
    }
}

/// Load a DLL (PE) from `path`, initialize it with `DllMain(hModule, DLL_PROCESS_ATTACH,
/// NULL)`, register it in the global module list, and return the `HMODULE` (image base).
///
/// Loading a DLL reuses every stage of the normal image load — parse, map, relocations,
/// import resolution into ABI-correct trampolines — except the image base is chosen by
/// the kernel (never `MAP_FIXED`, so an already-running image cannot be disturbed) and
/// the entrypoint is invoked with the `DllMain` argument convention. Loading is
/// idempotent: loading an already-loaded path returns the existing module handle.
///
/// `path` may be relative (resolved against the process cwd, like a Windows search-path
/// hit) or absolute. It must be called on a thread whose `gs` base is a live TEB when the
/// DLL's entrypoint is expected to touch `gs:[...]` (the loader's guest threads qualify;
/// a plain host thread is fine for DllMain implementations that never read the TEB).
pub fn load_dll(path: &Path) -> Result<*mut c_void, LoadError> {
    load_dll_ex(path, true)
}

/// The DLL load core behind [`load_dll`]: as `[load_dll]` but with the `DllMain(
/// DLL_PROCESS_ATTACH)` initialization optionally skipped (the
/// `LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)` semantics: map + bind the image without
/// running its initialization — used by tools that checksum a DLL file's contents).
pub fn load_dll_ex(path: &Path, run_dll_main: bool) -> Result<*mut c_void, LoadError> {
    // Canonicalize so a second `LoadLibrary` of the same file (by any path spelling)
    // hits the already-loaded-module check instead of mapping a second copy.
    let canonical_path = std::fs::canonicalize(path).map_err(LoadError::Read)?;
    let canonical = canonical_path.to_string_lossy().into_owned();
    if let Some(h) = lookup_by_path(&canonical) {
        log::debug!(
            "DLL {canonical} already loaded; returning existing handle {:#x}",
            h as usize
        );
        return Ok(h);
    }

    let bytes = std::fs::read(path).map_err(LoadError::Read)?;
    let pe = goblin::pe::PE::parse(&bytes)?;
    if pe.header.coff_header.characteristics & IMAGE_FILE_DLL == 0 {
        return Err(LoadError::Bootstrap(format!(
            "{canonical} is not a DLL (IMAGE_FILE_DLL flag not set)"
        )));
    }
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| LoadError::Bootstrap("PE has no optional header".to_string()))?;

    // Map the image anywhere the kernel likes; relocations make it position-independent.
    let mapped = map_image_anywhere(&bytes, &pe)?;

    // Apply base relocations so absolute addresses match the actual base.
    if let Some(reloc_dir) = opt.data_directories.get_base_relocation_table() {
        apply_relocations(&mapped, &bytes, &pe, *reloc_dir)?;
    }

    // Resolve the DLL's imports against our own implementation surface: the DLL calls
    // our kernel32/user32/... exports through the same Win64->SysV thunk arena the main
    // image uses. This also lets a guest DLL call `LoadLibraryA` itself — its thunk
    // lands in the kernel32 export, which re-enters this function.
    let mut thunk_arena = ThunkArena::with_capacity(32 * 1024)
        .map_err(|e| LoadError::Bootstrap(format!("thunk arena alloc: {e}")))?;
    let table = ImplTable::build(&mut thunk_arena);
    let resolved = crate::imports::resolve(&pe.imports, &table);
    write_iat(&mapped, &pe.imports, &resolved.resolved);
    thunk_arena
        .finalize()
        .map_err(|e| LoadError::Bootstrap(format!("thunk arena seal: {e}")))?;

    // Parse the export directory out of the mapped image (post-relocation, so it is
    // exactly what `GetProcAddress` walks later, with absolute data already fixed).
    let exports = parse_export_table(&mapped);

    // Run the entrypoint as DllMain(hModule, DLL_PROCESS_ATTACH, NULL) on a fresh guest
    // stack. The `gs` base is not touched: the calling thread's TEB (installed by the
    // main image run) stays valid for the whole call, matching Windows, where DllMain
    // runs on the calling thread.
    let stack = nigg_runtime::Stack::new_default()
        .map_err(|e| LoadError::Bootstrap(format!("DllMain stack allocation failed: {e}")))?;
    let entry_rva = opt.standard_fields.address_of_entry_point as u32;
    if !run_dll_main {
        // `LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)`: map + bind the image, but never
        // run its initialization.
        log::debug!(
            "LoadLibraryEx for {canonical}: DONT_RESOLVE_DLL_REFERENCES set; imports bound, DllMain skipped"
        );
    } else if entry_rva == 0 {
        log::warn!("DLL {canonical} has no entrypoint; skipping DllMain(DLL_PROCESS_ATTACH)");
    } else {
        let entry = mapped.rva_to_ptr(entry_rva).ok_or_else(|| {
            LoadError::Bootstrap(format!(
                "DLL entrypoint RVA {entry_rva:#x} is outside the mapped image"
            ))
        })?;
        // SAFETY: `entry` is the DLL's mapped, relocated entrypoint (validated in-bounds
        // by `MappedImage::rva_to_ptr` and made executable by the section mapping);
        // `stack.top()` is a fresh, 16-aligned writable stack with ample space below it;
        // `mapped.base` is the live `HMODULE` the DLL expects in RCX.
        let result = unsafe {
            nigg_runtime::run_dll_main_win64(
                entry as *const (),
                stack.top(),
                mapped.base as usize as *mut (),
                1, // DLL_PROCESS_ATTACH
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            // Unload mappings before reporting the failure (the module never registered).
            mapped.unmap();
            return Err(LoadError::Bootstrap(format!(
                "DllMain(DLL_PROCESS_ATTACH) for {canonical} returned FALSE; load failed"
            )));
        }
    }

    let module_name = module_name_of(&canonical);
    let h_module = mapped.base as *mut c_void;
    let len = exports.names.len();
    log::info!(
        "loaded DLL {:#x} ({module_name}, {len} named exports)",
        h_module as usize
    );
    MODULES
        .lock()
        .expect("module registry poisoned")
        .push(Arc::new(LoadedModule {
            h_module,
            module_path: canonical,
            module_name,
            exports,
            image: mapped,
            _stack: stack,
            _thunk_arena: thunk_arena,
        }));
    Ok(h_module)
}

/// `GetProcAddress`-style lookup: find `name` (or a `MAKEINTRESOURCE` ordinal) among the
/// exports of the module with handle `h_module` and return the export's real Win64 code
/// address (`base + RVA`). Returns NULL when the module is unknown, the name is absent,
/// or the address cannot be resolved.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_proc_address(h_module: *mut c_void, name: *const u8) -> *mut c_void {
    if h_module.is_null() {
        return std::ptr::null_mut();
    }

    // Check if this is a fake handle from GetModuleHandleW (EXE_BASE + offset).
    // These represent known DLLs we implement ourselves — resolve through the
    // import table built by ImplTable::build.
    const EXE_BASE: usize = 0x1_4000_0000;
    let handle_val = h_module as usize;
    if (EXE_BASE..EXE_BASE + 0x10000).contains(&handle_val) {
        // This is a known-DLL fake handle. Resolve the symbol through our
        // ImplTable instead of walking a real export directory.
        let dll_name = match handle_val - EXE_BASE {
            0 => "kernel32.dll", // EXE base — not a real DLL
            0x1000 => "kernel32.dll",
            0x2000 => "ntdll.dll",
            0x3000 => "kernel32.dll", // kernelbase → kernel32
            0x4000 => "user32.dll",
            0x5000 => "gdi32.dll",
            0x6000 => "advapi32.dll",
            _ => "kernel32.dll", // default for api-ms-win-* pseudo-DLLs
        };

        // Read the symbol name from guest memory.
        let sym_str = if (name as usize) < 0x1_0000 {
            // Ordinal import — not supported for fake handles.
            return std::ptr::null_mut();
        } else {
            // SAFETY: `name` is a NUL-terminated C string in guest memory.
            let mut bytes = Vec::new();
            let mut i = 0;
            unsafe {
                while *name.add(i) != 0 && i < 256 {
                    bytes.push(*name.add(i));
                    i += 1;
                }
            }
            match std::ffi::CString::new(&bytes[..]) {
                Ok(cstr) => cstr,
                Err(_) => return std::ptr::null_mut(),
            }
        };
        let sym_str = sym_str.to_string_lossy().into_owned();

        // Build a fresh ImplTable and look up the symbol.
        // This is not ideal (rebuilds the table each call) but GetProcAddress
        // on these fake handles is rare — mainly during CRT init.
        let mut arena = crate::thunk::ThunkArena::with_capacity(32 * 1024)
            .expect("thunk arena for GetProcAddress bridge");
        let table = crate::imports::ImplTable::build(&mut arena);
        arena.finalize().expect("seal thunk arena");
        if let Some(ptr) = table.lookup(dll_name, &sym_str) {
            log::debug!(
                "GetProcAddress: resolved {dll_name}!{sym_str} from ImplTable (fake handle {handle_val:#x})"
            );
            // Keep the arena alive — leak it so the thunk stays valid.
            std::mem::forget(arena);
            return ptr as *mut c_void;
        }
        log::debug!(
            "GetProcAddress: {dll_name}!{sym_str} not found in ImplTable (fake handle {handle_val:#x})"
        );
        return std::ptr::null_mut();
    }

    let Some(module) = find_by_handle(h_module) else {
        log::warn!(
            "GetProcAddress on unknown module handle {:#x}",
            h_module as usize
        );
        return std::ptr::null_mut();
    };

    // Windows rule: when the name argument's value is below 0x10000 it encodes an
    // ordinal (`MAKEINTRESOURCE`), not a pointer to a string.
    if (name as usize) < 0x1_0000 {
        let ordinal = (name as usize) as u32;
        let Some(rva) = module.exports.function_rva_by_ordinal(ordinal) else {
            log::debug!(
                "GetProcAddress({}): ordinal {ordinal} not found",
                module.module_name
            );
            return std::ptr::null_mut();
        };
        return export_addr(&module, rva);
    }

    let Some(sym) = read_guest_cstring(name) else {
        log::warn!(
            "GetProcAddress({}): name pointer is not readable",
            module.module_name
        );
        return std::ptr::null_mut();
    };
    let Some(&rva) = module.exports.names.get(&sym) else {
        log::debug!(
            "GetProcAddress({}): export {} not found",
            module.module_name,
            String::from_utf8_lossy(&sym)
        );
        return std::ptr::null_mut();
    };
    export_addr(&module, rva)
}

/// Resolve an export RVA to its absolute address in the module, refusing the
/// forwarder-export case (an RVA inside the export directory is a name string, not
/// callable code).
fn export_addr(module: &LoadedModule, rva: u32) -> *mut c_void {
    let dir = module.exports.export_dir;
    let forwarder = rva == 0 || (dir.rva <= rva && rva < dir.rva.saturating_add(dir.size));
    if forwarder {
        log::warn!(
            "GetProcAddress({}): export RVA {rva:#x} is a forwarded export; returning NULL",
            module.module_name
        );
        return std::ptr::null_mut();
    }
    let Some(addr) = module.image.rva_to_ptr(rva) else {
        log::warn!(
            "GetProcAddress({}): export RVA {rva:#x} is outside the image",
            module.module_name
        );
        return std::ptr::null_mut();
    };
    addr as *mut c_void
}

/// `FreeLibrary`-style unload: remove the module from the registry and release its
/// mapping and every allocation it owns. Returns true when the handle was a registered
/// module.
pub fn free_library(h_module: *mut c_void) -> bool {
    let mut modules = MODULES.lock().expect("module registry poisoned");
    let Some(idx) = modules.iter().position(|m| m.h_module == h_module) else {
        log::warn!(
            "FreeLibrary on unknown module handle {:#x}",
            h_module as usize
        );
        return false;
    };
    let module = modules.remove(idx);
    drop(modules);
    // Dropping `module` unmaps the image and frees the stack/thunk arena. The Arc keeps
    // it alive until every outstanding reference (none by contract — the caller asked to
    // free it) goes away.
    drop(module);
    true
}

/// Find a loaded module by canonicalized path (for idempotent `LoadLibrary` calls).
fn lookup_by_path(canonical: &str) -> Option<*mut c_void> {
    let modules = MODULES.lock().expect("module registry poisoned");
    modules
        .iter()
        .find(|m| m.module_path == canonical)
        .map(|m| m.h_module)
}

/// Find a loaded module by `HMODULE`.
fn find_by_handle(h_module: *mut c_void) -> Option<Arc<LoadedModule>> {
    let modules = MODULES.lock().expect("module registry poisoned");
    modules
        .iter()
        .find(|m| m.h_module == h_module)
        .map(Arc::clone)
}

/// Lowercased file name (with extension) of a path, e.g. `"/x/y/My.DLL"` -> `"my.dll"`.
fn module_name_of(path: &str) -> String {
    PathBuf::from(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Export directory parsing (from the mapped image)
// ---------------------------------------------------------------------------

/// Parse the export directory of a *mapped* image by walking its PE headers in memory.
///
/// Every read is bounds-checked against the mapped image: a malformed header or an
/// out-of-image directory yields an empty table rather than an invalid access.
fn parse_export_table(img: &MappedImage) -> ExportTable {
    let mut out = ExportTable {
        names: HashMap::new(),
        function_rvas: Vec::new(),
        ordinal_base: 1,
        export_dir: ExportDirSpan { rva: 0, size: 0 },
    };
    let Some(dir) = locate_export_dir(img) else {
        return out; // no export directory
    };
    out.export_dir = dir;

    // Fields of IMAGE_EXPORT_DIRECTORY (40 bytes, all u32 here):
    //   +16 Base, +20 NumberOfFunctions, +24 NumberOfNames,
    //   +28 AddressOfFunctions, +32 AddressOfNames, +36 AddressOfNameOrdinals.
    let mut truncated = false;
    let read_field = |off: u32| read_u32(img, dir.rva.saturating_add(off));
    let mut extract = |off: u32| {
        read_field(off).unwrap_or_else(|| {
            truncated = true;
            0
        })
    };
    let ordinal_base = extract(16);
    let n_functions = extract(20);
    let n_names = extract(24);
    let addr_functions = extract(28);
    let addr_names = extract(32);
    let addr_ordinals = extract(36);
    if truncated {
        log::warn!(
            "truncated export directory at RVA {:#x}; treating image as export-less",
            dir.rva
        );
        return out;
    }
    out.ordinal_base = ordinal_base;

    // Named exports: names[i] is the export name string, and via the number-ordinal
    // array an index into the function RVA array.
    for i in 0..n_names {
        let Some(name_rva) = read_u32(img, elem_rva(addr_names, i, 4)) else {
            break;
        };
        let Some(ord_idx) = read_u16(img, elem_rva(addr_ordinals, i, 2)) else {
            break;
        };
        let Some(func_rva) = read_u32(img, elem_rva(addr_functions, ord_idx as u32, 4)) else {
            break;
        };
        let Some(name) = read_bytes_nul(img, name_rva) else {
            break;
        };
        out.names.insert(name, func_rva);
    }

    // All function RVAs (indexed by `ordinal - ordinal_base`) for ordinal lookups.
    out.function_rvas = (0..n_functions)
        .filter_map(|i| read_u32(img, elem_rva(addr_functions, i, 4)))
        .collect();
    out
}

/// Address of element `index` (each `elem_size` bytes) in the array at `array_rva`,
/// saturating against overflow so corrupt directory data cannot wrap addresses.
fn elem_rva(array_rva: u32, index: u32, elem_size: u32) -> u32 {
    array_rva.saturating_add(index.saturating_mul(elem_size))
}

/// Locate the export data directory by parsing the mapped image's DOS/PE headers.
fn locate_export_dir(img: &MappedImage) -> Option<ExportDirSpan> {
    let magic_dos = read_u16(img, 0)?;
    if magic_dos != 0x5A4D {
        return None; // not "MZ"
    }
    let e_lfanew = read_u32(img, 0x3C)?;
    let coff = e_lfanew.checked_add(4)?; // past "PE\0\0"
    let opt = coff.checked_add(20)?; // COFF header is 20 bytes
    match read_u16(img, opt)? {
        // PE32+ (magic 0x20B): data directories start at optional header + 112.
        0x20B => read_export_dir_at(img, opt.checked_add(112)?),
        // PE32 (magic 0x10B): data directories start at optional header + 96.
        0x10B => read_export_dir_at(img, opt.checked_add(96)?),
        _ => None,
    }
}

/// Read the export directory entry (data directory 0) at `dd_offset`.
fn read_export_dir_at(img: &MappedImage, dd_offset: u32) -> Option<ExportDirSpan> {
    let rva = read_u32(img, dd_offset)?;
    let size = read_u32(img, dd_offset.checked_add(4)?)?;
    if rva == 0 {
        return None; // no export directory
    }
    Some(ExportDirSpan { rva, size })
}

// ---------------------------------------------------------------------------
// Bounds-checked readers over the mapped image
// ---------------------------------------------------------------------------

/// Read a `u16` at RVA `rva` from the mapped image (`None` when out of bounds).
fn read_u16(img: &MappedImage, rva: u32) -> Option<u16> {
    let p = img.rva_to_ptr(rva)? as *const u16;
    // SAFETY: `p` is within the mapped image (checked by `rva_to_ptr`); the read may be
    // unaligned relative to a `u16`, so we use read_unaligned.
    Some(unsafe { std::ptr::read_unaligned(p) })
}

/// Read a `u32` at RVA `rva` from the mapped image (`None` when out of bounds).
fn read_u32(img: &MappedImage, rva: u32) -> Option<u32> {
    let p = img.rva_to_ptr(rva)? as *const u32;
    // SAFETY: `p` is within the mapped image (checked by `rva_to_ptr`); the read may be
    // unaligned relative to `u32`, so read_unaligned is used.
    Some(unsafe { std::ptr::read_unaligned(p) })
}

/// Read a NUL-terminated byte string at RVA `rva` (up to [`MAX_NAME_LEN`] bytes).
fn read_bytes_nul(img: &MappedImage, rva: u32) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = rva;
    for _ in 0..MAX_NAME_LEN {
        // Bounds-checked: each byte must still be inside the mapped image.
        let p = img.rva_to_ptr(off)?;
        // SAFETY: `p` is within the mapped image (checked above). We stop at NUL or at
        // the image end.
        let b = unsafe { *p };
        if b == 0 {
            return Some(out);
        }
        out.push(b);
        // The next byte is at most `img.size` bytes further; rva_to_ptr bounds-checks.
        off = off.checked_add(1)?;
    }
    None
}

/// Read a NUL-terminated string from a raw guest pointer (the `GetProcAddress` name
/// argument), capped at [`MAX_NAME_LEN`] bytes. `None` only when the pointer is NULL.
fn read_guest_cstring(name: *const u8) -> Option<Vec<u8>> {
    if name.is_null() {
        return None;
    }
    let mut out = Vec::new();
    // SAFETY: the caller (guest code) guarantees the pointer identifies a NUL-terminated
    // export name in this process's address space (`GetProcAddress` contract); we stop
    // at NUL or after `MAX_NAME_LEN` bytes so a bad pointer only ever reads *up to* the
    // cap rather than looping forever.
    unsafe {
        let mut p = name;
        for _ in 0..MAX_NAME_LEN {
            let b = *p;
            if b == 0 {
                break;
            }
            out.push(b);
            p = p.add(1);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// kernel32 registration bridge
// ---------------------------------------------------------------------------

/// Install the kernel32-side function pointers so the `LoadLibrary*`/`GetProcAddress`/
/// `FreeLibrary` exports in `nigg-win32-kernel32` call back into this module. `kernel32`
/// cannot depend on `nigg-pe-loader` (reverse crate dependency), so the pointers are
/// threaded through `dllload::register`'s `OnceLock`s. Registration is idempotent: the
/// first `set` wins.
pub fn register_kernel32_bridge() {
    nigg_win32_kernel32::dllload::register(load_dll_str_proxy, get_proc_address, free_library);
}

/// Proxy matching `dllload::LoadDllFn`: load by path string with the caller's choice of
/// initialization, logging (not propagating) failures — the Windows `LoadLibrary` API
/// family returns NULL on failure, so the kernel32 side follows that contract.
fn load_dll_str_proxy(path: &str, run_dll_main: bool) -> *mut c_void {
    match load_dll_ex(Path::new(path), run_dll_main) {
        Ok(h) => h,
        Err(e) => {
            log::debug!("LoadLibrary({path}) failed: {e}");
            std::ptr::null_mut()
        }
    }
}
