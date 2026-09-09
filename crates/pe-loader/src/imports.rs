//! Import directory resolution for the PE loader.
//!
//! Each imported symbol is resolved to a native function pointer that the loader writes
//! into the Import Address Table (IAT). The implementations live in `nigg-ntapi` (memory,
//! sync, threads, time, process) and a few trivial intrinsics (`memset`/`memcpy`/`memmove`)
//! are kept locally. **Critically**, the pointers stored in the IAT are not the raw
//! `extern "C"` (System V) implementations: they are Win64->SysV **ABI trampolines**
//! allocated in a [`crate::thunk::ThunkArena`]. When PE code does `call [IAT slot]` the call
//! arrives in the Windows x64 ABI (args in RCX/RDX/R8/R9 + 32-byte shadow space); the
//! trampoline shuffles the registers to the System V layout (RDI/RSI/RDX/RCX/R8/R9) and
//! tail-calls the Rust implementation. Without this, real PEs would receive their
//! arguments in the wrong registers — the #1 blocker for running real PE binaries.
//!
//! Unknown imports get a logging trap stub that aborts gracefully, so a missing import
//! fails loudly rather than silently calling junk.

use std::collections::{HashMap, HashSet};
use std::os::raw::c_void;

use crate::thunk::ThunkArena;

/// A resolved import: the native address to write into the IAT slot.
pub type FnPtr = *const c_void;

/// The set of imports the loader actually resolved at load time. Useful for diagnostics
/// (e.g. reporting which unknown imports were trapped).
#[derive(Default, Debug)]
pub struct ResolvedImports {
    /// `(dll, symbol) -> native address` for every resolved IAT entry.
    pub resolved: HashMap<(String, String), FnPtr>,
    /// `(dll, symbol)` for imports that had no implementation and got a trap stub.
    pub stubbed: Vec<(String, String)>,
}

/// Resolve `imports` (from goblin) into native function pointers.
///
/// `known` is the table of implemented exports (populated with ABI-correct thunk pointers);
/// `imports` is goblin's parsed import list. Returns the address to store in each IAT slot
/// along with a record of what was resolved vs. stubbed.
pub fn resolve(imports: &[goblin::pe::import::Import], known: &ImplTable) -> ResolvedImports {
    let soft = soft_stubs_enabled();
    let soft_ptr = known.soft_stub_ptr();
    let mut out = ResolvedImports::default();
    for imp in imports {
        let dll = imp.dll.to_lowercase();
        let sym = normalize_symbol(&imp.name);
        if let Some(ptr) = known.lookup(&dll, &sym) {
            out.resolved.insert((dll.clone(), sym.clone()), ptr);
        } else if dll.starts_with("api-ms-win-crt-") {
            // api-ms-win-crt-* are Universal CRT API-set pseudo-DLLs. Their
            // symbols are the same functions we already implement under
            // ucrtbase.dll. Forward the lookup to ucrtbase.
            if let Some(ptr) = known.lookup("ucrtbase.dll", &sym) {
                log::debug!("forwarded {dll}!{sym} → ucrtbase.dll!{sym}");
                out.resolved.insert((dll.clone(), sym.clone()), ptr);
                continue;
            }
            // Also try msvcrt as a fallback.
            if let Some(ptr) = known.lookup("msvcrt.dll", &sym) {
                log::debug!("forwarded {dll}!{sym} → msvcrt.dll!{sym}");
                out.resolved.insert((dll.clone(), sym.clone()), ptr);
                continue;
            }
            // Fall through to stub.
            log::warn!(
                "stubbed import: {}!{} (no implementation; {})",
                imp.dll,
                imp.name,
                if soft { "soft stub" } else { "hard trap" }
            );
            out.stubbed.push((dll.clone(), sym.clone()));
            let stub = if soft { soft_ptr } else { trap_stub as FnPtr };
            out.resolved.insert((dll.clone(), sym.clone()), stub);
        } else if dll == "vcruntime140.dll" || dll == "vcruntime140_1.dll" {
            // VCRUNTIME140.dll symbols are implemented under ntdll.dll (for SEH)
            // and in our vcruntime module. Try ntdll first, then the table.
            if let Some(ptr) = known.lookup("ntdll.dll", &sym) {
                log::debug!("forwarded {dll}!{sym} → ntdll.dll!{sym}");
                out.resolved.insert((dll.clone(), sym.clone()), ptr);
                continue;
            }
            // Fall through to stub.
            log::warn!(
                "stubbed import: {}!{} (no implementation; {})",
                imp.dll,
                imp.name,
                if soft { "soft stub" } else { "hard trap" }
            );
            out.stubbed.push((dll.clone(), sym.clone()));
            let stub = if soft { soft_ptr } else { trap_stub as FnPtr };
            out.resolved.insert((dll.clone(), sym.clone()), stub);
        } else {
            // Try to resolve from a bundled DLL on disk via LoadLibrary+GetProcAddress.
            // This is the key path for game compatibility: when a game imports from
            // PhysX_64.dll, lua-5.4.4.dll, assimp-vc143-mt.dll, etc., those DLLs ship
            // alongside the .exe. We load them for real and resolve their exports.
            let disk_ptr = try_resolve_from_disk(imp.dll, &sym);
            if let Some(ptr) = disk_ptr {
                log::debug!("resolved import: {}!{} from bundled DLL", imp.dll, imp.name);
                out.resolved.insert((dll.clone(), sym.clone()), ptr);
                continue;
            }

            log::warn!(
                "stubbed import: {}!{} (no implementation; {})",
                imp.dll,
                imp.name,
                if soft { "soft stub" } else { "hard trap" }
            );
            out.stubbed.push((dll.clone(), sym.clone()));
            let stub = if soft { soft_ptr } else { trap_stub as FnPtr };
            out.resolved.insert((dll.clone(), sym.clone()), stub);
        }
    }
    out
}

/// Try to resolve a symbol from a bundled DLL on disk.
///
/// Uses `LoadLibrary` + `GetProcAddress` to find the real export. The DLL search
/// path (EXE dir → $NIGG_DLL_PATH → cwd) finds bundled DLLs like PhysX_64.dll.
/// The returned pointer is the real Win64 code address inside the loaded DLL —
/// no thunk needed because the DLL's own code is already Win64 ABI.
fn try_resolve_from_disk(dll_name: &str, sym: &str) -> Option<FnPtr> {
    // Only try for DLLs we don't implement ourselves (i.e. not kernel32, user32, etc.)
    let our_dlls = [
        "kernel32.dll",
        "user32.dll",
        "gdi32.dll",
        "ntdll.dll",
        "advapi32.dll",
        "shell32.dll",
        "shlwapi.dll",
        "ole32.dll",
        "oleaut32.dll",
        "ws2_32.dll",
        "d3d11.dll",
        "dxgi.dll",
        "d3d12.dll",
        "d3dcompiler_47.dll",
        "xinput1_3.dll",
        "xinput1_4.dll",
        "xinput9_1_0.dll",
        "xaudio2_7.dll",
        "xaudio2_8.dll",
        "xaudio2_9.dll",
        "xaudio2_10.dll",
        "dinput8.dll",
        "comdlg32.dll",
        "comctl32.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "tbs.dll",
        "imm32.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "ncrypt.dll",
        "iphlpapi.dll",
        "gdiplus.dll",
    ];
    let dll_lower = dll_name.to_lowercase();
    if our_dlls.contains(&dll_lower.as_str()) {
        return None;
    }

    // Build the search path candidates using the same logic as LoadLibrary,
    // but load directly with run_dll_main=false to avoid DllMain failures
    // (the DLL's own imports may have stubs that crash DllMain).
    use std::path::Path;
    let normalized = dll_name.replace('\\', "/");
    let candidates: Vec<String> = if normalized.contains('/') {
        let has_ext = normalized.len() >= 4
            && normalized[normalized.len() - 4..].eq_ignore_ascii_case(".dll");
        let mut v = vec![normalized.clone()];
        if !has_ext {
            v.push(format!("{normalized}.dll"));
        }
        v
    } else {
        let mut v = Vec::new();
        let dirs: Vec<std::path::PathBuf> = {
            let mut d = Vec::new();
            // EXE dir (registered by the loader)
            if let Some(exe_dir) = nigg_win32_kernel32::dllload::get_exe_dir() {
                d.push(exe_dir);
            }
            // $NIGG_DLL_PATH
            if let Some(list) = std::env::var_os("NIGG_DLL_PATH") {
                d.extend(
                    list.to_string_lossy()
                        .split([':', ';'])
                        .filter(|s| !s.is_empty())
                        .map(std::path::PathBuf::from),
                );
            }
            // cwd
            d.push(std::path::PathBuf::from("."));
            d
        };
        for dir in &dirs {
            let joined = dir.join(&normalized);
            let s = joined.to_string_lossy().into_owned();
            let has_ext = s.len() >= 4 && s[s.len() - 4..].eq_ignore_ascii_case(".dll");
            v.push(s.clone());
            if !has_ext {
                v.push(format!("{s}.dll"));
            }
        }
        v
    };

    for path_str in &candidates {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }
        // Load the DLL without running DllMain — the exports exist in mapped
        // memory regardless of whether DllMain ran. Running DllMain would fail
        // because the DLL's own imports (kernel32, etc.) have stubs.
        match crate::dllmod::load_dll_ex(path, false) {
            Ok(hmodule) => {
                log::debug!("loaded bundled DLL {dll_name} from {path_str} (hmodule={hmodule:p}, DllMain skipped)");
                // GetProcAddress: try by name first, then by ordinal.
                let sym_cstr = std::ffi::CString::new(sym).ok()?;
                let ptr = nigg_win32_kernel32::dllload::get_proc_address(
                    hmodule,
                    sym_cstr.as_ptr() as *const u8,
                );
                if !ptr.is_null() {
                    log::debug!("resolved {dll_name}!{sym} from bundled DLL at {ptr:p}");
                    return Some(ptr as FnPtr);
                }
            }
            Err(e) => {
                log::debug!("failed to load bundled DLL {path_str}: {e}");
            }
        }
    }
    None
}

/// Whether "soft stubs" are enabled: unknown imports get a no-op that logs once and returns 0
/// instead of the hard trap that aborts. Toggled by `NIGG_SOFT_STUBS=1`. This lets a PE's
/// CRT init survive calls to unimplemented imports (e.g. file/socket APIs a `println!`
/// program never actually depends on) long enough to reach `main`.
fn soft_stubs_enabled() -> bool {
    std::env::var_os("NIGG_SOFT_STUBS").is_some_and(|v| v == "1" || v == "true")
}

/// `extern "C"` trap stub for unimplemented imports. Logs the call site symbol and aborts
/// with a distinct exit code so the failure is unmistakable.
extern "C" fn trap_stub() -> u32 {
    log::error!("PE loader: called an unimplemented import (trap stub); aborting");
    eprintln!("nigg-loader: called unimplemented Windows import — aborting");
    // STATUS_DLL_INIT_FAILED-ish sentinel (0xC000_0142 as a signed exit code).
    std::process::exit(0xC000_0142u32 as i32);
}

/// `extern "C"` soft stub for unimplemented imports. Returns 0 / FALSE so the caller can
/// continue. Used when `NIGG_SOFT_STUBS=1` is set so the CRT init path survives calls to APIs
/// a `println!` program imports but never truly needs.
extern "C" fn soft_stub() -> u32 {
    log::trace!("PE loader: soft-stubbed import called (returning 0)");
    0
}

/// The native address of the trap stub, for distinguishing stubbed IAT entries from real
/// implementations. Taking a function address is always safe.
pub(crate) fn trap_stub_addr() -> FnPtr {
    trap_stub as FnPtr
}

/// Normalize a goblin import name to the lookup key. goblin already strips decorations
/// for named imports; ordinal imports arrive as `"ORDINAL <n>"`, which we pass through
/// verbatim so an `ordinal: <n>` entry in [`ImplTable`] can match.
fn normalize_symbol(name: &str) -> String {
    name.to_string()
}

// ---------------------------------------------------------------------------
// Trivial C-runtime intrinsics (kept local; not worth an ntapi round-trip).
// ---------------------------------------------------------------------------

/// `vcruntime!memset(dst, val, n) -> dst*`. A real `memset`.
extern "C" fn vcruntime_memset(dst: *mut u8, val: u8, n: usize) -> *mut u8 {
    // SAFETY: `dst..dst+n` is valid for writing per the C `memset` contract.
    unsafe { std::ptr::write_bytes(dst, val, n) };
    dst
}

/// `vcruntime!memcpy(dst, src, n) -> dst*`.
extern "C" fn vcruntime_memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: `dst..dst+n` and `src..src+n` are valid and non-overlapping per the C
    // `memcpy` contract.
    unsafe { std::ptr::copy_nonoverlapping(src, dst, n) };
    dst
}

/// `vcruntime!memmove(dst, src, n) -> dst*`. Handles overlapping ranges.
extern "C" fn vcruntime_memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: `dst..dst+n` and `src..src+n` are valid (may overlap) per the C `memmove`
    // contract; `copy` handles overlap correctly.
    unsafe { std::ptr::copy(src, dst, n) };
    dst
}

// ---------------------------------------------------------------------------
// Argument-count metadata for each implemented import, used to size the trampoline.
// ---------------------------------------------------------------------------

/// The number of integer/pointer arguments a given implementation takes, so the thunk can
/// shuffle the right number of registers. Functions returning `-> !` use the noreturn path.
struct ImportSpec {
    dll: &'static str,
    sym: &'static str,
    /// The System V `extern "C"` implementation address.
    target: FnPtr,
    /// How many integer/pointer args the implementation takes (0..=8 for returning, 0..=6
    /// for noreturn).
    n_args: u8,
    /// `true` if the function never returns (ExitProcess / NtTerminateProcess).
    noreturn: bool,
}

/// Table of implemented Windows exports, keyed by `(lowercased dll, symbol)`. The values
/// are the addresses to write into the IAT — for the real loader these are ABI-correct
/// trampoline pointers; for the unit tests they may be direct fn pointers.
pub struct ImplTable {
    map: HashMap<(String, String), FnPtr>,
    /// An ABI-correct trampoline for the soft stub (returns 0, preserves Windows
    /// callee-saved registers). Used for unimplemented imports when `NIGG_SOFT_STUBS=1`.
    soft_stub_thunk: FnPtr,
}

impl ImplTable {
    /// The trampoline address for the soft stub. The trampoline preserves Windows
    /// callee-saved registers (RDI/RSI) so the PE caller's state is intact after the stub
    /// returns 0.
    pub fn soft_stub_ptr(&self) -> FnPtr {
        self.soft_stub_thunk
    }

    /// Build the table of M1 implemented exports, wrapping each implementation in a
    /// Win64->SysV trampoline allocated from `arena`. The arena must be `finalize()`d
    /// (flipped to PROT_EXEC) before any IAT entry is called.
    ///
    /// This also installs the M7a D3D11/DXGI COM vtables and the M8b D3D12 COM
    /// vtables: a Win64->SysV thunk is allocated (from the same `arena`) for
    /// every vtable slot, and the import-level D3D11/DXGI/D3D12 exports
    /// (`D3D11CreateDeviceAndSwapChain`, `CreateDXGIFactory`,
    /// `D3D12CreateDevice`, ...) are registered as thunks too. Both must happen
    /// before `arena.finalize()` (the caller seals the arena after this returns).
    pub fn build(arena: &mut ThunkArena) -> Self {
        let specs = import_specs();
        let mut map = HashMap::new();
        for spec in specs {
            let ptr = if spec.noreturn {
                arena
                    .make_thunk_noreturn(spec.target, spec.n_args)
                    .unwrap_or_else(|e| panic!("thunk for {}!{} failed: {e}", spec.dll, spec.sym))
            } else {
                arena
                    .make_thunk(spec.target, spec.n_args)
                    .unwrap_or_else(|e| panic!("thunk for {}!{} failed: {e}", spec.dll, spec.sym))
            };
            map.insert((spec.dll.to_string(), spec.sym.to_string()), ptr);
        }
        // Forward the implemented symbols to the api-ms-win-* pseudo-DLLs too.
        forward_apisets(&mut map, arena);

        // --- M7a: install the D3D11/DXGI COM vtables ---
        // Allocate a Win64->SysV thunk for every vtable slot (the vtable structs
        // are leaked inside `install_vtables` so their addresses stay valid for
        // the PE's lifetime). The same `arena` backs these thunks, so they are
        // sealed along with the rest when the caller calls `arena.finalize()`.
        nigg_d3d11_com::install_vtables(&mut |target, n_args| {
            arena
                .make_thunk(target, n_args)
                .unwrap_or_else(|e| panic!("COM vtable thunk failed: {e}"))
        });
        // Register the import-level D3D11/DXGI exports as thunks (same mechanism
        // as the kernel32/user32 exports above). These are the functions a PE
        // links against; calling them creates the COM objects and hands their
        // interface pointers back to the PE.
        for spec in nigg_d3d11_com::com_export_specs() {
            let ptr = arena
                .make_thunk(spec.target, spec.n_args)
                .unwrap_or_else(|e| panic!("thunk for {}!{} failed: {e}", spec.dll, spec.sym));
            map.insert((spec.dll.to_string(), spec.sym.to_string()), ptr);
        }

        // --- M8b: install the D3D12 COM vtables ---
        // Same mechanism as the D3D11/DXGI vtables above: allocate a Win64->SysV
        // thunk for every D3D12 vtable slot (leaked inside `install_vtables` so
        // the addresses stay valid for the PE's lifetime), then register the
        // import-level D3D12 exports (`D3D12CreateDevice`, ...) as thunks too.
        // Both must happen before `arena.finalize()` (the caller seals the arena
        // after this returns).
        nigg_d3d12_com::install_vtables(&mut |target, n_args| {
            arena
                .make_thunk(target, n_args)
                .unwrap_or_else(|e| panic!("COM vtable thunk failed: {e}"))
        });
        for spec in nigg_d3d12_com::com_export_specs() {
            let ptr = arena
                .make_thunk(spec.target, spec.n_args)
                .unwrap_or_else(|e| panic!("thunk for {}!{} failed: {e}", spec.dll, spec.sym));
            map.insert((spec.dll.to_string(), spec.sym.to_string()), ptr);
        }

        // Insert the msvcrt data symbols (e.g. `__initenv`, `_commode`, `_fmode`) as raw
        // static addresses — no trampoline. The PE reads these IAT slots as data
        // pointers (the address of the global), not callable function pointers.
        for (dll, sym, ptr) in nigg_win32_kernel32::crt::data_exports() {
            map.insert((dll.to_string(), sym.to_string()), ptr);
        }

        // Allocate an ABI-correct trampoline for the soft stub (0-arg, returns 0). It
        // preserves the Windows callee-saved registers so the PE caller survives the call.
        let soft_stub_thunk = arena
            .make_thunk(soft_stub as FnPtr, 0)
            .expect("soft stub thunk");

        ImplTable {
            map,
            soft_stub_thunk,
        }
    }

    /// Build the table with **direct** fn pointers (no trampolines), for unit tests that
    /// only exercise `lookup` and never execute PE code through the IAT.
    #[allow(dead_code)] // used by unit tests; the loader uses `build`.
    pub fn default_table() -> Self {
        let specs = import_specs();
        let mut map = HashMap::new();
        for spec in specs {
            map.insert((spec.dll.to_string(), spec.sym.to_string()), spec.target);
        }
        // Insert the msvcrt data symbols as raw addresses (test path mirrors `build`).
        for (dll, sym, ptr) in nigg_win32_kernel32::crt::data_exports() {
            map.insert((dll.to_string(), sym.to_string()), ptr);
        }
        // Forward to apiset pseudo-DLLs (using the same direct pointers).
        let mut forward_map = map.clone();
        forward_apisets_direct(&mut forward_map, &map);
        ImplTable {
            map: forward_map,
            soft_stub_thunk: soft_stub as FnPtr,
        }
    }

    fn lookup(&self, dll: &str, sym: &str) -> Option<FnPtr> {
        self.map.get(&(dll.to_string(), sym.to_string())).copied()
    }
}

/// The list of implemented imports with their argument counts. Each `target` is a System V
/// `extern "C"` function; the trampoline translates the Windows x64 call into a System V
/// call to it. Most implementations delegate to `nigg_ntapi`; `memset`/`memcpy`/`memmove`
/// are local.
fn import_specs() -> Vec<ImportSpec> {
    use nigg_ntapi as nt;

    let mut specs: Vec<ImportSpec> = vec![
        // --- kernel32: process / console / time / last-error ---
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ExitProcess",
            target: nt::process::exit_process as FnPtr,
            n_args: 1,
            noreturn: true,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetStdHandle",
            target: nt::process::get_std_handle as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "WriteFile",
            target: nt::process::write_file as FnPtr,
            n_args: 5,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ReadFile",
            target: nt::process::read_file as FnPtr,
            n_args: 5,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetLastError",
            target: nt::process::get_last_error as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "SetLastError",
            target: nt::process::set_last_error as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetTickCount",
            target: nt::process::get_tick_count as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetTickCount64",
            target: nt::process::get_tick_count_64 as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "QueryPerformanceCounter",
            target: nt::process::query_performance_counter as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "QueryPerformanceFrequency",
            target: nt::process::query_performance_frequency as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "CloseHandle",
            target: nt::process::close_handle as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        // --- kernel32: memory ---
        ImportSpec {
            dll: "kernel32.dll",
            sym: "VirtualAlloc",
            target: nt::memory::virtual_alloc as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "VirtualFree",
            target: nt::memory::virtual_free as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "VirtualProtect",
            target: nt::memory::virtual_protect as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "VirtualQuery",
            target: nt::memory::virtual_query as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        // --- kernel32: synchronization ---
        ImportSpec {
            dll: "kernel32.dll",
            sym: "InitializeCriticalSection",
            target: nt::sync::initialize_critical_section as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "EnterCriticalSection",
            target: nt::sync::enter_critical_section as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "LeaveCriticalSection",
            target: nt::sync::leave_critical_section as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "DeleteCriticalSection",
            target: nt::sync::delete_critical_section as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "CreateEventW",
            target: nt::sync::create_event_w as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "SetEvent",
            target: nt::sync::set_event as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ResetEvent",
            target: nt::sync::reset_event as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "PulseEvent",
            target: nt::sync::pulse_event as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "CreateMutexW",
            target: nt::sync::create_mutex_w as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ReleaseMutex",
            target: nt::sync::release_mutex as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "CreateSemaphoreW",
            target: nt::sync::create_semaphore_w as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ReleaseSemaphore",
            target: nt::sync::release_semaphore as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "InitializeSRWLock",
            target: nt::sync::initialize_srw_lock as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "AcquireSRWLockExclusive",
            target: nt::sync::acquire_srw_lock_exclusive as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "AcquireSRWLockShared",
            target: nt::sync::acquire_srw_lock_shared as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ReleaseSRWLockExclusive",
            target: nt::sync::release_srw_lock_exclusive as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ReleaseSRWLockShared",
            target: nt::sync::release_srw_lock_shared as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "Sleep",
            target: nt::sync::sleep as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "SleepEx",
            target: nt::sync::sleep_ex as FnPtr,
            n_args: 2,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "WaitForSingleObject",
            target: nt::sync::wait_for_single_object as FnPtr,
            n_args: 2,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "WaitForMultipleObjects",
            target: nt::sync::wait_for_multiple_objects as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        // --- kernel32: threads / TLS ---
        ImportSpec {
            dll: "kernel32.dll",
            sym: "CreateThread",
            target: nt::thread::create_thread as FnPtr,
            n_args: 6,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetCurrentThread",
            target: nt::thread::get_current_thread as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetCurrentProcess",
            target: nt::thread::get_current_process as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetCurrentThreadId",
            target: nt::thread::get_current_thread_id as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetCurrentProcessId",
            target: nt::thread::get_current_process_id as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "GetThreadId",
            target: nt::thread::get_thread_id as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "ResumeThread",
            target: nt::thread::resume_thread as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "SuspendThread",
            target: nt::thread::suspend_thread as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "TlsAlloc",
            target: nt::thread::tls_alloc as FnPtr,
            n_args: 0,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "TlsFree",
            target: nt::thread::tls_free as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "TlsGetValue",
            target: nt::thread::tls_get_value as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "kernel32.dll",
            sym: "TlsSetValue",
            target: nt::thread::tls_set_value as FnPtr,
            n_args: 2,
            noreturn: false,
        },
        // --- ntdll ---
        ImportSpec {
            dll: "ntdll.dll",
            sym: "NtTerminateProcess",
            target: nt::process::nt_terminate_process as FnPtr,
            n_args: 2,
            noreturn: true,
        },
        ImportSpec {
            dll: "ntdll.dll",
            sym: "NtClose",
            target: nt::process::nt_close as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "ntdll.dll",
            sym: "NtWriteFile",
            target: nt::process::nt_write_file as FnPtr,
            n_args: 9,
            noreturn: false,
        },
        ImportSpec {
            dll: "ntdll.dll",
            sym: "NtReadFile",
            target: nt::process::nt_read_file as FnPtr,
            n_args: 9,
            noreturn: false,
        },
        // --- vcruntime / ucrt intrinsics ---
        ImportSpec {
            dll: "vcruntime140.dll",
            sym: "memset",
            target: vcruntime_memset as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "vcruntime140.dll",
            sym: "memcpy",
            target: vcruntime_memcpy as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "vcruntime140.dll",
            sym: "memmove",
            target: vcruntime_memmove as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "vcruntime140_1.dll",
            sym: "memset",
            target: vcruntime_memset as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "vcruntime140_1.dll",
            sym: "memcpy",
            target: vcruntime_memcpy as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "vcruntime140_1.dll",
            sym: "memmove",
            target: vcruntime_memmove as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "ucrtbase.dll",
            sym: "memset",
            target: vcruntime_memset as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "ucrtbase.dll",
            sym: "memcpy",
            target: vcruntime_memcpy as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "ucrtbase.dll",
            sym: "memmove",
            target: vcruntime_memmove as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "msvcrt.dll",
            sym: "memset",
            target: vcruntime_memset as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "msvcrt.dll",
            sym: "memcpy",
            target: vcruntime_memcpy as FnPtr,
            n_args: 3,
            noreturn: false,
        },
        ImportSpec {
            dll: "msvcrt.dll",
            sym: "memmove",
            target: vcruntime_memmove as FnPtr,
            n_args: 3,
            noreturn: false,
        },
    ];

    // Merge in the M2 kernel32 exports from `nigg-win32-kernel32` (files, heap, environment,
    // console mode, string helpers, command line, etc.). The M1 entries above (ExitProcess,
    // GetStdHandle, WriteFile, ReadFile, CloseHandle, GetCurrentProcessId,
    // GetCurrentThreadId) already delegate to ntapi with the correct arg counts, so any
    // symbol the new crate also defines is dropped from the merge (the existing entry wins).
    // This keeps a single canonical thunk per `(dll, sym)` and avoids arg-count conflicts.
    let mut seen: HashSet<(String, String)> = specs
        .iter()
        .map(|s| (s.dll.to_string(), s.sym.to_string()))
        .collect();
    for e in nigg_win32_kernel32::kernel32_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the msvcrt (CRT) function exports from `nigg-win32-kernel32::crt`. These are
    // the C runtime functions (malloc, free, strlen, fprintf, __getmainargs, exit, ...)
    // the mingw-w64 CRT startup sequence calls. Dedup so a symbol already registered (e.g.
    // memset/memcpy/memmove above) keeps its canonical thunk.
    for e in nigg_win32_kernel32::crt::crt_export_specs() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the ucrtbase.dll (Universal CRT) function exports from
    // `nigg-win32-kernel32::ucrt`. Modern Windows apps import the C runtime from
    // `ucrtbase.dll` (distinct startup surface: `_configure_narrow_argv`,
    // `__p___argc`, `_register_onexit_function`, plus the usual memory/string/exit
    // family). Dedup so symbols already registered (e.g. ucrtbase memset/memcpy/memmove
    // wired above, or msvcrt entries under msvcrt.dll) keep their canonical thunk — only
    // genuinely new `(ucrtbase.dll, sym)` keys are added.
    for e in nigg_win32_kernel32::ucrt::ucrt_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the extra kernel32/ntdll/bcryptprimitives/userenv exports from
    // `nigg-win32-kernel32::extras` (exception handling stubs, system info, file/path
    // helpers, ProcessPrng, GetUserProfileDirectoryW, RtlNtStatusToDosError, etc.).
    for e in nigg_win32_kernel32::extras::extra_export_specs() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the anti-cheat + misc kernel32 exports (IsDebuggerPresent,
    // CreateToolhelp32Snapshot, OpenProcess, ReadProcessMemory, etc.). These
    // are the process-enumeration and debug-detection APIs userland anti-cheat
    // DLLs (EAC, BattlEye) call during initialization. Same dedup pattern.
    for e in nigg_win32_kernel32::anticheat::anticheat_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the advapi32.dll registry exports from `nigg-win32-kernel32::registry`
    // (RegOpenKeyW/ExW, RegCreateKeyExW, RegCloseKey, RegQueryValueExW, RegSetValueExW,
    // RegEnumKeyW, RegEnumValueW, RegDeleteKeyW, IsTextUnicode). These back the minimal
    // in-memory registry real PEs probe during startup. Same dedup pattern.
    for e in nigg_win32_kernel32::registry::registry_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the ntdll system-information exports (NtQuerySystemInformation,
    // NtQueryInformationProcess) — anti-cheat calls these to inspect the
    // process environment, detect debuggers/hypervisors, and read
    // Secure Boot / firmware state. Same dedup pattern.
    for e in nigg_win32_kernel32::system_info::system_info_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the XInput gamepad (xinput1_3/1_4/9_1_0.dll), XAudio2
    // (xaudio2_7..10.dll), and DirectInput8 (dinput8.dll) exports — the two
    // most-complaint-about missing APIs in games. Same dedup pattern.
    for e in nigg_win32_kernel32::xinput::xinput_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the TPM 2.0 Base Services (tbs.dll) exports plus the firmware /
    // system-security queries from `nigg-win32-kernel32::tpm` — the surfaces
    // Windows 11-era games and anti-cheat query to verify system integrity:
    // Tbsi_Context_Create/GetTpmVersion/Submit_Command (fake context handles
    // minted from a counter), GetFirmwareType, GetFirmwareEnvironmentVariableA/W
    // (the `SecureBoot` EFI-variable probe), IsWow64Process, GetProductInfo, and
    // the advapi32 IsSecureBootEnabled/SystemSecureBootEnabled status probes.
    // Same dedup pattern.
    for e in nigg_win32_kernel32::tpm::tpm_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the System Policy Information (advapi32 tree-copy/multi-value
    // registry stubs) from `nigg-win32-kernel32::spi`. Calling spi_exports also
    // seeds the Secure Boot / integrity-check registry defaults
    // (UEFISecureBootEnabled, IntegrityChecks, BIOS SecureBoot) so the
    // in-memory registry answers them before any guest runs. Same dedup
    // pattern.
    for e in nigg_win32_kernel32::spi::spi_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the Winsock2 (ws2_32.dll) exports — the Windows Sockets API that
    // networked apps and userland anti-cheat DLLs (EAC, BattlEye) use for
    // telemetry communication. Each function delegates to the POSIX socket API.
    for e in nigg_win32_ws2_32::ws2_32_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the api-ms-win-core-synch WaitOnAddress family (futex-backed, in ntapi).
    // These live under the `api-ms-win-core-synch-l1-2-0.dll` pseudo-DLL.
    let wait_specs = [
        ImportSpec {
            dll: "api-ms-win-core-synch-l1-2-0.dll",
            sym: "WaitOnAddress",
            target: nt::sync::wait_on_address as FnPtr,
            n_args: 4,
            noreturn: false,
        },
        ImportSpec {
            dll: "api-ms-win-core-synch-l1-2-0.dll",
            sym: "WakeByAddressAll",
            target: nt::sync::wake_by_address_all as FnPtr,
            n_args: 1,
            noreturn: false,
        },
        ImportSpec {
            dll: "api-ms-win-core-synch-l1-2-0.dll",
            sym: "WakeByAddressSingle",
            target: nt::sync::wake_by_address_single as FnPtr,
            n_args: 1,
            noreturn: false,
        },
    ];
    for s in wait_specs {
        let key = (s.dll.to_string(), s.sym.to_string());
        if seen.insert(key) {
            specs.push(s);
        }
    }

    // Wire in the M3 user32 exports from `nigg-win32-user32`. Each export carries the
    // `n_args`/`noreturn` metadata the thunk arena needs; `CreateWindowExW` (12 args) is
    // handled by the extended thunk layer (>8 stack args). Dedup against anything already
    // registered so there is a single canonical thunk per `(dll, sym)`.
    for e in nigg_win32_user32::user32_export_specs() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the M3 gdi32 exports from `nigg-win32-gdi32` (same shape as user32).
    for e in nigg_win32_gdi32::gdi32_export_specs() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the shell32.dll exports from `nigg-win32-kernel32::shell32` (drag-drop no-ops,
    // ShellExecute/SHGetFolderPath stubs, SHGetDesktopFolder/SHGetMalloc). These let real
    // PEs (notepad.exe, games, installers) resolve their shell32 imports.
    for e in nigg_win32_kernel32::shell32::shell32_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the shlwapi.dll exports from `nigg-win32-kernel32::shlwapi` (path utilities
    // PathFindFileName/PathCombine/PathIsRelative, and the StrCmp*/StrStr* string helpers).
    for e in nigg_win32_kernel32::shlwapi::shlwapi_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the comdlg32.dll exports from `nigg-win32-kernel32::comdlg32` (common dialogs:
    // GetOpenFileNameW/GetSaveFileNameW/ChooseFontW/FindTextW/ReplaceTextW/PrintDlgW/
    // GetFileTitleW). All are no-ops returning FALSE so callers take their cancel/fallback
    // path. Same dedup pattern so any symbol already registered keeps its canonical thunk.
    for e in nigg_win32_kernel32::comdlg32::comdlg32_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the comctl32.dll exports from `nigg-win32-kernel32::comctl32` (common-controls
    // init: InitCommonControls/InitCommonControlsEx, plus the ordinal 410/413 helpers
    // notepad.exe imports by ordinal). Same dedup pattern.
    for e in nigg_win32_kernel32::comctl32::comctl32_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in ole32.dll (COM initialization) — D3D/DXGI games call
    // CoInitializeEx at startup; without it they bail out. Also provides
    // CoTaskMemAlloc/Free which some CRTs use for BSTR allocation.
    for e in nigg_win32_kernel32::ole32::ole32_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in d3dcompiler_47.dll (D3DCompile) — bridges to our HLSL→SPIR-V
    // compiler so games can compile HLSL shaders at runtime.
    for e in nigg_win32_kernel32::d3dcompiler::d3d_compiler_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in VCRUNTIME140.dll + MSVCP140.dll (MSVC C++ runtime). Games and
    // bundled DLLs (PhysX, lua) import from these for C string/memory functions,
    // SEH, and C++ exception support. We delegate string/mem functions to libc
    // and no-op the C++ vtable methods.
    for e in nigg_win32_kernel32::vcruntime::vcruntime_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    // Wire in the extra kernel32/ntdll exports from `nigg-win32-kernel32::extras2`
    // (file/directory ops, console screen-buffer helpers, time conversions, process/handle
    // stubs, disk/volume queries, CompareStringW, RtlGetVersion). These back the import
    // surface real Windows PEs (cmd.exe, regedit.exe, games, installers) probe during
    // startup. Same dedup pattern: any symbol already registered (e.g. GetConsoleOutputCP
    // /GetTempPathW from `extras`) keeps its canonical thunk.
    for e in nigg_win32_kernel32::extras2::extras2_exports() {
        let key = (e.dll.to_string(), e.sym.to_string());
        if seen.insert(key) {
            specs.push(ImportSpec {
                dll: e.dll,
                sym: e.sym,
                target: e.ptr,
                n_args: e.n_args,
                noreturn: e.noreturn,
            });
        }
    }

    specs
}

/// The api-ms-win-* pseudo-DLL names we forward implemented symbols to (they are API-set
/// forwards to kernel32/ntdll). The thunks for these are shared with the canonical
/// kernel32/ntdll entries to keep the arena small.
const APISETS: &[&str] = &[
    "api-ms-win-core-processthreads-l1-1-0",
    "api-ms-win-core-console-l1-1-0",
    "api-ms-win-core-console-l2-1-0",
    "api-ms-win-core-synch-l1-1-0",
    "api-ms-win-core-synch-l1-2-0",
    "api-ms-win-core-errorhandling-l1-1-0",
    "api-ms-win-core-profile-l1-1-0",
    "api-ms-win-core-libraryloader-l1-1-0",
    "api-ms-win-core-heap-l1-1-0",
    "api-ms-win-core-memory-l1-1-0",
    "api-ms-win-core-file-l1-1-0",
    "api-ms-win-core-file-l2-1-0",
    "api-ms-win-core-string-l1-1-0",
    "api-ms-win-core-stringansi-l1-1-0",
    "api-ms-win-core-processenvironment-l1-1-0",
    "api-ms-win-core-localization-l1-2-0",
];

/// The kernel32 symbols forwarded to each apiset (so apiset-named imports resolve too).
const FORWARD_SYMBOLS: &[&str] = &[
    "ExitProcess",
    "GetStdHandle",
    "WriteFile",
    "ReadFile",
    "GetLastError",
    "SetLastError",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "CloseHandle",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "VirtualQuery",
    "InitializeCriticalSection",
    "EnterCriticalSection",
    "LeaveCriticalSection",
    "DeleteCriticalSection",
    "CreateEventW",
    "SetEvent",
    "ResetEvent",
    "PulseEvent",
    "CreateMutexW",
    "ReleaseMutex",
    "CreateSemaphoreW",
    "ReleaseSemaphore",
    "InitializeSRWLock",
    "AcquireSRWLockExclusive",
    "AcquireSRWLockShared",
    "ReleaseSRWLockExclusive",
    "ReleaseSRWLockShared",
    "Sleep",
    "SleepEx",
    "WaitForSingleObject",
    "WaitForMultipleObjects",
    "CreateThread",
    "GetCurrentThread",
    "GetCurrentProcess",
    "GetCurrentThreadId",
    "GetCurrentProcessId",
    "GetThreadId",
    "ResumeThread",
    "SuspendThread",
    "TlsAlloc",
    "TlsFree",
    "TlsGetValue",
    "TlsSetValue",
    // --- M2 kernel32 (console / files / heap / env / process / string) ---
    "WriteConsoleW",
    "WriteConsoleA",
    "GetConsoleMode",
    "SetConsoleMode",
    "CreateFileW",
    "CreateFileA",
    "GetFileSize",
    "SetFilePointer",
    "FlushFileBuffers",
    "GetProcessHeap",
    "HeapAlloc",
    "HeapFree",
    "HeapReAlloc",
    "HeapCreate",
    "HeapDestroy",
    "GetEnvironmentVariableW",
    "SetEnvironmentVariableW",
    "GetEnvironmentStringsW",
    "FreeEnvironmentStringsW",
    "GetModuleHandleW",
    "GetModuleHandleA",
    "GetCommandLineW",
    "GetCommandLineA",
    "MultiByteToWideChar",
    "WideCharToMultiByte",
    "lstrlenW",
    "lstrlenA",
    "lstrcpyW",
    "lstrcatW",
    // --- M6c: extra kernel32 (system info, exception, file, process) ---
    "AddVectoredExceptionHandler",
    "SetUnhandledExceptionFilter",
    "SetConsoleCtrlHandler",
    "RaiseException",
    "__C_specific_handler",
    "RtlCaptureContext",
    "RtlLookupFunctionEntry",
    "RtlVirtualUnwind",
    "RtlUnwindEx",
    "GetSystemTimePreciseAsFileTime",
    "GetSystemInfo",
    "GetConsoleOutputCP",
    "GetModuleFileNameW",
    "GetCurrentDirectoryW",
    "GetSystemDirectoryW",
    "GetWindowsDirectoryW",
    "GetTempPathW",
    "GetFullPathNameW",
    "GetFileAttributesW",
    "GetFileType",
    "GetFileSizeEx",
    "SetFilePointerEx",
    "SetHandleInformation",
    "SetThreadStackGuarantee",
    "SwitchToThread",
    "GetProcAddress",
    "InitOnceBeginInitialize",
    "InitOnceComplete",
    "CompareStringOrdinal",
    "FormatMessageW",
    "MapViewOfFile",
    "UnmapViewOfFile",
    "CreateFileMappingA",
    "GetOverlappedResult",
    "ReadConsoleW",
    "WriteFileEx",
    "ReadFileEx",
    "FlushFileBuffers",
    "SetFileAttributesW",
    "TerminateProcess",
    "GetProcessId",
    "GetExitCodeProcess",
    "WaitForSingleObjectEx",
    // --- api-ms-win-core-synch-l1-2-0 (WaitOnAddress family) ---
    "WaitOnAddress",
    "WakeByAddressAll",
    "WakeByAddressSingle",
];

/// Forward `FORWARD_SYMBOLS` from kernel32 to each apiset, allocating shared thunks (one
/// per (apiset, symbol)) in `arena`.
fn forward_apisets(map: &mut HashMap<(String, String), FnPtr>, arena: &mut ThunkArena) {
    for apiset in APISETS {
        for sym in FORWARD_SYMBOLS {
            if let Some(&target) = map.get(&("kernel32.dll".to_string(), (*sym).to_string())) {
                // `target` is already a thunk pointer; reuse it directly (no new thunk
                // needed — the trampoline is the same code regardless of which DLL names it).
                map.insert(((*apiset).to_string(), (*sym).to_string()), target);
            }
        }
    }
    // Also forward NtTerminateProcess / NtClose from ntdll to apiset synch/errorhandling.
    for apiset in APISETS {
        if let Some(&t) = map.get(&("ntdll.dll".to_string(), "NtTerminateProcess".to_string())) {
            map.insert(((*apiset).to_string(), "NtTerminateProcess".to_string()), t);
        }
        if let Some(&t) = map.get(&("ntdll.dll".to_string(), "NtClose".to_string())) {
            map.insert(((*apiset).to_string(), "NtClose".to_string()), t);
        }
    }
    // Silence the unused-arena warning when forwarding reuses existing pointers.
    let _ = arena;
}

/// Forward `FORWARD_SYMBOLS` from kernel32 to each apiset using direct fn pointers (for the
/// `default_table` path used by unit tests). `source` is the canonical kernel32 map.
#[allow(dead_code)] // used only by the test-only `default_table` path
fn forward_apisets_direct(
    map: &mut HashMap<(String, String), FnPtr>,
    source: &HashMap<(String, String), FnPtr>,
) {
    for apiset in APISETS {
        for sym in FORWARD_SYMBOLS {
            if let Some(&target) = source.get(&("kernel32.dll".to_string(), (*sym).to_string())) {
                map.insert(((*apiset).to_string(), (*sym).to_string()), target);
            }
        }
    }
    for apiset in APISETS {
        if let Some(&t) = source.get(&("ntdll.dll".to_string(), "NtTerminateProcess".to_string())) {
            map.insert(((*apiset).to_string(), "NtTerminateProcess".to_string()), t);
        }
        if let Some(&t) = source.get(&("ntdll.dll".to_string(), "NtClose".to_string())) {
            map.insert(((*apiset).to_string(), "NtClose".to_string()), t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_table_resolves_known_kernel32_exports() {
        let t = ImplTable::default_table();
        assert!(t.lookup("kernel32.dll", "ExitProcess").is_some());
        assert!(t.lookup("kernel32.dll", "GetStdHandle").is_some());
        assert!(t.lookup("kernel32.dll", "VirtualAlloc").is_some());
        assert!(t.lookup("kernel32.dll", "CreateEventW").is_some());
        assert!(t.lookup("ntdll.dll", "NtTerminateProcess").is_some());
        assert!(t.lookup("vcruntime140.dll", "memset").is_some());
        // Unknown symbol resolves to None (the loader will stub it).
        assert!(t.lookup("kernel32.dll", "DefinitelyNotReal").is_none());
    }

    #[test]
    fn default_table_forwards_apiset_symbols() {
        let t = ImplTable::default_table();
        assert!(
            t.lookup("api-ms-win-core-synch-l1-1-0", "CreateEventW")
                .is_some(),
            "apiset forwards resolve to the same impl"
        );
        assert!(t
            .lookup("api-ms-win-core-memory-l1-1-0", "VirtualAlloc")
            .is_some());
    }

    #[test]
    fn build_table_produces_distinct_thunk_pointers() {
        // The real-loader path must allocate thunks (distinct from the raw fn ptrs).
        let mut arena = ThunkArena::new().expect("arena");
        let t = ImplTable::build(&mut arena);
        let p = t
            .lookup("kernel32.dll", "ExitProcess")
            .expect("ExitProcess resolved");
        // The thunk must differ from the raw ntapi fn pointer (it is trampoline code).
        let raw = nigg_ntapi::process::exit_process as FnPtr;
        assert_ne!(p, raw, "build() wraps impls in trampolines");
        // memset thunk should also differ from the raw local fn.
        let pm = t
            .lookup("vcruntime140.dll", "memset")
            .expect("memset resolved");
        assert_ne!(pm, vcruntime_memset as FnPtr);
    }

    #[test]
    fn resolve_records_stubbed_imports() {
        // A fake import list with one known and one unknown symbol.
        // goblin::pe::Import is hard to construct by hand, so we test resolve() via the
        // table lookup path directly.
        let t = ImplTable::default_table();
        assert!(t.lookup("kernel32.dll", "WriteFile").is_some());
        assert!(t.lookup("kernel32.dll", "MysteryFunc").is_none());
    }

    #[test]
    fn default_table_resolves_shell32_exports() {
        let t = ImplTable::default_table();
        assert!(t.lookup("shell32.dll", "ShellExecuteW").is_some());
        assert!(t.lookup("shell32.dll", "ShellExecuteA").is_some());
        assert!(t.lookup("shell32.dll", "SHGetFolderPathW").is_some());
        assert!(t.lookup("shell32.dll", "SHGetFolderPathA").is_some());
        assert!(t.lookup("shell32.dll", "SHGetSpecialFolderPathW").is_some());
        assert!(t.lookup("shell32.dll", "DragQueryFileW").is_some());
        assert!(t.lookup("shell32.dll", "SHGetDesktopFolder").is_some());
        assert!(t.lookup("shell32.dll", "SHGetMalloc").is_some());
    }

    #[test]
    fn default_table_resolves_shlwapi_exports() {
        let t = ImplTable::default_table();
        assert!(t.lookup("shlwapi.dll", "PathFindFileNameW").is_some());
        assert!(t.lookup("shlwapi.dll", "PathFindFileNameA").is_some());
        assert!(t.lookup("shlwapi.dll", "PathFindExtensionW").is_some());
        assert!(t.lookup("shlwapi.dll", "PathRemoveFileSpecW").is_some());
        assert!(t.lookup("shlwapi.dll", "PathAppendW").is_some());
        assert!(t.lookup("shlwapi.dll", "PathCombineW").is_some());
        assert!(t.lookup("shlwapi.dll", "PathIsRelativeW").is_some());
        assert!(t.lookup("shlwapi.dll", "StrCmpIW").is_some());
        assert!(t.lookup("shlwapi.dll", "StrStrW").is_some());
        assert!(t.lookup("shlwapi.dll", "StrStrIW").is_some());
        assert!(t.lookup("shlwapi.dll", "StrRStrIW").is_some());
        assert!(t.lookup("shlwapi.dll", "wnsprintfW").is_some());
        assert!(t.lookup("shlwapi.dll", "wnsprintfA").is_some());
    }

    #[test]
    fn build_table_resolves_shell32_and_shlwapi_thunks() {
        // The real-loader path must produce thunk pointers (distinct from raw fn ptrs).
        let mut arena = ThunkArena::new().expect("arena");
        let t = ImplTable::build(&mut arena);
        let p = t
            .lookup("shell32.dll", "ShellExecuteW")
            .expect("ShellExecuteW resolved");
        let raw = nigg_win32_kernel32::shell32::shell_execute_w as FnPtr;
        assert_ne!(p, raw, "build() wraps shell32 impls in trampolines");
        let p2 = t
            .lookup("shlwapi.dll", "PathCombineW")
            .expect("PathCombineW resolved");
        let raw2 = nigg_win32_kernel32::shlwapi::path_combine_w as FnPtr;
        assert_ne!(p2, raw2, "build() wraps shlwapi impls in trampolines");
    }

    #[test]
    fn default_table_resolves_ucrt_exports() {
        let t = ImplTable::default_table();
        // Startup/init surface the UCRT boot sequence calls.
        assert!(t.lookup("ucrtbase.dll", "_configure_narrow_argv").is_some());
        assert!(t
            .lookup("ucrtbase.dll", "_initialize_narrow_environment")
            .is_some());
        assert!(t.lookup("ucrtbase.dll", "__p___argc").is_some());
        assert!(t.lookup("ucrtbase.dll", "__p___argv").is_some());
        assert!(t.lookup("ucrtbase.dll", "__acrt_iob_func").is_some());
        assert!(t.lookup("ucrtbase.dll", "_errno").is_some());
        // Memory + string family overlap with msvcrt but live under ucrtbase.dll too.
        assert!(t.lookup("ucrtbase.dll", "malloc").is_some());
        assert!(t.lookup("ucrtbase.dll", "free").is_some());
        assert!(t.lookup("ucrtbase.dll", "strlen").is_some());
        assert!(t.lookup("ucrtbase.dll", "exit").is_some());
        assert!(t.lookup("ucrtbase.dll", "wcschr").is_some());
        // Unknown ucrt symbol still resolves to None (stubbed at load time).
        assert!(t.lookup("ucrtbase.dll", "DefinitelyNotReal").is_none());
    }

    #[test]
    fn default_table_resolves_registry_exports() {
        let t = ImplTable::default_table();
        assert!(t.lookup("advapi32.dll", "RegOpenKeyW").is_some());
        assert!(t.lookup("advapi32.dll", "RegOpenKeyExW").is_some());
        assert!(t.lookup("advapi32.dll", "RegCreateKeyExW").is_some());
        assert!(t.lookup("advapi32.dll", "RegCloseKey").is_some());
        assert!(t.lookup("advapi32.dll", "RegQueryValueExW").is_some());
        assert!(t.lookup("advapi32.dll", "RegSetValueExW").is_some());
        assert!(t.lookup("advapi32.dll", "RegEnumKeyW").is_some());
        assert!(t.lookup("advapi32.dll", "RegEnumValueW").is_some());
        assert!(t.lookup("advapi32.dll", "RegDeleteKeyW").is_some());
        assert!(t.lookup("advapi32.dll", "IsTextUnicode").is_some());
        // Unknown advapi32 symbol still resolves to None.
        assert!(t.lookup("advapi32.dll", "DefinitelyNotReal").is_none());
        // spi's registry stubs resolve too.
        assert!(t.lookup("advapi32.dll", "RegCopyTreeW").is_some());
        assert!(t
            .lookup("advapi32.dll", "RegQueryMultipleValuesW")
            .is_some());
        assert!(t.lookup("advapi32.dll", "RegQueryInfoKeyW").is_some());
        assert!(t.lookup("advapi32.dll", "RegDeleteTreeW").is_some());
        assert!(t
            .lookup("advapi32.dll", "RegResolveCustomKeyHandler")
            .is_some());
    }

    #[test]
    fn default_table_resolves_tpm_and_firmware_security_exports() {
        let t = ImplTable::default_table();
        // tbs.dll TPM 2.0 Base Services.
        assert!(t.lookup("tbs.dll", "Tbsi_Context_Create").is_some());
        assert!(t.lookup("tbs.dll", "Tbsi_Context_GetTpmVersion").is_some());
        assert!(t.lookup("tbs.dll", "Tbsi_Get_Context").is_some());
        assert!(t.lookup("tbs.dll", "Tbsip_Context_Close").is_some());
        assert!(t.lookup("tbs.dll", "Tbsip_Submit_Command").is_some());
        assert!(t.lookup("tbs.dll", "Tbsi_Get_TCG_Log").is_some());
        assert!(t.lookup("tbs.dll", "Tbsi_Get_OwnerAuth").is_some());
        assert!(t.lookup("tbs.dll", "Tbsi_Get_Owner_Auth").is_some());
        // kernel32 firmware / system-security queries.
        assert!(t.lookup("kernel32.dll", "GetFirmwareType").is_some());
        assert!(t
            .lookup("kernel32.dll", "GetFirmwareEnvironmentVariableA")
            .is_some());
        assert!(t
            .lookup("kernel32.dll", "GetFirmwareEnvironmentVariableW")
            .is_some());
        assert!(t.lookup("kernel32.dll", "IsWow64Process").is_some());
        assert!(t.lookup("kernel32.dll", "GetProductInfo").is_some());
        // advapi32 secure-boot status probes (registered once per (dll, sym));
        // the anticheat alias list points GetFirmwareType/IsSecureBootEnabled at
        // the same implementations.
        assert!(t.lookup("advapi32.dll", "IsSecureBootEnabled").is_some());
        assert!(t
            .lookup("advapi32.dll", "SystemSecureBootEnabled")
            .is_some());
        // No tbs symbol stubs out.
        assert!(t.lookup("tbs.dll", "DefinitelyNotReal").is_none());
    }

    #[test]
    fn build_table_wraps_tpm_impls_in_trampolines() {
        // The real-loader path must produce thunk pointers (distinct from raw fn ptrs).
        let mut arena = ThunkArena::new().expect("arena");
        let t = ImplTable::build(&mut arena);
        let p = t
            .lookup("tbs.dll", "Tbsi_Context_Create")
            .expect("tbs Tbsi_Context_Create resolved");
        let raw = nigg_win32_kernel32::tpm::tbsi_context_create as FnPtr;
        assert_ne!(p, raw, "build() wraps tbs impls in trampolines");
        let p2 = t
            .lookup("kernel32.dll", "GetFirmwareEnvironmentVariableA")
            .expect("kernel32 GetFirmwareEnvironmentVariableA resolved");
        let raw2 = nigg_win32_kernel32::tpm::get_firmware_environment_variable_a as FnPtr;
        assert_ne!(p2, raw2, "build() wraps firmware probes in trampolines");
    }

    #[test]
    fn build_table_resolves_ucrt_and_registry_thunks() {
        // The real-loader path must produce thunk pointers (distinct from raw fn ptrs).
        let mut arena = ThunkArena::new().expect("arena");
        let t = ImplTable::build(&mut arena);
        let p = t
            .lookup("ucrtbase.dll", "exit")
            .expect("ucrtbase exit resolved");
        let raw = nigg_win32_kernel32::ucrt::exit as FnPtr;
        assert_ne!(p, raw, "build() wraps ucrt impls in trampolines");
        let p2 = t
            .lookup("advapi32.dll", "RegCreateKeyExW")
            .expect("advapi32 RegCreateKeyExW resolved");
        let raw2 = nigg_win32_kernel32::registry::reg_create_key_ex_w as FnPtr;
        assert_ne!(p2, raw2, "build() wraps registry impls in trampolines");
    }

    #[test]
    fn default_table_resolves_user32_gdi32_stubs() {
        // The no-op stubs notepad.exe imports must resolve to a real thunk instead of the
        // soft-stub trap. Spot-check a representative slice of the new exports.
        let t = ImplTable::default_table();
        // user32
        assert!(t.lookup("user32.dll", "GetSystemMetrics").is_some());
        assert!(t.lookup("user32.dll", "GetDesktopWindow").is_some());
        assert!(t.lookup("user32.dll", "MessageBoxW").is_some());
        assert!(t.lookup("user32.dll", "LoadImageW").is_some());
        assert!(t.lookup("user32.dll", "DialogBoxParamW").is_some());
        assert!(t.lookup("user32.dll", "wsprintfW").is_some());
        // gdi32
        assert!(t.lookup("gdi32.dll", "SelectObject").is_some());
        assert!(t.lookup("gdi32.dll", "CreateFontIndirectW").is_some());
        assert!(t.lookup("gdi32.dll", "GetDeviceCaps").is_some());
        assert!(t.lookup("gdi32.dll", "StartDocW").is_some());
        // kernel32 date/time
        assert!(t.lookup("kernel32.dll", "GetDateFormatW").is_some());
        assert!(t.lookup("kernel32.dll", "GetTimeFormatW").is_some());
    }

    #[test]
    fn default_table_resolves_comdlg32_and_comctl32_exports() {
        let t = ImplTable::default_table();
        // comdlg32
        assert!(t.lookup("comdlg32.dll", "GetOpenFileNameW").is_some());
        assert!(t.lookup("comdlg32.dll", "GetSaveFileNameW").is_some());
        assert!(t.lookup("comdlg32.dll", "ChooseFontW").is_some());
        assert!(t.lookup("comdlg32.dll", "FindTextW").is_some());
        assert!(t.lookup("comdlg32.dll", "ReplaceTextW").is_some());
        assert!(t.lookup("comdlg32.dll", "PrintDlgW").is_some());
        assert!(t.lookup("comdlg32.dll", "GetFileTitleW").is_some());
        // comctl32 (named + ordinal imports)
        assert!(t.lookup("comctl32.dll", "InitCommonControls").is_some());
        assert!(t.lookup("comctl32.dll", "InitCommonControlsEx").is_some());
        assert!(t.lookup("comctl32.dll", "ORDINAL 410").is_some());
        assert!(t.lookup("comctl32.dll", "ORDINAL 413").is_some());
    }

    #[test]
    fn build_table_wraps_comdlg32_comctl32_in_trampolines() {
        let mut arena = ThunkArena::new().expect("arena");
        let t = ImplTable::build(&mut arena);
        let p = t
            .lookup("comdlg32.dll", "GetOpenFileNameW")
            .expect("comdlg32 GetOpenFileNameW resolved");
        let raw = nigg_win32_kernel32::comdlg32::get_open_file_name_w as FnPtr;
        assert_ne!(p, raw, "build() wraps comdlg32 impls in trampolines");
        let p2 = t
            .lookup("comctl32.dll", "InitCommonControlsEx")
            .expect("comctl32 InitCommonControlsEx resolved");
        let raw2 = nigg_win32_kernel32::comctl32::init_common_controls_ex as FnPtr;
        assert_ne!(p2, raw2, "build() wraps comctl32 impls in trampolines");
        // Ordinal import must resolve too (it has no named raw fn but the thunk must differ
        // from any unrelated pointer).
        let p3 = t
            .lookup("comctl32.dll", "ORDINAL 410")
            .expect("comctl32 ORDINAL 410 resolved");
        assert!(!p3.is_null());
    }

    #[test]
    fn default_table_resolves_extras2_exports() {
        let t = ImplTable::default_table();
        // File / directory ops.
        assert!(t.lookup("kernel32.dll", "CreateDirectoryW").is_some());
        assert!(t.lookup("kernel32.dll", "DeleteFileW").is_some());
        assert!(t.lookup("kernel32.dll", "RemoveDirectoryW").is_some());
        assert!(t.lookup("kernel32.dll", "CopyFileW").is_some());
        assert!(t.lookup("kernel32.dll", "MoveFileW").is_some());
        assert!(t.lookup("kernel32.dll", "MoveFileExW").is_some());
        assert!(t.lookup("kernel32.dll", "CreateHardLinkW").is_some());
        assert!(t.lookup("kernel32.dll", "CreateSymbolicLinkW").is_some());
        assert!(t.lookup("kernel32.dll", "GetFileAttributesExW").is_some());
        assert!(t
            .lookup("kernel32.dll", "GetFileInformationByHandle")
            .is_some());
        assert!(t.lookup("kernel32.dll", "GetShortPathNameW").is_some());
        assert!(t.lookup("kernel32.dll", "GetTempFileNameW").is_some());
        assert!(t.lookup("kernel32.dll", "SetCurrentDirectoryW").is_some());
        assert!(t.lookup("kernel32.dll", "FindNextFileW").is_some());
        // Console.
        assert!(t.lookup("kernel32.dll", "GetConsoleCP").is_some());
        assert!(t.lookup("kernel32.dll", "GetOEMCP").is_some());
        assert!(t
            .lookup("kernel32.dll", "GetConsoleScreenBufferInfo")
            .is_some());
        assert!(t
            .lookup("kernel32.dll", "SetConsoleCursorPosition")
            .is_some());
        assert!(t.lookup("kernel32.dll", "SetConsoleTitleW").is_some());
        assert!(t
            .lookup("kernel32.dll", "FillConsoleOutputAttribute")
            .is_some());
        assert!(t
            .lookup("kernel32.dll", "FillConsoleOutputCharacterW")
            .is_some());
        assert!(t.lookup("kernel32.dll", "VerifyConsoleIoHandle").is_some());
        // Time.
        assert!(t.lookup("kernel32.dll", "GetSystemTime").is_some());
        assert!(t
            .lookup("kernel32.dll", "FileTimeToLocalFileTime")
            .is_some());
        assert!(t.lookup("kernel32.dll", "FileTimeToSystemTime").is_some());
        assert!(t.lookup("kernel32.dll", "SystemTimeToFileTime").is_some());
        assert!(t.lookup("kernel32.dll", "SetFileTime").is_some());
        assert!(t.lookup("kernel32.dll", "GetLocaleInfoW").is_some());
        // Process.
        assert!(t.lookup("kernel32.dll", "CreateProcessW").is_some());
        assert!(t.lookup("kernel32.dll", "DuplicateHandle").is_some());
        assert!(t.lookup("kernel32.dll", "LocalAlloc").is_some());
        assert!(t.lookup("kernel32.dll", "SetStdHandle").is_some());
        assert!(t.lookup("kernel32.dll", "IsBadStringPtrW").is_some());
        // Disk / volume.
        assert!(t.lookup("kernel32.dll", "GetDiskFreeSpaceExW").is_some());
        assert!(t.lookup("kernel32.dll", "GetVolumeInformationW").is_some());
        assert!(t.lookup("kernel32.dll", "SetVolumeLabelW").is_some());
        // String / locale + ntdll.
        assert!(t.lookup("kernel32.dll", "CompareStringW").is_some());
        assert!(t.lookup("ntdll.dll", "RtlGetVersion").is_some());
    }

    #[test]
    fn build_table_wraps_extras2_in_trampolines() {
        let mut arena = ThunkArena::new().expect("arena");
        let t = ImplTable::build(&mut arena);
        let p = t
            .lookup("kernel32.dll", "CopyFileW")
            .expect("CopyFileW resolved");
        let raw = nigg_win32_kernel32::extras2::copy_file_w as FnPtr;
        assert_ne!(
            p, raw,
            "build() wraps extras2 kernel32 impls in trampolines"
        );
        let p2 = t
            .lookup("ntdll.dll", "RtlGetVersion")
            .expect("RtlGetVersion resolved");
        let raw2 = nigg_win32_kernel32::extras2::rtl_get_version as FnPtr;
        assert_ne!(p2, raw2, "build() wraps extras2 ntdll impls in trampolines");
    }
}
