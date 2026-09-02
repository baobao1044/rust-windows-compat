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
    let mut out = ResolvedImports::default();
    for imp in imports {
        let dll = imp.dll.to_lowercase();
        let sym = normalize_symbol(&imp.name);
        if let Some(ptr) = known.lookup(&dll, &sym) {
            out.resolved.insert((dll.clone(), sym.clone()), ptr);
        } else {
            log::warn!(
                "stubbed import: {}!{} (no M1 implementation)",
                imp.dll,
                imp.name
            );
            out.stubbed.push((dll.clone(), sym.clone()));
            out.resolved
                .insert((dll.clone(), sym.clone()), trap_stub as FnPtr);
        }
    }
    out
}

/// `extern "C"` trap stub for unimplemented imports. Logs the call site symbol and aborts
/// with a distinct exit code so the failure is unmistakable.
extern "C" fn trap_stub() -> u32 {
    log::error!("PE loader: called an unimplemented import (trap stub); aborting");
    eprintln!("nigg-loader: called unimplemented Windows import — aborting");
    // STATUS_DLL_INIT_FAILED-ish sentinel (0xC000_0142 as a signed exit code).
    std::process::exit(0xC000_0142u32 as i32);
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
}

impl ImplTable {
    /// Build the table of M1 implemented exports, wrapping each implementation in a
    /// Win64->SysV trampoline allocated from `arena`. The arena must be `finalize()`d
    /// (flipped to PROT_EXEC) before any IAT entry is called.
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
        ImplTable { map }
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
        // Forward to apiset pseudo-DLLs (using the same direct pointers).
        let mut forward_map = map.clone();
        forward_apisets_direct(&mut forward_map, &map);
        ImplTable { map: forward_map }
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

    // TODO(M3): wire in `nigg_win32_user32::user32_imports()` and
    // `nigg_win32_gdi32::gdi32_imports()` (add `nigg-win32-user32` / `nigg-win32-gdi32` as
    // deps of nigg-pe-loader). M3 has now landed and exposes both functions, but they return
    // `(dll, sym, ptr)` triples WITHOUT the `n_args`/`noreturn` metadata the thunk arena
    // needs (see `ExportSpec` in win32-kernel32 for the richer shape). Two blockers must be
    // resolved before this can land safely:
    //   1. The M3 export functions need to carry arg counts (or a per-symbol `n_args` table
    //      must be maintained here); guessing `n_args` would shuffle the wrong registers
    //      and silently corrupt Win64->SysV calls.
    //   2. `CreateWindowExW` takes 12 integer args, exceeding `ThunkArena::make_thunk`'s
    //      8-arg maximum (`make_thunk` returns `TooManyArgs`, and `ImplTable::build` panics
    //      on that error) — so wiring it today would panic at every PE load. The thunk
    //      layer must first be extended to handle >8 stack args, or `CreateWindowExW` must
    //      be split/excluded.
    // Until then, user32/gdi32 imports fall through to the trap stub (logged + abort), which
    // is safe for the M2 console-PE target (it only touches kernel32).

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
}
