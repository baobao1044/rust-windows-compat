//! kernel32 reimplementation built on top of [`nigg-ntapi`].
//!
//! This crate implements the subset of `kernel32.dll` exports needed to run console-mode
//! Windows PE binaries on Linux. Every export is an ordinary `extern "C"` Rust function;
//! the PE loader's ABI thunk layer (`nigg-pe-loader::thunk`) wraps each one in a Win64->SysV
//! trampoline before writing its address into the Import Address Table, so the exports can
//! be called directly from PE machine code using the Windows x64 calling convention.
//!
//! Where [`nigg-ntapi`] already provides the underlying primitive (stdio, memory,
//! synchronization, threads, time), the kernel32 export simply delegates to it. The rest
//! (files, heap, environment, console mode, string helpers, command line) is implemented
//! here on top of `libc`, `std::env`, and `std::os::raw`.
//!
//! # Modules
//!
//! - [`console`] — `GetStdHandle`, `WriteFile`/`ReadFile` (delegates), `WriteConsoleW`/`A`,
//!   `GetConsoleMode`, `SetConsoleMode`.
//! - [`file`] — `CreateFileW`/`A`, `ReadFile`/`WriteFile`, `CloseHandle`, `GetFileSize`,
//!   `SetFilePointer`, `FlushFileBuffers`.
//! - [`heap`] — `GetProcessHeap`, `HeapAlloc`/`HeapFree`/`HeapReAlloc`/`HeapCreate`/
//!   `HeapDestroy` backed by `libc::malloc`/`free`/`realloc`.
//! - [`env`] — `GetEnvironmentVariableW`/`SetEnvironmentVariableW`/`GetEnvironmentStringsW`/
//!   `FreeEnvironmentStringsW` mapped onto `std::env`.
//! - [`process`] — `GetCurrentProcessId`/`GetCurrentThreadId` (delegates), `GetModuleHandleW`,
//!   `GetCommandLineW`/`GetCommandLineA`.
//! - [`dllload`] — `LoadLibraryA`/`W`/`ExA`/`ExW`, `GetProcAddress`, `FreeLibrary`,
//!   `DisableThreadLibraryCalls`: the module-loading surface, bridged to the real PE
//!   loader (`nigg-pe-loader`) via function-pointer registration to avoid a reverse
//!   crate dependency.
//! - [`registry`] — advapi32 registry (in-memory store, seeded by [`spi`] with the
//!   Secure Boot / integrity-check security-policy values) + `IsTextUnicode`.
//! - [`tpm`] — TPM 2.0 Base Services (`tbs.dll` fake context handles, command probes)
//!   plus the firmware/system-security queries (`GetFirmwareType`,
//!   `GetFirmwareEnvironmentVariableA/W` — the `SecureBoot` EFI variable —,
//!   `IsWow64Process`, `GetProductInfo`) and the advapi32 secure-boot probes.
//! - [`string`] — `MultiByteToWideChar`/`WideCharToMultiByte`, `lstrlenW`/`lstrlenA`,
//!   `lstrcpyW`/`lstrcatW`.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment. The exports take raw pointers (they are called from PE machine code), so
//! `clippy::not_unsafe_ptr_arg_deref` is allowed.

#![deny(unsafe_op_in_unsafe_fn)]
// The `extern "C"` functions in this crate implement Windows APIs that take raw pointers.
// They are called from PE machine code via ABI trampolines, not from safe Rust callers, so
// marking them `unsafe` would not help — the lint does not apply to this use case.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::c_void;

pub mod anticheat;
pub mod comctl32;
pub mod comdlg32;
pub mod console;
pub mod crt;
pub mod d3dcompiler;
pub mod dllload;
pub mod env;
pub mod extras;
pub mod extras2;
pub mod file;
pub mod heap;
pub mod ole32;
pub mod process;
pub mod registry;
pub mod shell32;
pub mod shlwapi;
pub mod spi;
pub mod string;
pub mod system_info;
pub mod tpm;
pub mod ucrt;
pub mod xinput;

/// A Windows `HANDLE`: an opaque, process-local 64-bit value (re-exported from ntapi).
pub type Handle = u64;
/// The Windows `HMODULE`/pointer-sized module handle.
pub type Hmodule = *mut c_void;

/// The raw function-pointer type written into the PE Import Address Table. Matches the
/// `FnPtr` alias in `nigg-pe-loader::imports`.
pub type FnPtr = *const c_void;

/// Metadata for a single kernel32 export, used by the PE loader to build the ABI thunk for
/// the import. The loader needs the argument count (to size the Win64->SysV trampoline)
/// and the `noreturn` flag (to pick the tail-call vs. call-and-return trampoline flavor).
#[derive(Clone, Copy)]
pub struct ExportSpec {
    /// DLL the symbol belongs to (`"kernel32.dll"`).
    pub dll: &'static str,
    /// Undecorated export name (e.g. `"CreateFileW"`).
    pub sym: &'static str,
    /// The System V `extern "C"` implementation address.
    pub ptr: FnPtr,
    /// How many integer/pointer args the implementation takes (0..=8 for returning, 0..=6
    /// for noreturn).
    pub n_args: u8,
    /// `true` if the function never returns (`ExitProcess`).
    pub noreturn: bool,
}

/// The full list of kernel32 exports implemented by this crate, with the metadata the PE
/// loader needs to build ABI thunks. Callers that only need `(dll, sym, ptr)` triples
/// should use [`kernel32_imports`] instead.
pub fn kernel32_exports() -> Vec<ExportSpec> {
    use self::console::*;
    use self::env::*;
    use self::file::*;
    use self::heap::*;
    use self::process::*;
    use self::string::*;

    // Each entry: (dll, sym, ptr as FnPtr, n_args, noreturn).
    macro_rules! k {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "kernel32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }
    macro_rules! kn {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "kernel32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: true,
            }
        };
    }

    vec![
        // --- console ---
        k!("GetStdHandle", get_std_handle, 1),
        k!("WriteFile", write_file, 5),
        k!("ReadFile", read_file, 5),
        k!("WriteConsoleW", write_console_w, 5),
        k!("WriteConsoleA", write_console_a, 5),
        k!("GetConsoleMode", get_console_mode, 2),
        k!("SetConsoleMode", set_console_mode, 2),
        // --- file ---
        k!("CreateFileW", create_file_w, 7),
        k!("CreateFileA", create_file_a, 7),
        k!("GetFileSize", get_file_size, 2),
        k!("SetFilePointer", set_file_pointer, 4),
        k!("FlushFileBuffers", flush_file_buffers, 1),
        // --- heap ---
        k!("GetProcessHeap", get_process_heap, 0),
        k!("HeapAlloc", heap_alloc, 3),
        k!("HeapFree", heap_free, 3),
        k!("HeapReAlloc", heap_re_alloc, 5),
        k!("HeapCreate", heap_create, 3),
        k!("HeapDestroy", heap_destroy, 1),
        // --- environment ---
        k!("GetEnvironmentVariableW", get_environment_variable_w, 4),
        k!("SetEnvironmentVariableW", set_environment_variable_w, 2),
        k!("GetEnvironmentStringsW", get_environment_strings_w, 0),
        k!("FreeEnvironmentStringsW", free_environment_strings_w, 1),
        // --- process / module ---
        k!("GetCurrentProcessId", get_current_process_id, 0),
        k!("GetCurrentThreadId", get_current_thread_id, 0),
        k!("GetModuleHandleW", get_module_handle_w, 1),
        k!("GetModuleHandleA", get_module_handle_a, 1),
        k!("GetCommandLineW", get_command_line_w, 0),
        k!("GetCommandLineA", get_command_line_a, 0),
        // --- string ---
        k!("MultiByteToWideChar", multi_byte_to_wide_char, 6),
        k!("WideCharToMultiByte", wide_char_to_multi_byte, 8),
        k!("lstrlenW", lstrlen_w, 1),
        k!("lstrlenA", lstrlen_a, 1),
        k!("lstrcpyW", lstrcpy_w, 2),
        k!("lstrcatW", lstrcat_w, 2),
        // --- process termination (noreturn) ---
        kn!("ExitProcess", exit_process, 1),
    ]
}

/// `(dll, symbol, ptr)` triples for every kernel32 export, in the shape the rest of the
/// loader expects for cross-crate wiring (matching the convention used by the sibling
/// `nigg-win32-user32` / `nigg-win32-gdi32` crates). Callers that need the argument-count
/// metadata for ABI thunks should use [`kernel32_exports`] instead.
pub fn kernel32_imports() -> Vec<(&'static str, &'static str, FnPtr)> {
    kernel32_exports()
        .into_iter()
        .map(|e| (e.dll, e.sym, e.ptr))
        .collect()
}
