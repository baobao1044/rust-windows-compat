//! Process / module / command-line helpers: `GetCurrentProcessId`/`GetCurrentThreadId`
//! (delegates), `GetModuleHandleW`/`GetModuleHandleA`, `GetCommandLineW`/`GetCommandLineA`,
//! and `ExitProcess` (delegates to ntapi).
//!
//! `GetModuleHandle` returns a fake but stable module base for `kernel32`/`ntdll`/the host
//! executable. A null module name means "the main executable's image base", which we
//! approximate with the canonical PE default `0x140000000` (the brief calls this out as a
//! stub: returning the exe's ImageBase requires coordinating with the loader's mapped
//! base; that coordination is a later refinement). The command line is synthesized from
//! the host `argv` joined the way Windows would (program name quoted if it contains
//! spaces) and cached for the process lifetime.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;
use std::sync::OnceLock;

use crate::{Handle, Hmodule};

/// The fake but stable base we report for the main executable module when the guest asks
/// for `GetModuleHandle(NULL)`. Real Windows returns the EXE's mapped image base; the
/// loader sets the PEB `ImageBaseAddress` to the actual mapped base, so a guest that reads
/// the PEB gets the truth. This stub covers the `GetModuleHandle(NULL)` path until we wire
/// The actual mapped base of the main EXE. Set by the PE loader at load time
/// via [`register_exe_base`]. Falls back to the default PE image base
/// (0x140000000) when not set (bare unit tests).
static EXE_BASE: OnceLock<usize> = OnceLock::new();

/// Register the actual mapped base of the main EXE so GetModuleHandleW and
/// GetModuleHandleA can return the correct handle. Called by the PE loader
/// after mapping the image.
pub fn register_exe_base(base: usize) {
    let _ = EXE_BASE.set(base);
}

pub(crate) fn exe_base() -> usize {
    *EXE_BASE.get().unwrap_or(&0x1_4000_0000)
}

/// `kernel32!GetCurrentProcessId() -> DWORD`. Delegates to ntapi.
pub extern "C" fn get_current_process_id() -> u32 {
    nigg_ntapi::thread::get_current_process_id()
}

/// `kernel32!GetCurrentThreadId() -> DWORD`. Delegates to ntapi.
pub extern "C" fn get_current_thread_id() -> u32 {
    nigg_ntapi::thread::get_current_thread_id()
}

/// `kernel32!ExitProcess(uExitCode) -> !`. Delegates to ntapi's `_exit`-backed terminator.
pub extern "C" fn exit_process(exit_code: u32) -> ! {
    nigg_ntapi::process::exit_process(exit_code)
}

/// `kernel32!GetModuleHandleW(lpModuleName) -> HMODULE`. With a null name returns a stable
/// fake EXE base; with a known DLL name (`kernel32.dll`, `ntdll.dll`) returns a stable
/// fake base for that DLL; an unknown name returns NULL.
pub extern "C" fn get_module_handle_w(module_name: *const u16) -> Hmodule {
    eprintln!("[nigg process] GetModuleHandleW");
    // SAFETY: `module_name` is a NUL-terminated UTF-16 buffer (or null).
    let name = unsafe { crate::string::utf16_to_string(module_name) };
    resolve_module_handle(&name)
}

/// `kernel32!GetModuleHandleA(lpModuleName) -> HMODULE`. ANSI variant of
/// [`get_module_handle_w`].
pub extern "C" fn get_module_handle_a(module_name: *const u8) -> Hmodule {
    // SAFETY: `module_name` is a NUL-terminated byte string (or null).
    let name = unsafe { crate::string::bytes_to_string(module_name) };
    resolve_module_handle(&name)
}

/// Map a (lowercased, trimmed) module name to a stable fake base. An empty name (the
/// "current module" request) returns the EXE base.
fn resolve_module_handle(name: &str) -> Hmodule {
    if name.is_empty() {
        return exe_base() as Hmodule;
    }
    match name.to_lowercase().as_str() {
        "kernel32.dll" | "kernel32" => (exe_base() + 0x1000) as Hmodule,
        "ntdll.dll" | "ntdll" => (exe_base() + 0x2000) as Hmodule,
        "kernelbase.dll" | "kernelbase" => (exe_base() + 0x3000) as Hmodule,
        // api-ms-win-* pseudo-DLLs are aliases for kernel32 functions. Return
        // the kernel32 handle so GetProcAddress can resolve through it.
        n if n.starts_with("api-ms-win-") => (exe_base() + 0x1000) as Hmodule,
        "user32.dll" | "user32" => (exe_base() + 0x4000) as Hmodule,
        "gdi32.dll" | "gdi32" => (exe_base() + 0x5000) as Hmodule,
        "advapi32.dll" | "advapi32" => (exe_base() + 0x6000) as Hmodule,
        _ => std::ptr::null_mut(),
    }
}

/// `kernel32!GetCommandLineW() -> LPCWSTR`. Returns a pointer to a cached, NUL-terminated
/// UTF-16 copy of the process command line synthesized from the host `argv`. The pointer
/// is valid for the process lifetime (the cache outlives any caller).
pub extern "C" fn get_command_line_w() -> *const u16 {
    static LINE: OnceLock<Vec<u16>> = OnceLock::new();
    let line = LINE.get_or_init(|| build_command_line().encode_utf16().chain([0]).collect());
    line.as_ptr()
}

/// `kernel32!GetCommandLineA() -> LPCSTR`. Returns a pointer to a cached, NUL-terminated
/// byte copy of the process command line.
pub extern "C" fn get_command_line_a() -> *const u8 {
    static LINE: OnceLock<Vec<u8>> = OnceLock::new();
    let line = LINE.get_or_init(|| {
        build_command_line()
            .bytes()
            .chain(std::iter::once(0))
            .collect()
    });
    line.as_ptr()
}

/// Build the Windows-style command line: argv[0] (quoted if it contains spaces) followed by
/// the rest of the host args, each quoted if it contains spaces. This is a best-effort
/// reconstruction; precise Windows quoting rules are a later refinement.
fn build_command_line() -> String {
    let args: Vec<String> = std::env::args().collect();
    if args.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::with_capacity(args.len());
    for a in &args {
        if a.contains(' ') || a.contains('\t') {
            parts.push(format!("\"{}\"", a));
        } else {
            parts.push(a.clone());
        }
    }
    parts.join(" ")
}

/// Silence unused-import noise for `Handle`/`c_void` (kept in the module surface for
/// callers that pass handles through the process helpers).
#[allow(dead_code)]
fn _type_anchors() -> (Handle, *mut c_void) {
    (0, std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_and_thread_ids_are_nonzero() {
        assert_ne!(get_current_process_id(), 0);
        assert_ne!(get_current_thread_id(), 0);
    }

    #[test]
    fn module_handle_null_is_exe_base() {
        let h = get_module_handle_w(std::ptr::null());
        assert_eq!(h as usize, exe_base());
    }

    #[test]
    fn module_handle_kernel32_is_stable() {
        let name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let h = get_module_handle_w(name.as_ptr());
        assert_eq!(h as usize, exe_base() + 0x1000);
    }

    #[test]
    fn command_lines_are_cached_and_nul_terminated() {
        let w = get_command_line_w();
        assert!(!w.is_null());
        let mut len = 0usize;
        // SAFETY: the cached command line is NUL-terminated; we stop at the first 0 code unit.
        unsafe {
            while *w.add(len) != 0 {
                len += 1;
            }
        }
        assert!(len > 0, "command line has at least argv[0]");

        let a = get_command_line_a();
        assert!(!a.is_null());
        // SAFETY: the cached command line is a NUL-terminated byte string; `CStr::from_ptr`
        // walks to the terminating NUL.
        let cstr = unsafe { std::ffi::CStr::from_ptr(a as *const i8) };
        assert!(!cstr.to_bytes().is_empty());
    }
}
