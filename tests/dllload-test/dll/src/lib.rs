//! A minimal Windows PE DLL for the `LoadLibrary`/`GetProcAddress` acceptance test.
//!
//! The DLL is a plain Rust `cdylib` cross-compiled for `x86_64-pc-windows-gnu`, so it is
//! a real native Windows image: Windows x64 calling convention, a real export directory
//! (the `#[no_mangle] extern "system"` functions are auto-exported from cdylibs), and a
//! `DllMainCRTStartup` CRT entry that the PE loader's `DllMain(hModule,
//! DLL_PROCESS_ATTACH)` call fences.
//!
//! It exports:
//! - `dll_increment` — adds 1 to an internal atomic counter and returns the new value.
//! - `dll_count`     — reads the counter without changing it.
//!
//! The companion EXE (`nigg_dllload.exe`) loads this file through
//! `kernel32!LoadLibraryA`, resolves both exports with `kernel32!GetProcAddress`,
//! verifies `GetProcAddress(NULL)`-style failures for a missing export name, calls
//! `dll_increment` (which must make `dll_count` move by exactly 1), and checks
//! `FreeLibrary`.

#![no_std]
#![allow(dead_code)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

/// The counter the EXE observes changing through the exports.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// `BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)`.
///
/// Provided explicitly so the DLL's initialization is exercised end to end by the
/// loader's `DllMain(hModule, DLL_PROCESS_ATTACH = 1, NULL)`: we record that the attach
/// notification arrived (bumping the counter from 0 to 1 would conflate DllMain with the
/// export path, so an `ATTACH_COUNT` flag would be overkill — instead, a `DllMain` that
/// returns `FALSE` for `DLL_PROCESS_ATTACH` would fail the load, and returning `TRUE`
/// here is exactly what keeps `LoadLibraryA` succeeding).
#[no_mangle]
pub extern "system" fn DllMain(_hinst: *mut c_void, _reason: u32, _reserved: *mut c_void) -> i32 {
    1 // TRUE — initialization succeeded
}

/// `u32 dll_increment(void)` — Windows x64 ABI export: bumps the counter, returns the
/// new value. Called by the EXE through the `GetProcAddress` result.
#[no_mangle]
pub extern "system" fn dll_increment() -> u32 {
    COUNTER.fetch_add(1, Ordering::SeqCst) + 1
}

/// `u32 dll_count(void)` — export: reads the counter without changing it.
#[no_mangle]
pub extern "system" fn dll_count() -> u32 {
    COUNTER.load(Ordering::SeqCst)
}

/// `dll_get_proc_a_name_not_present` would defeat the point — this export deliberately
/// does NOT exist, so the EXE's negative `GetProcAddress` probe must not find it.
/// (Kept as a comment documenting the fixture contract; no code needed.)

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // A fixture DLL must not panic; spin forever so a failure is unmistakable instead
    // of silently unwinding into missing CRT machinery.
    loop {}
}

/// Personality stub the GNU toolchain's unwinding metadata references even in
/// `panic=abort` builds (`libcore`'s `.xdata` names it); a no-op keeps the link happy
/// — no exception ever reaches it.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
