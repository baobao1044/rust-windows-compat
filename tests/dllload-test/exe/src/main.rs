//! Runtime DLL-loading acceptance PE.
//!
//! A `#![no_std]`/`#![no_main]` Windows console EXE (raw-dylib against kernel32) that
//! exercises the compatibility layer's `LoadLibraryA` -> `DllMain(DLL_PROCESS_ATTACH)` ->
//! `GetProcAddress` -> export-call -> `FreeLibrary` pipeline against the companion
//! `nigg_dllload.dll` built by this workspace. Exit code 0 means every stage passed; the
//! stages return distinct codes in the 10..=19 range so a failure is pinpointed.

#![no_std]
#![no_main]
#![allow(dead_code)]

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "C" {
    fn LoadLibraryA(name: *const u8) -> *mut u8;
    fn GetProcAddress(hmodule: *mut u8, name: *const u8) -> *mut u8;
    fn FreeLibrary(hmodule: *mut u8) -> i32;
    fn ExitProcess(code: u32) -> !;
}

/// The export the fixture expects to find: `dll_increment()` / `dll_count()` (no args,
/// returning the counter value). Transmuted from the `GetProcAddress` return values.
type IncrementFn = unsafe extern "system" fn() -> u32;
type CountFn = unsafe extern "system" fn() -> u32;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// CRT entry (the `-nostartfiles` link uses this as the image entrypoint).
#[no_mangle]
pub unsafe extern "C" fn mainCRTStartup() {
    let exit = unsafe { try_run() };
    unsafe { ExitProcess(exit as u32) };
}

/// End-to-end check. Each stage returns its own distinct code so a failure is
/// pinpointed:
/// 10 = LoadLibraryA failed, 11 = GetProcAddress("dll_increment") NULL,
/// 12 = GetProcAddress("dll_count") NULL, 13 = GetProcAddress("dll_absent") not NULL,
/// 14 = counter did not advance by exactly one, 15 = FreeLibrary returned FALSE.
unsafe fn try_run() -> i32 {
    // 1. Load the DLL: the loader searches the process working directory (where the
    //    cross-compiled `nigg_dllload.dll` lives), maps it, runs DllMain(ATTACH).
    let hmodule = unsafe { LoadLibraryA(b"nigg_dllload.dll\0".as_ptr()) };
    if hmodule.is_null() {
        return 10;
    }

    // 2. Resolve the exports: real Win64 addresses inside the mapped DLL.
    let increment = unsafe { GetProcAddress(hmodule, b"dll_increment\0".as_ptr()) };
    if increment.is_null() {
        return 11;
    }
    let count = unsafe { GetProcAddress(hmodule, b"dll_count\0".as_ptr()) };
    if count.is_null() {
        return 12;
    }

    // 3. Negative probe: a name absent from the export table must resolve to NULL.
    if !unsafe { GetProcAddress(hmodule, b"dll_absent\0".as_ptr()) }.is_null() {
        return 13;
    }

    // 4. Call the exports (native Windows x64 code): increment once, then confirm the
    //    counter moved by exactly one.
    //
    // SAFETY: the count/increment pointers are genuine exports of the DLL we just
    // loaded (verified non-NULL above); they take no arguments in either ABI and their
    // image sections are mapped executable, so a direct Win64-ABI call is valid.
    let before = unsafe { core::mem::transmute::<*mut u8, CountFn>(count)() };
    unsafe { core::mem::transmute::<*mut u8, IncrementFn>(increment)() };
    let after = unsafe { core::mem::transmute::<*mut u8, CountFn>(count)() };
    if after != before + 1 {
        return 14;
    }

    // 5. Unload: the module leaves the registry and its mapping is released.
    if unsafe { FreeLibrary(hmodule) } == 0 {
        return 15;
    }

    0
}
