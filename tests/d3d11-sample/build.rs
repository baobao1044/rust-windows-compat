//! Build script for the M7a D3D11 sample.
//!
//! The sample is a `#![no_std]`/`#![no_main]` program with a custom entry point
//! (`mainCRTStartup`) and no CRT. To avoid a duplicate `mainCRTStartup` from
//! `crt2.o` and an unresolved `WinMain`, we pass `-nostartfiles` +
//! `-nodefaultlibs` to the linker for this bin.

fn main() {
    // The sample has its own `mainCRTStartup` and no `WinMain`; `-nostartfiles`
    // skips `crt2.o` (which defines `mainCRTStartup` and calls `WinMain`). The
    // `rust_eh_personality` symbol referenced by the precompiled `core`'s
    // `.pdata` is provided as a no-op stub in `main.rs` (our panic handler
    // loops, so unwinding never runs).
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rerun-if-changed=build.rs");
}
