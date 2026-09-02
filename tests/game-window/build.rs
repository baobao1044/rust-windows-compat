//! Build script for the game-window sample.
//!
//! The sample is a `#![no_std]`/`#![no_main]` program with a custom entry point
//! (`mainCRTStartup`) and no CRT. To avoid a duplicate `mainCRTStartup` from
//! `crt2.o` and an unresolved `WinMain`, we pass `-nostartfiles` to the linker.

fn main() {
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rerun-if-changed=build.rs");
}
