fn main() {
    // Link without the CRT startup: the fixture provides its own `mainCRTStartup` (a
    // `#![no_std]`, `#![no_main]` PE), matching the other nigg fixture EXEs.
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rerun-if-changed=build.rs");
}
