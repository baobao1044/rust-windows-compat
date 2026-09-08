fn main() {
    println!("cargo:rustc-link-arg=-nostartfiles");
    println!("cargo:rerun-if-changed=build.rs");
}
