// Minimal Windows console EXE built for x86_64-pc-windows-gnu.
// Prints nothing and exits with status 42. Used to verify the loader forwards the
// process exit code through its native runtime.
fn main() {
    std::process::exit(42);
}
