// Minimal Windows console EXE built for x86_64-pc-windows-gnu.
// Prints each command-line argument (argv) on its own line, argv[0] first. Used to
// verify the loader assembles the process command line and argv vector correctly.
fn main() {
    for arg in std::env::args() {
        println!("{arg}");
    }
}
