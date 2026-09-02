// CLI entrypoint: `nigg-loader <exe.exe>` loads and runs a Windows PE binary natively.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: nigg-loader <exe>");
        std::process::exit(2);
    }
    eprintln!("nigg-loader: loading {} (loader not yet implemented)", args[1]);
    std::process::exit(1);
}
