// CLI entrypoint: `nigg-hlslc <input.hlsl> -o <output.spv>` compiles an HLSL shader to SPIR-V.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    eprintln!("nigg-hlslc: args={:?} (compiler not yet implemented)", &args[1..]);
    std::process::exit(1);
}
