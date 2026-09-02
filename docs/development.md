# Development guide

How to build, test, and cross-compile the Nigg compatibility layer. The project is a
Cargo workspace; see [architecture.md](architecture.md) for the layering and the top-level
[README](../README.md) for the milestone ladder.

## Prerequisites

### Rust

A stable Rust toolchain. The repo pins `stable` (with `rustfmt` and `clippy`) and the
`x86_64-unknown-linux-gnu` + `x86_64-pc-windows-gnu` targets via
[`rust-toolchain.toml`](../rust-toolchain.toml); `rustup` installs them automatically on
first build. The host target is `x86_64-unknown-linux-gnu`.

### mingw-w64 (cross-compiler for test fixtures)

The test fixtures are tiny Windows console EXEs cross-compiled for
`x86_64-pc-windows-gnu`. Install the mingw-w64 toolchain (provides
`x86_64-w64-mingw32-gcc`):

```sh
sudo apt-get install -y mingw-w64
```

### Native libraries (Linux host bindings)

The `wsi`, `input`, and `audio` crates link against Linux host libraries via Rust
bindings. Install their dev headers:

```sh
sudo apt-get install -y \
  libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev \
  libvulkan-dev libasound2-dev
```

PipeWire (`libpipewire-0.3-dev`) is **only** required if you enable the audio
`pipewire` feature; it is a non-default feature and is not needed for the standard
build or for CI.

## Build

```sh
# Build the whole workspace (host target)
cargo build --workspace

# Build a single crate, e.g. the PE loader
cargo build -p nigg-pe-loader
```

## Test

```sh
# Run the whole test suite
cargo test --workspace

# Run just the test harness
cargo test -p nigg-tests

# Show skip reasons / println output
cargo test -p nigg-tests -- --nocapture
```

The `nigg-tests` harness locates cross-compiled fixture EXEs and validates them as
PE32+. Tests that need a fixture skip gracefully (with a clear message) when the fixture
has not been built yet, so `cargo test --workspace` is green even before the fixtures are
cross-compiled.

## Cross-compile the test fixtures

The fixtures live in [`tests/fixtures`](../tests/fixtures) (`hello`, `exit_code`, `args`).
Build them for Windows:

```sh
cargo build --target x86_64-pc-windows-gnu -p nigg-tests-fixtures
```

The EXEs land under `target/x86_64-pc-windows-gnu/debug/`:

- `hello.exe` — prints `hello from windows binary`, exits 0 (the M0 fixture)
- `exit_code.exe` — prints nothing, exits 42
- `args.exe` — prints each argv on its own line

Confirm they are valid PE32+ images:

```sh
file target/x86_64-pc-windows-gnu/debug/*.exe
# -> PE32+ executable for MS Windows 5.02 (console), x86-64
```

Once built, the harness PE32+ validation test (`hello_exe_is_valid_pe32_plus`) runs
instead of skipping. Use `NIGG_FIXTURE_PROFILE=release` (and a release build) to point
the harness at release-profile fixtures.

## Run the tools

### `nigg-loader`

Loads and runs a Windows PE binary natively. (Loader logic lands with WS-A; the CLI
currently reports it is not yet implemented.)

```sh
cargo run -p nigg-pe-loader --bin nigg-loader -- path/to/hello.exe
# or, after `cargo build`:
./target/debug/nigg-loader path/to/hello.exe
```

Against a cross-compiled fixture:

```sh
cargo run -p nigg-pe-loader --bin nigg-loader -- \
  target/x86_64-pc-windows-gnu/debug/hello.exe
```

The end-to-end `loader_runs_hello_exe` test (in `nigg-tests`) is `#[ignore]` until WS-A
lands; run it explicitly with:

```sh
cargo test -p nigg-tests -- --ignored loader_runs_hello_exe
```

### `nigg-hlslc`

Compiles an HLSL shader to SPIR-V. (Compiler logic lands with WS-F; the CLI currently
reports it is not yet implemented.)

```sh
cargo run -p nigg-hlsl-compiler --bin nigg-hlslc -- shader.hlsl -o shader.spv
# or, after `cargo build`:
./target/debug/nigg-hlslc shader.hlsl -o shader.spv
```

## Lints and formatting

```sh
cargo fmt --all              # format
cargo fmt --all -- --check   # check only (CI gate)
cargo clippy --workspace --all-targets   # CI runs this with -D warnings
```

## Makefile shortcuts

A [`Makefile`](../Makefile) wraps the common commands:

```sh
make check        # cargo check --workspace
make build        # cargo build --workspace
make test         # cargo test --workspace
make clippy       # cargo clippy --workspace --all-targets
make fmt          # cargo fmt --all
make fmt-check    # cargo fmt --all -- --check
make cross        # cross-compile the test fixtures (windows-gnu)
make ci           # fmt-check + clippy + build + test
```

## CI

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on `ubuntu-22.04`:
`fmt-check`, `clippy`, `build --workspace`, `test --workspace`, then cross-compiles the
test fixtures. `RUSTFLAGS="-D warnings"` is enforced.
