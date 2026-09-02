# Contributing

Thanks for working on Nigg. This is a research project rebuilding a Windows
compatibility layer in Rust from scratch; coordination matters because multiple
workstreams land in parallel. Please read [architecture.md](architecture.md) first.

## Workstream ownership

Each crate is owned by one workstream. Do not rewrite another workstream's crate source
without coordinating with its owner. Shared config (`Cargo.toml`, `rust-toolchain.toml`)
may be adjusted with minimal additive changes by anyone, but prefer to raise it with
the affected owner first.

| Workstream | Owns | Depends on |
|------------|------|------------|
| WS-A | `crates/pe-loader` (`nigg-pe-loader`, `nigg-loader` bin), `crates/runtime` (`nigg-runtime`) | — |
| WS-B | `crates/ntapi` (`nigg-ntapi`) | WS-A |
| WS-C | `crates/win32-kernel32`, `crates/win32-user32`, `crates/win32-gdi32` | WS-B |
| WS-D | `crates/wsi` (`nigg-wsi`), `crates/input` (`nigg-input`), `crates/audio` (`nigg-audio`) | — |
| WS-E | `crates/dxgi` (`nigg-dxgi`), `crates/d3d11` (`nigg-d3d11`), `crates/d3d12` (`nigg-d3d12`) | WS-C + WS-D |
| WS-F | `crates/hlsl-compiler` (`nigg-hlsl-compiler`, `nigg-hlslc` bin) | — |
| WS-G | `crates/tests` (`nigg-tests`), `tests/fixtures` (`nigg-tests-fixtures`), `.github/workflows/ci.yml`, `docs/`, `Makefile` | — |

If a crate you depend on has a compile issue you cannot fix without touching its source,
note it in your report rather than editing the other owner's code.

## Branches

- Branch off `main`.
- Name feature branches `ws-<letter>/<short-topic>` (e.g. `ws-a/pe-relocs`) or
  `feat/<short-topic>`.
- Keep branches focused; one workstream's work per branch where practical.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes, matching the
existing history (e.g. `chore: scaffold Nigg workspace …`):

- `feat:` a new capability
- `fix:` a bug fix
- `docs:` documentation only
- `test:` test harness / fixtures
- `ci:` CI / build infrastructure
- `chore:` tooling, deps, formatting

Keep the subject line to ~50–72 chars, imperative mood, no trailing period.

## Build & test before pushing

```sh
make ci          # fmt-check + clippy + build --workspace + test --workspace
make cross       # cross-compile the test fixtures (windows-gnu)
```

`RUSTFLAGS="-D warnings"` is enforced in CI; clippy must be clean. See
[development.md](development.md) for prerequisites.

## Honesty policy for the compatibility matrix

[compatibility.md](compatibility.md) is the source of truth for what runs. It must stay
honest:

- **✅ "Runs"** means the scenario has been verified end-to-end in **this project's test
  harness** (`nigg-tests`), driving a fixture/sample through `nigg-loader` with the
  asserted behavior observed. Do not mark a cell ✅ on the basis of "it should work" or
  because Wine/DXVK can run it — only this project's own harness counts.
- **🚧 "in progress"** is for the active milestone target only.
- **❌ "not supported"** must include the reason (e.g. kernel-mode anti-cheat cannot run
  on Linux without a VM and is not circumvented).
- **— "not yet reached"** is the honest default for anything unverified. Prefer an empty
  cell over a hopeful claim.

When a milestone is reached, update the matrix in the same PR that lands the verifying
harness test.

## Reuse policy

100% Rust. Do not reuse Wine, DXVK, VKD3D, ntsync, or shaderc/DXC/glslang source. Format
parsers (`goblin`, `pelite`) and host-driver bindings (`ash`, `x11rb`, `evdev`,
`pipewire`, `rspirv`) are allowed — they are bindings to Linux infrastructure / file
formats, not Windows-compatibility code.
