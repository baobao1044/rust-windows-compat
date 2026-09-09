# Nigg — Pure-Rust Windows Compatibility Layer for Linux

Run Windows applications and games on Linux **natively** — no virtual machine, no Wine.
The compatibility layer is implemented from scratch in Rust, including the PE loader, the
NT/Win32 API surface, the DXGI/D3D11/D3D12 → Vulkan translation, and an HLSL → SPIR-V
shader compiler.

> **Research project.** Wine is 30+ years of work; DXVK/VKD3D are large C++ projects. This
> project rebuilds the equivalent functionality in Rust from a blank page. The long-term
> goal ("north star") is running a modern D3D11/D3D12 game. There is no guarantee that goal
> is reached — even Wine does not run every title after three decades. Progress is tracked
> against a realistic milestone ladder, and the compatibility matrix is kept honest.

## What this project does

- Loads and executes native Windows PE binaries on Linux without Wine.
- Reimplements the Windows NT/Win32 API surface in Rust (memory, sync, threads, handles,
  windowing, input, audio).
- Translates DirectX 11/12 graphics calls to Vulkan, and compiles HLSL shaders to SPIR-V.

## What this project does **not** do

- It does **not** run kernel-mode Windows drivers. Consequently, kernel-level anti-cheat
  systems (e.g. Riot Vanguard) **cannot** work on Linux without a VM — this is a hard
  technical limit, not a goal this project pursues. The project does not circumvent
  anti-cheat or any other ToS/DMCA-protected mechanism.
- It does **not** reuse the Wine, DXVK, VKD3D, ntsync, or shaderc/DXC/glslang codebases.
  System-driver bindings written in Rust (Vulkan via `ash`, X11/Wayland, evdev, PipeWire,
  SPIR-V emission via `rspirv`) are used to talk to the host — these are *bindings to Linux
  infrastructure*, not Windows-compatibility code.
- The TPM 2.0 (`tbs.dll`) and Secure Boot surfaces are **platform-query compatibility
  shims**, in the same spirit as Wine's registry and version reporting: they answer the
  standard Windows platform probes so a PE's startup path does not abort. They do **not**
  forge attestation material, touch a host TPM, or modify firmware state. See
  [docs/anti-cheat.md](docs/anti-cheat.md) for the full scope statement.

## Milestone ladder

| Milestone | Goal |
|-----------|------|
| M0 | `pe-loader` runs a console `hello.exe` natively |
| M1 | NTAPI memory + futex sync + threads |
| M2 | kernel32 subset; simple console app runs |
| M3 | user32 windowing over X11/Wayland + input |
| M4 | DXGI + minimal D3D11 over Vulkan (clear/triangle) |
| M5 | HLSL→SPIR-V compiler MVP (SM5.0 VS/PS subset) |
| M6 | D3D11 + shaders; textured triangle / D3D11 sample |
| M7 | simple indie D3D9/11 game runs |
| M8 | D3D12 → Vulkan; D3D12 sample runs |
| M9 (north star) | a modern D3D11/12 game runs |

## Workspace layout

```
crates/
  pe-loader/        PE32/PE32+ loader, TEB/PEB, relocations, imports
  runtime/          process bootstrap, import thunk resolution, SEH→signals
  ntapi/            ntdll: memory, futex sync, threads, handles, registry, files
  win32-kernel32/   kernel32: files, console, environment
  win32-user32/     user32: windowing, message loop
  win32-gdi32/      gdi32: basic 2D
  wsi/              window-system integration (X11/Wayland surface)
  input/            keyboard/mouse/gamepad (XInput → evdev)
  audio/            XAudio/WASAPI → PipeWire
  dxgi/             DXGI swap chain/factory → Vulkan
  d3d11/            D3D11 → Vulkan
  d3d12/            D3D12 → Vulkan
  hlsl-compiler/    HLSL → SPIR-V
  tests/            test EXEs + harness
docs/               architecture & compatibility matrix
```

## Status

Pre-alpha, 270 tests passing. Verified end-to-end through `nigg-loader`:

| Fixture | Result |
|---------|--------|
| `hello.exe` — Rust std console PE (180 imports) | exits 0, prints to stdout |
| `d3d11_sample.exe` — D3D11 clear + present | exits 0 |
| `d3d11_triangle.exe` — D3D11 draw with HLSL shaders | exits 0 |
| `d3d12_sample.exe` — D3D12 command-list pipeline | exits 0 |
| `game_window.exe` — user32 window + D3D11 swap chain | exits 0 |
| `dllload_test.exe` — LoadLibrary + GetProcAddress + DllMain | exits 0 |
| `anticheat_sim.exe` — userland anti-cheat init sequence | exits 0 |
| `tpm_secureboot_sim.exe` — TPM 2.0 + Secure Boot probes | exits 0 |
| **`notepad.exe`** — real Windows x64 binary | 0 stubbed imports, opens a real X11 window |
| `cmd.exe` — real Windows x64 binary | 0 stubbed imports, starts executing |

Roughly 370 API exports are implemented across kernel32, user32, gdi32, ntdll,
ucrtbase/msvcrt, advapi32, shell32, shlwapi, ws2_32, xinput/xaudio2/dinput8, and
the D3D11/D3D12/DXGI COM vtables.

The north star (M9 — a modern game with anti-cheat) is **not** reached and remains
multi-year work. See [docs/compatibility.md](docs/compatibility.md) for the honest
matrix and [docs/anti-cheat.md](docs/anti-cheat.md) for what is and is not possible.

See also [docs/architecture.md](docs/architecture.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
