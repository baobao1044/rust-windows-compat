# Architecture

## Design principles

1. **Pure Rust.** Every line of Windows-compatibility logic is written in Rust. No Wine,
   DXVK, VKD3D, ntsync, or shaderc/DXC/glslang source is reused.
2. **System-driver bindings are allowed.** The layer talks to the Linux host through
   Rust bindings to host infrastructure: Vulkan (`ash`), X11/Wayland, evdev, PipeWire,
   and SPIR-V emission (`rspirv`). These are *bindings to Linux*, not Windows-compat code.
3. **Honest compatibility.** A maintained matrix records what runs and what does not.
   Kernel-mode anti-cheat is documented as unsupported; nothing is circumvented.

## Layering

```
                ┌─────────────────────────────────────────┐
   Win app .exe │  pe-loader ─► runtime ─► ntapi (ntdll)   │
                │      │                       │          │
                │      ▼                       ▼          │
                │  win32-kernel32 / user32 / gdi32        │
                │      │                       │          │
                │      ▼                       ▼          │
                │   wsi (X11/Wayland)   input   audio      │
                │      └──────────┬──────────┘            │
                │                 ▼                        │
                │     dxgi ─► d3d11 / d3d12 ──► Vulkan     │
                │                 ▲                        │
                │          hlsl-compiler (→ SPIR-V)        │
                └─────────────────────────────────────────┘
                                │
                          Linux kernel (mmap, futex, io_uring)
```

### Dependency direction

- `pe-loader` + `runtime` are the foundation; everything else builds on them.
- `ntapi` depends on `runtime`.
- `win32-*` depend on `ntapi`.
- `wsi` / `input` / `audio` are independent of the Win32 stack (they talk to the host).
- `dxgi` / `d3d11` / `d3d12` depend on `wsi` + `win32-user32`.
- `hlsl-compiler` is fully independent (frontend + SPIR-V codegen).

## Windows process model reimplementation

On Windows, a loaded image has:
- Image base mapped with sections at their RVAs.
- A TEB (Thread Environment Block) per thread, pointed at by `gs:[0]` (x64).
- A PEB (Process Environment Block) shared across the process.
- An import table resolved to host exports at load time.
- Relocations applied to absolute addresses.

This project rebuilds these structures in Rust and lays them out in the loaded image's
memory. The runtime sets the `gs` base (via `arch_prctl(ARCH_SET_GS)`) to point at the
TEB so Windows code that reads `gs:[0x...]` (the TIB/TEB fields) keeps working.

## Synchronization

Windows sync primitives (critical sections, events, mutexes, SRW locks, condition
variables) map to Linux `futex(2)` syscalls. Each primitive is reimplemented in `ntapi`
on top of futex, matching Windows semantics (recursive mutexes, auto/manual-reset
events, etc.).

## Graphics translation

D3D11/D3D12 are translated to Vulkan via `ash` (the pure-Rust Vulkan binding calling the
system loader). DXGI swap chains present to a surface provided by `wsi`. HLSL shaders
are compiled to SPIR-V by the `hlsl-compiler` crate and fed to Vulkan pipelines.

## Subagent / workstream split

| Workstream | Crates | Depends on |
|------------|--------|------------|
| WS-A | pe-loader, runtime | — |
| WS-B | ntapi | WS-A |
| WS-C | win32-* | WS-B |
| WS-D | wsi, input, audio | — (parallel from day 1) |
| WS-E | dxgi, d3d11, d3d12 | WS-C + WS-D |
| WS-F | hlsl-compiler | — (parallel from day 1, long pole) |
| WS-G | tests, CI, docs | — (parallel from day 1) |

Four workstreams (A, D, F, G) run in parallel from day one.
