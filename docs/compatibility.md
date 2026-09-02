# Compatibility Matrix

This matrix is kept honest. "Runs" means the scenario has been verified end-to-end in
this project's test harness. Empty cells mean not-yet-reached.

## Application classes

| Class | Status | Notes |
|-------|--------|-------|
| Minimal PE (exit code) | ✅ M0 | `mov eax,42; ret` — runs natively via nigg-loader, exits 42 |
| PE importing kernel32 (ExitProcess) | ✅ M1 | PE calls `kernel32!ExitProcess(42)` via Win64→SysV ABI thunk, exits 42 |
| Console PE (WriteFile + ExitProcess) | ✅ M2 | PE prints "hello" via `WriteFile` to stdout, exits 0 |
| Rust-std console (hello.exe) | 🚧 M2 stretch | needs ~180 imports (Winsock, CRT, etc.) — 53/180 implemented |
| Win32 GUI (window + message loop) | ✅ M3 | user32 RegisterClass/CreateWindow/GetMessage/DispatchMessage — headless-safe unit test; wired into pe-loader imports |
| D3D11 clear+triangle (Rust-native) | ✅ M6b | DXGI swap chain + D3D11 device over Vulkan; HLSL→SPIR-V; clear red + green triangle — verified via `clear_triangle` example |
| D3D11 sample via nigg-loader (PE) | 🚧 M7a | COM vtable for D3D11/DXGI in progress |
| D3D11 indie game | — | M7 |
| D3D12 sample | — | M8 |
| Modern D3D11/12 game | — | M9 north star |
| .NET / WPF app | — | out of initial scope; needs CLR translation |

## HLSL→SPIR-V compiler coverage

| Feature | Status | Notes |
|---------|--------|-------|
| Trivial return-constant (VS/PS) | ✅ | `float4 main() : SV_Target { return float4(...); }` |
| Control flow (if/else/for) | ✅ | `OpSelectionMerge` + `OpBranchConditional` + `OpLoopMerge` |
| Constant buffers (cbuffer) | ✅ | `OpTypeStruct` + `OpVariable` (Uniform) with binding decorations |
| Textures + samplers | ✅ | `OpTypeImage`/`OpTypeSampledImage`/`OpTypeSampler` + `.Sample` |
| Intrinsics (dot/mul/cross/normalize/clamp/lerp/abs/saturate/etc.) | ✅ | via `GLSL.std.450` `OpExtInst` |
| Vector swizzles (r-value) | ✅ | `OpVectorShuffle` + `OpCompositeExtract` |
| VS inputs/outputs (struct semantics) | ✅ | `OpVariable` Input/Output with `Location`/`BuiltIn` |
| l-value swizzles | — | not yet implemented |

## Anti-cheat

| Anti-cheat | Mode | Status | Reason |
|------------|------|--------|--------|
| EAC (with Linux support enabled by dev) | userland | ❌ not yet | requires M7+ |
| BattlEye (with Linux support enabled by dev) | userland | ❌ not yet | requires M7+ |
| Riot Vanguard | kernel | ❌ never (on Linux without VM) | loads a Windows kernel driver; cannot run on Linux without a VM. Not circumvented. |
| GameGuard | kernel | ❌ never (on Linux without VM) | same reason |

## Implemented Windows API surface

### PE loader (M0)
- PE32+ parsing, section mapping (W^X mmap), base relocations (DIR64), import resolution, TEB/PEB construction.

### Win64→SysV ABI thunk layer (M1)
- Inline-asm trampolines: register shuffle (RCX→RDI, RDX→RSI, R8→RDX, R9→RCX), stack arg repositioning, shadow space. Supports up to 32 args.
- `run_entrypoint_win64`: calls PE entrypoint with RCX=PEB, 32-byte shadow space.

### ntdll / ntapi (M1)
- Memory: VirtualAlloc/Free/Protect/Query (mmap/munmap/mprotect).
- Sync (futex-based): CRITICAL_SECTION (recursive), Event (auto/manual reset), Mutex (recursive), Semaphore, SRWLock, Sleep/WaitForSingleObject/MultipleObjects.
- Threads: CreateThread, GetCurrentThread/Process/Id, TLS (TlsAlloc/Get/Set/Free).
- Time: GetTickCount/64, QueryPerformanceCounter/Frequency.
- Process: ExitProcess/NtTerminateProcess, GetStdHandle/WriteFile/ReadFile, GetLastError/SetLastError.

### kernel32 / win32-kernel32 (M2)
- Console: GetStdHandle, WriteFile/ReadFile, WriteConsoleW/A, GetConsoleMode/SetConsoleMode.
- Files: CreateFileW/A, ReadFile/WriteFile, CloseHandle, GetFileSize, SetFilePointer, FlushFileBuffers.
- Heap: GetProcessHeap, HeapAlloc/Free/ReAlloc/Create/Destroy (libc malloc-backed).
- Environment: Get/SetEnvironmentVariableW, GetEnvironmentStringsW/Free.
- Process: GetCurrentProcessId/ThreadId, GetModuleHandleW/A, GetCommandLineW/A.
- String: MultiByteToWideChar/WideCharToMultiByte, lstrlenW/A, lstrcpyW/lstrcatW.

### user32 / win32-user32 (M3)
- Window class: RegisterClassExW, UnregisterClassW.
- Window: CreateWindowExW (backed by wsi::Window, headless-safe), DestroyWindow, ShowWindow, UpdateWindow.
- Geometry: GetClientRect, GetWindowRect, SetWindowPos, MoveWindow.
- Text: GetWindowTextW, SetWindowTextW.
- Message loop: GetMessageW, PeekMessageW, TranslateMessage, DispatchMessageW, PostQuitMessage, PostMessageW, SendMessageW, DefWindowProcW.
- Win64→SysV wndproc thunk (inline asm: 4 args via stack-packed array, shadow space, tail-call).

### gdi32 / win32-gdi32 (M3)
- Device contexts: GetDC/ReleaseDC, BeginPaint/EndPaint, CreateCompatibleDC/DeleteDC.
- Painting: ValidateRect, InvalidateRect, DeleteObject, SetPixel.

### Graphics (M6b)
- DXGI: Factory (Vulkan instance + device enumeration), SwapChain (headless VkSurfaceKHR + VkSwapchainKHR, Present, GetBuffer, ResizeBuffers).
- D3D11: Device (CreateTexture2D, CreateRenderTargetView, CreateShader, CreateBuffer, one_shot), DeviceContext (OMSetRenderTargets, ClearRenderTargetView, VSSetShader, PSSetShader, IASetVertexBuffers, Draw/DrawIndexed, Flush).
- HLSL→SPIR-V: see compiler coverage table above.

## Legend

- ✅ verified end-to-end in test harness
- 🚧 in progress
- ❌ not supported (with reason)
- — not yet reached

"Verified end-to-end" means a fixture or sample was driven through `nigg-loader` in the
`nigg-tests` harness (for PE targets) or the `clear_triangle` example (for Rust-native
D3D11) with the asserted behavior observed. See [development.md](development.md) for how
to build the fixtures and run the harness.
