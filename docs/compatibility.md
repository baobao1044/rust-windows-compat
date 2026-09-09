# Compatibility Matrix

This matrix is kept honest. "Runs" means the scenario has been verified end-to-end in
this project's test harness. Empty cells mean not-yet-reached.

## Application classes

| Class | Status | Notes |
|-------|--------|-------|
| Minimal PE (exit code) | ✅ M0 | `mov eax,42; ret` — runs natively via nigg-loader, exits 42 |
| PE importing kernel32 (ExitProcess) | ✅ M1 | PE calls `kernel32!ExitProcess(42)` via Win64→SysV ABI thunk, exits 42 |
| Console PE (WriteFile + ExitProcess) | ✅ M2 | PE prints "hello" via `WriteFile` to stdout, exits 0 |
| Rust-std console (hello.exe) | ✅ M7c | ~180 imports (Winsock, CRT, etc.) — all implemented via CRT expansion + soft-stub mode; `hello from windows binary` prints, exits 0 |
| Win32 GUI (window + message loop) | ✅ M3 | user32 RegisterClass/CreateWindow/GetMessage/DispatchMessage — headless-safe unit test; wired into pe-loader imports |
| D3D11 clear+triangle (Rust-native) | ✅ M6b | DXGI swap chain + D3D11 device over Vulkan; HLSL→SPIR-V; clear red + green triangle — verified via `clear_triangle` example |
| D3D11 sample via nigg-loader (PE) | ✅ M7c | COM vtable for D3D11/DXGI — d3d11_sample.exe + d3d11_triangle.exe both run through nigg-loader, exit 0 |
| Win32 GUI + D3D11 (game-window PE) | ✅ M7+ | RegisterClassExW + CreateWindowExW + D3D11CreateDeviceAndSwapChain (with HWND) + ClearRenderTargetView + Present + PeekMessageW — game_window.exe exits 0 |
| Real Windows app (notepad.exe) | ✅ M7+ | Real Windows x64 PE — 92 imports all resolved (0 stubs), survives CRT init + enters message loop |
| Game-like PE (system-integrity + D3D11) | ✅ M9d | Anti-cheat simulation + D3D11 clear+present in a single fixture — game_visual.exe exits 0 via nigg-loader (debugger/module/SecureBoot checks pass, then D3D11 pipeline) |
| D3D11 game engine (StarEngine) | 🚧 M9 | Real x64 D3D11 game engine (StarGame.exe, 2.5MB, 14 DLLs, 204 imports) — loads via nigg-loader, survives CRT init, calls GetModuleHandleW, starts executing game code. Crashes when PhysX/lua/assimp stubs return NULL (DLLs not available). Next: implement remaining DLL stubs or LoadLibrary-from-disk for the game's bundled DLLs. |
| D3D12 clear-screen (Rust-native) | ✅ M8 | D3D12 → Vulkan: Device, CommandQueue, CommandList, DescriptorHeap, Resource, PipelineState, RootSignature — clear-screen test exercises real Vulkan path end-to-end |
| D3D12 sample via nigg-loader (PE) | ✅ M8b | COM vtable for D3D12 — d3d12_sample.exe runs full command-list pipeline through nigg-loader, exit 0 |
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

### ntdll / ntapi (M1, M7c)
- Memory: VirtualAlloc/Free/Protect/Query (mmap/munmap/mprotect).
- Sync (futex-based): CRITICAL_SECTION (recursive), Event (auto/manual reset), Mutex (recursive), Semaphore, SRWLock, Sleep/WaitForSingleObject/MultipleObjects.
- Threads: CreateThread, GetCurrentThread/Process/Id, TLS (TlsAlloc/Get/Set/Free).
- Time: GetTickCount/64, QueryPerformanceCounter/Frequency.
- Process: ExitProcess/NtTerminateProcess, GetStdHandle/WriteFile/ReadFile, GetLastError/SetLastError.
- Files: NtWriteFile/NtReadFile (real stdout/stdin path for Rust std; fill IO_STATUS_BLOCK).

### kernel32 / win32-kernel32 (M2, M7c)
- Console: GetStdHandle, WriteFile/ReadFile, WriteConsoleW/A, GetConsoleMode/SetConsoleMode.
- Files: CreateFileW/A, ReadFile/WriteFile, CloseHandle, GetFileSize, SetFilePointer, FlushFileBuffers.
- Heap: GetProcessHeap, HeapAlloc/Free/ReAlloc/Create/Destroy (libc malloc-backed).
- Environment: Get/SetEnvironmentVariableW, GetEnvironmentStringsW/Free.
- Process: GetCurrentProcessId/ThreadId, GetModuleHandleW/A, GetCommandLineW/A.
- String: MultiByteToWideChar/WideCharToMultiByte, lstrlenW/A, lstrcpyW/lstrcatW.
- CRT (msvcrt, M7c): malloc/calloc/free/realloc, strlen/strncmp/memcmp, fprintf/vfprintf, __getmainargs/__initenv/__set_app_type/__setusermatherr/_amsg_exit/_cexit/_commode/_fmode/_fpreset/_initterm/atexit/abort/exit/signal.
- Extras (M7c): InitOnceBeginInitialize/Complete (tracks completed INIT_ONCE by address), AddVectoredExceptionHandler, GetSystemTimePreciseAsFileTime, WaitOnAddress/WakeByAddressAll/WakeByAddressSingle, ProcessPrng, RtlCaptureContext.
- Soft-stub mode (NIGG_SOFT_STUBS=1): unimplemented imports get a no-op that logs once and returns 0, so CRT init survives calls to unimplemented APIs.

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

### Graphics (M6b, M8, M8b)
- DXGI: Factory (Vulkan instance + device enumeration), SwapChain (headless VkSurfaceKHR + VkSwapchainKHR, Present, GetBuffer, ResizeBuffers).
- D3D11: Device (CreateTexture2D, CreateRenderTargetView, CreateShader, CreateBuffer), DeviceContext (OMSetRenderTargets, ClearRenderTargetView, VSSetShader, PSSetShader, IASetVertexBuffers, Draw/DrawIndexed, Flush).
- D3D12 (M8): Device (CreateCommandQueue/Allocator/List, CreateDescriptorHeap, CreateRenderTargetView, CreateCommittedResource, CreatePipelineState, CreateRootSignature), CommandQueue (ExecuteCommandLists), GraphicsCommandList (Close, SetPipelineState, SetRenderTargets, ClearRenderTargetView, ResourceBarrier, SetViewport, SetScissorRect, DrawInstanced), DescriptorHeap (RTV/DSV/CBV_SRV_UAV/Sampler), Resource (Map/Unmap), PipelineState, RootSignature.
- HLSL→SPIR-V: see compiler coverage table above.

### Anti-cheat support APIs (M7+)
- Debug detection: IsDebuggerPresent, CheckRemoteDebuggerPresent, OutputDebugStringA/W.
- Process enumeration: CreateToolhelp32Snapshot, Process32FirstW/NextW, Module32FirstW/NextW.
- Process memory: OpenProcess, ReadProcessMemory, WriteProcessMemory (self-process → memcpy).
- Winsock2 (ws2_32.dll, M7+): WSAStartup/Cleanup/GetLastError, socket, connect, bind, listen, accept, send, recv, sendto, recvfrom, setsockopt, getsockopt, ioctlsocket, gethostname, inet_addr, htons/htonl/ntohs/ntohl, shutdown, select — 24 exports for anti-cheat network telemetry.
- Registry (advapi32.dll): RegOpenKeyW/ExW, RegCreateKeyExW, RegCloseKey, RegQueryValueExW, RegSetValueExW, RegEnumKeyW, RegEnumValueW, RegDeleteKeyW, IsTextUnicode.

### Additional DLLs (M7+)
- ucrtbase.dll (Universal CRT): 57 exports — malloc/calloc/free/realloc, string functions, CRT init, exit family, formatted I/O.
- shell32.dll: 12 exports — DragAcceptFiles/Finish/QueryFile, ShellAboutW, ShellExecuteW/A, SHGetFolderPathW/A.
- shlwapi.dll: 18 exports — path helpers (PathFindFileNameW/A, PathAppendW, etc.), string compare (StrCmpIW/W/NIW/NW), substring search (StrStrW/IW).
- comdlg32.dll: 7 exports — GetOpenFileNameW, GetSaveFileNameW, ChooseFontW, etc. (stubs).
- comctl32.dll: InitCommonControls/Ex + ordinals (stubs).

## Legend

- ✅ verified end-to-end in test harness
- 🚧 in progress
- ❌ not supported (with reason)
- — not yet reached

"Verified end-to-end" means a fixture or sample was driven through `nigg-loader` in the
`nigg-tests` harness (for PE targets) or the `clear_triangle` example (for Rust-native
D3D11) with the asserted behavior observed. See [development.md](development.md) for how
to build the fixtures and run the harness.
