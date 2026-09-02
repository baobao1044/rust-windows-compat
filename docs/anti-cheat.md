# Anti-Cheat Support — Honest Assessment

This document is kept honest. We do not circumvent anti-cheat systems, DMCA
protections, or Terms of Service. We document what is technically feasible
through legitimate compatibility and what is not.

## TL;DR

- **Kernel-level anti-cheat** (Vanguard, GameGuard, nProtect, Denuvo Anti-Cheat):
  **cannot run on Linux without a VM**. They load Windows kernel drivers that
  require the Windows kernel. This is a hard technical limitation, not a matter
  of implementation effort. We do not and will not circumvent them.
- **Userland anti-cheat** (EAC, BattlEye with Linux support enabled by the
  developer): **theoretically feasible** through our compatibility layer, but
  requires the game itself to run first and many anti-cheat-specific APIs to be
  implemented. This is a very long-term goal.
- **Games with native Linux ports**: already run on Linux without our layer.
  Steam's Proton already handles most of these cases via Wine/DXVK.

## Anti-Cheat Categories

### 1. Kernel-Level (NOT Supported, NOT Circumvented)

| Anti-Cheat | Vendor | Mechanism | Linux Without VM |
|------------|--------|-----------|------------------|
| Riot Vanguard | Riot Games | Loads `vgk.sys` kernel driver at boot | ❌ Impossible — requires Windows kernel |
| nProtect GameGuard | INCA Internet | Loads kernel driver `npggNT.sys` | ❌ Impossible — requires Windows kernel |
| Denuvo Anti-Cheat | Denuvo | Kernel-mode driver | ❌ Impossible — requires Windows kernel |
| FaceIT Anti-Cheat | FaceIT | Kernel driver `faceit.sys` | ❌ Impossible — requires Windows kernel |
| EQU8 | EQU8 | Kernel driver | ❌ Impossible — requires Windows kernel |

**Why these cannot work:** These anti-cheat systems load a Windows kernel
driver (`.sys` file) that hooks into the Windows kernel's internal structures
(`PsSetCreateProcessNotifyRoutine`, `MmCopyVirtualMemory`, SSDT hooks, etc.).
The Linux kernel has a completely different architecture. Running a Windows
kernel driver on Linux would require either:
- A full virtual machine (which we explicitly do not do)
- A Windows kernel emulation layer (which is effectively writing a Windows
  kernel — orders of magnitude harder than what we're doing)

**We do NOT attempt to circumvent these.** We document them as unsupported.

### 2. Userland (Theoretically Feasible, Long-Term)

| Anti-Cheat | Vendor | Mechanism | Feasibility |
|------------|--------|-----------|-------------|
| Easy Anti-Cheat (EAC) | Epic Games | Userland DLL `EasyAntiCheat.dll` | 🟡 Feasible if dev enables Linux support AND the game runs |
| BattlEye | BattlEye | Userland DLL `BEClient.dll` | 🟡 Same as EAC |
| VAC (Valve) | Valve | Userland, kernel-mode optional | 🟡 VAC is already lightweight; mostly signature-based |

**How userland anti-cheat works:** The game loads a DLL (e.g.
`EasyAntiCheat.dll`) at startup. This DLL:
1. Validates the game process integrity (checksums, module enumeration)
2. Scans for known cheat signatures (memory scanning)
3. Monitors for debugger attachment (`IsDebuggerPresent`, `NtQueryInformationProcess`)
4. Enumerates loaded modules (`EnumProcessModules`, `Module32First/Next`)
5. Checks for hooks in critical functions
6. Sends telemetry to the anti-cheat server

**What we need to support userland anti-cheat:**

The anti-cheat DLL is just another PE DLL. It loads through our PE loader and
calls Windows APIs through our thunk layer. The critical APIs it needs:

#### Process/Module Enumeration
- `EnumProcessModules` / `EnumProcessModulesEx` (psapi.dll)
- `GetModuleInformation` (psapi.dll)
- `GetModuleBaseNameW` / `GetModuleFileNameExW` (psapi.dll)
- `Module32FirstW` / `Module32NextW` (kernel32.dll, via CreateToolhelp32Snapshot)
- `Process32FirstW` / `Process32NextW` (kernel32.dll, via CreateToolhelp32Snapshot)
- `CreateToolhelp32Snapshot` (kernel32.dll)

#### Process Information
- `OpenProcess` (kernel32.dll) — return a pseudo-handle for current process
- `GetCurrentProcess` / `GetCurrentProcessId` (kernel32.dll) — ✅ already implemented
- `NtQueryInformationProcess` (ntdll.dll) — return basic process info
- `GetExitCodeProcess` (kernel32.dll)
- `WaitForSingleObject` / `WaitForMultipleObjects` (kernel32.dll) — ✅ already implemented

#### Memory Operations
- `ReadProcessMemory` / `WriteProcessMemory` (kernel32.dll) — for self-process, delegate to memcpy
- `VirtualQuery` / `VirtualQueryEx` (kernel32.dll) — ✅ VirtualQuery partially implemented
- `VirtualProtect` / `VirtualProtectEx` (kernel32.dll) — ✅ already implemented

#### Debug Detection
- `IsDebuggerPresent` (kernel32.dll) — return FALSE
- `CheckRemoteDebuggerPresent` (kernel32.dll) — set result to FALSE
- `OutputDebugStringA` / `OutputDebugStringW` (kernel32.dll) — no-op

#### Integrity Checking
- `GetTickCount64` / `QueryPerformanceCounter` (kernel32.dll) — ✅ already implemented
- `GetSystemTimeAsFileTime` (kernel32.dll) — ✅ partially implemented
- `CreateFileW` / `ReadFile` (kernel32.dll) — ✅ already implemented
- `GetFileAttributesW` (kernel32.dll) — needed
- `MapFileToMemory` (via CreateFileMapping + MapViewOfFile) — needed

#### Network (Telemetry)
- `WSASend` / `WSARecv` / `WSAStartup` / `WSACleanup` (ws2_32.dll) — needed for network
- `getaddrinfo` / `gethostbyname` (ws2_32.dll) — needed for DNS
- `connect` / `send` / `recv` (ws2_32.dll) — needed for TCP

### 3. Already Working (Steam/Linux Native)

Many games with EAC or BattlEye already run on Linux through Steam's Proton
(Wine + DXVK) when the developer enables Linux support:
- Fortnite (EAC with Linux support) — runs via Wine/Proton
- Rust (EAC with Linux support) — runs via Wine/Proton
- ARK: Survival Evolved (BattlEye with Linux support) — runs via Wine/Proton
- DayZ (BattlEye with Linux support) — runs via Wine/Proton

For these games, our compatibility layer is NOT needed — Steam Proton already
handles them. Our layer is for the case where the developer has NOT enabled
Linux support and the anti-cheat runs in userland mode.

## Current Status (M8b)

| Capability | Status | Notes |
|-----------|--------|-------|
| PE loader (x64) | ✅ | Loads real Windows x64 PEs (notepad.exe loads with soft stubs) |
| ABI thunk (Win64→SysV) | ✅ | Register shuffle, stack args, shadow space, up to 32 args |
| kernel32 subset | ✅ | ~80 APIs (console, files, heap, env, strings, process, time, sync) |
| user32 subset | ✅ | ~20 APIs (window class, create window, message loop, wndproc) |
| gdi32 subset | ✅ | ~10 APIs (DC, paint — minimal) |
| msvcrt CRT | ✅ | ~30 functions (malloc, string, printf, CRT init) |
| ucrtbase CRT | 🚧 | In progress (agent implementing) |
| advapi32 registry | 🚧 | In progress (agent implementing) |
| shell32/shlwapi | 🚧 | In progress (agent implementing) |
| D3D11 → Vulkan | ✅ | Device, context, textures, shaders, render targets |
| D3D12 → Vulkan | ✅ | Device, command queue/list, descriptor heaps, pipeline state |
| HLSL → SPIR-V | ✅ | Lexer, parser, codegen (6 features) |
| DXGI swap chain | ✅ | Headless VkSurfaceKHR + VkSwapchainKHR |
| Process/module enumeration | ❌ | Needed for anti-cheat (psapi, toolhelp) |
| Network (ws2_32) | ❌ | Needed for anti-cheat telemetry |
| Debug detection APIs | ❌ | IsDebuggerPresent, CheckRemoteDebuggerPresent |
| psapi.dll | ❌ | EnumProcessModules, GetModuleInformation |
| CreateToolhelp32Snapshot | ❌ | Process32First/Next, Module32First/Next |
| CreateFileMapping/MapViewOfFile | ❌ | Needed for integrity checking |

## Path to Anti-Cheat Support

### Phase 1: Real Game Binary Loads (current)
- ✅ PE loader works for x64 PEs
- ✅ D3D11/D3D12 over Vulkan works
- 🚧 Implementing missing DLLs (ucrtbase, advapi32, shell32, shlwapi)
- Next: implement comctl32, comdlg32, more kernel32, psapi

### Phase 2: Game Runs (renders + accepts input)
- Implement more kernel32 (FindFirstFile, MulDiv, LocalFree, etc.)
- Implement comctl32 (InitCommonControls)
- Wire up real X11/Wayland window to DXGI swap chain (currently headless)
- Implement XInput → evdev gamepad input
- Implement audio (XAudio → PipeWire)
- Target: a real indie game (e.g. a small D3D11 game) runs and renders

### Phase 3: Anti-Cheat DLL Loads
- Implement psapi.dll (EnumProcessModules, GetModuleInformation)
- Implement CreateToolhelp32Snapshot + Process32/Module32 enumeration
- Implement IsDebuggerPresent, CheckRemoteDebuggerPresent, OutputDebugString
- Implement ReadProcessMemory/WriteProcessMemory (self-process → memcpy)
- Implement CreateFileMapping + MapViewOfFile
- Implement ws2_32.dll (socket, connect, send, recv, WSAStartup)
- Target: an EAC/BattlEye DLL loads and initializes without crashing

### Phase 4: Anti-Cheat Passes Validation
- The anti-cheat DLL validates the process and sends telemetry
- The anti-cheat server accepts or rejects the connection
- This depends on the anti-cheat server's tolerance for non-Windows clients
- **This phase may never work** — the server can detect we're not Windows

## Honest Assessment

Running a game with anti-cheat through our compatibility layer is a
**multi-year research effort** with no guarantee of success:

1. The game itself must run (requires 1000+ Windows APIs — we have ~200)
2. The anti-cheat DLL must load (requires psapi, toolhelp, network APIs)
3. The anti-cheat server must accept our client (may detect non-Windows)
4. The anti-cheat's integrity checks must pass (may detect our translation layer)

We document this honestly. We do not claim anti-cheat works. We do not
circumvent anti-cheat. We build the compatibility infrastructure and let
the community assess what's possible.

The most realistic path to running games with anti-cheat on Linux remains:
- **Games with Linux-native anti-cheat support** → use Steam Proton (Wine + DXVK)
- **Games with kernel-level anti-cheat** → not possible without a VM
- **Games with userland anti-cheat, no Linux support** → our layer is the
  long-term research path, but success is not guaranteed

## API Implementation Priority for Anti-Cheat

These are the APIs needed for Phase 3 (anti-cheat DLL loads), in priority order:

1. `CreateToolhelp32Snapshot` + `Process32FirstW`/`Process32NextW` + `Module32FirstW`/`Module32NextW`
2. `EnumProcessModules` + `GetModuleBaseNameW` + `GetModuleFileNameExW` (psapi.dll)
3. `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` + `OutputDebugStringA/W`
4. `OpenProcess` (return pseudo-handle for current process)
5. `ReadProcessMemory` + `WriteProcessMemory` (self-process → memcpy)
6. `CreateFileMappingW` + `MapViewOfFile` + `UnmapViewOfFile`
7. `NtQueryInformationProcess` (return ProcessBasicInfo)
8. `WSAStartup` + `socket` + `connect` + `send` + `recv` + `closesocket` (ws2_32.dll)
9. `GetFileAttributesW` + `SetFileAttributesW`
10. `GetUserNameW` + `GetComputerNameW`
