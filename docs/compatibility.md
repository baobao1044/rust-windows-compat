# Compatibility Matrix

This matrix is kept honest. "Runs" means the scenario has been verified end-to-end in
this project's test harness. Empty cells mean not-yet-reached.

## Application classes

| Class | Status | Notes |
|-------|--------|-------|
| Console hello-world (x64) | 🚧 M0 target | first milestone |
| Console app with file I/O | — | M1/M2 |
| Win32 GUI (window + input) | — | M3 |
| .NET / WPF app | — | out of initial scope; needs CLR translation |
| D3D11 sample (clear/triangle) | — | M4/M6 |
| D3D11 indie game | — | M7 |
| D3D12 sample | — | M8 |
| Modern D3D11/12 game | — | M9 north star |

## Anti-cheat

| Anti-cheat | Mode | Status | Reason |
|------------|------|--------|--------|
| EAC (with Linux support enabled by dev) | userland | ❌ not yet | requires M6+ |
| BattlEye (with Linux support enabled by dev) | userland | ❌ not yet | requires M6+ |
| Riot Vanguard | kernel | ❌ never (on Linux without VM) | loads a Windows kernel driver; cannot run on Linux without a VM. Not circumvented. |
| GameGuard | kernel | ❌ never (on Linux without VM) | same reason |

## Legend

- ✅ verified end-to-end in test harness
- 🚧 in progress
- ❌ not supported (with reason)
- — not yet reached

"Verified end-to-end" means a fixture or sample was driven through `nigg-loader` in the
`nigg-tests` harness with the asserted behavior observed. See
[development.md](development.md) for how to build the fixtures and run the harness.
