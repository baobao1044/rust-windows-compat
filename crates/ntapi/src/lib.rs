//! ntdll / kernel32 reimplementation: memory, futex-based synchronization, threads,
//! handles, files, time, and process termination — all built on Linux syscalls.
//!
//! This crate provides the Windows API surface the PE loader's import thunks call into.
//! Every implementation is pure Rust on top of `libc` (Linux syscalls) plus a few host
//! bindings (`parking_lot`, `bitflags`); no Wine/ntsync code is reused.
//!
//! # Modules
//!
//! - `futex` — thin wrappers over the Linux `futex(2)` syscall used by the sync primitives.
//! - `handle` — the process-global `HANDLE -> Object` table and `NtClose`.
//! - `sync` — `CRITICAL_SECTION`, `Event`, `Mutex`, `Semaphore`, `SRWLock`, `Sleep`,
//!   `WaitForSingleObject`/`WaitForMultipleObjects`.
//! - `thread` — `CreateThread`, `GetCurrentThread`/`Id`, TLS (`TlsAlloc`/`Get`/`Set`/`Free`).
//! - `memory` — `VirtualAlloc`/`VirtualFree`/`VirtualProtect`/`VirtualQuery`.
//! - `process` — `ExitProcess`/`NtTerminateProcess`, time (`GetTickCount`/`64`,
//!   `QueryPerformanceCounter`/`Frequency`), stdio (`GetStdHandle`/`WriteFile`/`ReadFile`),
//!   `GetLastError`/`SetLastError`, and the `NtCreateFile`/`NtClose` file layer.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment.

#![deny(unsafe_op_in_unsafe_fn)]
// The `extern "C"` functions in this crate implement Windows APIs that take raw pointers.
// They are called from PE machine code via ABI trampolines, not from safe Rust callers, so
// marking them `unsafe` would not help — the lint does not apply to this use case.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod futex;
pub mod handle;
pub mod memory;
pub mod process;
pub mod sync;
pub mod thread;

// Re-export the most commonly used types and constants at the crate root for convenience.
pub use handle::Handle;

/// `INFINITE` wait timeout (re-exported for callers).
pub const INFINITE: u32 = 0xFFFF_FFFF;
