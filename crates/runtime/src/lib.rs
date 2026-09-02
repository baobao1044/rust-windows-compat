//! Process bootstrap for running mapped Windows PE images natively on Linux.
//!
//! This crate provides the low-level primitives the PE loader needs to actually *execute*
//! a loaded image:
//!
//! - [`set_thread_gs_base`] installs a Thread Environment Block (TEB) pointer into the
//!   x86-64 `gs` base via `arch_prctl(ARCH_SET_GS)`, so Windows code that reads the TIB
//!   fields through `gs:[0x...]` keeps working.
//! - [`Stack`] allocates a private, zeroed call stack with a guard page via `mmap`.
//! - [`run_entrypoint`] switches to that stack and calls the PE entrypoint as a
//!   parameterless `extern "C" fn() -> i32`, returning the process exit code.
//!
//! ## Simplifications (Phase 1 / M0)
//!
//! The real Windows entrypoint (`DllMain` / `mainCRTStartup`) receives arguments in the
//! x64 Windows calling convention: `RCX = ImageBase`, `RDX = ...`, etc. For M0 the
//! entrypoint is treated as a **parameterless** function returning the exit code in
//! `eax`/`rax`. Both the Windows x64 and System V x64 ABIs return `i32` in `eax`, so a
//! plain `extern "C"` (System V) call of a parameterless entry yields the correct exit
//! code for the minimal fixture. Argument passing is deferred to a later milestone.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced: every `unsafe` block carries a
//! `SAFETY:` comment justifying why the operation is sound.

#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use std::fmt;

/// `ARCH_SET_GS` code for `arch_prctl(2)` on x86-64 (not exposed by `libc`; documented in
/// `arch_prctl(2)`). Sets the `gs` base register to the given address.
const ARCH_SET_GS: i64 = 0x1001;

/// Default stack size for a guest thread (1 MiB committed), matching a conservative
/// Windows default. `mmap` is lazy, so only touched pages consume physical memory.
const DEFAULT_STACK_SIZE: usize = 1 << 20;
/// Size of a guard page placed at the bottom of the stack to catch overflow.
const GUARD_PAGE_SIZE: usize = 4096;

/// A privately `mmap`-allocated call stack for executing a PE entrypoint on.
///
/// The usable region is `[base + GUARD_PAGE_SIZE, base + GUARD_PAGE_SIZE + len)`. The
/// bottom page is mapped `PROT_NONE` as a stack-overflow guard. The stack grows down,
/// so the initial stack pointer is the top of the usable region, 16-byte aligned to
/// satisfy the System V x86-64 ABI at the point of the `call` instruction.
pub struct Stack {
    base: *mut u8,
    // Total mapped length, including the guard page. Kept so `Drop` can unmap the whole
    // mapping even though `top()` only exposes the usable region.
    total_len: usize,
}

impl Stack {
    /// Allocate a stack of `len` usable bytes (plus one guard page).
    ///
    /// Returns a [`Stack`] whose [`Stack::top`] is the aligned initial stack pointer.
    pub fn new(len: usize) -> Result<Stack, StackError> {
        // Round the usable length up to a page so the guard page and usable region land
        // on page boundaries required by `mprotect`.
        let usable = round_up_to_page(len);
        let total_len = usable + GUARD_PAGE_SIZE;

        // SAFETY: `mmap` with `MAP_ANONYMOUS | MAP_PRIVATE` and `fd = -1` requests a new
        // zero-filled anonymous mapping. `addr = null` lets the kernel choose the
        // address. The returned pointer is valid for `total_len` bytes on success.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(StackError::MapFailed(errno()));
        }

        let base = base as *mut u8;

        // Drop the bottom guard page to `PROT_NONE` so a stack overflow traps with SIGSEGV
        // rather than silently corrupting neighbouring memory.
        // SAFETY: `base` is a valid mapping of `total_len` bytes returned by `mmap`, and
        // `GUARD_PAGE_SIZE` is page-aligned and within that mapping.
        let guard =
            unsafe { libc::mprotect(base as *mut libc::c_void, GUARD_PAGE_SIZE, libc::PROT_NONE) };
        if guard != 0 {
            // SAFETY: `base` was successfully mapped above for `total_len` bytes; we own it
            // and must release it before returning an error.
            unsafe { libc::munmap(base as *mut libc::c_void, total_len) };
            return Err(StackError::GuardFailed(errno()));
        }

        Ok(Stack { base, total_len })
    }

    /// Allocate a stack of the default size (1 MiB usable).
    ///
    /// Named `new_default` rather than `default` because the latter shadows
    /// [`std::default::Default::default`]; `Stack` cannot implement `Default` since
    /// allocation is fallible (returns `Result`).
    pub fn new_default() -> Result<Stack, StackError> {
        Self::new(DEFAULT_STACK_SIZE)
    }

    /// The initial stack pointer for this stack: the top of the usable region, aligned
    /// down to 16 bytes to satisfy the System V x86-64 ABI at the `call` site.
    pub fn top(&self) -> *mut u8 {
        let usable_top = unsafe { self.base.add(GUARD_PAGE_SIZE + self.usable_len()) };
        // `mmap` returns a page-aligned address and `usable_len` is page-aligned, so the
        // top is already page-aligned (hence 16-aligned). Align defensively anyway.
        let addr = usable_top as usize;
        let aligned = addr & !0xF;
        aligned as *mut u8
    }

    fn usable_len(&self) -> usize {
        self.total_len - GUARD_PAGE_SIZE
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // SAFETY: `self.base`/`self.total_len` describe the exact mapping obtained in
        // `new` (or the leftover after a partial failure already unmapped it, in which
        // case a second `munmap` is a harmless no-op error). We unmap it exactly once.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.total_len);
        }
    }
}

impl fmt::Debug for Stack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stack")
            .field("base", &self.base)
            .field("total_len", &self.total_len)
            .field("top", &self.top())
            .finish()
    }
}

#[derive(Debug)]
pub enum StackError {
    /// `mmap` of the stack region failed.
    MapFailed(i32),
    /// `mprotect` of the guard page failed.
    GuardFailed(i32),
}

impl std::error::Error for StackError {}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StackError::MapFailed(e) => write!(f, "mmap of stack failed (errno {e})"),
            StackError::GuardFailed(e) => {
                write!(f, "mprotect of stack guard page failed (errno {e})")
            }
        }
    }
}

/// Install `teb` as the x86-64 `gs` base so that `gs:[0x...]` reads land in the TEB.
///
/// On Windows the per-thread TEB is reached through the `gs` segment register. On
/// Linux/x86-64 the equivalent is the `gs` base register, set through
/// `arch_prctl(ARCH_SET_GS, addr)`.
pub fn set_thread_gs_base(teb: *mut ()) -> Result<(), BootstrapError> {
    // SAFETY: `arch_prctl` is a Linux x86-64 syscall (number 158, exposed by libc as
    // `SYS_arch_prctl`). `ARCH_SET_GS` sets the `gs` base to the provided address. The
    // address must be a valid, readable, naturally-aligned userspace pointer; the caller
    // supplies the TEB, which is a live, page-aligned allocation. `syscall` returns 0 on
    // success or a negative errno on failure.
    let rc = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, teb as *mut libc::c_void) };
    if rc != 0 {
        return Err(BootstrapError::SetGsFailed((-rc) as i32));
    }
    Ok(())
}

/// Call the PE `entry` on `stack_top`, returning the value left in `eax` (the exit code).
///
/// The function pointer is the image's entrypoint address, treated as a parameterless
/// `extern "C" fn() -> i32` (see the crate-level simplifications note). The stack pointer
/// must be 16-byte aligned; [`Stack::top`] guarantees this.
///
/// # Safety
///
/// `entry` must point to valid, executable, position-appropriate machine code (a mapped
/// PE entrypoint with relocations applied), and `stack_top` must be a valid, writable,
/// 16-aligned stack pointer with sufficient space below it. The caller upholds these by
/// passing the loader's resolved entrypoint and a freshly allocated [`Stack::top`].
pub unsafe fn run_entrypoint(entry: *const (), stack_top: *mut u8) -> i32 {
    let mut result: i32;

    // We use r12 to stash the caller's RSP across the call. r12 is callee-saved under the
    // System V x86-64 ABI, so the called PE entrypoint will not clobber it, which lets us
    // recover the original stack after the entrypoint returns. Declaring r12 as an output
    // tells the compiler it is modified by this block, so it saves/restores the caller's
    // r12 around us.
    //
    // Clobbers: the `call` transfers control to System V code that may freely modify the
    // caller-saved registers rax (the return value, captured below), rcx, rdx, rsi, rdi,
    // r8-r11. The flags register is implicitly clobbered (we do not set `preserves_flags`).
    // rbp, rbx and r13-r15 are callee-saved and intentionally not listed.
    //
    // SAFETY: inline assembly that swaps `rsp` to `stack_top`, calls `entry`, and
    // restores `rsp` from r12. `stack_top` is 16-byte aligned (ABI requirement at the
    // `call` instruction) and has usable space below it; `entry` is a valid executable
    // entrypoint supplied by the caller. `extern "C"` (System V) and Windows x64 both
    // return `i32` in `eax`/`rax`, so `out("rax") result` captures the exit code.
    unsafe {
        asm!(
            "mov r12, rsp",
            "mov rsp, {sp}",
            "call {entry}",
            "mov rsp, r12",
            sp = in(reg) stack_top,
            entry = in(reg) entry,
            out("r12") _,
            out("rax") result,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }

    result
}

/// Call the PE `entry` on `stack_top` using the **Windows x64 calling convention** for the
/// entrypoint, returning the value left in `eax` (the exit code).
///
/// Real Windows PE entrypoints expect to be called per the Windows x64 ABI: the caller must
/// reserve a 32-byte "shadow space" on the stack (above the return address) that the callee
/// may use to spill the first four register arguments, and `RSP` must be 16-byte aligned at
/// the `call` instruction. We place the first argument in `RCX` and the second in `RDX`:
///
/// - `RCX = peb`  — the PEB pointer (read by `mainCRTStartup`-style entries via `gs:[0x60]`,
///   and a harmless non-null value for entries that ignore it).
/// - `RDX = 0`    — the second parameter, unused for EXE CRT startup (it would be the
///   `DllMain` reason for a DLL; we pass 0).
///
/// This is the simple convention the task brief asks for; richer entrypoint signatures
/// (`main(argc, argv, envp)` in RCX/RDX/R8) are a later refinement. The minimal fixture
/// (`mov eax,42; ret`) ignores all arguments, so it keeps working under this calling
/// convention.
///
/// # Safety
///
/// `entry` must point to valid, executable, position-appropriate machine code (a mapped PE
/// entrypoint with relocations applied), and `stack_top` must be a valid, writable,
/// 16-aligned stack pointer with at least 40 bytes (32 shadow + 8 return address) of usable
/// space below it. `peb` must be a valid readable pointer if the entrypoint dereferences it
/// (the loader supplies the live PEB). The caller upholds these by passing the loader's
/// resolved entrypoint, a freshly allocated [`Stack::top`], and the TEB/PEB's PEB address.
pub unsafe fn run_entrypoint_win64(entry: *const (), stack_top: *mut u8, peb: *mut ()) -> i32 {
    let mut result: i32;

    // We reserve 32 bytes of shadow space at [stack_top - 0x20, stack_top). The `call` then
    // pushes the return address at [stack_top - 0x28], so the entrypoint sees RSP =
    // stack_top - 0x28 ≡ 8 (mod 16) (since stack_top is 16-aligned), which is the Windows
    // x64 callee-entry alignment. The shadow space lives at [RSP+8 .. RSP+0x28].
    //
    // r12 stashes the caller's RSP (callee-saved by the PE entry under the Windows ABI,
    // which — like System V — preserves r12/rbp/rbx/r13-r15). We load RCX=peb and RDX=0,
    // switch to the guest stack with the shadow space carved out, `call` the entrypoint,
    // and restore RSP from r12. RAX holds the i32 return value (same register in both
    // ABIs).
    //
    // SAFETY: `entry` is a valid executable entrypoint; `stack_top` is 16-aligned with >=
    // 40 bytes of usable space below it (the loader's Stack guarantees far more); `peb` is
    // the live PEB pointer. The inline asm only manipulates RSP and the argument registers
    // and captures RAX; r12 is restored by `mov rsp, r12` (it survives the call because it
    // is callee-saved).
    unsafe {
        asm!(
            "mov r12, rsp",
            "mov rcx, {peb}",
            "xor rdx, rdx",
            "mov rsp, {sp}",
            "sub rsp, 0x20",
            "call {entry}",
            "mov rsp, r12",
            sp = in(reg) stack_top,
            peb = in(reg) peb,
            entry = in(reg) entry,
            out("r12") _,
            out("rax") result,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }

    result
}

#[derive(Debug)]
pub enum BootstrapError {
    /// `arch_prctl(ARCH_SET_GS)` failed.
    SetGsFailed(i32),
}

impl std::error::Error for BootstrapError {}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapError::SetGsFailed(e) => {
                write!(f, "arch_prctl(ARCH_SET_GS) failed (errno {e})")
            }
        }
    }
}

/// Round `n` up to a multiple of the page size.
fn round_up_to_page(n: usize) -> usize {
    let page = page_size();
    (n + page - 1) & !(page - 1)
}

fn page_size() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` is always safe to call and returns the page size,
    // or -1 on error (which we treat as 4096, the x86-64 Linux default).
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p <= 0 {
        4096
    } else {
        p as usize
    }
}

/// Read the thread-local `errno` value via `__errno_location`.
fn errno() -> i32 {
    // SAFETY: `__errno_location` returns a pointer to a thread-local `int` holding the
    // most recent syscall error; reading it is safe and does not race (thread-local).
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly allocated stack reports a 16-byte-aligned top and a non-null base.
    #[test]
    fn stack_is_aligned_and_nonnull() {
        let stack = Stack::new_default().expect("stack alloc");
        let top = stack.top();
        assert!(!top.is_null());
        assert_eq!(top as usize % 16, 0, "stack top must be 16-byte aligned");
    }

    /// `set_thread_gs_base` accepts a valid aligned buffer and does not error. We point
    /// `gs` at a throwaway page-aligned allocation; subsequent `gs:[...]` reads are not
    /// exercised here, only that the `arch_prctl` call itself succeeds.
    #[test]
    fn set_gs_base_accepts_aligned_pointer() {
        // mmap a page to use as a stand-in TEB so the address is valid and page-aligned.
        // SAFETY: anonymous private mapping of one page; checked against MAP_FAILED.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let res = set_thread_gs_base(p as *mut ());
        // SAFETY: release the one-page mapping we allocated for the test.
        unsafe {
            libc::munmap(p, 4096);
        }
        res.expect("arch_prctl(ARCH_SET_GS) should succeed for a valid pointer");
    }
}

#[cfg(test)]
mod trampoline_tests {
    use super::*;

    extern "C" fn returns_42() -> i32 {
        42
    }

    /// The trampoline switches to a fresh stack, calls a Rust `extern "C"` fn, restores the
    /// original stack, and returns the value. This validates the inline-asm stack switch in
    /// isolation before the PE loader relies on it for arbitrary mapped machine code.
    #[test]
    fn trampoline_calls_function_on_fresh_stack() {
        let stack = Stack::new_default().expect("stack alloc");
        // SAFETY: `returns_42` is a normal, executable Rust function and `stack.top()` is a
        // valid, 16-byte-aligned, writable stack pointer with space below it.
        let code = unsafe { run_entrypoint(returns_42 as *const (), stack.top()) };
        assert_eq!(
            code, 42,
            "trampoline must return the entrypoint's return value"
        );
    }
}
