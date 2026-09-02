//! Windows x64 -> System V x64 ABI translation thunks.
//!
//! Windows PE code calls imported functions through the Import Address Table (IAT): the
//! PE does `call [iat_slot]`, so control lands in whatever function pointer the loader
//! wrote into the slot. On Windows those calls use the **Windows x64 ABI**: integer/pointer
//! arguments travel in `RCX, RDX, R8, R9` (then the stack, after a 32-byte shadow space the
//! caller reserves), and the return value comes back in `RAX`.
//!
//! Our import implementations are ordinary Rust `extern "C"` functions, which on Linux use
//! the **System V x64 ABI**: arguments travel in `RDI, RSI, RDX, RCX, R8, R9` (then the
//! stack), return value in `RAX`.
//!
//! Feeding the PE's Windows-ABI `call` straight into a System-V Rust function is the #1
//! blocker for real PE binaries: the first four arguments land in the wrong registers. This
//! module fixes that by generating a tiny per-import **trampoline** in executable memory.
//! The trampoline is the address written into the IAT. When the PE calls it, the trampoline
//! shuffles the Windows argument registers into the System V ones, copies any stack
//! arguments into the System V stack layout, and tail-calls (or call+ret for returning
//! functions) the Rust implementation.
//!
//! ## Register shuffle (Windows -> System V, first 4 integer args)
//!
//! ```text
//! Windows arg1 = RCX  ->  RDI  (System V arg1)
//! Windows arg2 = RDX  ->  RSI  (System V arg2)
//! Windows arg3 = R8   ->  RDX  (System V arg3)
//! Windows arg4 = R9   ->  RCX  (System V arg4)
//! ```
//!
//! The move order is chosen so no source is clobbered before it is consumed:
//! `rdi<-rcx; rsi<-rdx; rdx<-r8; rcx<-r9`.
//!
//! ## Stack arguments (5th argument and beyond)
//!
//! At trampoline entry the PE caller has pushed a return address and reserved a 32-byte
//! shadow space, so the 5th Windows argument lives at `[rsp+0x28]`, the 6th at `[rsp+0x30]`,
//! etc. The System V callee instead expects the 5th argument at `[rsp+0x08]` (immediately
//! above its own return address). The trampoline copies each stack argument from the
//! Windows slot to the System V slot.
//!
//! ## Two flavors
//!
//! * [`ThunkArena::make_thunk`] is for functions that **return**. It saves the Windows
//!   callee-saved registers `RDI`/`RSI` (which System V treats as caller-saved, so a Rust
//!   callee may clobber them), calls the implementation, restores them, and returns `RAX`
//!   to the PE caller. This preserves the Windows ABI's callee-saved guarantee.
//! * [`ThunkArena::make_thunk_noreturn`] is for functions that never return
//!   (`ExitProcess`, `NtTerminateProcess`). It shuffles the registers and tail-calls
//!   (`jmp`) the implementation; no frame or register preservation is needed.
//!
//! Both flavors support up to 32 integer arguments (4 register + up to 28 stack),
//! which covers every Windows API we implement (the worst case is `CreateWindowExW`
//! at 12 args).

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;

/// Errors raised while building a Win64->SysV trampoline.
#[derive(Debug, thiserror::Error)]
pub enum ThunkError {
    #[error("thunk argument count {n} exceeds the supported maximum of 32")]
    TooManyArgs { n: u8 },
    #[error("failed to allocate executable thunk memory ({size} bytes): {msg}")]
    AllocFailed { size: usize, msg: String },
    #[error("failed to make thunk memory executable ({size} bytes): {msg}")]
    ExecFailed { size: usize, msg: String },
}

/// An arena of executable Win64->SysV trampolines, all backed by one anonymous mapping.
///
/// The mapping is allocated read/write while code is emitted, then flipped to
/// read/execute (never writable, honoring W^X) via [`ThunkArena::finalize`]. Thunk
/// pointers handed out by `make_thunk*` stay valid for as long as the arena lives.
pub struct ThunkArena {
    base: *mut u8,
    len: usize,
    /// Current write cursor (offset from `base`).
    cursor: usize,
    /// `true` once the arena has been flipped to PROT_EXEC (no more writes allowed).
    sealed: bool,
}

// SAFETY: the arena owns its mapping and the thunks are plain code blobs with no shared
// Rust state; it can move between threads.
unsafe impl Send for ThunkArena {}
unsafe impl Sync for ThunkArena {}

impl ThunkArena {
    /// Create an empty thunk arena with an initial executable mapping.
    #[allow(dead_code)] // used by unit tests; the loader uses `with_capacity`.
    pub fn new() -> Result<Self, ThunkError> {
        // 4 KiB holds ~200 thunks, plenty for the handful of imports we implement.
        Self::with_capacity(4096)
    }

    /// Create an empty thunk arena sized to at least `capacity` bytes (page-rounded).
    pub fn with_capacity(capacity: usize) -> Result<Self, ThunkError> {
        let page = page_size();
        let len = round_up(capacity.max(page), page);
        // SAFETY: anonymous private mapping, kernel-chosen address, zero-filled. We own
        // `len` bytes on success. Allocated RW so we can emit code, then sealed to RX.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(ThunkError::AllocFailed {
                size: len,
                msg: errno_str(),
            });
        }
        Ok(ThunkArena {
            base: base as *mut u8,
            len,
            cursor: 0,
            sealed: false,
        })
    }

    /// Build a trampoline for a **returning** Rust `extern "C"` function `target` taking
    /// `n_args` integer/pointer arguments (0..=32), returning the callable address to store
    /// in an IAT slot.
    pub fn make_thunk(
        &mut self,
        target: *const c_void,
        n_args: u8,
    ) -> Result<*const c_void, ThunkError> {
        if n_args > 32 {
            return Err(ThunkError::TooManyArgs { n: n_args });
        }
        let code = emit_returning(target, n_args);
        let off = self.alloc(code.len())?;
        // SAFETY: `off..off+len` is within the RW mapping and `alloc` reserved the space.
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), self.base.add(off), code.len());
        }
        Ok(unsafe { self.base.add(off) } as *const c_void)
    }

    /// Build a trampoline for a **non-returning** Rust `extern "C"` function `target`
    /// (`-> !`) taking `n_args` arguments (0..=6 supported; such functions never have more
    /// than 6 integer args in our set). Returns the callable address to store in an IAT slot.
    pub fn make_thunk_noreturn(
        &mut self,
        target: *const c_void,
        n_args: u8,
    ) -> Result<*const c_void, ThunkError> {
        if n_args > 6 {
            return Err(ThunkError::TooManyArgs { n: n_args });
        }
        let code = emit_noreturn(target, n_args);
        let off = self.alloc(code.len())?;
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), self.base.add(off), code.len());
        }
        Ok(unsafe { self.base.add(off) } as *const c_void)
    }

    /// Flip the whole arena from read/write to read/execute (W^X). Must be called before
    /// any thunk is invoked. Further `make_thunk*` calls after sealing are rejected.
    pub fn finalize(&mut self) -> Result<(), ThunkError> {
        if self.sealed {
            return Ok(());
        }
        // SAFETY: `base..base+len` is the whole owned mapping, page-aligned; mprotect
        // requires page-aligned address+length.
        let rc = unsafe {
            libc::mprotect(
                self.base as *mut libc::c_void,
                self.len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if rc != 0 {
            return Err(ThunkError::ExecFailed {
                size: self.len,
                msg: errno_str(),
            });
        }
        self.sealed = true;
        Ok(())
    }

    /// Reserve `n` bytes at the current cursor (page-aligning the start for clean code
    /// placement) and grow the arena if needed. Returns the offset of the reserved span.
    fn alloc(&mut self, n: usize) -> Result<usize, ThunkError> {
        if self.sealed {
            return Err(ThunkError::AllocFailed {
                size: n,
                msg: "arena is sealed (finalized); cannot emit more thunks".to_string(),
            });
        }
        // Align each thunk to 16 bytes so the code starts on a clean boundary.
        let aligned = round_up(self.cursor, 16);
        let end = aligned + n;
        if end > self.len {
            self.grow(end)?;
        }
        self.cursor = end;
        Ok(aligned)
    }

    /// Grow the mapping (via a new larger allocation + copy + unmap) to at least `need`
    /// bytes. We re-mmap rather than mremap to stay portable and simple.
    fn grow(&mut self, need: usize) -> Result<(), ThunkError> {
        let page = page_size();
        let new_len = round_up(need.max(self.len * 2), page);
        // SAFETY: a fresh anonymous mapping of `new_len` bytes, RW.
        let new_base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                new_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if new_base == libc::MAP_FAILED {
            return Err(ThunkError::AllocFailed {
                size: new_len,
                msg: errno_str(),
            });
        }
        // SAFETY: copy the already-emitted code from the old mapping into the new one,
        // then release the old mapping. `self.cursor` bytes are valid in the old mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(self.base, new_base as *mut u8, self.cursor);
            libc::munmap(self.base as *mut libc::c_void, self.len);
        }
        self.base = new_base as *mut u8;
        self.len = new_len;
        // After growth the arena is RW again; the caller (finalize) re-applies PROT_EXEC.
        self.sealed = false;
        Ok(())
    }
}

impl Drop for ThunkArena {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` describe the mapping we own; unmap exactly once. If `grow`
        // already unmapped a previous mapping, `base`/`len` point at the current one.
        if !self.base.is_null() {
            unsafe {
                libc::munmap(self.base as *mut libc::c_void, self.len);
            }
        }
    }
}

/// Emit the machine code for a **returning** trampoline targeting `target` with `n_args`
/// integer arguments (0..=32). See the module docs for the layout.
///
/// Argument mapping (Windows -> System V):
///   win arg1 (rcx) -> sysv arg1 (rdi)
///   win arg2 (rdx) -> sysv arg2 (rsi)
///   win arg3 (r8)  -> sysv arg3 (rdx)
///   win arg4 (r9)  -> sysv arg4 (rcx)
///   win arg5 (stack [RSPe+0x28]) -> sysv arg5 (r8)      [register, not stack]
///   win arg6 (stack [RSPe+0x30]) -> sysv arg6 (r9)      [register, not stack]
///   win arg7+ (stack [RSPe+0x38+8i]) -> sysv arg7+ (stack)
///
/// System V x64 passes the first 6 integer args in registers (rdi,rsi,rdx,rcx,r8,r9); the
/// 7th and beyond travel on the stack. So only Windows args 7+ need stack repositioning.
fn emit_returning(target: *const c_void, n_args: u8) -> Vec<u8> {
    // Number of System V *stack* arguments = Windows args 7..n.
    let s = n_args.saturating_sub(6) as usize;
    // Frame size for the System V stack args + alignment. After `push rdi; push rsi` RSP is
    // RSP_entry - 16. RSP_entry ≡ 8 (mod 16) (the caller's `call` pushed the return address
    // from a 16-aligned RSP). We need RSP ≡ 0 (mod 16) right before `call rax` so the Rust
    // callee sees the standard RSP ≡ 8 (mod 16) entry. RSP_before_call = RSP_entry - 16 -
    // frame ≡ 8 - 16 - frame ≡ -8 - frame (mod 16); we want ≡ 0, so frame ≡ -8 ≡ 8 (mod 16).
    // 8*s ≡ 0 (mod 16) when s even, ≡ 8 when s odd. Pad by 8 when s is even.
    let frame = 8 * s + if s.is_multiple_of(2) { 8 } else { 0 };
    let frame_imm = frame as u32;

    let mut v = Vec::with_capacity(80);

    // Save Windows callee-saved RDI/RSI (System V treats them as caller-saved).
    v.push(0x57); // push rdi
    v.push(0x56); // push rsi

    // Reserve the System V stack-arg frame (0 for n_args <= 6).
    if frame > 0 {
        v.extend_from_slice(&[0x48, 0x81, 0xEC]); // sub rsp, imm32
        v.extend_from_slice(&frame_imm.to_le_bytes());
    }

    // Shuffle the first 4 Windows register args into System V registers. Order chosen so
    // each source is consumed before it is overwritten (rcx,rdx read first; r8,r9 read
    // before we load arg5/arg6 into them below).
    v.extend_from_slice(&[0x48, 0x89, 0xCF]); // mov rdi, rcx   (arg1)
    v.extend_from_slice(&[0x48, 0x89, 0xD6]); // mov rsi, rdx   (arg2)
    v.extend_from_slice(&[0x4C, 0x89, 0xC2]); // mov rdx, r8    (arg3)
    v.extend_from_slice(&[0x4C, 0x89, 0xC9]); // mov rcx, r9    (arg4)

    // Windows args 5 and 6 live on the Windows stack but go into System V *registers* r8
    // and r9 (the 5th/6th SysV arg registers). Win arg5 at [RSP_entry + 0x28]; relative to
    // the current RSP (= RSP_entry - 16 - frame) that is [rsp + 0x38 + frame].
    if n_args >= 5 {
        let disp = (0x38 + frame) as u32;
        // mov r8, [rsp + disp]
        v.extend_from_slice(&[0x4C, 0x8B, 0x84, 0x24]);
        v.extend_from_slice(&disp.to_le_bytes());
    }
    if n_args >= 6 {
        let disp = (0x40 + frame) as u32;
        // mov r9, [rsp + disp]
        v.extend_from_slice(&[0x4C, 0x8B, 0x8C, 0x24]);
        v.extend_from_slice(&disp.to_le_bytes());
    }

    // Copy Windows args 7+ from the Windows stack to the System V stack. Win arg(7+i) is at
    // [RSP_entry + 0x38 + 8*i]; relative to the current RSP that is [rsp + 0x48 + frame +
    // 8*i]. The System V slot is [rsp + 8*i] (callee reads its 7th+ args at [RSP_callee+8+
    // 8*i] = [rsp + 8*i]). With s <= 2 the destination sits below the saved-register region,
    // so a low-to-high copy is safe.
    for i in 0..s {
        let src_disp = (0x48 + frame + 8 * i) as u32;
        let dst_disp = (8 * i) as u32;
        // mov rax, [rsp + src_disp]
        v.extend_from_slice(&[0x48, 0x8B, 0x84, 0x24]);
        v.extend_from_slice(&src_disp.to_le_bytes());
        // mov [rsp + dst_disp], rax
        v.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
        v.extend_from_slice(&dst_disp.to_le_bytes());
    }

    // Load the implementation address and call it (System V ABI at the callee entry).
    v.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    v.extend_from_slice(&(target as u64).to_le_bytes());
    v.extend_from_slice(&[0xFF, 0xD0]); // call rax

    // Tear down the frame, restore Windows RDI/RSI, and return RAX to the PE caller.
    if frame > 0 {
        v.extend_from_slice(&[0x48, 0x81, 0xC4]); // add rsp, imm32
        v.extend_from_slice(&frame_imm.to_le_bytes());
    }
    v.push(0x5E); // pop rsi
    v.push(0x5F); // pop rdi
    v.push(0xC3); // ret

    v
}

/// Emit the machine code for a **non-returning** trampoline targeting `target` with up to
/// 6 integer arguments. It shuffles the registers (and loads stack args 5/6 into r8/r9 for
/// the System V callee) and tail-calls (`jmp`) the implementation; the implementation never
/// returns, so no frame or register preservation is needed.
///
/// The arg5/arg6 stack loads are only emitted when `n_args >= 5`/`>= 6`, matching
/// `emit_returning`. Emitting them unconditionally reads past the Windows caller's
/// shadow space into the 5th/6th argument slots, which may be unmapped when the caller
/// didn't actually pass that many arguments (e.g. a 1-arg `ExitProcess` call whose
/// `[rsp+0x30]` is above the guest stack top).
fn emit_noreturn(target: *const c_void, n_args: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(48);
    v.extend_from_slice(&[0x48, 0x89, 0xCF]); // mov rdi, rcx   (arg1)
    v.extend_from_slice(&[0x48, 0x89, 0xD6]); // mov rsi, rdx   (arg2)
    v.extend_from_slice(&[0x4C, 0x89, 0xC2]); // mov rdx, r8    (arg3)
    v.extend_from_slice(&[0x4C, 0x89, 0xC9]); // mov rcx, r9    (arg4)

    // Windows args 5 and 6 live on the Windows stack but go into System V *registers* r8
    // and r9. Only emit these loads when the callee actually takes that many args; reading
    // [rsp+0x28]/[rsp+0x30] when the caller didn't provide them can touch unmapped memory
    // above the guest stack top.
    if n_args >= 5 {
        // mov r8, [rsp + 0x28]   (win arg5 -> sysv arg5)
        v.extend_from_slice(&[0x4C, 0x8B, 0x84, 0x24]);
        v.extend_from_slice(&0x28u32.to_le_bytes());
    }
    if n_args >= 6 {
        // mov r9, [rsp + 0x30]   (win arg6 -> sysv arg6)
        v.extend_from_slice(&[0x4C, 0x8B, 0x8C, 0x24]);
        v.extend_from_slice(&0x30u32.to_le_bytes());
    }

    v.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    v.extend_from_slice(&(target as u64).to_le_bytes());
    v.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
    v
}

/// Round `n` up to a multiple of `page`.
fn round_up(n: usize, page: usize) -> usize {
    (n + page - 1) & !(page - 1)
}

fn page_size() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` is always safe and returns the page size.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p <= 0 {
        4096
    } else {
        p as usize
    }
}

fn errno_str() -> String {
    // SAFETY: `__errno_location` returns a thread-local pointer safe to read.
    let e = unsafe { *libc::__errno_location() };
    format!("errno {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::arch::asm;

    // -- A few System V `extern "C"` functions to call through the thunks. --

    extern "C" fn add_four(a: u64, b: u64, c: u64, d: u64) -> u64 {
        a + b + c + d
    }

    extern "C" fn add_six(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
        a + b + c + d + e + f
    }

    extern "C" fn add_seven(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64) -> u64 {
        a + b + c + d + e + f + g
    }

    extern "C" fn echo_first(a: u64) -> u64 {
        a
    }

    extern "C" fn combine_ptrs(a: *const u8, b: *const u8) -> usize {
        (a as usize) ^ (b as usize)
    }

    /// Drive a thunk by hand-crafting a Windows-ABI call site: place args in RCX/RDX/R8/R9
    /// (and stack for extras, with a 32-byte shadow space), `call` the thunk, and read RAX.
    /// This validates the shuffle + stack-arg copy end to end.
    fn call_thunk_win64(thunk: *const c_void, args: &[u64]) -> u64 {
        // We build a Windows-ABI caller frame on a private mmap. Layout relative to the
        // value we load into RSP (`sp`): the `call {thunk}` pushes the return address at
        // [sp-8], so the trampoline's entry RSP = sp-8. The Windows ABI then places the
        // 32-byte shadow space at [RSP_entry+0x08..0x28] == [sp..sp+0x20] and the 5th+ stack
        // args at [RSP_entry+0x28+8*i] == [sp+0x20+8*i]. Below `sp` the trampoline and the
        // Rust callee use the stack, so we keep `sp` well inside the mapping with room both
        // above (shadow + stack args) and below (frames).
        let n_stack = args.len().saturating_sub(4);
        let len = 65536; // 16 pages: ample room above and below `sp`.
                         // SAFETY: anonymous RW mapping used as a scratch stack for the synthetic call.
        let stk = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(stk, libc::MAP_FAILED);

        // Place `sp` 256 bytes below the top, 16-aligned. Args occupy up to
        // [sp + 0x20 + 8*n_stack), well within the mapping; below `sp` is ~64 KiB for frames.
        let mut sp = (stk as usize + len - 0x100) & !0xF;
        // Keep `sp` inside the mapping (defensive: never past the end).
        sp = sp.min(stk as usize + len - 0x40);
        for i in 0..n_stack {
            let addr = sp + 0x20 + 8 * i;
            // SAFETY: `addr` is within the scratch mapping (above `sp`, below `stk+len`).
            unsafe { std::ptr::write_unaligned(addr as *mut u64, args[4 + i]) };
        }

        let mut result: u64;
        // SAFETY: inline asm that loads the first 4 args into Windows registers (RCX/RDX/
        // R8/R9), switches RSP to our scratch frame, `call`s the thunk, restores RSP, and
        // captures RAX. The thunk reads its Windows-ABI args exactly as a PE caller would
        // provide them (stack args pre-placed at [RSP_entry+0x28]). The arg registers are
        // marked `inout` so the compiler knows the thunk clobbers them; r12 is our saved-RSP
        // scratch (callee-saved by the thunk); rsi/rdi/r10/r11/rax are caller-saved by the
        // thunk and listed as clobbered. `sp` leaves `len - 8` bytes below it for the
        // trampoline's frame + the Rust callee's stack (plenty for these tiny functions).
        unsafe {
            asm!(
                "mov r12, rsp",
                "mov rsp, {sp}",
                "call {thunk}",
                "mov rsp, r12",
                sp = in(reg) sp,
                thunk = in(reg) thunk,
                inout("rcx") args.first().copied().unwrap_or(0) => _,
                inout("rdx") args.get(1).copied().unwrap_or(0) => _,
                inout("r8") args.get(2).copied().unwrap_or(0) => _,
                inout("r9") args.get(3).copied().unwrap_or(0) => _,
                out("r12") _,
                out("rax") result,
                out("rsi") _,
                out("rdi") _,
                out("r10") _,
                out("r11") _,
            );
        }
        // SAFETY: release the scratch mapping.
        unsafe {
            libc::munmap(stk, len);
        }
        result
    }

    #[test]
    fn thunk_translates_one_arg() {
        let mut arena = ThunkArena::new().expect("arena");
        let thunk = arena
            .make_thunk(echo_first as *const c_void, 1)
            .expect("thunk");
        arena.finalize().expect("seal");
        let r = call_thunk_win64(thunk, &[42]);
        assert_eq!(r, 42);
    }

    #[test]
    fn thunk_translates_four_args() {
        let mut arena = ThunkArena::new().expect("arena");
        let thunk = arena
            .make_thunk(add_four as *const c_void, 4)
            .expect("thunk");
        arena.finalize().expect("seal");
        let r = call_thunk_win64(thunk, &[10, 20, 30, 40]);
        assert_eq!(r, 100);
    }

    #[test]
    fn thunk_translates_six_register_args() {
        let mut arena = ThunkArena::new().expect("arena");
        let thunk = arena
            .make_thunk(add_six as *const c_void, 6)
            .expect("thunk");
        arena.finalize().expect("seal");
        // Windows args 5/6 travel on the Windows stack; the trampoline loads them into
        // the System V 5th/6th arg registers (r8/r9).
        let r = call_thunk_win64(thunk, &[1, 2, 3, 4, 50, 60]);
        assert_eq!(r, 120, "5th/6th args must land in System V r8/r9");
    }

    #[test]
    fn thunk_translates_seven_args_with_stack_copy() {
        let mut arena = ThunkArena::new().expect("arena");
        let thunk = arena
            .make_thunk(add_seven as *const c_void, 7)
            .expect("thunk");
        arena.finalize().expect("seal");
        // Windows args 5/6 -> r8/r9; Windows arg 7 (3rd Windows stack arg) -> System V 7th
        // arg, which lives on the System V stack. The trampoline must reposition it.
        let r = call_thunk_win64(thunk, &[1, 2, 3, 4, 50, 60, 70]);
        assert_eq!(r, 190, "7th arg must be copied to the System V stack");
    }

    #[test]
    fn thunk_preserves_pointer_args() {
        let mut arena = ThunkArena::new().expect("arena");
        let thunk = arena
            .make_thunk(combine_ptrs as *const c_void, 2)
            .expect("thunk");
        arena.finalize().expect("seal");
        let a = 0x1000u64;
        let b = 0x00FFu64;
        let r = call_thunk_win64(thunk, &[a, b]);
        assert_eq!(r, a ^ b);
    }

    #[test]
    fn reject_too_many_args() {
        let mut arena = ThunkArena::new().expect("arena");
        assert!(arena.make_thunk(echo_first as *const c_void, 33).is_err());
    }

    #[test]
    fn finalize_is_idempotent_and_seals() {
        let mut arena = ThunkArena::new().expect("arena");
        let _ = arena
            .make_thunk(echo_first as *const c_void, 1)
            .expect("thunk");
        arena.finalize().expect("seal once");
        arena.finalize().expect("seal twice is a no-op");
        // After sealing, emitting another thunk must fail.
        assert!(arena.make_thunk(echo_first as *const c_void, 1).is_err());
    }
}
