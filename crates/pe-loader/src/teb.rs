//! Minimal Windows x64 TEB (Thread Environment Block) and PEB (Process Environment
//! Block) construction.
//!
//! On Windows the per-thread TEB is reached through the `gs` segment register: `gs:[0]`
//! is the start of the TEB, whose first 56 bytes are the `NT_TIB64` (the Thread
//! Information Block). The most commonly-read fields are:
//!
//!   - `gs:[0x00]` `NT_TIB64.ExceptionList`  (SEH chain head; 0 in modern code)
//!   - `gs:[0x08]` `NT_TIB64.StackBase`       (top of the thread stack)
//!   - `gs:[0x10]` `NT_TIB64.StackLimit`      (bottom of the committed stack)
//!   - `gs:[0x18]` `NT_TIB64.SubSystemTib`
//!   - `gs:[0x20]` `NT_TIB64.FiberData` / `Version`
//!   - `gs:[0x28]` `NT_TIB64.ArbitraryUserPointer`
//!   - `gs:[0x30]` `NT_TIB64.Self`            (self pointer to this TEB)
//!   - `gs:[0x60]` `TEB.ProcessEnvironmentBlock` (pointer to the PEB)
//!
//! We don't need every field for Phase 1; we lay out enough to satisfy guest code that
//! probes the TIB/TEB. The full TEB on x64 is 4096+ bytes; we allocate a page and place
//! the documented fields at their correct offsets so `gs:[offset]` reads are correct.

// The documented TIB/TEB offsets and the `peb_ptr` accessor are part of the public
// surface (used by tests now and by other crates later); allow them to exist unused
// without dead-code noise.
#![allow(dead_code)]

use std::alloc::Layout;

/// The `NT_TIB64` self-pointer offset (`gs:[0x30]`).
pub const TIB_SELF_OFFSET: usize = 0x30;
/// The PEB pointer offset within the TEB (`gs:[0x60]`).
pub const TEB_PEB_OFFSET: usize = 0x60;

/// A page-aligned, heap-allocated TEB + PEB pair for a guest thread.
///
/// `teb_ptr()` returns the address to install as the `gs` base. The TEB is laid out at
/// offset 0; the PEB follows it within the same allocation at a page boundary.
pub struct TebPeb {
    base: *mut u8,
    layout: Layout,
    peb_offset: usize,
}

impl TebPeb {
    /// Allocate and initialize a TEB/PEB for the current process.
    ///
    /// `stack_base`/`stack_limit` describe the guest thread stack (copied into the TIB's
    /// `StackBase`/`StackLimit` so `gs:[0x08]`/`gs:[0x10]` return sane values).
    /// `image_base` is the actual mapped image base, stored in the PEB so guest code that
    /// reads the PEB `ImageBaseAddress` sees the relocated base.
    pub fn new(stack_base: usize, stack_limit: usize, image_base: usize) -> Box<Self> {
        // One page for the TEB, one page for the PEB. Both are page-aligned and contiguous
        // within a single allocation so we can hand out stable pointers for the process
        // lifetime.
        let layout = Layout::from_size_align(2 * 4096, 4096).expect("2-page layout is valid");

        // SAFETY: `layout` is valid (non-zero size, power-of-two alignment) so this is a
        // sound allocation. We zero it so every field defaults to 0 (NULL), which is the
        // correct "absent" value for the TIB/PEB fields we don't explicitly set.
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!base.is_null(), "TEB/PEB allocation failed");

        let peb_offset = 4096;

        let mut me = Box::new(TebPeb {
            base,
            layout,
            peb_offset,
        });

        me.init_teb(stack_base, stack_limit);
        me.init_peb(image_base);
        me
    }

    fn init_teb(&mut self, stack_base: usize, stack_limit: usize) {
        let teb = self.base as usize;
        // SAFETY: `self.base` is a valid, page-aligned, zeroed region of 4096 bytes; all
        // writes below are within the first 0x68 bytes, well inside that range. We write
        // at the documented TIB/TEB offsets.
        unsafe {
            write_u64(teb, 0); // NT_TIB.ExceptionList (no SEH chain on Linux)
            write_u64(teb + 0x08, stack_base as u64); // NT_TIB.StackBase
            write_u64(teb + 0x10, stack_limit as u64); // NT_TIB.StackLimit
            write_u64(teb + 0x18, 0); // NT_TIB.SubSystemTib
            write_u64(teb + 0x20, 0); // NT_TIB.FiberData / Version
            write_u64(teb + 0x28, 0); // NT_TIB.ArbitraryUserPointer
            write_u64(teb + 0x30, teb as u64); // NT_TIB.Self -> this TEB
            write_u64(
                teb + TEB_PEB_OFFSET,
                (self.base as usize + self.peb_offset) as u64,
            );
            // TEB.LastErrorValue lives at +0x68 (DWORD); leave it 0 (no last error).
        }
    }

    fn init_peb(&mut self, image_base: usize) {
        let peb = self.base as usize + self.peb_offset;
        // SAFETY: the PEB page is a valid, page-aligned, zeroed region immediately
        // following the TEB page. We set the few PEB fields guest code commonly reads.
        unsafe {
            // PEB.BeingDebugged is at offset 0x02 (after two Reserved1 bytes). Leave it 0
            // (not being debugged). PEB.ImageBaseAddress is at offset 0x10.
            write_u64(peb + 0x10, image_base as u64); // PEB.ImageBaseAddress
        }
    }

    /// The address to install as the `gs` base (the TEB start).
    pub fn teb_ptr(&self) -> *mut () {
        self.base as *mut ()
    }

    /// The PEB address (for completeness; usually read by guest code via `gs:[0x60]`).
    pub fn peb_ptr(&self) -> *mut () {
        (self.base as usize + self.peb_offset) as *mut ()
    }
}

impl Drop for TebPeb {
    fn drop(&mut self) {
        // SAFETY: `self.base` was allocated with `self.layout` in `new` and is still
        // valid; we deallocate it exactly once.
        unsafe { std::alloc::dealloc(self.base, self.layout) };
    }
}

/// Write a little-endian `u64` at `addr`.
///
/// # Safety
///
/// `addr..addr+8` must be a valid, writable region.
unsafe fn write_u64(addr: usize, val: u64) {
    unsafe {
        std::ptr::write_unaligned(addr as *mut u64, val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teb_self_and_peb_offsets_are_correct() {
        // Offsets are documented and cross-checked against the mingw-w64 SDK headers and
        // the windows-sys crate: NT_TIB64.Self = 0x30, TEB.ProcessEnvironmentBlock = 0x60.
        assert_eq!(TIB_SELF_OFFSET, 0x30);
        assert_eq!(TEB_PEB_OFFSET, 0x60);
    }

    #[test]
    fn teb_peb_round_trip_fields() {
        let tp = TebPeb::new(0x1000, 0x0800, 0x140000000);
        let teb = tp.teb_ptr() as usize;

        // SAFETY: the TEB is a live allocation; reading the offsets we initialized is
        // sound. We read via unaligned-safe reads.
        unsafe {
            assert_eq!(
                read_u64(teb + 0x30),
                teb as u64,
                "Self must point at the TEB"
            );
            assert_eq!(
                read_u64(teb + TEB_PEB_OFFSET),
                tp.peb_ptr() as usize as u64,
                "PEB pointer must point at the PEB page"
            );
            assert_eq!(read_u64(teb + 0x08), 0x1000, "StackBase copied");
            assert_eq!(read_u64(teb + 0x10), 0x0800, "StackLimit copied");
            assert_eq!(
                read_u64(tp.peb_ptr() as usize + 0x10),
                0x140000000,
                "PEB.ImageBaseAddress set"
            );
        }
    }

    /// # Safety
    ///
    /// `addr..addr+8` must be valid for reading.
    unsafe fn read_u64(addr: usize) -> u64 {
        unsafe { std::ptr::read_unaligned(addr as *const u64) }
    }
}
