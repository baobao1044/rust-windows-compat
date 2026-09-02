//! Windows virtual memory primitives reimplemented on Linux `mmap`/`mprotect`.
//!
//! Covers `VirtualAlloc` (reserve+commit, with allocation type and protection flags),
//! `VirtualFree` (decommit/release), `VirtualProtect` (change page protection), and
//! `VirtualQuery` (describe a region). Allocations are tracked in a global table so
//! `VirtualQuery` can report the size and protection of any region we handed out. The
//! mapping between Windows `flProtect`/`flAllocationType` flags and Linux `prot`/`mmap`
//! flags is done with `bitflags`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::os::raw::c_void;
use std::sync::OnceLock;

use bitflags::bitflags;
use parking_lot::Mutex;

// ---------------------------------------------------------------------------
// Windows allocation/protection flag constants
// ---------------------------------------------------------------------------

/// `MEM_COMMIT` (Windows): allocate committed memory.
pub const MEM_COMMIT: u32 = 0x0000_1000;
/// `MEM_RESERVE` (Windows): reserve address space without committing.
pub const MEM_RESERVE: u32 = 0x0000_2000;
/// `MEM_RELEASE` (Windows): release the region (with `VirtualFree`).
pub const MEM_RELEASE: u32 = 0x0000_8000;
/// `MEM_DECOMMIT` (Windows): decommit (return to reserved state).
pub const MEM_DECOMMIT: u32 = 0x0000_4000;

/// `PAGE_NOACCESS` (Windows): no access.
pub const PAGE_NOACCESS: u32 = 0x01;
/// `PAGE_READONLY` (Windows).
pub const PAGE_READONLY: u32 = 0x02;
/// `PAGE_READWRITE` (Windows).
pub const PAGE_READWRITE: u32 = 0x04;
/// `PAGE_EXECUTE` (Windows).
pub const PAGE_EXECUTE: u32 = 0x10;
/// `PAGE_EXECUTE_READ` (Windows).
pub const PAGE_EXECUTE_READ: u32 = 0x20;
/// `PAGE_EXECUTE_READWRITE` (Windows).
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ---------------------------------------------------------------------------
// Allocation tracking
// ---------------------------------------------------------------------------

/// A tracked `VirtualAlloc` region: its base, size, and current protection.
#[derive(Clone, Copy)]
struct Region {
    base: usize,
    size: usize,
    prot: i32,
}

/// The global allocation table, mapping base address -> Region.
struct AllocTable {
    regions: BTreeMap<usize, Region>,
}

impl AllocTable {
    fn new() -> Self {
        AllocTable {
            regions: BTreeMap::new(),
        }
    }

    fn insert(&mut self, base: usize, size: usize, prot: i32) {
        self.regions.insert(base, Region { base, size, prot });
    }

    fn remove(&mut self, base: usize) -> Option<Region> {
        self.regions.remove(&base)
    }

    /// Find the region containing `addr` (if any).
    fn containing(&self, addr: usize) -> Option<&Region> {
        // BTreeMap is sorted by base; find the last base <= addr and check it covers addr.
        let mut iter = self.regions.range(..=addr);
        iter.next_back().and_then(|(_, r)| {
            if addr >= r.base && addr < r.base + r.size {
                Some(r)
            } else {
                None
            }
        })
    }
}

fn table() -> &'static Mutex<AllocTable> {
    static TABLE: OnceLock<Mutex<AllocTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(AllocTable::new()))
}

// ---------------------------------------------------------------------------
// Flag translation
// ---------------------------------------------------------------------------

bitflags! {
    /// Windows `flAllocationType` for `VirtualAlloc`, parsed into a bitflags struct.
    pub struct AllocType: u32 {
        const COMMIT = MEM_COMMIT;
        const RESERVE = MEM_RESERVE;
    }
}

/// Translate a Windows page protection flag to a Linux `mprotect` prot value.
fn win_prot_to_linux(prot: u32) -> i32 {
    let mut p: i32 = 0;
    if prot & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE) != 0 {
        p |= libc::PROT_READ | libc::PROT_WRITE;
    }
    if prot & (PAGE_READONLY | PAGE_EXECUTE_READ) != 0 {
        p |= libc::PROT_READ;
    }
    if prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE) != 0 {
        p |= libc::PROT_EXEC;
    }
    if prot == PAGE_NOACCESS {
        p = libc::PROT_NONE;
    }
    p
}

// ---------------------------------------------------------------------------
// VirtualAlloc / VirtualFree / VirtualProtect / VirtualQuery
// ---------------------------------------------------------------------------

/// `kernel32!VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) -> LPVOID`.
///
/// M1 treats `MEM_RESERVE` like `MEM_COMMIT` (Linux `mmap` commits lazily anyway) and
/// ignores a non-null `lpAddress` (does not support placing at a caller-chosen address).
/// Returns the base address on success, NULL on failure.
pub extern "C" fn virtual_alloc(
    _addr: *const c_void,
    size: usize,
    alloc_type: u32,
    prot: u32,
) -> *mut c_void {
    if size == 0 {
        return std::ptr::null_mut();
    }
    let flags = AllocType::from_bits_truncate(alloc_type);
    // M1: accept COMMIT, RESERVE, or both. Reject pure-zero (no op requested).
    if !flags.intersects(AllocType::COMMIT | AllocType::RESERVE) {
        return std::ptr::null_mut();
    }
    let page = page_size();
    let rounded = round_up(size, page);
    let linux_prot = win_prot_to_linux(prot);
    // SAFETY: anonymous private mapping, kernel-chosen address, zero-filled.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            rounded,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return std::ptr::null_mut();
    }
    // Apply the requested protection (the mapping was RW so we could zero it; mprotect to
    // the real prot now). For PAGE_NOACCESS this removes all access.
    if linux_prot != (libc::PROT_READ | libc::PROT_WRITE) {
        // SAFETY: `base` is a valid page-aligned mapping of `rounded` bytes we own.
        let rc = unsafe { libc::mprotect(base, rounded, linux_prot) };
        if rc != 0 {
            // SAFETY: release the mapping on failure to avoid leaking it.
            unsafe { libc::munmap(base, rounded) };
            return std::ptr::null_mut();
        }
    }
    let base_addr = base as usize;
    table().lock().insert(base_addr, rounded, linux_prot);
    base as *mut c_void
}

/// `kernel32!VirtualFree(lpAddress, dwSize, dwFreeType) -> BOOL`.
///
/// `MEM_RELEASE`: unmap the whole region (`dwSize` must be 0). `MEM_DECOMMIT`: unmap the
/// pages (we treat decommit as full release in M1).
pub extern "C" fn virtual_free(addr: *const c_void, size: usize, free_type: u32) -> i32 {
    if addr.is_null() {
        return 0; // FALSE
    }
    let base = addr as usize;
    if free_type & MEM_RELEASE != 0 {
        // Release the whole recorded region (size must be 0 per the Windows contract).
        let region = table().lock().remove(base);
        let Some(r) = region else {
            return 0; // FALSE: not a region we tracked
        };
        // SAFETY: `base`/`r.size` describe the mapping we created in `virtual_alloc`.
        let rc = unsafe { libc::munmap(base as *mut c_void, r.size) };
        if rc != 0 {
            return 0;
        }
        1 // TRUE
    } else if free_type & MEM_DECOMMIT != 0 {
        // Decommit `size` bytes (round to pages). M1 unmaps and re-maps a PROT_NONE region so
        // the address range stays reserved but inaccessible, matching "decommitted".
        if size == 0 {
            return 0;
        }
        let page = page_size();
        let rounded = round_up(size, page);
        let base_aligned = round_down(base, page);
        // SAFETY: unmap the decommitted range (assumed within a tracked region).
        let rc = unsafe { libc::munmap(base_aligned as *mut c_void, rounded) };
        if rc != 0 {
            return 0;
        }
        // Re-map PROT_NONE at the same address to keep it reserved.
        // SAFETY: `MAP_FIXED` re-places the address with a PROT_NONE anonymous mapping.
        let remap = unsafe {
            libc::mmap(
                base_aligned as *mut c_void,
                rounded,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if remap == libc::MAP_FAILED {
            return 0;
        }
        1 // TRUE
    } else {
        0 // FALSE: unknown free type
    }
}

/// `kernel32!VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) -> BOOL`.
pub extern "C" fn virtual_protect(
    addr: *const c_void,
    size: usize,
    new_prot: u32,
    old_prot: *mut u32,
) -> i32 {
    if addr.is_null() || size == 0 {
        return 0; // FALSE
    }
    let base = addr as usize;
    let page = page_size();
    let base_aligned = round_down(base, page);
    let rounded = round_up(size + (base - base_aligned), page);
    // Record the old protection from the tracked region (if any) before changing.
    let old = {
        let g = table().lock();
        g.containing(base)
            .map(|r| r.prot)
            .unwrap_or(libc::PROT_READ | libc::PROT_WRITE)
    };
    let linux_prot = win_prot_to_linux(new_prot);
    // SAFETY: `base_aligned..+rounded` is page-aligned and within a mapping we tracked.
    let rc = unsafe { libc::mprotect(base_aligned as *mut c_void, rounded, linux_prot) };
    if rc != 0 {
        return 0;
    }
    // Translate the old Linux prot back to a Windows protection flag (best-effort).
    if !old_prot.is_null() {
        let old_win = linux_prot_to_win(old);
        // SAFETY: `old_prot` is a guest out-pointer valid for one u32.
        unsafe { std::ptr::write_unaligned(old_prot, old_win) };
    }
    // Update the tracked region's protection (if it was tracked as a single region).
    {
        let mut g = table().lock();
        if let Some(r) = g.regions.get_mut(&round_down(base, page)) {
            r.prot = linux_prot;
        }
    }
    1 // TRUE
}

/// `kernel32!VirtualQuery(lpAddress, lpBuffer, dwLength) -> usize`.
///
/// Fills a `MEMORY_BASIC_INFORMATION`-shaped struct (we return only BaseAddress, RegionSize,
/// State, Protect). Returns the size written, or 0 on failure.
pub extern "C" fn virtual_query(addr: *const c_void, buffer: *mut c_void, length: usize) -> usize {
    if buffer.is_null() || length == 0 {
        return 0;
    }
    let a = addr as usize;
    // The MEMORY_BASIC_INFORMATION layout we fill (u64 fields, Windows x64 ABI sizes):
    //   BaseAddress        u64  (offset 0)
    //   AllocationBase     u64  (offset 8)
    //   AllocationProtect  u32  (offset 16)
    //   __alignment1       u32  (offset 20)
    //   RegionSize         u64  (offset 24)
    //   State              u32  (offset 32)  (MEM_COMMIT=0x1000)
    //   Protect            u32  (offset 36)
    //   Type               u32  (offset 40)  (MEM_PRIVATE=0x20000)
    //   __alignment2       u32  (offset 44)
    // Total 48 bytes.
    if length < 48 {
        return 0;
    }
    let g = table().lock();
    let Some(r) = g.containing(a) else {
        return 0;
    };
    // SAFETY: `buffer` is a guest-provided struct valid for at least 48 bytes.
    unsafe {
        let p = buffer as *mut u8;
        std::ptr::write_unaligned(p as *mut u64, r.base as u64); // BaseAddress
        std::ptr::write_unaligned(p.add(8) as *mut u64, r.base as u64); // AllocationBase
        std::ptr::write_unaligned(p.add(16) as *mut u32, PAGE_READWRITE); // AllocationProtect
        std::ptr::write_unaligned(p.add(24) as *mut u64, r.size as u64); // RegionSize
        std::ptr::write_unaligned(p.add(32) as *mut u32, MEM_COMMIT); // State
        std::ptr::write_unaligned(p.add(36) as *mut u32, linux_prot_to_win(r.prot)); // Protect
        std::ptr::write_unaligned(p.add(40) as *mut u32, 0x0002_0000); // Type = MEM_PRIVATE
    }
    48
}

/// Translate a Linux prot back to a Windows page-protection flag (best-effort inverse).
fn linux_prot_to_win(prot: i32) -> u32 {
    let r = prot & libc::PROT_READ != 0;
    let w = prot & libc::PROT_WRITE != 0;
    let x = prot & libc::PROT_EXEC != 0;
    match (r, w, x) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (true, true, false) => PAGE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        _ => PAGE_READWRITE,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn round_up(n: usize, page: usize) -> usize {
    (n + page - 1) & !(page - 1)
}
fn round_down(n: usize, page: usize) -> usize {
    n & !(page - 1)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_alloc_round_trip() {
        let p = virtual_alloc(std::ptr::null(), 4096, MEM_COMMIT, PAGE_READWRITE);
        assert!(!p.is_null(), "VirtualAlloc returned a non-null base");
        // The region should be writable (the prot we asked for).
        // SAFETY: the allocation is valid for 4096 bytes.
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xAB, 4096) };
        // VirtualQuery reports the region.
        let mut info = [0u8; 48];
        let n = virtual_query(p, info.as_mut_ptr() as *mut c_void, 48);
        assert_eq!(n, 48, "VirtualQuery wrote the full struct");
        let base = u64::from_le_bytes(info[0..8].try_into().unwrap());
        assert_eq!(base, p as u64, "BaseAddress matches");
        // VirtualFree with MEM_RELEASE unmaps it.
        assert_eq!(virtual_free(p, 0, MEM_RELEASE), 1);
    }

    #[test]
    fn virtual_protect_changes_protection() {
        let p = virtual_alloc(std::ptr::null(), 4096, MEM_COMMIT, PAGE_READWRITE);
        assert!(!p.is_null());
        let mut old = 0u32;
        // SAFETY: `old` is a valid out-pointer.
        assert_eq!(virtual_protect(p, 4096, PAGE_READONLY, &mut old), 1);
        assert_eq!(old, PAGE_READWRITE, "old protection reported as READWRITE");
        // Writing now would SIGSEGV; we only verify the call succeeded. Clean up.
        assert_eq!(virtual_free(p, 0, MEM_RELEASE), 1);
    }

    #[test]
    fn win_prot_round_trip_for_common_flags() {
        assert_eq!(win_prot_to_linux(PAGE_NOACCESS), libc::PROT_NONE);
        assert_eq!(win_prot_to_linux(PAGE_READONLY), libc::PROT_READ);
        assert_eq!(
            win_prot_to_linux(PAGE_READWRITE),
            libc::PROT_READ | libc::PROT_WRITE
        );
        assert_eq!(
            win_prot_to_linux(PAGE_EXECUTE_READ),
            libc::PROT_READ | libc::PROT_EXEC
        );
        assert_eq!(
            win_prot_to_linux(PAGE_EXECUTE_READWRITE),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
    }
}
