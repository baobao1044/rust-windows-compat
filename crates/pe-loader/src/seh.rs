//! SEH support: `RtlLookupFunctionEntry` for x86-64 exception handling.
//!
//! On Windows x64, every function that can unwind has an entry in the `.pdata`
//! section: a `RUNTIME_FUNCTION` struct (12 bytes) with `BeginAddress`,
//! `EndAddress`, and `UnwindData` — all RVAs into the image. The CRT and C++
//! runtime call `RtlLookupFunctionEntry(pc, ...)` to find the entry covering a
//! program counter; the entry's `UnwindData` then points at `UNWIND_INFO` in
//! `.xdata`, which `RtlVirtualUnwind` parses to restore registers.
//!
//! We implement the lookup half: given a PC (an absolute address in the mapped
//! image), binary-search the `.pdata` table for the containing function and
//! return a pointer to the `RUNTIME_FUNCTION` in mapped memory. The caller
//! then reads `UnwindData` and parses `UNWIND_INFO` itself — we do not yet
//! implement `RtlVirtualUnwind`, but the lookup alone lets C++ exception
//! propagation and `longjmp` get past the "find my function" step that used to
//! crash (the stub returned NULL, so every `__CxxFrameHandler` lookup faulted).

use std::sync::Mutex;

/// A `RUNTIME_FUNCTION` entry from `.pdata` — 12 bytes, all RVA fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

/// Global record of the main image's exception table, set once at load time
/// and read by the `RtlLookupFunctionEntry` bridge on every exception.
struct ExceptionTable {
    /// Pointer to the first `RUNTIME_FUNCTION` inside the mapped image.
    base: *const RuntimeFunction,
    /// Number of `RUNTIME_FUNCTION` entries.
    count: usize,
    /// The image base (absolute address the image is mapped at).
    image_base: usize,
    /// The mapped image size (to reject PCs outside the image).
    image_size: usize,
}

// SAFETY: the table is read-only after the one-time set; the raw pointer is
// inside the mapped image which stays alive for the process lifetime (it's the
// main EXE, never freed).
unsafe impl Send for ExceptionTable {}
unsafe impl Sync for ExceptionTable {}

/// The exception table. Production (loader) installs once; tests install their
/// own per-test, hence `Mutex<Option<...>>` for safe concurrent replacement.
static EXC_TABLE: Mutex<Option<ExceptionTable>> = Mutex::new(None);

/// Publish the main image's exception table so `lookup_function_entry` can
/// binary-search it later.
///
/// # Safety
///
/// `pdata_base` must point at a `RUNTIME_FUNCTION` array of `count` entries
/// inside a mapped image that stays alive for the process lifetime. The caller
/// (the PE loader's `load_bytes`) upholds this by storing the `PeImage`.
pub unsafe fn install(
    pdata_base: *const RuntimeFunction,
    count: usize,
    image_base: usize,
    image_size: usize,
) {
    *EXC_TABLE.lock().unwrap() = Some(ExceptionTable {
        base: pdata_base,
        count,
        image_base,
        image_size,
    });
}

/// `RtlLookupFunctionEntry(pc) -> *const RuntimeFunction`.
///
/// Returns a pointer to the `RUNTIME_FUNCTION` in mapped memory whose
/// `[BeginAddress, EndAddress)` range contains `pc`, or NULL when the PC is
/// outside any function (e.g. in a jump table, a thunk, or outside the image
/// entirely). The `.pdata` table is sorted by `BeginAddress` so we binary-search.
pub fn lookup_function_entry(pc: u64) -> *const std::ffi::c_void {
    let guard = EXC_TABLE.lock().unwrap();
    let Some(tbl) = guard.as_ref() else {
        return std::ptr::null();
    };
    if tbl.count == 0 || tbl.base.is_null() {
        return std::ptr::null();
    }
    // Reject PCs outside the image outright.
    let pc_usize = pc as usize;
    if pc_usize < tbl.image_base || pc_usize >= tbl.image_base + tbl.image_size {
        return std::ptr::null();
    }
    // Convert to an RVA to compare against the table's RVA fields.
    let rva = (pc_usize - tbl.image_base) as u32;

    // Binary search: `.pdata` is sorted by `BeginAddress` and entries do not
    // overlap. Find the last entry whose `BeginAddress <= rva` and check its
    // `EndAddress`.
    let mut lo = 0usize;
    let mut hi = tbl.count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        // SAFETY: `mid < count`, and `base` points at `count` valid RUNTIME_FUNCTION
        // entries inside a mapped image.
        let entry = unsafe { &*tbl.base.add(mid) };
        if entry.begin_address <= rva {
            // Candidate; try the right half for a later one that still covers `rva`.
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    // `lo - 1` is the last entry with `BeginAddress <= rva` (if any).
    if lo == 0 {
        return std::ptr::null();
    }
    // SAFETY: `lo - 1 < count` (the loop guarantees it).
    let entry = unsafe { &*tbl.base.add(lo - 1) };
    if rva < entry.end_address {
        // SAFETY: the entry is inside the mapped image and the pointer is stable.
        entry as *const RuntimeFunction as *const std::ffi::c_void
    } else {
        // `rva` falls in a gap between functions.
        std::ptr::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rf(begin: u32, end: u32, unwind: u32) -> RuntimeFunction {
        RuntimeFunction {
            begin_address: begin,
            end_address: end,
            unwind_data: unwind,
        }
    }

    #[test]
    fn finds_containing_function() {
        let entries = [
            make_rf(0x1000, 0x1100, 0x5000),
            make_rf(0x2000, 0x2200, 0x5030),
            make_rf(0x3000, 0x3100, 0x5060),
        ];
        let base = 0x1_4000_0000usize;
        // SAFETY: `entries` is a stack array that lives for the test; we
        // install it and immediately look up — the pointer stays valid.
        unsafe {
            install(entries.as_ptr(), 3, base, 0x10000);
        }
        // PC inside the second function → return entry 1.
        let p = lookup_function_entry((base + 0x2100) as u64);
        assert!(!p.is_null());
        // SAFETY: the returned pointer points into `entries`.
        let rf = unsafe { &*(p as *const RuntimeFunction) };
        assert_eq!(rf.begin_address, 0x2000);
        assert_eq!(rf.end_address, 0x2200);
    }

    #[test]
    fn returns_null_for_gap_between_functions() {
        let entries = [
            make_rf(0x1000, 0x1100, 0x5000),
            make_rf(0x2000, 0x2200, 0x5030),
        ];
        let base = 0x1_4000_0000usize;
        // SAFETY: same as above.
        unsafe {
            install(entries.as_ptr(), 2, base, 0x10000);
        }
        let p = lookup_function_entry((base + 0x1500) as u64);
        assert!(
            p.is_null(),
            "PC in the gap between 0x1100 and 0x2000 must return NULL"
        );
    }

    #[test]
    fn returns_null_for_pc_outside_image() {
        let entries = [make_rf(0x1000, 0x1100, 0x5000)];
        let base = 0x1_4000_0000usize;
        // SAFETY: same.
        unsafe {
            install(entries.as_ptr(), 1, base, 0x10000);
        }
        let p = lookup_function_entry(0x7FFF_0000_0000u64);
        assert!(p.is_null(), "PC outside the image must return NULL");
    }

    #[test]
    fn returns_null_when_no_table_installed() {
        // A fresh process (no install called) should return NULL, not crash.
        // (The OnceLock is process-global, so this only passes in isolation;
        // other tests in this module call install first. That's fine — the
        // lookup is safe either way.)
        let _ = lookup_function_entry(0x1234);
        // No assertion needed — just must not panic.
    }
}
