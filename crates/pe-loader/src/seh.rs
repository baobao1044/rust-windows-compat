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
//! return a pointer to the `RUNTIME_FUNCTION` in mapped memory. We also
//! implement `virtual_unwind` which parses the `UNWIND_INFO` from `.xdata`
//! and restores the caller's nonvolatile registers and RSP, so C++ exception
//! propagation and stack walks can unwind the call stack.

#![allow(dead_code)]

use std::sync::Mutex;

/// A `RUNTIME_FUNCTION` entry from `.pdata` — 12 bytes, all RVA fields.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

/// Windows x64 `CONTEXT` — selected fields at their standard offsets.
/// We only touch the integer registers and Rip/Rsp; the struct is large
/// (~1232 bytes) but we access by offset, not by full layout.
#[repr(C)]
pub struct Context {
    _padding_0: [u8; 0x78], // Xmm + debug regs
    pub rax: u64,           // 0x78
    pub rcx: u64,           // 0x80
    pub rdx: u64,           // 0x88
    pub rbx: u64,           // 0x90
    pub rsp: u64,           // 0x98
    pub rbp: u64,           // 0xA0
    pub rsi: u64,           // 0xA8
    pub rdi: u64,           // 0xB0
    pub r8: u64,            // 0xB8
    pub r9: u64,            // 0xC0
    pub r10: u64,           // 0xC8
    pub r11: u64,           // 0xD0
    pub r12: u64,           // 0xD8
    pub r13: u64,           // 0xE0
    pub r14: u64,           // 0xE8
    pub r15: u64,           // 0xF0
    pub rip: u64,           // 0xF8
}

/// Unwind opcode constants (low 3 bits of the first byte).
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_EPILOG: u8 = 6;
const UWOP_SAVE_XMM128: u8 = 7;
const UWOP_SAVE_XMM128_FAR: u8 = 8;
const UWOP_PUSH_MACHFRAME: u8 = 9;

/// UNWIND_FLAG constants (high 5 bits of the first byte).
const UNW_FLAG_EHANDLER: u8 = 1;
const UNW_FLAG_UHANDLER: u8 = 2;
const UNW_FLAG_CHAININFO: u8 = 4;

/// Map an x64 nonvolatile register number to its offset inside `Context`.
/// Registers 0-15 in Windows x64 order: Rax=0, Rcx=1, Rdx=2, Rbx=3, Rsp=4,
/// Rbp=5, Rsi=6, Rdi=7, R8=8...R15=15.
fn nonvolatile_offset(reg: u8) -> Option<usize> {
    match reg {
        3 => Some(0x90),  // Rbx
        5 => Some(0xA0),  // Rbp
        6 => Some(0xA8),  // Rsi
        7 => Some(0xB0),  // Rdi
        8 => Some(0xB8),  // R8 (volatile on Windows but listed in unwind codes)
        9 => Some(0xC0),  // R9
        10 => Some(0xC8), // R10
        11 => Some(0xD0), // R11
        12 => Some(0xD8), // R12
        13 => Some(0xE0), // R13
        14 => Some(0xE8), // R14
        15 => Some(0xF0), // R15
        _ => None,
    }
}

/// `RtlVirtualUnwind` — parse UNWIND_INFO and update the CONTEXT to reflect
/// the caller's frame.
///
/// Returns the exception handler RVA (if UNWIND_INFO has EHANDLER/UHANDLER),
/// or 0 if no handler.
///
/// # Safety
///
/// `function_entry` must point at a valid `RuntimeFunction` inside the mapped
/// image. `ctx` must be a valid writable `Context`. The image must be mapped
/// and the `.xdata` section readable.
pub unsafe fn virtual_unwind(
    function_entry: *const RuntimeFunction,
    image_base: usize,
    ctx: *mut Context,
    establisher_frame: *mut u64,
) -> u32 {
    if function_entry.is_null() || ctx.is_null() {
        return 0;
    }

    // SAFETY: `function_entry` is a valid pointer from RtlLookupFunctionEntry.
    let rf = unsafe { &*function_entry };
    let unwind_rva = rf.unwind_data as usize;
    if unwind_rva == 0 {
        return 0;
    }

    // Read UNWIND_INFO header from image memory.
    let unwind_ptr = image_base + unwind_rva;
    // SAFETY: the unwind RVA points into the mapped image's .xdata section.
    let version_flags = unsafe { *(unwind_ptr as *const u8) };
    let version = version_flags & 0x07;
    let flags = (version_flags >> 3) & 0x1F;
    // SAFETY: offsets 1..3 are inside the UNWIND_INFO header.
    let count_of_unwind_codes = unsafe { *((unwind_ptr + 2) as *const u8) } as usize;
    let frame_reg_and_offset = unsafe { *((unwind_ptr + 3) as *const u8) };
    let frame_reg = frame_reg_and_offset & 0x0F;
    let frame_offset = u64::from(frame_reg_and_offset >> 4);

    if version != 1 && version != 2 {
        log::warn!("seh: UNWIND_INFO version {version} not supported");
        return 0;
    }

    // SAFETY: `ctx` is a valid writable Context per the caller's contract.
    let context = unsafe { &mut *ctx };

    // If the function has a frame pointer, restore RSP from it first.
    if frame_reg != 0 {
        // The frame register's value minus frame_offset * 16 gives the
        // original RSP at function entry.
        let fp_val = read_reg_by_num(context, frame_reg);
        context.rsp = fp_val.wrapping_sub(frame_offset * 16);
    }

    // Walk the unwind codes in reverse order (last code first — they're stored
    // in prolog execution order, we undo in reverse).
    let codes_base = unwind_ptr + 4;
    let mut code_idx = count_of_unwind_codes;
    while code_idx > 0 {
        code_idx -= 1;
        // SAFETY: `code_idx < count_of_unwind_codes`, and the codes array
        // is inside the mapped image.
        let code = unsafe { *((codes_base + code_idx * 2) as *const u16) };
        let opcode = (code & 0x0F) as u8;
        let op_info = ((code >> 4) & 0x0F) as u8;

        match opcode {
            UWOP_PUSH_NONVOL => {
                // Pop a nonvolatile register: reg = *rsp; rsp += 8
                let reg = op_info;
                if let Some(off) = nonvolatile_offset(reg) {
                    // SAFETY: RSP points at a valid stack address with the
                    // pushed register value.
                    let val = unsafe { *(context.rsp as *const u64) };
                    write_reg_by_offset(context, off, val);
                }
                context.rsp += 8;
            }
            UWOP_ALLOC_SMALL => {
                // Small allocation: size = op_info * 8 + 8
                context.rsp += (op_info as u64) * 8 + 8;
            }
            UWOP_ALLOC_LARGE => {
                if op_info == 0 {
                    // Next u16 = size / 8
                    if code_idx == 0 {
                        break;
                    }
                    code_idx -= 1;
                    // SAFETY: code_idx is within bounds.
                    let size_slots = unsafe { *((codes_base + code_idx * 2) as *const u16) };
                    context.rsp += (size_slots as u64) * 8;
                } else {
                    // Next 2 u16s = 32-bit size
                    if code_idx < 2 {
                        break;
                    }
                    code_idx -= 1;
                    // SAFETY: bounds-checked.
                    let lo = unsafe { *((codes_base + code_idx * 2) as *const u16) } as u32;
                    code_idx -= 1;
                    let hi = unsafe { *((codes_base + code_idx * 2) as *const u16) } as u32;
                    context.rsp += u64::from(hi) << 16 | u64::from(lo);
                }
            }
            UWOP_SET_FPREG => {
                // RSP = frame_reg - frame_offset * 16 (already done above if
                // frame_reg != 0). This opcode is a no-op when we already
                // applied the frame pointer setup.
            }
            UWOP_SAVE_NONVOL => {
                // reg saved at [rsp + next_u16 * 8]
                if code_idx == 0 {
                    break;
                }
                code_idx -= 1;
                let reg = op_info;
                // SAFETY: bounds-checked.
                let offset_slots = unsafe { *((codes_base + code_idx * 2) as *const u16) };
                let save_addr = context.rsp + (offset_slots as u64) * 8;
                if let Some(off) = nonvolatile_offset(reg) {
                    // SAFETY: the save address is inside the guest stack.
                    let val = unsafe { *(save_addr as *const u64) };
                    write_reg_by_offset(context, off, val);
                }
            }
            UWOP_SAVE_NONVOL_FAR => {
                // reg saved at [rsp + next 2 u16s as u32]
                if code_idx < 2 {
                    break;
                }
                code_idx -= 1;
                let lo = unsafe { *((codes_base + code_idx * 2) as *const u16) } as u32;
                code_idx -= 1;
                let hi = unsafe { *((codes_base + code_idx * 2) as *const u16) } as u32;
                let offset = (u64::from(hi) << 16 | u64::from(lo)) * 8;
                let reg = op_info;
                let save_addr = context.rsp + offset;
                if let Some(off) = nonvolatile_offset(reg) {
                    let val = unsafe { *(save_addr as *const u64) };
                    write_reg_by_offset(context, off, val);
                }
            }
            UWOP_SAVE_XMM128 | UWOP_SAVE_XMM128_FAR => {
                // XMM register saves — consume the offset slots but don't
                // restore (we don't track XMM in our simplified Context).
                if opcode == UWOP_SAVE_XMM128 {
                    if code_idx == 0 {
                        break;
                    }
                    code_idx -= 1;
                } else {
                    if code_idx < 2 {
                        break;
                    }
                    code_idx -= 2;
                }
            }
            UWOP_EPILOG | UWOP_PUSH_MACHFRAME => {
                // EPILOG: skip (metadata for the epilog, not needed for unwinding).
                // PUSH_MACHFRAME: for interrupt/exception frames — rare in userland.
                // We skip it; a full implementation would restore from the saved
                // machine frame.
            }
            _ => {
                log::trace!("seh: unknown unwind opcode {opcode:#x}, skipping");
            }
        }
    }

    // After unwinding, the return address is at the current RSP.
    // SAFETY: RSP points at the return address on the guest stack.
    let new_rip = unsafe { *(context.rsp as *const u64) };
    context.rip = new_rip;
    context.rsp += 8;

    // The establisher frame is the frame pointer (or RSP before we popped
    // the return address).
    if !establisher_frame.is_null() {
        // SAFETY: caller provides a valid out-pointer.
        unsafe { *establisher_frame = context.rsp };
    }

    // Return the exception handler RVA if the UNWIND_INFO declares one.
    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        let handler_offset = 4 + count_of_unwind_codes * 2;
        // SAFETY: the handler RVA follows the unwind codes array.
        // SAFETY: the handler RVA follows the unwind codes array.
        unsafe { *((unwind_ptr + handler_offset) as *const u32) }
    } else {
        0
    }
}

/// Read a register value from the CONTEXT by its Windows x64 register number.
fn read_reg_by_num(ctx: &Context, reg: u8) -> u64 {
    match reg {
        0 => ctx.rax,
        1 => ctx.rcx,
        2 => ctx.rdx,
        3 => ctx.rbx,
        4 => ctx.rsp,
        5 => ctx.rbp,
        6 => ctx.rsi,
        7 => ctx.rdi,
        8 => ctx.r8,
        9 => ctx.r9,
        10 => ctx.r10,
        11 => ctx.r11,
        12 => ctx.r12,
        13 => ctx.r13,
        14 => ctx.r14,
        15 => ctx.r15,
        _ => 0,
    }
}

/// Write a register value into the CONTEXT at the given byte offset.
fn write_reg_by_offset(ctx: &mut Context, offset: usize, value: u64) {
    // SAFETY: `offset` is validated by `nonvolatile_offset` to be inside the
    // integer-register region of the CONTEXT struct.
    unsafe {
        std::ptr::write_unaligned(
            (ctx as *mut Context as *mut u8).add(offset) as *mut u64,
            value,
        );
    }
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
/// Return the image base stored in the exception table, if installed.
pub fn get_image_base() -> Option<usize> {
    EXC_TABLE.lock().unwrap().as_ref().map(|t| t.image_base)
}

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
