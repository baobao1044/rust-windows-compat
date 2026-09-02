//! Section mapping and base-relocation application for the PE loader.
//!
//! The loader maps the whole image as one anonymous reservation of `size_of_image` bytes
//! (rounded to a page), then copies each section's raw data to its RVA and zeroes the
//! `.bss`-style slack. Permissions are applied per-section with `mprotect`; we avoid
//! W+X by mapping everything RW first and downgrading executable sections to RX (read +
//! execute, no write) after copying data. After mapping, base relocations are applied so
//! absolute addresses match the actual (possibly relocated) image base.

use std::io;
use std::os::raw::{c_int, c_void};

/// Result of mapping an image into memory.
pub struct MappedImage {
    /// The actual base address the image was mapped at (`ImageBase` after relocation).
    pub base: *mut u8,
    /// Total mapped size in bytes (`SizeOfImage`, page-rounded).
    pub size: usize,
    /// The preferred (link-time) image base from the optional header.
    pub preferred_base: u64,
}

impl MappedImage {
    /// Translate a Relative Virtual Address (RVA) to a host pointer into the mapping.
    ///
    /// Returns `None` if `rva` is outside the mapped image.
    pub fn rva_to_ptr(&self, rva: u32) -> Option<*mut u8> {
        let rva = rva as usize;
        if rva < self.size {
            // SAFETY: `base..base+size` is a valid mapping and `rva < size`, so the offset
            // arithmetic stays in-bounds.
            Some(unsafe { self.base.add(rva) })
        } else {
            None
        }
    }
}

/// Errors that can occur during mapping or relocation.
#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("mmap of image ({size} bytes) failed: {msg}")]
    MmapFailed { size: usize, msg: String },
    #[error("mprotect of section {section:?} ({addr:#p}, {len} bytes) failed: {msg}")]
    MprotectFailed {
        section: String,
        addr: *const u8,
        len: usize,
        msg: String,
    },
    #[error("relocation RVA {0:#x} is outside the image")]
    RelocRvaOutOfRange(u32),
    #[error("relocation block overflows the relocation directory")]
    RelocBlockOverflow,
    #[error("relocation directory at RVA {0:#x} is outside the image")]
    RelocDirOutOfRange(u32),
    #[error(transparent)]
    Goblin(#[from] goblin::error::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Map a parsed PE into an anonymous memory region, applying per-section permissions.
///
/// `bytes` is the raw PE file; `pe` is goblin's parsed view. The image is mapped at the
/// preferred `ImageBase` if possible (using `MAP_FIXED`), otherwise the kernel picks an
/// address and the caller must apply relocations.
pub fn map_image(bytes: &[u8], pe: &goblin::pe::PE) -> Result<MappedImage, MapError> {
    let opt = pe
        .header
        .optional_header
        .expect("PE without optional header cannot be mapped");
    let windows = opt.windows_fields;
    let size_of_image = windows.size_of_image as usize;
    let preferred = windows.image_base;
    let section_alignment = windows.section_alignment as usize;

    let page = page_size();
    let mapped_size = round_up(size_of_image, page);
    if mapped_size == 0 {
        return Err(MapError::MmapFailed {
            size: 0,
            msg: "SizeOfImage is zero".to_string(),
        });
    }

    // First try to map at the preferred base with MAP_FIXED. If that fails (address in
    // use), fall back to a kernel-chosen address and relocations.
    let base = match try_map_at(preferred as usize, mapped_size) {
        Some(b) => b,
        None => {
            // SAFETY: anonymous private mapping, kernel-chosen address. Returns MAP_FAILED
            // on failure.
            let b = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mapped_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if b == libc::MAP_FAILED {
                return Err(MapError::MmapFailed {
                    size: mapped_size,
                    msg: errno_str(),
                });
            }
            b as *mut u8
        }
    };

    // Zero the whole region first (mmap already does this, but being explicit protects
    // against any future non-zeroed allocation path). Then copy headers and sections.
    //
    // SAFETY: `base..base+mapped_size` is a valid anonymous mapping we just made and own.
    // Writing `0` across it is sound and within bounds.
    unsafe { std::ptr::write_bytes(base, 0, mapped_size) };

    // Copy the PE headers (up to size_of_headers) into the mapping.
    let size_of_headers = windows.size_of_headers as usize;
    let header_len = size_of_headers.min(bytes.len()).min(mapped_size);
    // SAFETY: `bytes[..header_len]` is valid to read; `base[..header_len]` is valid to
    // write and within the mapping.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base, header_len);
    }

    // Copy each section's raw data to its RVA, zeroing the rest of the virtual section
    // (which covers uninitialized `.bss` slack).
    for sec in &pe.sections {
        let virt_size = sec.virtual_size as usize;
        if virt_size == 0 {
            continue;
        }
        let rva = sec.virtual_address as usize;
        if rva >= mapped_size {
            continue;
        }
        let dst = unsafe { base.add(rva) };
        let section_end = (rva + virt_size).min(mapped_size);
        let copy_len = section_end - rva;

        // Zero the section's virtual range first (covers .bss slack past the raw data).
        // SAFETY: `dst..dst+copy_len` is within `base..base+mapped_size`.
        unsafe { std::ptr::write_bytes(dst, 0, copy_len) };

        let raw_size = sec.size_of_raw_data as usize;
        let raw_off = sec.pointer_to_raw_data as usize;
        if raw_size > 0 && raw_off < bytes.len() {
            let src_len = raw_size.min(bytes.len() - raw_off).min(copy_len);
            // SAFETY: `bytes[raw_off..raw_off+src_len]` is valid; `dst..dst+src_len` valid.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(raw_off), dst, src_len);
            }
        }
    }

    // Apply per-section permissions. Map everything RW during copy (above), then
    // downgrade executable sections to RX (drop write) and read-only data to RO.
    for sec in &pe.sections {
        let rva = sec.virtual_address as usize;
        let virt_size = sec.virtual_size as usize;
        if virt_size == 0 || rva >= mapped_size {
            continue;
        }
        let prot = section_prot(sec.name().unwrap_or(""), sec.characteristics);
        if prot == (libc::PROT_READ | libc::PROT_WRITE) {
            continue; // already RW
        }
        // Round the protection region to page boundaries: a section's first page may
        // overlap with the previous section (Windows packs sections by section_alignment,
        // which is >= page size, so in practice they don't overlap, but we page-align to
        // satisfy mprotect's requirement).
        let start = round_down(rva, page);
        let end = round_up((rva + virt_size).min(mapped_size), page);
        let len = end - start;
        // SAFETY: `base+start..base+start+len` is a valid, page-aligned sub-region of the
        // mapping we own; `mprotect` requires page-aligned addresses and lengths.
        let rc = unsafe { libc::mprotect((base as *mut c_void).add(start), len, prot) };
        if rc != 0 {
            let name = sec.name().unwrap_or("").to_string();
            return Err(MapError::MprotectFailed {
                section: name,
                addr: unsafe { base.add(start) },
                len,
                msg: errno_str(),
            });
        }
    }

    // Silence unused warning: section_alignment is documented for future use.
    let _ = section_alignment;

    Ok(MappedImage {
        base,
        size: mapped_size,
        preferred_base: preferred,
    })
}

/// Map a helper to try `MAP_FIXED` at `preferred`. Returns the address on success.
fn try_map_at(preferred: usize, size: usize) -> Option<*mut u8> {
    if preferred == 0 {
        return None;
    }
    // SAFETY: `MAP_FIXED` with `addr != 0` requests a specific address. If it fails we
    // return None; if it succeeds we own a `size`-byte anonymous mapping at `preferred`.
    let p = unsafe {
        libc::mmap(
            preferred as *mut c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        None
    } else {
        Some(p as *mut u8)
    }
}

/// Translate section characteristics into `mprotect` prot flags.
///
/// W^X: a section is executable (PROT_EXEC) only if `IMAGE_SCN_MEM_EXECUTE` is set, and in
/// that case we drop `PROT_WRITE` so it is never W+X. Read-only data sections lose write.
fn section_prot(name: &str, characteristics: u32) -> c_int {
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_READ: u32 = 0x4000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;

    let executable = characteristics & MEM_EXECUTE != 0;
    let readable = characteristics & MEM_READ != 0;
    let writable = characteristics & MEM_WRITE != 0;

    let mut prot: c_int = 0;
    if executable {
        prot |= libc::PROT_EXEC;
    }
    if readable || prot == 0 {
        prot |= libc::PROT_READ;
    }
    if writable && !executable {
        prot |= libc::PROT_WRITE;
    }
    // Debug sections are never executed; downgrade any stray EXEC on them.
    if name.starts_with(".debug") {
        prot &= !libc::PROT_EXEC;
    }
    prot
}

/// Apply the PE base relocation table so absolute addresses match the actual `base`.
///
/// `reloc_dir` is the base-relocation data directory (`(rva, size)`). We walk the block
/// stream: each block is a 4-byte page RVA, a 4-byte count, then `count` 2-byte entries
/// whose low 4 bits are the relocation type and high 12 bits are the page offset.
pub fn apply_relocations(
    img: &MappedImage,
    bytes: &[u8],
    reloc_dir: goblin::pe::data_directories::DataDirectory,
) -> Result<(), MapError> {
    let dir_rva = reloc_dir.virtual_address;
    let dir_size = reloc_dir.size as usize;
    if dir_rva == 0 || dir_size == 0 {
        return Ok(()); // no relocations (e.g. the minimal fixture)
    }

    let delta = (img.base as u64).wrapping_sub(img.preferred_base) as i64;

    // Resolve the relocation directory bytes from the file. We read from the file bytes
    // (which contain the raw .reloc section) using goblin's RVA->offset helpers via the
    // section table. For simplicity, and because .reloc is always within the loaded
    // headers/sections region, we also mirror it from the mapped image.
    let reloc_start = match rva_to_file_offset(bytes, dir_rva) {
        Some(off) => off,
        None => return Err(MapError::RelocDirOutOfRange(dir_rva)),
    };
    if reloc_start + dir_size > bytes.len() {
        return Err(MapError::RelocDirOutOfRange(dir_rva));
    }
    let reloc_bytes = &bytes[reloc_start..reloc_start + dir_size];

    let mut pos = 0usize;
    while pos + 8 <= reloc_bytes.len() {
        let page_rva = u32::from_le_bytes([
            reloc_bytes[pos],
            reloc_bytes[pos + 1],
            reloc_bytes[pos + 2],
            reloc_bytes[pos + 3],
        ]);
        let block_size = u32::from_le_bytes([
            reloc_bytes[pos + 4],
            reloc_bytes[pos + 5],
            reloc_bytes[pos + 6],
            reloc_bytes[pos + 7],
        ]) as usize;
        if block_size < 8 || pos + block_size > reloc_bytes.len() {
            return Err(MapError::RelocBlockOverflow);
        }
        let entries = &reloc_bytes[pos + 8..pos + block_size];
        let n = entries.len() / 2;
        for i in 0..n {
            let entry = u16::from_le_bytes([entries[i * 2], entries[i * 2 + 1]]);
            let typ = entry >> 12;
            let offset = (entry & 0x0FFF) as usize;
            if typ == 0 {
                continue; // IMAGE_REL_ABSOLUTE — padding, skip
            }
            let target_rva = page_rva as usize + offset;
            let target = match img.rva_to_ptr(target_rva as u32) {
                Some(p) => p,
                None => return Err(MapError::RelocRvaOutOfRange(target_rva as u32)),
            };
            apply_one_reloc(target, typ, delta)?;
        }
        pos += block_size;
    }

    Ok(())
}

/// Apply a single relocation at `target` of `typ` with the `delta` to add.
fn apply_one_reloc(target: *mut u8, typ: u16, delta: i64) -> Result<(), MapError> {
    // AMD64 relocation types we handle: 0 = absolute (skip), 1 = DIR64 (add delta to a
    // 64-bit value). Others are rare in x64 images and are left untouched (logged).
    match typ {
        // IMAGE_REL_AMD64_ABSOLUTE
        0 => Ok(()),
        // IMAGE_REL_AMD64_ADDR64
        1 => {
            // SAFETY: `target..target+8` is within the mapped image (validated by
            // rva_to_ptr) and was mapped writable-or-relocated. We read-modify-write a
            // little-endian u64 adding `delta`.
            let old = unsafe { std::ptr::read_unaligned(target as *const u64) };
            let new = (old as i64).wrapping_add(delta) as u64;
            unsafe { std::ptr::write_unaligned(target as *mut u64, new) };
            Ok(())
        }
        // IMAGE_REL_AMD64_ADDR32NB (RVA-only) — no delta for image-relative references.
        3 => Ok(()),
        // IMAGE_REL_AMD64_SECREL (32-bit section-relative offset) — the offset
        // is relative to the section start, not the image base, so it doesn't
        // change when we relocate. Used in .pdata exception tables.
        10 => Ok(()),
        // IMAGE_REL_AMD64_SECTION (16-bit section index) — no adjustment needed.
        11 => Ok(()),
        other => {
            log::debug!("skipping unsupported relocation type {other} at {target:p}");
            Ok(())
        }
    }
}

/// Resolve a Relative Virtual Address to a file offset using the section table embedded in
/// `bytes`. This mirrors what goblin does internally but is kept local so we read the raw
/// `.reloc` bytes directly.
fn rva_to_file_offset(bytes: &[u8], rva: u32) -> Option<usize> {
    // Re-parse only the section table header via goblin to get section RVAs/offsets.
    let pe = goblin::pe::PE::parse(bytes).ok()?;
    for sec in &pe.sections {
        let va = sec.virtual_address as usize;
        let vsz = sec.virtual_size as usize;
        let rsz = sec.size_of_raw_data as usize;
        let raw = sec.pointer_to_raw_data as usize;
        if (rva as usize) >= va && (rva as usize) < va + vsz.max(rsz) {
            let off = (rva as usize) - va;
            if off < rsz && raw + off < bytes.len() {
                return Some(raw + off);
            }
        }
    }
    None
}

/// Write the resolved IAT entries into the mapped image.
///
/// The IAT typically lives in a read-only `.rdata` section whose protection `map_image`
/// has already downgraded to `PROT_READ`. A real loader makes the IAT pages writable during
/// import binding (then flips them back); we make the slot's page `PROT_READ|PROT_WRITE`
/// for the duration of the write and leave it writable (flipping it back to RO is a later
/// refinement). This matches the Windows loader's "IAT is writable during load" contract.
pub fn write_iat(
    img: &MappedImage,
    imports: &[goblin::pe::import::Import],
    resolved: &std::collections::HashMap<(String, String), *const c_void>,
) {
    let page = page_size();
    for imp in imports {
        let dll = imp.dll.to_lowercase();
        let sym = imp.name.to_string();
        let key = (dll, sym);
        let Some(&ptr) = resolved.get(&key) else {
            continue;
        };
        // goblin's Import.offset is the IAT slot RVA.
        let Some(slot) = img.rva_to_ptr(imp.offset as u32) else {
            log::warn!("IAT slot at RVA {:#x} out of range", imp.offset);
            continue;
        };
        // Make the page(s) covering the 8-byte IAT slot writable before the write. Round the
        // span [slot, slot+8) to page boundaries so a slot straddling a page edge is covered.
        let start = (slot as usize) & !(page - 1);
        let end = round_up(slot as usize + 8, page);
        let len = end - start;
        // SAFETY: `start..start+len` is a page-aligned sub-region of the mapping we own
        // (`slot` was validated to be within `img.base..img.base+img.size`). mprotect to RW
        // so the slot is writable; we leave it RW (a later refinement restores RO).
        let rc = unsafe {
            libc::mprotect(
                start as *mut c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if rc != 0 {
            log::warn!(
                "mprotect(RW) of IAT slot at {slot:p} failed (errno {}); write may fault",
                unsafe { *libc::__errno_location() }
            );
        }
        // SAFETY: the IAT slot is within the mapped image and is now writable. Writing one
        // u64 is sound; the page was made RW above (or was already RW).
        unsafe { std::ptr::write_unaligned(slot as *mut u64, ptr as u64) };
    }
}

/// Round `n` up to a multiple of `page`.
fn round_up(n: usize, page: usize) -> usize {
    (n + page - 1) & !(page - 1)
}
/// Round `n` down to a multiple of `page`.
fn round_down(n: usize, page: usize) -> usize {
    n & !(page - 1)
}

/// Page size via `sysconf`.
fn page_size() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` is always safe and returns the page size.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p <= 0 {
        4096
    } else {
        p as usize
    }
}

/// Stringify the current thread's errno.
fn errno_str() -> String {
    // SAFETY: `__errno_location` returns a thread-local pointer safe to read.
    let e = unsafe { *libc::__errno_location() };
    format!("errno {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_prot_is_never_w_and_x() {
        // CODE | EXECUTE | READ | WRITE -> should drop WRITE (W^X), keep EXEC+READ.
        let p = section_prot(
            ".text",
            0x6000_0020 | 0x2000_0000 | 0x4000_0000 | 0x8000_0000,
        );
        assert_ne!(p & libc::PROT_EXEC, 0, "executable section keeps EXEC");
        assert_eq!(
            p & libc::PROT_WRITE,
            0,
            "executable section must not be writable"
        );
        assert_ne!(p & libc::PROT_READ, 0, "executable section keeps READ");
    }

    #[test]
    fn section_prot_writable_data_keeps_write() {
        let p = section_prot(".data", 0xC000_0040); // INITIALIZED_DATA | READ | WRITE
        assert_ne!(p & libc::PROT_WRITE, 0);
        assert_eq!(p & libc::PROT_EXEC, 0);
    }
}
