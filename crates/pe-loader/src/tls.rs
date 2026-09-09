//! PE TLS directory support: static thread-local storage and TLS callbacks.
//!
//! An MSVC-linked PE (which is to say: most real Windows programs, and every
//! game we care about) can carry an `IMAGE_TLS_DIRECTORY64` in data directory
//! slot 9. It describes two things the loader must set up *before* the entry
//! point runs:
//!
//! 1. **Static TLS data.** `RawDataStart..RawDataEnd` is a template block that
//!    every thread gets a private copy of, plus `SizeOfZeroFill` bytes of
//!    zeroes after it. The per-thread copy is reached through the TEB: slot
//!    `*AddressOfIndex` indexes `TEB.ThreadLocalStoragePointer` (`gs:[0x58]`),
//!    which points at an array of per-module TLS blocks. Code compiled with
//!    `__declspec(thread)` loads `gs:[0x58]`, indexes it, and dereferences —
//!    so if we leave `gs:[0x58]` NULL the guest faults on its first
//!    thread-local access.
//!
//! 2. **TLS callbacks.** `AddressOfCallBacks` points at a NULL-terminated array
//!    of `PIMAGE_TLS_CALLBACK`. Windows invokes each one with the same
//!    `(hModule, reason, reserved)` signature as `DllMain`, and — importantly —
//!    it runs them with `DLL_PROCESS_ATTACH` **before** the executable's entry
//!    point. The MSVC CRT registers its thread-state initializer here, and
//!    userland anti-cheat commonly places its earliest hook in a TLS callback
//!    precisely because it runs before `main`. Skipping them means either
//!    crashing later on uninitialized CRT state, or silently not running code
//!    the program expects to have run.
//!
//! We model a single module's static TLS: one block, index 0, pointed at by a
//! one-entry TLS array. That covers a self-contained EXE. A future milestone
//! that supports static TLS in several simultaneously-loaded modules needs a
//! real slot allocator here.

use std::os::raw::c_void;

/// `DLL_PROCESS_ATTACH` — the reason code Windows passes to TLS callbacks
/// during process startup.
pub const DLL_PROCESS_ATTACH: u32 = 1;

/// The parsed `IMAGE_TLS_DIRECTORY64` fields we act on.
#[derive(Debug, Clone, Copy)]
pub struct TlsDirectory {
    /// VA of the start of the static TLS template block.
    pub raw_data_start: u64,
    /// VA of the end of the template block (exclusive).
    pub raw_data_end: u64,
    /// VA of the `DWORD` that receives the module's TLS slot index.
    pub address_of_index: u64,
    /// VA of the NULL-terminated `PIMAGE_TLS_CALLBACK` array (0 when absent).
    pub address_of_callbacks: u64,
    /// Bytes of zero-fill that follow the template block.
    pub size_of_zero_fill: u32,
}

impl TlsDirectory {
    /// Size of the initialized part of the TLS template.
    pub fn raw_size(&self) -> usize {
        self.raw_data_end.saturating_sub(self.raw_data_start) as usize
    }

    /// Total per-thread TLS block size (template + zero fill).
    pub fn block_size(&self) -> usize {
        self.raw_size() + self.size_of_zero_fill as usize
    }
}

/// Errors raised while setting up static TLS.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("TLS directory RVA {rva:#x} is outside the mapped image")]
    OutOfBounds { rva: u32 },
    #[error("TLS directory is malformed: RawDataEnd {end:#x} < RawDataStart {start:#x}")]
    Malformed { start: u64, end: u64 },
}

/// Per-thread static TLS storage, kept alive for as long as the image runs.
///
/// The guest reaches this through `TEB.ThreadLocalStoragePointer`, so the
/// allocation must outlive every guest thread that can touch it. Dropping it
/// while the guest still runs would dangle `gs:[0x58]`.
pub struct TlsBlock {
    /// The per-module TLS data block the guest reads and writes.
    /// The per-module TLS data block the guest reads and writes through the slot
    /// pointer in `slots`. The guest reaches the bytes by dereferencing
    /// `gs:[0x58]` + the module's TLS index, so the `Vec` backing memory must stay
    /// alive as long as any guest thread can run, but no Rust code reads it
    /// directly — it's purely a backing allocation for a guest-visible address.
    #[allow(dead_code)]
    data: Vec<u8>,
    /// The one-entry TLS array `TEB.ThreadLocalStoragePointer` points at. Boxed
    /// so its address is stable regardless of where the `TlsBlock` itself moves.
    slots: Box<[*mut c_void; 1]>,
}

// SAFETY: the block owns its allocations; the raw pointer inside `slots` refers
// to `data`, which is owned by the same struct and never aliased from Rust.
unsafe impl Send for TlsBlock {}
unsafe impl Sync for TlsBlock {}

impl TlsBlock {
    /// The value to store in `TEB.ThreadLocalStoragePointer` (`gs:[0x58]`).
    pub fn teb_tls_pointer(&self) -> *mut c_void {
        self.slots.as_ptr() as *mut c_void
    }
}

/// Read the `IMAGE_TLS_DIRECTORY64` at `rva` out of the mapped image.
///
/// Returns `None` when the image has no TLS directory (the common case for the
/// hand-built fixtures and for mingw-linked binaries).
///
/// # Safety
///
/// `base` must point at a mapped image of at least `image_size` bytes, with the
/// TLS directory contents already relocated.
pub unsafe fn read_tls_directory(
    base: *const u8,
    image_size: usize,
    rva: u32,
) -> Result<TlsDirectory, TlsError> {
    // The structure is 40 bytes: 4 u64 VAs, then u32 zero-fill + u32 flags.
    const TLS_DIR_SIZE: usize = 40;
    if rva == 0 || rva as usize + TLS_DIR_SIZE > image_size {
        return Err(TlsError::OutOfBounds { rva });
    }
    // SAFETY: the bounds check above keeps the whole struct inside the mapping;
    // reads are unaligned-safe.
    let p = unsafe { base.add(rva as usize) };
    let rd = |off: usize| -> u64 {
        // SAFETY: `off` stays within TLS_DIR_SIZE, validated above.
        unsafe { std::ptr::read_unaligned(p.add(off) as *const u64) }
    };
    let raw_data_start = rd(0);
    let raw_data_end = rd(8);
    let address_of_index = rd(16);
    let address_of_callbacks = rd(24);
    // SAFETY: offset 32 is inside the validated struct.
    let size_of_zero_fill = unsafe { std::ptr::read_unaligned(p.add(32) as *const u32) };

    if raw_data_end < raw_data_start {
        return Err(TlsError::Malformed {
            start: raw_data_start,
            end: raw_data_end,
        });
    }

    Ok(TlsDirectory {
        raw_data_start,
        raw_data_end,
        address_of_index,
        address_of_callbacks,
        size_of_zero_fill,
    })
}

/// Allocate the per-thread static TLS block, seed it from the image template,
/// and publish the module's slot index into `*AddressOfIndex`.
///
/// # Safety
///
/// `base`/`image_size` must describe the live mapped image, and `dir` must have
/// come from [`read_tls_directory`] on that same image. `AddressOfIndex` must
/// point into writable image memory (it lives in `.data` for every real PE).
pub unsafe fn init_static_tls(
    base: *mut u8,
    image_size: usize,
    image_base: u64,
    dir: &TlsDirectory,
) -> Result<TlsBlock, TlsError> {
    let block_size = dir.block_size();
    let mut data = vec![0u8; block_size.max(1)];

    // Copy the initialized template, when the directory declares one. The VAs in
    // the directory are absolute (already relocated), so convert back to an RVA.
    let raw_size = dir.raw_size();
    if raw_size > 0 {
        let template_rva = dir.raw_data_start.saturating_sub(image_base) as usize;
        if template_rva + raw_size > image_size {
            return Err(TlsError::OutOfBounds {
                rva: template_rva as u32,
            });
        }
        // SAFETY: the bounds check above keeps the source inside the mapping, and
        // `data` was sized to hold at least `raw_size` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(base.add(template_rva), data.as_mut_ptr(), raw_size);
        }
    }

    let slots: Box<[*mut c_void; 1]> = Box::new([data.as_mut_ptr() as *mut c_void]);

    // Publish slot index 0 into `*AddressOfIndex`. Guest code loads this DWORD to
    // find its entry in the TLS array, so leaving it unwritten sends every
    // thread-local access to the wrong slot.
    if dir.address_of_index != 0 {
        let index_rva = dir.address_of_index.saturating_sub(image_base) as usize;
        if index_rva + 4 <= image_size {
            // SAFETY: bounds-checked against the mapping; `.data` is mapped writable
            // at this point (permissions are downgraded after load).
            unsafe { std::ptr::write_unaligned(base.add(index_rva) as *mut u32, 0) };
        } else {
            return Err(TlsError::OutOfBounds {
                rva: index_rva as u32,
            });
        }
    }

    Ok(TlsBlock { data, slots })
}

/// Collect the TLS callback function pointers, in order.
///
/// The array is NULL-terminated. We cap the walk so a corrupt or hostile image
/// cannot spin us forever.
///
/// # Safety
///
/// `base`/`image_size` must describe the live mapped image and `dir` must have
/// come from [`read_tls_directory`] on it.
pub unsafe fn collect_callbacks(
    base: *const u8,
    image_size: usize,
    image_base: u64,
    dir: &TlsDirectory,
) -> Vec<*const ()> {
    /// No real image registers anywhere near this many TLS callbacks.
    const MAX_CALLBACKS: usize = 64;

    let mut out = Vec::new();
    if dir.address_of_callbacks == 0 {
        return out;
    }
    let mut rva = dir.address_of_callbacks.saturating_sub(image_base) as usize;
    for _ in 0..MAX_CALLBACKS {
        if rva + 8 > image_size {
            log::warn!("pe-loader: TLS callback array runs past the image; stopping");
            break;
        }
        // SAFETY: bounds-checked against the mapping on each iteration.
        let va = unsafe { std::ptr::read_unaligned(base.add(rva) as *const u64) };
        if va == 0 {
            break;
        }
        // Callback VAs are absolute and already relocated; make sure the target is
        // inside the image before we agree to jump to it.
        let target_rva = va.saturating_sub(image_base) as usize;
        if target_rva >= image_size {
            log::warn!("pe-loader: TLS callback {va:#x} points outside the image; skipping");
            rva += 8;
            continue;
        }
        // SAFETY: `target_rva` is inside the mapping, which is executable where code
        // lives.
        out.push(unsafe { base.add(target_rva) } as *const ());
        rva += 8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fake 40-byte TLS directory inside a scratch "image".
    fn scratch_image() -> (Vec<u8>, u64) {
        // 4 KiB image at base 0x140000000. TLS dir at RVA 0x100.
        let mut img = vec![0u8; 4096];
        let base = 0x1_4000_0000u64;
        let dir_rva = 0x100usize;
        let template_rva = 0x200u64;
        let index_rva = 0x300u64;

        let put = |img: &mut Vec<u8>, off: usize, v: u64| {
            img[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        put(&mut img, dir_rva, base + template_rva); // RawDataStart
        put(&mut img, dir_rva + 8, base + template_rva + 16); // RawDataEnd
        put(&mut img, dir_rva + 16, base + index_rva); // AddressOfIndex
        put(&mut img, dir_rva + 24, 0); // AddressOfCallBacks (none)
        img[dir_rva + 32..dir_rva + 36].copy_from_slice(&8u32.to_le_bytes()); // zero fill

        // Template bytes 0..16 = 1..16 so we can assert the copy.
        for i in 0..16usize {
            img[template_rva as usize + i] = (i + 1) as u8;
        }
        (img, base)
    }

    #[test]
    fn reads_directory_fields() {
        let (img, base) = scratch_image();
        // SAFETY: `img` is a 4096-byte scratch image and 0x100 is in bounds.
        let dir = unsafe { read_tls_directory(img.as_ptr(), img.len(), 0x100) }.expect("dir");
        assert_eq!(dir.raw_size(), 16);
        assert_eq!(dir.size_of_zero_fill, 8);
        assert_eq!(dir.block_size(), 24);
        assert_eq!(dir.address_of_index, base + 0x300);
    }

    #[test]
    fn copies_template_and_publishes_index() {
        let (mut img, base) = scratch_image();
        let len = img.len();
        // SAFETY: scratch image, in-bounds RVA.
        let dir = unsafe { read_tls_directory(img.as_ptr(), len, 0x100) }.expect("dir");
        // SAFETY: same scratch image; the directory came from it.
        let block = unsafe { init_static_tls(img.as_mut_ptr(), len, base, &dir) }.expect("tls");

        // The template's 16 bytes are copied, the 8 zero-fill bytes stay zero.
        assert_eq!(&block.data[..16], &(1..=16).collect::<Vec<u8>>()[..]);
        assert_eq!(&block.data[16..24], &[0u8; 8]);

        // Slot index 0 was published into *AddressOfIndex.
        let idx = u32::from_le_bytes(img[0x300..0x304].try_into().unwrap());
        assert_eq!(idx, 0);

        // The TEB pointer is non-null and points at the one-entry slot array.
        assert!(!block.teb_tls_pointer().is_null());
    }

    #[test]
    fn no_callbacks_when_array_absent() {
        let (img, base) = scratch_image();
        // SAFETY: scratch image, in-bounds RVA.
        let dir = unsafe { read_tls_directory(img.as_ptr(), img.len(), 0x100) }.expect("dir");
        // SAFETY: same image.
        let cbs = unsafe { collect_callbacks(img.as_ptr(), img.len(), base, &dir) };
        assert!(cbs.is_empty());
    }

    #[test]
    fn walks_callback_array_and_stops_at_null() {
        let (mut img, base) = scratch_image();
        let cb_rva = 0x400usize;
        // Point the directory at a callback array with two in-image entries.
        img[0x100 + 24..0x100 + 32].copy_from_slice(&(base + cb_rva as u64).to_le_bytes());
        img[cb_rva..cb_rva + 8].copy_from_slice(&(base + 0x500).to_le_bytes());
        img[cb_rva + 8..cb_rva + 16].copy_from_slice(&(base + 0x520).to_le_bytes());
        // Third entry stays zero → terminator.

        // SAFETY: scratch image, in-bounds RVA.
        let dir = unsafe { read_tls_directory(img.as_ptr(), img.len(), 0x100) }.expect("dir");
        // SAFETY: same image.
        let cbs = unsafe { collect_callbacks(img.as_ptr(), img.len(), base, &dir) };
        assert_eq!(cbs.len(), 2);
        // SAFETY: pointer arithmetic on the scratch buffer for comparison only.
        assert_eq!(cbs[0], unsafe { img.as_ptr().add(0x500) } as *const ());
        assert_eq!(cbs[1], unsafe { img.as_ptr().add(0x520) } as *const ());
    }

    #[test]
    fn rejects_out_of_bounds_directory() {
        let (img, _) = scratch_image();
        // SAFETY: deliberately out-of-range RVA; the function must reject it.
        let r = unsafe { read_tls_directory(img.as_ptr(), img.len(), 0xF000) };
        assert!(matches!(r, Err(TlsError::OutOfBounds { .. })));
    }

    #[test]
    fn skips_callback_pointing_outside_the_image() {
        let (mut img, base) = scratch_image();
        let cb_rva = 0x400usize;
        img[0x100 + 24..0x100 + 32].copy_from_slice(&(base + cb_rva as u64).to_le_bytes());
        // First entry is way past the image; second is valid.
        img[cb_rva..cb_rva + 8].copy_from_slice(&(base + 0xF_0000).to_le_bytes());
        img[cb_rva + 8..cb_rva + 16].copy_from_slice(&(base + 0x500).to_le_bytes());

        // SAFETY: scratch image, in-bounds RVA.
        let dir = unsafe { read_tls_directory(img.as_ptr(), img.len(), 0x100) }.expect("dir");
        // SAFETY: same image.
        let cbs = unsafe { collect_callbacks(img.as_ptr(), img.len(), base, &dir) };
        assert_eq!(cbs.len(), 1, "the out-of-image callback must be skipped");
        // SAFETY: comparison only.
        assert_eq!(cbs[0], unsafe { img.as_ptr().add(0x500) } as *const ());
    }
}
