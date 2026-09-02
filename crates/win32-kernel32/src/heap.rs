//! Heap manager: `GetProcessHeap`, `HeapAlloc`/`HeapFree`/`HeapReAlloc`/`HeapCreate`/
//! `HeapDestroy`.
//!
//! Windows exposes a per-process default heap and lets callers create private heaps. We
//! model every heap as a single sentinel handle (the default heap is `1`, created heaps
//! are a small set of higher handles); all allocation actually goes through `libc::malloc`
//! /`free`/`realloc`. This matches the Windows contract that `HeapAlloc` returns
//! 8-byte-aligned, individually freeable memory and that `GetProcessHeap` returns a stable
//! process-wide handle.
//!
//! Each `HeapAlloc`/`HeapReAlloc` allocation stores its own byte length in a header word
//! immediately before the returned pointer so `HeapFree`/`HeapSize` know the size without
//! tracking it in a side table. The header is 8 bytes so the payload stays 8-byte aligned
//! (glibc `malloc` already returns 16-aligned memory, but the header logic is independent).

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;
use std::sync::OnceLock;

use crate::Handle;

/// The sentinel handle returned by `GetProcessHeap` and `HeapCreate` (a small nonzero
/// value that is never a real fd-backed handle in the ntapi handle table, so it never
/// collides with a file/thread/event object).
const HEAP_HANDLE: Handle = 0x0001_0000_0000_0001;

/// `ERROR_NOT_ENOUGH_MEMORY` (8) — written when `malloc` returns NULL.
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// The global heap-table registry. Real Windows heaps are distinct objects; for the
/// console-PE use case one process heap plus any number of `HeapCreate` handles is plenty,
/// so we just record which handles are live heaps.
fn known_heaps() -> &'static parking_lot::Mutex<std::collections::HashSet<Handle>> {
    static H: OnceLock<parking_lot::Mutex<std::collections::HashSet<Handle>>> = OnceLock::new();
    H.get_or_init(|| parking_lot::Mutex::new(std::collections::HashSet::new()))
}

/// Register the default process heap on first use.
fn ensure_default_heap() {
    let mut g = known_heaps().lock();
    if g.is_empty() {
        g.insert(HEAP_HANDLE);
    }
}

/// `kernel32!GetProcessHeap() -> HANDLE`. Returns the stable sentinel process-heap handle.
pub extern "C" fn get_process_heap() -> Handle {
    ensure_default_heap();
    HEAP_HANDLE
}

/// `kernel32!HeapCreate(flOptions, dwInitialSize, dwMaximumSize) -> HANDLE`. We ignore the
/// size parameters (libc malloc grows on demand) and just mint a new heap sentinel.
pub extern "C" fn heap_create(_fl_options: u32, _initial_size: usize, _max_size: usize) -> Handle {
    // Pick a handle distinct from the default heap but still in the sentinel range.
    let mut g = known_heaps().lock();
    let next = 0x0001_0000_0000_0002 + g.len() as Handle;
    g.insert(next);
    next
}

/// `kernel32!HeapDestroy(hHeap) -> BOOL`. Always succeeds for a heap handle we know.
pub extern "C" fn heap_destroy(heap: Handle) -> i32 {
    let mut g = known_heaps().lock();
    if g.remove(&heap) || heap == HEAP_HANDLE {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// Layout of the per-allocation header: a single `usize` length word, then the payload.
const HEADER_SIZE: usize = std::mem::size_of::<usize>();

/// `kernel32!HeapAlloc(hHeap, dwFlags, dwBytes) -> LPVOID`. Backed by `libc::malloc`; stores
/// the requested size in a header word just before the returned payload pointer. `dwFlags`
/// may set `HEAP_ZERO_MEMORY` (0x08), in which case the payload is zeroed.
pub extern "C" fn heap_alloc(_heap: Handle, flags: u32, bytes: usize) -> *mut c_void {
    eprintln!("[nigg heap] HeapAlloc(bytes={bytes})");
    const HEAP_ZERO_MEMORY: u32 = 0x08;
    let total = bytes.saturating_add(HEADER_SIZE);
    // SAFETY: `libc::malloc(total)` returns a valid pointer to `total` bytes or NULL.
    let raw = unsafe { libc::malloc(total) };
    if raw.is_null() {
        nigg_ntapi::process::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return std::ptr::null_mut();
    }
    // SAFETY: `raw` is non-null and valid for `total` bytes; we write the header at the
    // start of the allocation.
    unsafe {
        std::ptr::write_unaligned(raw as *mut usize, bytes);
    }
    // SAFETY: `raw` is a valid allocation of `total` bytes and `HEADER_SIZE <= total`, so
    // `raw + HEADER_SIZE` is within the allocation.
    let payload = unsafe { (raw as *mut u8).add(HEADER_SIZE) } as *mut c_void;
    if flags & HEAP_ZERO_MEMORY != 0 {
        // SAFETY: `payload..payload+bytes` is within the allocation (after the header).
        unsafe { std::ptr::write_bytes(payload as *mut u8, 0, bytes) };
    }
    payload
}

/// `kernel32!HeapFree(hHeap, dwFlags, lpMem) -> BOOL`. Reads the header to recover the
/// allocation base, then `libc::free`s it. A null pointer is a no-op success.
pub extern "C" fn heap_free(_heap: Handle, _flags: u32, mem: *mut c_void) -> i32 {
    if mem.is_null() {
        return 1; // TRUE: freeing NULL is a no-op (matches the Windows best-effort contract)
    }
    let base = (mem as *mut u8).wrapping_sub(HEADER_SIZE) as *mut c_void;
    // SAFETY: `base` is the original `malloc` return (header precedes the payload we
    // handed out); `free` releases it.
    unsafe { libc::free(base) };
    1
}

/// `kernel32!HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes) -> LPVOID`. Grows/shrinks the
/// allocation via `libc::realloc`, copying the old contents (up to the new size). Preserves
/// the header so `HeapFree` keeps working. Supports `HEAP_ZERO_MEMORY`-style growth only
/// in the simplest sense (newly grown bytes are zeroed when the flag is set).
pub extern "C" fn heap_re_alloc(
    _heap: Handle,
    flags: u32,
    mem: *mut c_void,
    bytes: usize,
) -> *mut c_void {
    const HEAP_ZERO_MEMORY: u32 = 0x08;
    if mem.is_null() {
        // ReAlloc(NULL, n) is equivalent to HeapAlloc(n).
        return heap_alloc(0, flags, bytes);
    }
    let base = (mem as *mut u8).wrapping_sub(HEADER_SIZE) as *mut c_void;
    let total = bytes.saturating_add(HEADER_SIZE);
    // SAFETY: `base` is the original `malloc`/`realloc` allocation; `realloc` either
    // returns a fresh pointer for `total` bytes (copying the old contents up to the smaller
    // of old/new size) or NULL on failure.
    let new_raw = unsafe { libc::realloc(base, total) };
    if new_raw.is_null() {
        nigg_ntapi::process::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return std::ptr::null_mut();
    }
    // SAFETY: `new_raw` is non-null and valid for `total` bytes (realloc succeeded); reading
    // the first `usize` (the old header) is within bounds.
    let old_bytes = unsafe { std::ptr::read_unaligned(new_raw as *mut usize) };
    // SAFETY: `new_raw` is non-null and valid for `total` bytes; rewrite the header.
    unsafe {
        std::ptr::write_unaligned(new_raw as *mut usize, bytes);
    }
    // SAFETY: `new_raw` is a valid allocation of `total` bytes and `HEADER_SIZE <= total`,
    // so `new_raw + HEADER_SIZE` is within the allocation.
    let payload = unsafe { (new_raw as *mut u8).add(HEADER_SIZE) } as *mut c_void;
    if flags & HEAP_ZERO_MEMORY != 0 && bytes > old_bytes {
        // Zero the grown tail (bytes old_bytes..bytes).
        let off = old_bytes;
        // SAFETY: `payload+off .. payload+bytes` is within the allocation.
        unsafe {
            std::ptr::write_bytes((payload as *mut u8).add(off), 0, bytes - off);
        }
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_heap_is_stable_sentinel() {
        let a = get_process_heap();
        let b = get_process_heap();
        assert_eq!(a, b, "GetProcessHeap returns the same handle every call");
        assert_eq!(a, HEAP_HANDLE);
    }

    #[test]
    fn heap_alloc_free_round_trip() {
        let h = get_process_heap();
        let p = heap_alloc(h, 0, 64);
        assert!(!p.is_null());
        // Write some bytes to confirm the payload is usable.
        // SAFETY: `p` was just allocated for 64 bytes.
        unsafe {
            std::ptr::write_bytes(p as *mut u8, 0xAB, 64);
        }
        assert_eq!(heap_free(h, 0, p), 1);
    }

    #[test]
    fn heap_alloc_zero_memory() {
        let h = get_process_heap();
        let p = heap_alloc(h, 0x08, 32);
        assert!(!p.is_null());
        // SAFETY: `p` was just allocated for 32 bytes with the zero-memory flag.
        let buf = unsafe { std::slice::from_raw_parts(p as *const u8, 32) };
        assert!(
            buf.iter().all(|&b| b == 0),
            "HEAP_ZERO_MEMORY zeroes the payload"
        );
        heap_free(h, 0, p);
    }

    #[test]
    fn heap_realloc_grows_and_preserves() {
        let h = get_process_heap();
        let p = heap_alloc(h, 0, 8);
        // SAFETY: `p` is an 8-byte allocation.
        unsafe {
            std::ptr::write_bytes(p as *mut u8, 0x77, 8);
        }
        let q = heap_re_alloc(h, 0, p, 32);
        assert!(!q.is_null());
        // SAFETY: `q` is a 32-byte allocation; the first 8 bytes were copied from `p`.
        let buf = unsafe { std::slice::from_raw_parts(q as *const u8, 8) };
        assert!(
            buf.iter().all(|&b| b == 0x77),
            "realloc preserved the old contents"
        );
        heap_free(h, 0, q);
    }

    #[test]
    fn heap_create_destroy_round_trip() {
        let h = heap_create(0, 0x1000, 0);
        assert_ne!(h, 0, "HeapCreate returns a non-zero handle");
        let p = heap_alloc(h, 0, 16);
        assert!(!p.is_null());
        heap_free(h, 0, p);
        assert_eq!(
            heap_destroy(h),
            1,
            "HeapDestroy of a known heap returns TRUE"
        );
    }
}
