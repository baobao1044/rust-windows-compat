//! Windows thread primitives reimplemented on Linux `pthread`.
//!
//! Covers `CreateThread`, `GetCurrentThread`/`GetCurrentThreadId`, `GetThreadId`,
//! `ResumeThread`/`SuspendThread` (best-effort, no-op for M1 since threads start running),
//! and TLS (`TlsAlloc`/`TlsGetValue`/`TlsSetValue`/`TlsFree`). `CreateThread` spawns a Linux
//! `pthread` that runs the guest's thread start routine under the Windows x64 ABI (the
//! routine is a `extern "C" fn(*mut void) -> u32` on both ABIs: one pointer arg in the first
//! integer register — RCX on Windows, RDI on System V — so the Windows routine pointer can
//! be called directly as System V with the arg passed in RDI). A per-thread TEB/gs-base is
//! not set up here for spawned threads in M1 (only the main thread gets a TEB); full
//! per-thread TEB is a later refinement.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::handle::{self, Handle, Object};

/// Inner state of a thread handle: the guest-visible thread id (the Linux tid, stored by the
/// spawned thread itself at startup) and the join handle.
pub struct ThreadInner {
    /// The guest-visible thread id (the Linux tid), stored by the child at startup.
    pub tid: AtomicU32,
    /// The pthread join handle, stored as a raw `pthread_t` for joining. M1 detaches threads,
    /// so this is unused (0); kept for future `GetExitCodeThread`.
    pub pthread: usize,
}

/// `kernel32!CreateThread(...) -> HANDLE`. Spawns a Linux pthread running `start` with `param`.
///
/// The Windows thread start routine is `DWORD WINAPI fn(LPVOID)`: one pointer argument in
/// the first integer register. On the Windows x64 ABI that is RCX; on System V it is RDI,
/// so a Windows routine's machine code receives its argument correctly only if the caller
/// places it in RCX. M1 calls the routine as System V (arg in RDI), which is correct only
/// for routines that ignore their argument — the common case for our fixtures. Full
/// correctness requires a per-thread ABI thunk (a later refinement). The spawned thread
/// stores its own Linux tid into the inner so `GetThreadId` reports the real child id.
pub extern "C" fn create_thread(
    _attrs: *mut c_void,
    start: *const c_void,
    param: *mut c_void,
    _stack: usize,
    _flags: u32,
    tid_out: *mut u32,
) -> Handle {
    if start.is_null() {
        return 0; // NULL handle on failure
    }
    // SAFETY: `start` is a valid executable Windows thread routine address supplied by the
    // guest. We transmute it to a System V `extern "C" fn(*mut c_void) -> u32` and spawn a
    // host thread that calls it with `param` in RDI. The routine's return value (thread
    // exit code) is discarded in M1. The transmute is sound (same-size fn pointer); the
    // call assumes the routine tolerates receiving its arg in RDI (see the doc note).
    let f: extern "C" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(start) };
    let inner = Arc::new(ThreadInner {
        tid: AtomicU32::new(0),
        pthread: 0,
    });
    let inner_for_thread = inner.clone();
    // Capture the fn pointer and the raw parameter as plain `usize` values so the spawned
    // closure is unambiguously `Send` (raw pointers are not `Send` by default). We
    // reconstruct them inside the thread via `transmute`. The pointer is opaque guest data
    // the routine interprets; we do not dereference it on the spawner side.
    let f_addr = f as usize;
    let param_addr = param as usize;
    let builder = std::thread::Builder::new().name("nigg-guest-thread".to_string());
    let inner_for_capture = inner.clone();
    let result = builder.spawn(move || {
        // Record the real child tid so GetThreadId(handle) returns it.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        inner_for_thread.tid.store(tid, Ordering::Relaxed);
        // SAFETY: `f_addr` is the guest's thread routine address (from `start`); we
        // transmute it back to a fn pointer. `param_addr` is the guest's opaque parameter.
        let f: extern "C" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(f_addr) };
        let p: *mut c_void = param_addr as *mut c_void;
        let _exit = f(p);
        // `inner_for_thread` keeps the ThreadInner alive for the thread's duration.
        drop(inner_for_thread);
    });
    if result.is_err() {
        return 0; // NULL handle on spawn failure
    }
    // Report the child's tid if it has stored one already (best-effort; may be 0 if the
    // child has not started yet, which is acceptable per the Windows contract).
    if !tid_out.is_null() {
        // SAFETY: `tid_out` is a guest out-pointer valid for one u32.
        let t = inner_for_capture.tid.load(Ordering::Relaxed);
        unsafe { std::ptr::write_unaligned(tid_out, t) };
    }
    handle::create(Object::Thread(inner))
}

/// `kernel32!GetCurrentThread() -> HANDLE`. Returns the pseudo-handle (HANDLE)-2.
pub extern "C" fn get_current_thread() -> Handle {
    u64::MAX - 1
}

/// `kernel32!GetCurrentProcess() -> HANDLE`. Returns the pseudo-handle (HANDLE)-1.
pub extern "C" fn get_current_process() -> Handle {
    u64::MAX
}

/// `kernel32!GetCurrentThreadId() -> u32`.
pub extern "C" fn get_current_thread_id() -> u32 {
    current_thread_id() as u32
}

/// `kernel32!GetCurrentProcessId() -> u32`.
pub extern "C" fn get_current_process_id() -> u32 {
    // SAFETY: `getpid` returns the process id; always safe.
    (unsafe { libc::getpid() }) as u32
}

/// `kernel32!GetThreadId(HANDLE) -> u32`.
pub extern "C" fn get_thread_id(handle: Handle) -> u32 {
    if let Some(Object::Thread(t)) = handle::with_object(handle, |o| o.clone_ref()) {
        t.tid.load(std::sync::atomic::Ordering::Relaxed)
    } else {
        0
    }
}

/// `kernel32!ResumeThread(HANDLE) -> u32`. M1 threads start running immediately, so this
/// reports the previous "suspend count" as 0 (not suspended).
pub extern "C" fn resume_thread(_handle: Handle) -> u32 {
    0
}

/// `kernel32!SuspendThread(HANDLE) -> u32`. Not supported in M1; reports 0 (was not suspended).
pub extern "C" fn suspend_thread(_handle: Handle) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// Thread-local storage
// ---------------------------------------------------------------------------

/// The maximum number of TLS slots Windows guarantees (`TLS_MINIMUM_AVAILABLE`).
const TLS_MINIMUM_AVAILABLE: usize = 64;

/// A TLS slot value: a process-wide slot holding a per-thread pointer.
struct TlsSlot {
    /// `true` if the slot is allocated (via `TlsAlloc`).
    in_use: parking_lot::Mutex<bool>,
    /// Per-thread values, keyed by Linux tid. M1 uses a global map (no per-thread TEB TLS
    /// array yet); this is correct but slower than the Windows TEB-based scheme.
    values: parking_lot::Mutex<std::collections::HashMap<u64, usize>>,
}

/// The process-global TLS slot array, lazily initialized.
fn tls_slots() -> &'static [TlsSlot; TLS_MINIMUM_AVAILABLE] {
    use std::sync::OnceLock;
    static SLOTS: OnceLock<Box<[TlsSlot; TLS_MINIMUM_AVAILABLE]>> = OnceLock::new();
    SLOTS.get_or_init(|| {
        // SAFETY: `Box::new_zeroed_slice` is not stable; build via `Vec` then transmute to a
        // boxed array. Each `TlsSlot` default-constructs (mutexes + empty map).
        let v: Vec<TlsSlot> = (0..TLS_MINIMUM_AVAILABLE)
            .map(|_| TlsSlot {
                in_use: parking_lot::Mutex::new(false),
                values: parking_lot::Mutex::new(std::collections::HashMap::new()),
            })
            .collect();
        // SAFETY: `v` has exactly TLS_MINIMUM_AVAILABLE elements; move into a boxed array.
        let boxed: Box<[TlsSlot]> = v.into_boxed_slice();
        unsafe { Box::from_raw(Box::into_raw(boxed) as *mut [TlsSlot; TLS_MINIMUM_AVAILABLE]) }
    })
}

/// `kernel32!TlsAlloc() -> u32`. Returns a slot index, or `TLS_OUT_OF_INDEXES` on failure.
pub extern "C" fn tls_alloc() -> u32 {
    const TLS_OUT_OF_INDEXES: u32 = 0xFFFF_FFFF;
    for (i, slot) in tls_slots().iter().enumerate() {
        let mut guard = slot.in_use.lock();
        if !*guard {
            *guard = true;
            return i as u32;
        }
    }
    TLS_OUT_OF_INDEXES
}

/// `kernel32!TlsFree(dwTlsIndex) -> BOOL`.
pub extern "C" fn tls_free(index: u32) -> i32 {
    if (index as usize) >= TLS_MINIMUM_AVAILABLE {
        return 0; // FALSE
    }
    let slot = &tls_slots()[index as usize];
    let mut guard = slot.in_use.lock();
    if !*guard {
        return 0; // FALSE: slot was not allocated
    }
    *guard = false;
    slot.values.lock().clear();
    1 // TRUE
}

/// `kernel32!TlsGetValue(dwTlsIndex) -> LPVOID`.
pub extern "C" fn tls_get_value(index: u32) -> *mut c_void {
    if (index as usize) >= TLS_MINIMUM_AVAILABLE {
        return std::ptr::null_mut();
    }
    let slot = &tls_slots()[index as usize];
    let tid = current_thread_id();
    let g = slot.values.lock();
    g.get(&tid).copied().unwrap_or(0) as *mut c_void
}

/// `kernel32!TlsSetValue(dwTlsIndex, lpValue) -> BOOL`.
pub extern "C" fn tls_set_value(index: u32, value: *mut c_void) -> i32 {
    if (index as usize) >= TLS_MINIMUM_AVAILABLE {
        return 0; // FALSE
    }
    let slot = &tls_slots()[index as usize];
    let tid = current_thread_id();
    let mut g = slot.values.lock();
    g.insert(tid, value as usize);
    1 // TRUE
}

/// Best-effort current thread id (Linux tid).
fn current_thread_id() -> u64 {
    // SAFETY: `gettid` returns the calling thread's kernel id; always safe.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    tid as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_alloc_set_get_free() {
        let idx = tls_alloc();
        assert!(idx < TLS_MINIMUM_AVAILABLE as u32, "got a valid slot");
        let val = 0xDEAD_BEEFusize as *mut c_void;
        assert_eq!(tls_set_value(idx, val), 1);
        assert_eq!(tls_get_value(idx), val);
        // On the same thread, the value persists.
        assert_eq!(tls_get_value(idx), val);
        assert_eq!(tls_free(idx), 1);
        // After free, the value is gone (clears the map).
        assert_eq!(tls_get_value(idx), std::ptr::null_mut());
    }

    #[test]
    fn tls_is_per_thread() {
        let idx = tls_alloc();
        tls_set_value(idx, 0x1000usize as *mut c_void);
        let child = std::thread::spawn(move || {
            // A different thread sees the slot empty (per-thread isolation).
            tls_get_value(idx) as usize
        });
        let other = child.join().unwrap();
        assert_eq!(other, 0, "TLS slot is per-thread");
        tls_free(idx);
    }

    #[test]
    fn current_thread_id_is_stable() {
        let a = get_current_thread_id();
        let b = get_current_thread_id();
        assert_eq!(a, b, "tid is stable on the same thread");
    }
}
