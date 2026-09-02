//! Windows synchronization primitives reimplemented on Linux futexes.
//!
//! Covers `CRITICAL_SECTION` (recursive mutex), `Event` (auto- and manual-reset),
//! `Mutex` (recursive), `Semaphore`, `SRWLock`, `Sleep`/`SleepEx`, and
//! `WaitForSingleObject`/`WaitForMultipleObjects`. Each primitive backs its wait/wake with
//! the Linux `futex(2)` syscall on a 4-byte aligned state word held in a heap-allocated,
//! address-stable inner struct (so the futex word never moves).
//!
//! `CRITICAL_SECTION` and `SRWLOCK` are user-allocated structs; we store a `Box` pointer to
//! our inner state in the first 8 bytes of the user's struct (the contract is that the guest
//! only touches these via the API, never interprets the fields itself). Named objects
//! (`CreateEventW`/`CreateMutexW` with a name) live in the handle table.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::futex::{futex_wait, futex_wake, monotonic_ns};
use crate::handle::{self, FileObject, Handle, Object};

/// `INFINITE` wait timeout for the `WaitFor*` family.
const INFINITE: u32 = 0xFFFF_FFFF;
/// `WAIT_OBJECT_0`: the object was signaled.
pub const WAIT_OBJECT_0: u32 = 0;
/// `WAIT_TIMEOUT`: the timeout elapsed without the object being signaled.
pub const WAIT_TIMEOUT: u32 = 0x0000_0102;
/// `WAIT_FAILED`: the wait failed (invalid handle, etc.).
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
/// `TRUE` / `FALSE` for the Win32 `BOOL` return of `SetEvent` etc.
const TRUE: i32 = 1;
const FALSE: i32 = 0;

// ---------------------------------------------------------------------------
// Critical section (recursive mutex)
// ---------------------------------------------------------------------------

/// Inner state of a `CRITICAL_SECTION`. The `lock` word is the futex: 0 = free, 1 = held.
pub struct CriticalSectionInner {
    lock: AtomicU32,
    owner: AtomicU64,
    recursion: AtomicU32,
}

impl CriticalSectionInner {
    fn new() -> Self {
        CriticalSectionInner {
            lock: AtomicU32::new(0),
            owner: AtomicU64::new(0),
            recursion: AtomicU32::new(0),
        }
    }

    fn enter(&self) {
        let me = current_thread_id();
        // Fast path: already owned by this thread (recursive acquire).
        if self.owner.load(Ordering::Relaxed) == me {
            self.recursion.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Try to acquire the lock word (0 -> 1).
        loop {
            if self
                .lock
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.owner.store(me, Ordering::Relaxed);
                self.recursion.store(1, Ordering::Relaxed);
                return;
            }
            // Held by someone else: wait while `lock == 1`.
            futex_wait(&self.lock, 1, None);
            // Spurious wake or release: loop and retry the cmpxchg.
        }
    }

    fn leave(&self) {
        let me = current_thread_id();
        if self.owner.load(Ordering::Relaxed) != me {
            // Not the owner — a real Windows call would error; we no-op defensively.
            return;
        }
        let r = self.recursion.fetch_sub(1, Ordering::Relaxed) - 1;
        if r == 0 {
            self.owner.store(0, Ordering::Relaxed);
            self.lock.store(0, Ordering::Release);
            futex_wake(&self.lock, 1);
        }
    }
}

/// `kernel32!InitializeCriticalSection(LPCRITICAL_SECTION)`. Stores a heap-allocated inner
/// state pointer in the first 8 bytes of the caller's struct.
pub extern "C" fn initialize_critical_section(cs: *mut c_void) {
    if cs.is_null() {
        return;
    }
    let inner = Box::new(CriticalSectionInner::new());
    let raw = Box::into_raw(inner) as u64;
    // SAFETY: `cs` is a writable, 8-aligned CRITICAL_SECTION provided by the guest; we own
    // the stored raw pointer and will reclaim it in `delete_critical_section`.
    unsafe { std::ptr::write_unaligned(cs as *mut u64, raw) };
}

/// `kernel32!EnterCriticalSection(LPCRITICAL_SECTION)`.
pub extern "C" fn enter_critical_section(cs: *mut c_void) {
    if let Some(inner) = cs_inner(cs) {
        inner.enter();
    }
}

/// `kernel32!LeaveCriticalSection(LPCRITICAL_SECTION)`.
pub extern "C" fn leave_critical_section(cs: *mut c_void) {
    if let Some(inner) = cs_inner(cs) {
        inner.leave();
    }
}

/// `kernel32!DeleteCriticalSection(LPCRITICAL_SECTION)`. Reclaims the inner state.
pub extern "C" fn delete_critical_section(cs: *mut c_void) {
    if cs.is_null() {
        return;
    }
    // SAFETY: read the raw pointer we stored in `initialize_critical_section`; if it is
    // non-null, reclaim the Box. Zero the slot so a double-delete is a safe no-op.
    unsafe {
        let raw = std::ptr::read_unaligned(cs as *mut u64);
        if raw != 0 {
            drop(Box::from_raw(raw as *mut CriticalSectionInner));
            std::ptr::write_unaligned(cs as *mut u64, 0);
        }
    }
}

/// Read the stored inner pointer out of a CRITICAL_SECTION and return a reference.
fn cs_inner(cs: *mut c_void) -> Option<&'static CriticalSectionInner> {
    if cs.is_null() {
        return None;
    }
    // SAFETY: the guest initialized `cs` via `initialize_critical_section`, which stored a
    // valid `CriticalSectionInner` pointer at [cs]. We read it and treat the pointee as
    // alive for as long as the CRITICAL_SECTION exists (the guest must not delete it while
    // a thread is still using it, same contract as Windows).
    let raw = unsafe { std::ptr::read_unaligned(cs as *const u64) };
    if raw == 0 {
        return None;
    }
    // SAFETY: `raw` came from `Box::into_raw` and is valid until `delete_critical_section`.
    Some(unsafe { &*(raw as *const CriticalSectionInner) })
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// Inner state of an Event. `state` is the futex word: 0 = unsignaled, 1 = signaled.
pub struct EventInner {
    state: AtomicU32,
    manual_reset: bool,
}

impl EventInner {
    fn new(manual_reset: bool, initial: bool) -> Self {
        EventInner {
            state: AtomicU32::new(if initial { 1 } else { 0 }),
            manual_reset,
        }
    }

    fn set(&self) {
        self.state.store(1, Ordering::Release);
        // Wake one waiter for auto-reset (the woken waiter consumes the signal), all for
        // manual-reset (all waiters see the signaled state).
        futex_wake(&self.state, if self.manual_reset { i32::MAX } else { 1 });
    }

    fn reset(&self) {
        self.state.store(0, Ordering::Release);
    }

    fn pulse(&self) {
        self.state.store(1, Ordering::Release);
        futex_wake(&self.state, if self.manual_reset { i32::MAX } else { 1 });
        self.state.store(0, Ordering::Release);
    }

    fn wait(&self, timeout_ms: u32) -> u32 {
        let deadline = deadline_ns(timeout_ms);
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s == 1 {
                if self.manual_reset {
                    return WAIT_OBJECT_0;
                }
                // Auto-reset: try to consume the signal (1 -> 0). On success, this thread
                // was the one woken; on failure another thread stole it — retry.
                if self
                    .state
                    .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return WAIT_OBJECT_0;
                }
                continue; // lost the race to consume
            }
            // Unsiganled: compute remaining timeout and wait.
            let remaining = match deadline {
                Some(d) => {
                    let now = monotonic_ns();
                    if now >= d {
                        return WAIT_TIMEOUT;
                    }
                    Some(d - now)
                }
                None => None,
            };
            futex_wait(&self.state, 0, remaining);
        }
    }
}

/// `kernel32!CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName) -> HANDLE`.
pub extern "C" fn create_event_w(
    _attrs: *mut c_void,
    manual_reset: i32,
    initial: i32,
    _name: *const u16,
) -> Handle {
    let inner = Arc::new(EventInner::new(manual_reset != 0, initial != 0));
    handle::create(Object::Event(inner))
}

/// `kernel32!SetEvent(HANDLE) -> BOOL`.
pub extern "C" fn set_event(handle: Handle) -> i32 {
    if let Some(Object::Event(e)) = handle::with_object(handle, |o| o.clone_ref()) {
        e.set();
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!ResetEvent(HANDLE) -> BOOL`.
pub extern "C" fn reset_event(handle: Handle) -> i32 {
    if let Some(Object::Event(e)) = handle::with_object(handle, |o| o.clone_ref()) {
        e.reset();
        TRUE
    } else {
        FALSE
    }
}

/// `kernel32!PulseEvent(HANDLE) -> BOOL`.
pub extern "C" fn pulse_event(handle: Handle) -> i32 {
    if let Some(Object::Event(e)) = handle::with_object(handle, |o| o.clone_ref()) {
        e.pulse();
        TRUE
    } else {
        FALSE
    }
}

// ---------------------------------------------------------------------------
// Mutex (recursive, handle-backed)
// ---------------------------------------------------------------------------

/// Inner state of a named recursive Mutex (analogous to a CRITICAL_SECTION but handle-owned).
pub struct MutexInner {
    lock: AtomicU32,
    owner: AtomicU64,
    recursion: AtomicU32,
}

impl MutexInner {
    fn new() -> Self {
        MutexInner {
            lock: AtomicU32::new(0),
            owner: AtomicU64::new(0),
            recursion: AtomicU32::new(0),
        }
    }

    fn acquire(&self, timeout_ms: u32) -> u32 {
        let me = current_thread_id();
        if self.owner.load(Ordering::Relaxed) == me {
            self.recursion.fetch_add(1, Ordering::Relaxed);
            return WAIT_OBJECT_0;
        }
        let deadline = deadline_ns(timeout_ms);
        loop {
            if self
                .lock
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.owner.store(me, Ordering::Relaxed);
                self.recursion.store(1, Ordering::Relaxed);
                return WAIT_OBJECT_0;
            }
            let remaining = match deadline {
                Some(d) => {
                    let now = monotonic_ns();
                    if now >= d {
                        return WAIT_TIMEOUT;
                    }
                    Some(d - now)
                }
                None => None,
            };
            futex_wait(&self.lock, 1, remaining);
        }
    }

    fn release(&self) -> bool {
        let me = current_thread_id();
        if self.owner.load(Ordering::Relaxed) != me {
            return false;
        }
        let r = self.recursion.fetch_sub(1, Ordering::Relaxed) - 1;
        if r == 0 {
            self.owner.store(0, Ordering::Relaxed);
            self.lock.store(0, Ordering::Release);
            futex_wake(&self.lock, 1);
        }
        true
    }
}

/// `kernel32!CreateMutexW(...) -> HANDLE`.
pub extern "C" fn create_mutex_w(
    _attrs: *mut c_void,
    initial_owner: i32,
    _name: *const u16,
) -> Handle {
    let inner = Arc::new(MutexInner::new());
    if initial_owner != 0 {
        inner.lock.store(1, Ordering::Release);
        inner.owner.store(current_thread_id(), Ordering::Relaxed);
        inner.recursion.store(1, Ordering::Relaxed);
    }
    handle::create(Object::Mutex(inner))
}

/// `kernel32!ReleaseMutex(HANDLE) -> BOOL`.
pub extern "C" fn release_mutex(handle: Handle) -> i32 {
    if let Some(Object::Mutex(m)) = handle::with_object(handle, |o| o.clone_ref()) {
        if m.release() {
            TRUE
        } else {
            FALSE
        }
    } else {
        FALSE
    }
}

// ---------------------------------------------------------------------------
// Semaphore
// ---------------------------------------------------------------------------

/// Inner state of a counting semaphore: `count` is the futex word (available slots).
pub struct SemaphoreInner {
    count: AtomicU32,
}

impl SemaphoreInner {
    fn new(initial: u32) -> Self {
        SemaphoreInner {
            count: AtomicU32::new(initial),
        }
    }

    fn wait(&self, timeout_ms: u32) -> u32 {
        let deadline = deadline_ns(timeout_ms);
        loop {
            let c = self.count.load(Ordering::Acquire);
            if c > 0 {
                if self
                    .count
                    .compare_exchange(c, c - 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return WAIT_OBJECT_0;
                }
                continue;
            }
            let remaining = match deadline {
                Some(d) => {
                    let now = monotonic_ns();
                    if now >= d {
                        return WAIT_TIMEOUT;
                    }
                    Some(d - now)
                }
                None => None,
            };
            futex_wait(&self.count, 0, remaining);
        }
    }

    fn release(&self, release_count: u32, prev: *mut u32) -> bool {
        if !prev.is_null() {
            // SAFETY: `prev` is a guest out-pointer valid for one u32 (Windows contract).
            let old = self.count.load(Ordering::Relaxed);
            unsafe { std::ptr::write_unaligned(prev, old) };
        }
        self.count.fetch_add(release_count, Ordering::Release);
        futex_wake(&self.count, release_count as i32);
        true
    }
}

/// `kernel32!CreateSemaphoreW(...) -> HANDLE`.
pub extern "C" fn create_semaphore_w(
    _attrs: *mut c_void,
    initial: i32,
    _maximum: i32,
    _name: *const u16,
) -> Handle {
    handle::create(Object::Semaphore(Arc::new(SemaphoreInner::new(
        initial.max(0) as u32,
    ))))
}

/// `kernel32!ReleaseSemaphore(HANDLE, release_count, prev_count*) -> BOOL`.
pub extern "C" fn release_semaphore(handle: Handle, release: i32, prev: *mut u32) -> i32 {
    if let Some(Object::Semaphore(s)) = handle::with_object(handle, |o| o.clone_ref()) {
        if s.release(release.max(0) as u32, prev) {
            TRUE
        } else {
            FALSE
        }
    } else {
        FALSE
    }
}

// ---------------------------------------------------------------------------
// SRWLock
// ---------------------------------------------------------------------------

/// The single state word of an SRWLock, held in the user's `SRWLOCK` (a `ULONG_PTR`).
/// Bit 31 is the writer-held flag; bits 0..30 are the active reader count.
const SRW_WRITER: u32 = 1 << 31;
const SRW_READER_MASK: u32 = (1 << 31) - 1;

/// Inner state of an SRWLock. We store a `Box` pointer to this in the user's SRWLOCK.
pub struct SrwInner {
    state: AtomicU32,
}

impl SrwInner {
    fn new() -> Self {
        SrwInner {
            state: AtomicU32::new(0),
        }
    }

    fn acquire_exclusive(&self) {
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s == 0 {
                if self
                    .state
                    .compare_exchange(0, SRW_WRITER, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
            } else {
                futex_wait(&self.state, s, None);
            }
        }
    }

    fn acquire_shared(&self) {
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s & SRW_WRITER == 0 {
                // No writer: try to add a reader.
                if self
                    .state
                    .compare_exchange(s, s + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
            } else {
                futex_wait(&self.state, s, None);
            }
        }
    }

    fn release_exclusive(&self) {
        self.state.store(0, Ordering::Release);
        // A writer release can let in readers or a writer; wake everyone.
        futex_wake(&self.state, i32::MAX);
    }

    fn release_shared(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        // If this was the last reader, wake a waiting writer.
        if prev & SRW_READER_MASK == 1 {
            futex_wake(&self.state, 1);
        }
    }
}

/// `kernel32!InitializeSRWLock(PSRWLOCK)`.
pub extern "C" fn initialize_srw_lock(srw: *mut c_void) {
    if srw.is_null() {
        return;
    }
    let inner = Box::new(SrwInner::new());
    // SAFETY: `srw` is a writable, 8-aligned SRWLOCK provided by the guest.
    unsafe { std::ptr::write_unaligned(srw as *mut u64, Box::into_raw(inner) as u64) };
}

/// `kernel32!AcquireSRWLockExclusive(PSRWLOCK)`.
pub extern "C" fn acquire_srw_lock_exclusive(srw: *mut c_void) {
    if let Some(inner) = srw_inner(srw) {
        inner.acquire_exclusive();
    }
}

/// `kernel32!AcquireSRWLockShared(PSRWLOCK)`.
pub extern "C" fn acquire_srw_lock_shared(srw: *mut c_void) {
    if let Some(inner) = srw_inner(srw) {
        inner.acquire_shared();
    }
}

/// `kernel32!ReleaseSRWLockExclusive(PSRWLOCK)`.
pub extern "C" fn release_srw_lock_exclusive(srw: *mut c_void) {
    if let Some(inner) = srw_inner(srw) {
        inner.release_exclusive();
    }
}

/// `kernel32!ReleaseSRWLockShared(PSRWLOCK)`.
pub extern "C" fn release_srw_lock_shared(srw: *mut c_void) {
    if let Some(inner) = srw_inner(srw) {
        inner.release_shared();
    }
}

/// Read the stored inner pointer out of an SRWLOCK.
fn srw_inner(srw: *mut c_void) -> Option<&'static SrwInner> {
    if srw.is_null() {
        return None;
    }
    // SAFETY: the guest initialized `srw` via `initialize_srw_lock`, which stored a valid
    // `SrwInner` pointer at [srw]. Valid until the SRWLOCK is destroyed (SRWLocks have no
    // explicit delete; they live as long as the containing struct).
    let raw = unsafe { std::ptr::read_unaligned(srw as *const u64) };
    if raw == 0 {
        return None;
    }
    Some(unsafe { &*(raw as *const SrwInner) })
}

// ---------------------------------------------------------------------------
// Sleep / WaitFor*
// ---------------------------------------------------------------------------

/// `kernel32!Sleep(dwMilliseconds)`. Blocks the calling thread for at least `ms`.
pub extern "C" fn sleep(ms: u32) {
    sleep_ex(ms, 0);
}

/// `kernel32!SleepEx(dwMilliseconds, bAlertable) -> u32`. M1 has no alertable waits, so this
/// is just a timed sleep returning 0.
pub extern "C" fn sleep_ex(ms: u32, _alertable: i32) -> u32 {
    if ms == INFINITE {
        // Sleep "forever": a very long nanosleep, looped, since `nanosleep` cannot be truly
        // infinite. In practice the guest never passes INFINITE to `Sleep`.
        loop {
            nanosleep_ns(u64::MAX / 4);
        }
    }
    nanosleep_ns(ms as u64 * 1_000_000);
    0
}

/// `kernel32!WaitForSingleObject(HANDLE, dwMilliseconds) -> u32`.
pub extern "C" fn wait_for_single_object(handle: Handle, ms: u32) -> u32 {
    // Resolve the object's inner reference (clone the Arc) outside the wait so the handle
    // table lock is not held while we block.
    let obj = handle::with_object(handle, |o| o.clone_ref());
    match obj {
        Some(Object::Event(e)) => e.wait(ms),
        Some(Object::Mutex(m)) => m.acquire(ms),
        Some(Object::Semaphore(s)) => s.wait(ms),
        Some(Object::Thread(_)) => {
            // M1: thread waits are not fully supported; treat an already-finished or any
            // thread handle as signaled (best-effort) so callers do not deadlock.
            WAIT_OBJECT_0
        }
        Some(Object::Process) | None => {
            // Pseudo-process handle or invalid handle: signal immediately (best-effort).
            if handle == u64::MAX {
                WAIT_OBJECT_0
            } else {
                WAIT_FAILED
            }
        }
        Some(_) => WAIT_FAILED,
    }
}

/// `kernel32!WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds) -> u32`.
///
/// M1 implements a polling approximation: for `bWaitAll` it waits for every object to be
/// signaled (looping with the remaining timeout); for `!bWaitAll` it waits for the first
/// object that becomes signaled, returning its index + `WAIT_OBJECT_0`. This is not a
/// single futex wait but is correct for the cases our fixtures exercise.
pub extern "C" fn wait_for_multiple_objects(
    count: u32,
    handles: *const Handle,
    wait_all: i32,
    ms: u32,
) -> u32 {
    if handles.is_null() || count == 0 {
        return WAIT_FAILED;
    }
    let deadline = deadline_ns(ms);
    // SAFETY: `handles` points to `count` valid `HANDLE` values (Windows contract).
    let list = unsafe { std::slice::from_raw_parts(handles, count as usize) };
    loop {
        // Snapshot each object's signaled state by attempting a zero-timeout wait.
        let mut all_signaled = true;
        for (i, &h) in list.iter().enumerate() {
            let r = wait_for_single_object(h, 0);
            if r == WAIT_OBJECT_0 {
                if wait_all == 0 {
                    return i as u32 + WAIT_OBJECT_0;
                }
            } else if r == WAIT_TIMEOUT {
                all_signaled = false;
            } else {
                return WAIT_FAILED;
            }
        }
        if wait_all != 0 && all_signaled {
            return WAIT_OBJECT_0;
        }
        // Nothing ready: sleep a short slice and re-check, respecting the deadline.
        match deadline {
            Some(d) => {
                let now = monotonic_ns();
                if now >= d {
                    return WAIT_TIMEOUT;
                }
                nanosleep_ns((d - now).min(1_000_000)); // 1 ms poll, bounded by deadline
            }
            None => nanosleep_ns(1_000_000),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a Windows millisecond timeout into an absolute monotonic deadline in ns.
/// `INFINITE` maps to `None` (wait forever).
fn deadline_ns(ms: u32) -> Option<u64> {
    if ms == INFINITE {
        None
    } else {
        Some(monotonic_ns() + ms as u64 * 1_000_000)
    }
}

/// Sleep for `ns` nanoseconds via `nanosleep(2)` (looped on `EINTR`).
fn nanosleep_ns(ns: u64) {
    let mut req = libc::timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    };
    loop {
        let mut rem = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `nanosleep` reads `req` and may write the remaining time to `rem`; both
        // are valid stack structs. Returns 0 on success, -1/EINTR if interrupted.
        let rc = unsafe { libc::nanosleep(&req, &mut rem) };
        if rc == 0 {
            return;
        }
        // EINTR: resume with the remaining time.
        req = rem;
    }
}

/// Best-effort current thread id for recursive-lock ownership. Uses `gettid` so each guest
/// thread (and the host thread) has a distinct id.
fn current_thread_id() -> u64 {
    // SAFETY: `gettid` returns the calling thread's kernel id; always safe.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    tid as u64
}

/// A helper attached to `Object` to clone an `Arc` to the inner sync state without
/// pattern-matching the enum at every callsite. Lives on `Object` so the sync functions can
/// pull out a shared reference to the inner state without holding the handle-table lock.
impl Object {
    pub fn clone_ref(&self) -> Object {
        match self {
            Object::Event(e) => Object::Event(e.clone()),
            Object::Mutex(m) => Object::Mutex(m.clone()),
            Object::Semaphore(s) => Object::Semaphore(s.clone()),
            Object::Thread(t) => Object::Thread(t.clone()),
            Object::File(f) => Object::File(FileObject { fd: f.fd }),
            Object::Section { base, size } => Object::Section {
                base: *base,
                size: *size,
            },
            Object::Process => Object::Process,
        }
    }
}

/// Silence unused-import warning for `Duration` (kept for future timeout math).
#[allow(dead_code)]
fn _duration_used() {
    let _ = Duration::ZERO;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn critical_section_recursion_and_mutual_exclusion() {
        let mut cs_buf: [u64; 5] = [0; 5];
        let cs = cs_buf.as_mut_ptr() as *mut c_void;
        initialize_critical_section(cs);
        // Recursive enter: same thread can enter twice without blocking.
        enter_critical_section(cs);
        enter_critical_section(cs);
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();
        // Pass the pointer as a usize so the closure is `Send` (raw pointers are not Send).
        let cs_addr = cs as usize;
        let h = thread::spawn(move || {
            // A second thread must block until we release; it will then take the lock.
            let cs = cs_addr as *mut c_void;
            enter_critical_section(cs);
            c2.fetch_add(1, Ordering::Relaxed);
            leave_critical_section(cs);
        });
        // Give the blocked thread a moment, then release both holds.
        thread::sleep(Duration::from_millis(20));
        assert_eq!(counter.load(Ordering::Relaxed), 0, "child must be blocked");
        leave_critical_section(cs);
        leave_critical_section(cs);
        h.join().unwrap();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "child acquired after release"
        );
        delete_critical_section(cs);
    }

    #[test]
    fn auto_reset_event_set_and_wait() {
        let h = create_event_w(std::ptr::null_mut(), 0, 0, std::ptr::null());
        // Initially unsignaled: a zero-timeout wait times out.
        assert_eq!(wait_for_single_object(h, 0), WAIT_TIMEOUT);
        assert_eq!(set_event(h), TRUE);
        // One wait consumes the signal (auto-reset)...
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        // ...so a second immediate wait times out again.
        assert_eq!(wait_for_single_object(h, 0), WAIT_TIMEOUT);
        handle::close(h);
    }

    #[test]
    fn manual_reset_event_persists() {
        let h = create_event_w(std::ptr::null_mut(), 1, 0, std::ptr::null());
        assert_eq!(set_event(h), TRUE);
        // Manual-reset stays signaled for multiple waiters.
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        assert_eq!(reset_event(h), TRUE);
        assert_eq!(wait_for_single_object(h, 0), WAIT_TIMEOUT);
        handle::close(h);
    }

    #[test]
    fn event_wakes_blocked_waiter() {
        let h = create_event_w(std::ptr::null_mut(), 0, 0, std::ptr::null());
        let h2 = h;
        let done = Arc::new(AtomicUsize::new(0));
        let d = done.clone();
        let t = thread::spawn(move || {
            assert_eq!(wait_for_single_object(h2, 5000), WAIT_OBJECT_0);
            d.fetch_add(1, Ordering::Relaxed);
        });
        thread::sleep(Duration::from_millis(30));
        assert_eq!(done.load(Ordering::Relaxed), 0, "waiter still blocked");
        set_event(h);
        t.join().unwrap();
        assert_eq!(
            done.load(Ordering::Relaxed),
            1,
            "waiter released by SetEvent"
        );
        handle::close(h);
    }

    #[test]
    fn srw_lock_exclusive_mutual_exclusion() {
        let mut srw_buf: [u64; 1] = [0];
        let srw = srw_buf.as_mut_ptr() as *mut c_void;
        initialize_srw_lock(srw);
        acquire_srw_lock_exclusive(srw);
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let srw_addr = srw as usize;
        let h = thread::spawn(move || {
            let srw2 = srw_addr as *mut c_void;
            acquire_srw_lock_exclusive(srw2);
            c.fetch_add(1, Ordering::Relaxed);
            release_srw_lock_exclusive(srw2);
        });
        thread::sleep(Duration::from_millis(20));
        assert_eq!(counter.load(Ordering::Relaxed), 0, "writer blocked");
        release_srw_lock_exclusive(srw);
        h.join().unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn srw_lock_shared_concurrent() {
        let mut srw_buf: [u64; 1] = [0];
        let srw = srw_buf.as_mut_ptr() as *mut c_void;
        initialize_srw_lock(srw);
        acquire_srw_lock_shared(srw);
        // A second shared acquire on another thread should succeed promptly.
        let srw_addr = srw as usize;
        let ok = Arc::new(AtomicUsize::new(0));
        let o = ok.clone();
        let h = thread::spawn(move || {
            let srw2 = srw_addr as *mut c_void;
            acquire_srw_lock_shared(srw2);
            o.store(1, Ordering::Relaxed);
            release_srw_lock_shared(srw2);
        });
        h.join().unwrap();
        assert_eq!(ok.load(Ordering::Relaxed), 1, "shared readers do not block");
        release_srw_lock_shared(srw);
    }

    #[test]
    fn mutex_recursion() {
        let h = create_mutex_w(std::ptr::null_mut(), 1, std::ptr::null());
        // Initial owner: recursive acquire by the same (this) thread succeeds.
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        assert_eq!(release_mutex(h), TRUE);
        // After full release, another acquire works.
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        assert_eq!(release_mutex(h), TRUE);
        handle::close(h);
    }

    #[test]
    fn semaphore_release_and_wait() {
        let h = create_semaphore_w(std::ptr::null_mut(), 0, 10, std::ptr::null());
        assert_eq!(wait_for_single_object(h, 0), WAIT_TIMEOUT);
        assert_eq!(release_semaphore(h, 2, std::ptr::null_mut()), TRUE);
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        assert_eq!(wait_for_single_object(h, 0), WAIT_OBJECT_0);
        assert_eq!(wait_for_single_object(h, 0), WAIT_TIMEOUT);
        handle::close(h);
    }

    #[test]
    fn wait_for_multiple_any() {
        let a = create_event_w(std::ptr::null_mut(), 0, 0, std::ptr::null());
        let b = create_event_w(std::ptr::null_mut(), 0, 0, std::ptr::null());
        let handles = [a, b];
        set_event(b);
        // WaitForMultipleObjects(!wait_all) returns the index of the signaled object.
        let r = wait_for_multiple_objects(2, handles.as_ptr(), 0, 100);
        assert_eq!(r, 1 + WAIT_OBJECT_0, "second object was signaled");
        handle::close(a);
        handle::close(b);
    }
}
