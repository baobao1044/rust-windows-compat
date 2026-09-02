//! Linux `futex(2)` helpers used to reimplement Windows synchronization primitives.
//!
//! The Windows `Event`/`Mutex`/`CRITICAL_SECTION`/`SRWLock` semantics are rebuilt on top of
//! the Linux futex syscall: a 4-byte aligned state word in shared memory, with `FUTEX_WAIT`
//! to block until the word changes and `FUTEX_WAKE` to release waiters. This is a pure
//! Linux-syscall layer (no Windows-compat code reused).

#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::AtomicU32;

/// `FUTEX_WAIT` private flag (Linux). Waits while `*uaddr == val`.
const FUTEX_WAIT: i32 = 0;
/// `FUTEX_WAKE` private flag (Linux). Wakes at most `nr` waiters.
const FUTEX_WAKE: i32 = 1;
/// `FUTEX_WAIT_BITSET` with a bitset, for `WaitForMultipleObjects` style waits.
const FUTEX_WAIT_BITSET: i32 = 9;
/// `FUTEX_WAKE_BITSET` with a bitset.
const FUTEX_WAKE_BITSET: i32 = 10;
/// The "private futex" flag (Linux) — these futexes are process-local, so the kernel can
/// skip the shared-memory path. Our synchronization objects are all single-process.
const FUTEX_PRIVATE_FLAG: i32 = 128;

/// Block while `futex.word == expected`. Returns immediately if the word already differs.
/// Spurious wakes are handled by the caller (it must re-check the condition in a loop).
///
/// `timeout_ns` is an optional max wait in nanoseconds; `None` means wait forever.
pub fn futex_wait(futex: &AtomicU32, expected: u32, timeout_ns: Option<u64>) {
    let addr = futex as *const AtomicU32 as *const i32;
    let ts_ptr = match timeout_ns {
        Some(ns) => {
            // Build a `timespec { tv_sec, tv_nsec }` for the futex timeout.
            let secs = (ns / 1_000_000_000) as i64;
            let nsecs = (ns % 1_000_000_000) as i64;
            // SAFETY: `timespec` is a POD struct; we store it on the stack and pass its
            // address to the kernel, which copies it. Valid for the duration of the call.
            let ts = libc::timespec {
                tv_sec: secs,
                tv_nsec: nsecs,
            };
            Box::into_raw(Box::new(ts)) as *const libc::timespec
        }
        None => std::ptr::null(),
    };
    // SAFETY: `futex(2)` reads `*addr` atomically. `addr` is the address of the
    // `AtomicU32` we hold a reference to, so it is valid, 4-byte aligned, and live for the
    // call. `ts_ptr` is either null (infinite wait) or a valid heap `timespec` we own.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
            expected as i32,
            ts_ptr,
            0i64,
            0i32,
        )
    };
    // Free the timespec if we allocated one (the kernel copied it by value).
    if !ts_ptr.is_null() {
        // SAFETY: `ts_ptr` was allocated via `Box::into_raw` above and is valid.
        unsafe { drop(Box::from_raw(ts_ptr as *mut libc::timespec)) };
    }
    // rc < 0 means an error (EAGAIN if the word changed, ETIMEDOUT, EINTR); all are
    // normal futex outcomes — the caller re-checks the condition.
    let _ = rc;
}

/// Wake at most `nr` waiters blocked on `futex`. Returns the number woken.
pub fn futex_wake(futex: &AtomicU32, nr: i32) -> i32 {
    let addr = futex as *const AtomicU32 as *const i32;
    // SAFETY: `addr` is the valid, aligned, live address of our `AtomicU32`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
            nr,
            0i64,
            0i64,
            0i32,
        )
    };
    rc as i32
}

/// Bitset variants: wait until woken with a bit in `bitset` set, while the word equals
/// `expected`. Used by `WaitForMultipleObjects` to wait on several objects at once via a
/// single shared "generation" futex, where each object's `SetEvent` wakes with its bit.
pub fn futex_wait_bitset(futex: &AtomicU32, expected: u32, bitset: u32, timeout_ns: Option<u64>) {
    let addr = futex as *const AtomicU32 as *const i32;
    let ts_ptr = match timeout_ns {
        Some(ns) => {
            let ts = libc::timespec {
                tv_sec: (ns / 1_000_000_000) as i64,
                tv_nsec: (ns % 1_000_000_000) as i64,
            };
            Box::into_raw(Box::new(ts)) as *const libc::timespec
        }
        None => std::ptr::null(),
    };
    // SAFETY: as in `futex_wait`; the bitset is the 6th argument of `futex(2)` for the
    // BITSET variants.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
            expected as i32,
            ts_ptr,
            0i64,
            bitset as i32,
        )
    };
    if !ts_ptr.is_null() {
        // SAFETY: allocated above via `Box::into_raw`; valid for the duration of the call.
        unsafe { drop(Box::from_raw(ts_ptr as *mut libc::timespec)) };
    }
    let _ = rc;
}

/// Wake waiters whose bitset matches `bitset & waiter_bitset != 0`.
pub fn futex_wake_bitset(futex: &AtomicU32, nr: i32, bitset: u32) -> i32 {
    let addr = futex as *const AtomicU32 as *const i32;
    // SAFETY: `addr` is the valid, aligned, live address of our `AtomicU32`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG,
            nr,
            0i64,
            0i64,
            bitset as i32,
        )
    };
    rc as i32
}

/// Convenience: the current monotonic time in nanoseconds, used for timeout math.
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime(CLOCK_MONOTONIC)` writes a valid timespec; never fails here.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}
