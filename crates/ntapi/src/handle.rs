//! Process-global handle table for Windows kernel objects.
//!
//! Windows `HANDLE` is an opaque process-local value naming a kernel object (event,
//! mutex, thread, file, ...). We reimplement it as a process-global `HANDLE -> Object` map
//! guarded by a `parking_lot::Mutex`. Synchronization objects own their futex state on the
//! heap (inside an `Arc`) so its address is stable across HashMap rehashes — the futex
//! syscall requires the waited-on word to live at a fixed address.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use std::sync::OnceLock;

use crate::sync::{EventInner, MutexInner, SemaphoreInner};
use crate::thread::ThreadInner;

/// A Windows `HANDLE`: an opaque, process-local 64-bit value naming a kernel object.
pub type Handle = u64;

/// The kinds of Windows kernel object the handle table can name.
///
/// The sync-object variants hold an `Arc` to the heap-allocated, address-stable inner state
/// so the futex word never moves. `File` holds a raw Linux fd. `Thread` holds the guest
/// thread's inner state.
pub enum Object {
    /// A manual- or auto-reset event (`CreateEventW`).
    Event(Arc<EventInner>),
    /// A recursive mutex (`CreateMutexW`).
    Mutex(Arc<MutexInner>),
    /// A counting semaphore (`CreateSemaphoreW`).
    Semaphore(Arc<SemaphoreInner>),
    /// A thread (`CreateThread`).
    Thread(Arc<ThreadInner>),
    /// An open file/console (`NtCreateFile`/`CreateFileW`), backed by a Linux fd.
    File(FileObject),
    /// A memory section (`CreateFileMapping`); M1 stores only the mapping base/size.
    Section { base: *mut u8, size: usize },
    /// The current process (a pseudo-object; closed via the pseudo-handle path).
    Process,
}

// SAFETY: `Object` owns `Arc`s (Send+Sync) and a raw `FileObject`/section pointer that is
// process-local. The handle table is single-process; handles do not cross processes.
unsafe impl Send for Object {}
unsafe impl Sync for Object {}

/// An open file/console object: just a Linux fd plus the access mode it was opened with.
pub struct FileObject {
    /// The Linux file descriptor backing the Windows file handle.
    pub fd: i32,
}

impl Drop for FileObject {
    fn drop(&mut self) {
        // SAFETY: `fd` was obtained from `openat`/`open` and is valid; `close` releases it.
        // Closing an invalid fd is a no-op error, so a double-close is harmless.
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// The process-global handle table: `HANDLE -> Object`, plus a monotonic handle counter.
pub struct HandleTable {
    objects: HashMap<Handle, Object>,
    next: Handle,
}

impl HandleTable {
    fn new() -> Self {
        // Start handles well above the small values used as stdio fds (0,1,2) and the
        // Windows pseudo-handles (0xFFFF_FFFF...), so real handles never collide.
        HandleTable {
            objects: HashMap::new(),
            next: 0x0001_0000,
        }
    }

    /// Insert `obj` and return its new handle.
    fn insert(&mut self, obj: Object) -> Handle {
        let h = self.next;
        self.next = self.next.wrapping_add(1);
        self.objects.insert(h, obj);
        h
    }

    /// Remove a handle and return its object (so the caller can drop it / release fd).
    fn remove(&mut self, handle: Handle) -> Option<Object> {
        self.objects.remove(&handle)
    }
}

/// The global handle table, lazily initialized on first use.
fn table() -> &'static Mutex<HandleTable> {
    static TABLE: OnceLock<Mutex<HandleTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HandleTable::new()))
}

/// Register a new object and return its handle.
pub fn create(obj: Object) -> Handle {
    table().lock().insert(obj)
}

/// Look up a handle's object via a closure. Returns `None` if the handle is invalid.
pub fn with_object<R>(handle: Handle, f: impl FnOnce(&Object) -> R) -> Option<R> {
    let g = table().lock();
    g.objects.get(&handle).map(f)
}

/// Close a handle: remove and drop the object. Returns `true` on success.
///
/// Pseudo-handles (`GetCurrentProcess`/`GetCurrentThread`) and the stdio fd handles
/// (0,1,2) are not in the table; closing them is a no-op success (matching Windows, where
/// closing a pseudo-handle is a no-op).
pub fn close(handle: Handle) -> bool {
    // Pseudo-handles and stdio fds are not real handle-table entries.
    if is_pseudo_handle(handle) {
        return true;
    }
    let obj = table().lock().remove(handle);
    let was_present = obj.is_some();
    drop(obj); // runs the object's Drop (closes fd, releases sync state, etc.)
    was_present
}

/// `true` if `handle` is a Windows pseudo-handle (current process/thread) or a stdio fd
/// used directly as a handle, which are never stored in the handle table.
fn is_pseudo_handle(handle: Handle) -> bool {
    // GetCurrentProcess() = (HANDLE)-1, GetCurrentThread() = (HANDLE)-2.
    handle == u64::MAX || handle == u64::MAX - 1 || handle <= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_close_round_trip() {
        let h = create(Object::Process);
        assert!(h >= 0x0001_0000, "handles start above the stdio range");
        assert!(
            with_object(h, |_| ()).is_some(),
            "handle resolves before close"
        );
        assert!(close(h), "closing a real handle succeeds");
        assert!(
            with_object(h, |_| ()).is_none(),
            "handle is gone after close"
        );
        assert!(!close(h), "double close returns false");
    }

    #[test]
    fn pseudo_handles_close_as_no_op() {
        assert!(close(u64::MAX), "GetCurrentProcess pseudo-handle closes");
        assert!(close(u64::MAX - 1), "GetCurrentThread pseudo-handle closes");
        assert!(close(1), "stdout fd-as-handle closes as no-op");
    }

    #[test]
    fn handles_are_unique_and_monotonic() {
        let a = create(Object::Process);
        let b = create(Object::Process);
        assert_ne!(a, b, "successive handles differ");
        assert!(b > a, "handle counter is monotonic");
        close(a);
        close(b);
    }
}
