//! advapi32.dll registry reimplementation for the PE loader.
//!
//! Implements the subset of `advapi32.dll` registry functions a real Windows PE probes
//! during startup: `RegOpenKeyW`/`RegOpenKeyExW`, `RegCreateKeyExW`, `RegCloseKey`,
//! `RegQueryValueExW`, `RegSetValueExW`, `RegEnumKeyW`, `RegEnumValueW`,
//! `RegDeleteKeyW`, and `IsTextUnicode`.
//!
//! The registry is a minimal in-memory store keyed by full key path
//! (`"HKLM\\Software\\..."`). Each key holds a `String -> RegValue` map of its values.
//! Opened/created keys are minted as fake handles (distinct from the `HKEY_*` root
//! pseudo-handles and from the ntapi/kernel32 handle tables so they never collide); a
//! handle table maps each fake handle back to its full path. This mirrors the handle-table
//! pattern used by `nigg-ntapi::handle` (a process-global `Mutex<HashMap<Handle, ...>>`).
//!
//! `RegOpenKey`/`RegCreateKeyEx` always succeed and mint a handle (matching the soft-stub
//! baseline, so a PE that probes a registry key keeps loading); `RegQueryValueEx` returns
//! `ERROR_FILE_NOT_FOUND` for an unknown value and copies the stored data when present;
//! the enumerators return `ERROR_NO_MORE_ITEMS`; `IsTextUnicode` returns FALSE.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment.

#![deny(unsafe_op_in_unsafe_fn)]
// The `extern "C"` functions here implement Windows APIs that take raw pointers. They
// are called from PE machine code via ABI trampolines, not from safe Rust callers.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::FnPtr;
use crate::Handle;

// ---------------------------------------------------------------------------
// Windows registry constants
// ---------------------------------------------------------------------------

/// `HKEY_CLASSES_ROOT` root pseudo-handle.
const HKEY_CLASSES_ROOT: Handle = 0x8000_0000;
/// `HKEY_CURRENT_USER` root pseudo-handle.
const HKEY_CURRENT_USER: Handle = 0x8000_0001;
/// `HKEY_LOCAL_MACHINE` root pseudo-handle.
const HKEY_LOCAL_MACHINE: Handle = 0x8000_0002;
/// `HKEY_USERS` root pseudo-handle.
const HKEY_USERS: Handle = 0x8000_0003;
/// `HKEY_CURRENT_CONFIG` root pseudo-handle.
const HKEY_CURRENT_CONFIG: Handle = 0x8000_0005;

/// `ERROR_SUCCESS` (0) — the registry functions return this on success.
const ERROR_SUCCESS: i32 = 0;
/// `ERROR_FILE_NOT_FOUND` (2) — returned by `RegQueryValueExW` for an unknown value.
const ERROR_FILE_NOT_FOUND: i32 = 2;
/// `ERROR_NO_MORE_ITEMS` (259) — returned by the enumerators when the index is exhausted.
const ERROR_NO_MORE_ITEMS: i32 = 259;
/// `ERROR_INVALID_HANDLE` (6) — returned when the parent handle is neither a root nor open.
const ERROR_INVALID_HANDLE: i32 = 6;

/// `REG_CREATED_NEW_KEY` (1) — disposition written by `RegCreateKeyExW` for a new key.
const REG_CREATED_NEW_KEY: u32 = 1;
/// `REG_OPENED_EXISTING_KEY` (2) — disposition for an already-present key.
const REG_OPENED_EXISTING_KEY: u32 = 2;

// ---------------------------------------------------------------------------
// In-memory registry + handle table
// ---------------------------------------------------------------------------

/// A stored registry value: its type tag and raw data bytes.
#[derive(Clone)]
struct RegValue {
    reg_type: u32,
    data: Vec<u8>,
}

/// The data held for a single registry key: its named values. Subkeys are addressed by
/// full path (the path of a subkey is `"<parent path>\\<subkey name>"`), so we do not need
/// an explicit subkey tree here — the global `keys` map keys by full path.
#[derive(Default)]
struct RegKey {
    values: HashMap<String, RegValue>,
}

/// The process-global registry: a `full path -> RegKey` map plus a fake-handle table
/// mapping each opened/created handle back to its full path.
struct Registry {
    /// `full path -> key data`. A key is created here on `RegCreateKeyExW` (and lazily on
    /// open) so a later `RegSetValueExW`/`RegQueryValueExW` finds it.
    keys: HashMap<String, RegKey>,
    /// `fake handle -> full path` for every opened/created key.
    handles: HashMap<Handle, String>,
    /// Monotonic counter minting the next fake handle.
    next: Handle,
}

impl Registry {
    fn new() -> Self {
        // Start handles well above the `HKEY_*` root pseudo-handles (0x8000_0000..) and
        // the ntapi/kernel32 handle ranges so registry handles never collide with a file,
        // thread, event, or heap handle.
        Registry {
            keys: HashMap::new(),
            handles: HashMap::new(),
            next: 0x0002_0000_0000_0001,
        }
    }

    /// Mint a fresh fake handle and bind it to `path`. Returns the new handle.
    fn mint(&mut self, path: String) -> Handle {
        let h = self.next;
        self.next = self.next.wrapping_add(1);
        self.handles.insert(h, path);
        h
    }
}

/// The global registry, lazily initialized on first use (same pattern as
/// `nigg-ntapi::handle::table`).
fn registry() -> &'static parking_lot::Mutex<Registry> {
    static R: OnceLock<parking_lot::Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| parking_lot::Mutex::new(Registry::new()))
}

/// Resolve a root pseudo-handle to its short path name, or `None` if `h` is not a root.
fn root_name(h: Handle) -> Option<&'static str> {
    match h {
        HKEY_CLASSES_ROOT => Some("HKCR"),
        HKEY_CURRENT_USER => Some("HKCU"),
        HKEY_LOCAL_MACHINE => Some("HKLM"),
        HKEY_USERS => Some("HKU"),
        HKEY_CURRENT_CONFIG => Some("HKCC"),
        _ => None,
    }
}

/// Build the full path for a `(parent, subkey)` pair. `parent` is either a root
/// pseudo-handle (resolved via [`root_name`]) or a previously-opened handle (looked up in
/// the handle table). `subkey` is a NUL-terminated UTF-16 string (empty if null). Returns
/// `None` if `parent` is neither a root nor a known open handle.
///
/// Holds the registry lock across the lookup; callers must not already hold it.
fn build_path(parent: Handle, subkey: *const u16) -> Option<String> {
    let parent_path = if let Some(name) = root_name(parent) {
        Some(name.to_string())
    } else {
        let g = registry().lock();
        g.handles.get(&parent).cloned()
    };
    let parent_path = parent_path?;

    // SAFETY: `subkey` is a NUL-terminated UTF-16 buffer, or null (treated as empty).
    let sub = unsafe { utf16_to_string(subkey) };
    if sub.is_empty() {
        Some(parent_path)
    } else {
        Some(format!("{parent_path}\\{sub}"))
    }
}

/// Read a NUL-terminated UTF-16 buffer at `p` into a Rust `String`, dropping the NUL.
/// Returns an empty string for a null pointer.
///
/// # Safety
///
/// `p` must be a NUL-terminated UTF-16 buffer (a terminating `0x0000` code unit), or null.
unsafe fn utf16_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL-termination; we stop at the first 0 code unit.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` code units are valid to read per the NUL-termination contract.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------
// Registry API functions
// ---------------------------------------------------------------------------

/// `advapi32!RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) -> LSTATUS`.
///
/// Opens (or mints a handle to) the key at `hKey\lpSubKey`. Always succeeds and writes a
/// fake handle through `phkResult` (matching the soft-stub baseline so a probing PE keeps
/// loading). Returns `ERROR_SUCCESS`, or `ERROR_INVALID_HANDLE` if `hKey` is not a root
/// or known open handle.
pub extern "C" fn reg_open_key_w(hkey: Handle, subkey: *const u16, result: *mut Handle) -> i32 {
    let path = match build_path(hkey, subkey) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };
    let h = {
        let mut g = registry().lock();
        // Lazily create the key entry so a later RegSetValueExW has somewhere to write.
        g.keys.entry(path.clone()).or_default();
        g.mint(path)
    };
    if !result.is_null() {
        // SAFETY: `result` is a guest out-pointer valid for one `HKEY`.
        unsafe { std::ptr::write_unaligned(result, h) };
    }
    ERROR_SUCCESS
}

/// `advapi32!RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) -> LSTATUS`. Like
/// [`reg_open_key_w`] with extra reserved/access arguments (ignored).
pub extern "C" fn reg_open_key_ex_w(
    hkey: Handle,
    subkey: *const u16,
    _reserved: u32,
    _access: u32,
    result: *mut Handle,
) -> i32 {
    reg_open_key_w(hkey, subkey, result)
}

/// `advapi32!RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPTSTR, DWORD, REGSAM,
/// LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) -> LSTATUS`.
///
/// Creates the key at `hKey\lpSubKey` (if absent) and writes a fake handle through
/// `phkResult`. Sets `*lpdwDisposition` to `REG_CREATED_NEW_KEY` for a new key or
/// `REG_OPENED_EXISTING_KEY` if it already existed. Returns `ERROR_SUCCESS`, or
/// `ERROR_INVALID_HANDLE` for an unknown parent.
pub extern "C" fn reg_create_key_ex_w(
    hkey: Handle,
    subkey: *const u16,
    _reserved: u32,
    _class: *const u16,
    _options: u32,
    _access: u32,
    _sa: *mut std::ffi::c_void,
    result: *mut Handle,
    disp: *mut u32,
) -> i32 {
    let path = match build_path(hkey, subkey) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };
    let (h, disposition) = {
        let mut g = registry().lock();
        let created = !g.keys.contains_key(&path);
        g.keys.entry(path.clone()).or_default();
        let h = g.mint(path);
        (
            h,
            if created {
                REG_CREATED_NEW_KEY
            } else {
                REG_OPENED_EXISTING_KEY
            },
        )
    };
    if !result.is_null() {
        // SAFETY: `result` is a guest out-pointer valid for one `HKEY`.
        unsafe { std::ptr::write_unaligned(result, h) };
    }
    if !disp.is_null() {
        // SAFETY: `disp` is a guest out-pointer valid for one `DWORD`.
        unsafe { std::ptr::write_unaligned(disp, disposition) };
    }
    ERROR_SUCCESS
}

/// `advapi32!RegCloseKey(HKEY) -> LSTATUS`. Releases a fake handle. Root pseudo-handles
/// and unknown handles close as a no-op success (matching Windows). Returns `ERROR_SUCCESS`.
pub extern "C" fn reg_close_key(hkey: Handle) -> i32 {
    if root_name(hkey).is_some() {
        return ERROR_SUCCESS;
    }
    let mut g = registry().lock();
    g.handles.remove(&hkey);
    ERROR_SUCCESS
}

/// `advapi32!RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) -> LSTATUS`.
///
/// Reads the named value under the key named by `hkey`. Writes the value type through
/// `lpType` (if non-null) and the data bytes through `lpData` (if non-null and large
/// enough), and the required byte count through `lpcbData`. Returns `ERROR_FILE_NOT_FOUND`
/// if the value (or its key) is absent, `ERROR_SUCCESS` if the data fits, and
/// `ERROR_SUCCESS` with the required length in `lpcbData` when the buffer is too small
/// (matching Windows, which still reports the type on truncation).
pub extern "C" fn reg_query_value_ex_w(
    hkey: Handle,
    name: *const u16,
    _reserved: *mut u32,
    reg_type: *mut u32,
    data: *mut u8,
    len: *mut u32,
) -> i32 {
    let path = match resolve_path(hkey) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };
    // SAFETY: `name` is a NUL-terminated UTF-16 buffer, or null (the default/unnamed value).
    let name = unsafe { utf16_to_string(name) };

    let g = registry().lock();
    let Some(key) = g.keys.get(&path) else {
        return ERROR_FILE_NOT_FOUND;
    };
    let Some(val) = key.values.get(&name) else {
        return ERROR_FILE_NOT_FOUND;
    };

    let needed = val.data.len() as u32;
    if !reg_type.is_null() {
        // SAFETY: `reg_type` is a guest out-pointer valid for one `DWORD`.
        unsafe { std::ptr::write_unaligned(reg_type, val.reg_type) };
    }

    let cap = if len.is_null() {
        0
    } else {
        // SAFETY: `len` is a guest in/out-pointer valid for one `DWORD`.
        unsafe { std::ptr::read_unaligned(len) }
    };

    // Always report the required byte count (Windows writes it even on truncation).
    if !len.is_null() {
        // SAFETY: `len` is a guest out-pointer valid for one `DWORD`.
        unsafe { std::ptr::write_unaligned(len, needed) };
    }

    if data.is_null() || cap == 0 {
        // Caller is querying the length only.
        return ERROR_SUCCESS;
    }

    if needed > cap {
        // Buffer too small: Windows returns ERROR_MORE_DATA (234). We mirror that so a
        // caller sizing the buffer first sees a clean truncation signal.
        return 234; // ERROR_MORE_DATA
    }

    // SAFETY: `data` is writable for `cap` bytes and `needed <= cap`; copy the value bytes.
    unsafe { std::ptr::copy_nonoverlapping(val.data.as_ptr(), data, needed as usize) };
    ERROR_SUCCESS
}

/// `advapi32!RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD) -> LSTATUS`.
///
/// Stores `data` (cbData bytes) under the named value of the key named by `hkey`, tagged
/// with `dwType`. Creates the value if absent. Returns `ERROR_SUCCESS`, or
/// `ERROR_INVALID_HANDLE` for an unknown parent.
pub extern "C" fn reg_set_value_ex_w(
    hkey: Handle,
    name: *const u16,
    _reserved: u32,
    reg_type: u32,
    data: *const u8,
    cb_data: u32,
) -> i32 {
    let path = match resolve_path(hkey) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };
    // SAFETY: `name` is a NUL-terminated UTF-16 buffer, or null (the default/unnamed value).
    let name = unsafe { utf16_to_string(name) };

    let bytes = if data.is_null() || cb_data == 0 {
        Vec::new()
    } else {
        // SAFETY: `data` is readable for `cb_data` bytes per the Windows contract.
        unsafe { std::slice::from_raw_parts(data, cb_data as usize) }.to_vec()
    };

    let mut g = registry().lock();
    let key = g.keys.entry(path).or_default();
    key.values.insert(
        name,
        RegValue {
            reg_type,
            data: bytes,
        },
    );
    ERROR_SUCCESS
}

/// `advapi32!RegEnumKeyW(HKEY, DWORD index, LPWSTR, DWORD) -> LSTATUS`.
///
/// Enumerates the subkeys of the key named by `hkey`. We do not track an explicit subkey
/// list (subkeys are addressed by full path), so we report `ERROR_NO_MORE_ITEMS` for any
/// index — a probing PE treats this as "no subkeys" and moves on.
pub extern "C" fn reg_enum_key_w(_hkey: Handle, _index: u32, _name: *mut u16, _len: u32) -> i32 {
    ERROR_NO_MORE_ITEMS
}

/// `advapi32!RegEnumValueW(HKEY, DWORD index, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE,
/// LPDWORD) -> LSTATUS`.
///
/// Enumerates the values of the key named by `hkey`. Returns `ERROR_NO_MORE_ITEMS` for any
/// index (the in-memory store is not enumerated in order; a probing PE treats this as "no
/// values").
pub extern "C" fn reg_enum_value_w(
    _hkey: Handle,
    _index: u32,
    _name: *mut u16,
    _name_len: *mut u32,
    _reserved: *mut u32,
    _reg_type: *mut u32,
    _data: *mut u8,
    _data_len: *mut u32,
) -> i32 {
    ERROR_NO_MORE_ITEMS
}

/// `advapi32!RegDeleteKeyW(HKEY, LPCWSTR) -> LSTATUS`. Deletes the key at
/// `hKey\lpSubKey`. Returns `ERROR_FILE_NOT_FOUND` if absent, `ERROR_SUCCESS` otherwise.
pub extern "C" fn reg_delete_key_w(hkey: Handle, subkey: *const u16) -> i32 {
    let path = match build_path(hkey, subkey) {
        Some(p) => p,
        None => return ERROR_INVALID_HANDLE,
    };
    let mut g = registry().lock();
    if g.keys.remove(&path).is_some() {
        ERROR_SUCCESS
    } else {
        ERROR_FILE_NOT_FOUND
    }
}

/// `advapi32!IsTextUnicode(const void*, int, LPINT) -> BOOL`.
///
/// A simple heuristic for whether a buffer is UTF-16: returns FALSE (0) so callers treat
/// the buffer as ANSI/UTF-8. This avoids mis-detecting ASCII buffers as UTF-16 (the common
/// real-world failure mode of the full heuristic), which is the safe default for the
/// console-PE acceptance target.
pub extern "C" fn is_text_unicode(
    _buffer: *const std::ffi::c_void,
    _len: i32,
    _result: *mut i32,
) -> i32 {
    0 // FALSE
}

/// Resolve the full path bound to `hkey`, or `None` if it is neither a root nor a known
/// open handle. Holds the registry lock; callers must not already hold it.
fn resolve_path(hkey: Handle) -> Option<String> {
    if let Some(name) = root_name(hkey) {
        return Some(name.to_string());
    }
    let g = registry().lock();
    g.handles.get(&hkey).cloned()
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// Metadata for a single advapi32 export (same shape as `ExportSpec` in lib.rs).
#[derive(Clone, Copy)]
pub struct RegistrySpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: FnPtr,
    pub n_args: u8,
    pub noreturn: bool,
}

/// The full list of `advapi32.dll` function exports implemented by this crate, with the
/// metadata the PE loader needs to build ABI thunks.
pub fn registry_exports() -> Vec<RegistrySpec> {
    macro_rules! r {
        ($sym:literal, $f:expr, $n:literal) => {
            RegistrySpec {
                dll: "advapi32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        r!("RegOpenKeyW", reg_open_key_w, 3),
        r!("RegOpenKeyExW", reg_open_key_ex_w, 5),
        r!("RegCreateKeyExW", reg_create_key_ex_w, 9),
        r!("RegCloseKey", reg_close_key, 1),
        r!("RegQueryValueExW", reg_query_value_ex_w, 6),
        r!("RegSetValueExW", reg_set_value_ex_w, 6),
        r!("RegEnumKeyW", reg_enum_key_w, 4),
        r!("RegEnumValueW", reg_enum_value_w, 8),
        r!("RegDeleteKeyW", reg_delete_key_w, 2),
        r!("IsTextUnicode", is_text_unicode, 3),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a NUL-terminated UTF-16 buffer to a Rust `String` (test helper).
    fn wstr(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn open_and_close_round_trip() {
        let sub = wstr("Software\\nigg");
        let mut h: Handle = 0;
        assert_eq!(
            reg_open_key_w(HKEY_LOCAL_MACHINE, sub.as_ptr(), &mut h),
            ERROR_SUCCESS
        );
        assert!(h >= 0x0002_0000_0000_0001, "minted handle is a fake handle");
        assert_eq!(reg_close_key(h), ERROR_SUCCESS);
        // Closing a root pseudo-handle is a no-op success.
        assert_eq!(reg_close_key(HKEY_LOCAL_MACHINE), ERROR_SUCCESS);
    }

    #[test]
    fn open_with_empty_subkey_opens_root() {
        let mut h: Handle = 0;
        assert_eq!(
            reg_open_key_w(HKEY_CURRENT_USER, std::ptr::null(), &mut h),
            ERROR_SUCCESS
        );
        assert!(h != 0);
        reg_close_key(h);
    }

    #[test]
    fn create_sets_disposition_and_set_query_round_trip() {
        let sub = wstr("Software\\nigg-test");
        let mut h: Handle = 0;
        let mut disp: u32 = 0;
        assert_eq!(
            reg_create_key_ex_w(
                HKEY_LOCAL_MACHINE,
                sub.as_ptr(),
                0,
                std::ptr::null(),
                0,
                0,
                std::ptr::null_mut(),
                &mut h,
                &mut disp,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(disp, REG_CREATED_NEW_KEY, "first create makes a new key");

        // Create the same key again -> opened existing.
        let mut h2: Handle = 0;
        let mut disp2: u32 = 0;
        assert_eq!(
            reg_create_key_ex_w(
                HKEY_LOCAL_MACHINE,
                sub.as_ptr(),
                0,
                std::ptr::null(),
                0,
                0,
                std::ptr::null_mut(),
                &mut h2,
                &mut disp2,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(disp2, REG_OPENED_EXISTING_KEY);

        // Set a value.
        let name = wstr("Version");
        let payload: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            reg_set_value_ex_w(
                h,
                name.as_ptr(),
                0,
                4, /* REG_DWORD */
                payload.as_ptr(),
                4
            ),
            ERROR_SUCCESS
        );

        // Query it back.
        let mut ty: u32 = 0;
        let mut out = [0u8; 4];
        let mut out_len: u32 = out.len() as u32;
        assert_eq!(
            reg_query_value_ex_w(
                h,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                out.as_mut_ptr(),
                &mut out_len,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(ty, 4);
        assert_eq!(out_len, 4);
        assert_eq!(&out, &payload);

        // Query a missing value.
        let missing = wstr("Nope");
        assert_eq!(
            reg_query_value_ex_w(
                h,
                missing.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
            ERROR_FILE_NOT_FOUND
        );

        reg_close_key(h);
        reg_close_key(h2);
    }

    #[test]
    fn query_reports_length_on_truncation() {
        let sub = wstr("Software\\nigg-trunc");
        let mut h: Handle = 0;
        let mut disp: u32 = 0;
        reg_create_key_ex_w(
            HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            0,
            std::ptr::null(),
            0,
            0,
            std::ptr::null_mut(),
            &mut h,
            &mut disp,
        );
        let name = wstr("Blob");
        let payload = [0xABu8; 16];
        reg_set_value_ex_w(
            h,
            name.as_ptr(),
            0,
            3, /* REG_BINARY */
            payload.as_ptr(),
            16,
        );

        // Query with a too-small buffer.
        let mut ty: u32 = 0;
        let mut out = [0u8; 4];
        let mut out_len: u32 = out.len() as u32;
        let rc = reg_query_value_ex_w(
            h,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, 234, "ERROR_MORE_DATA on truncation");
        assert_eq!(out_len, 16, "reports the required length");

        // Query length only (null data pointer).
        let mut ty2: u32 = 0;
        let mut need: u32 = 0;
        assert_eq!(
            reg_query_value_ex_w(
                h,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut ty2,
                std::ptr::null_mut(),
                &mut need,
            ),
            ERROR_SUCCESS
        );
        assert_eq!(need, 16);
        assert_eq!(ty2, 3);
        reg_close_key(h);
    }

    #[test]
    fn enumerators_report_no_more_items() {
        let mut h: Handle = 0;
        reg_open_key_w(HKEY_LOCAL_MACHINE, std::ptr::null(), &mut h);
        let mut name = [0u16; 16];
        assert_eq!(
            reg_enum_key_w(h, 0, name.as_mut_ptr(), name.len() as u32),
            ERROR_NO_MORE_ITEMS
        );
        let mut vname = [0u16; 16];
        let mut vname_len: u32 = 16;
        let mut vdata = [0u8; 16];
        let mut vdata_len: u32 = 16;
        let mut vtype: u32 = 0;
        assert_eq!(
            reg_enum_value_w(
                h,
                0,
                vname.as_mut_ptr(),
                &mut vname_len,
                std::ptr::null_mut(),
                &mut vtype,
                vdata.as_mut_ptr(),
                &mut vdata_len,
            ),
            ERROR_NO_MORE_ITEMS
        );
        reg_close_key(h);
    }

    #[test]
    fn delete_key_round_trip() {
        let sub = wstr("Software\\nigg-del");
        let mut h: Handle = 0;
        let mut disp: u32 = 0;
        reg_create_key_ex_w(
            HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            0,
            std::ptr::null(),
            0,
            0,
            std::ptr::null_mut(),
            &mut h,
            &mut disp,
        );
        reg_close_key(h);
        assert_eq!(
            reg_delete_key_w(HKEY_LOCAL_MACHINE, sub.as_ptr()),
            ERROR_SUCCESS
        );
        // Deleting again -> not found.
        assert_eq!(
            reg_delete_key_w(HKEY_LOCAL_MACHINE, sub.as_ptr()),
            ERROR_FILE_NOT_FOUND
        );
    }

    #[test]
    fn is_text_unicode_returns_false() {
        let buf = b"hello";
        let mut flags: i32 = 0;
        assert_eq!(
            is_text_unicode(
                buf.as_ptr() as *const std::ffi::c_void,
                buf.len() as i32,
                &mut flags
            ),
            0
        );
    }

    #[test]
    fn invalid_parent_handle_is_rejected() {
        let mut h: Handle = 0;
        assert_eq!(
            reg_open_key_w(0xDEAD, std::ptr::null(), &mut h),
            ERROR_INVALID_HANDLE
        );
    }

    #[test]
    fn registry_exports_registered_with_correct_dll_and_counts() {
        let specs = registry_exports();
        assert!(specs.iter().all(|s| s.dll == "advapi32.dll"));
        let syms: Vec<&str> = specs.iter().map(|s| s.sym).collect();
        assert!(syms.contains(&"RegOpenKeyW"));
        assert!(syms.contains(&"RegCreateKeyExW"));
        assert!(syms.contains(&"RegCloseKey"));
        assert!(syms.contains(&"IsTextUnicode"));
        // RegCreateKeyExW takes 9 args; the thunk arena supports stack args beyond 8.
        let create = specs.iter().find(|s| s.sym == "RegCreateKeyExW").unwrap();
        assert_eq!(create.n_args, 9);
        assert!(!create.noreturn);
    }
}
