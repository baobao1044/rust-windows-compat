//! shell32.dll reimplementation for the PE loader.
//!
//! Implements the subset of `shell32.dll` exports that real Windows PEs (notepad.exe,
//! games, installers, ...) import during startup. Most are best-effort no-ops that return
//! success/NULL — enough for an app to resolve its imports and proceed past the shell
//! initialization path without depending on real drag-drop, folder resolution, or COM
//! shell integration.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; every `unsafe` block carries a SAFETY
//! comment. The exports take raw pointers (they are called from PE machine code via ABI
//! trampolines), so `clippy::not_unsafe_ptr_arg_deref` is allowed.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::c_void;

use crate::{ExportSpec, FnPtr};

/// `S_OK` (0) — success HRESULT returned by `SHGetFolderPathW`.
const S_OK: i32 = 0;
/// `E_NOTIMPL` (0x80004001) — "not implemented" HRESULT.
const E_NOTIMPL: i32 = 0x80004001u32 as i32;
/// A fake `HINSTANCE` (> 32) returned by `ShellExecuteW`/`A` to signal success. On Windows a
/// return value <= 32 (cast to `INT_PTR`) is an error code; > 32 is a valid instance handle.
const FAKE_HINST: *mut c_void = 33 as *mut c_void;

// ---------------------------------------------------------------------------
// Drag-drop (no-op)
// ---------------------------------------------------------------------------

/// `shell32!DragAcceptFiles(hwnd, accept)`. No-op returning 0 (we never deliver
/// `WM_DROPFILES`).
pub extern "C" fn drag_accept_files(_hwnd: *mut c_void, _accept: i32) -> i32 {
    0
}

/// `shell32!DragFinish(hdrop)`. No-op (we own no dropped-file memory).
pub extern "C" fn drag_finish(_hdrop: *mut c_void) {}

/// `shell32!DragQueryFileW(hdrop, index, buf, buf_size) -> UINT`. Returns 0 (no files).
pub extern "C" fn drag_query_file_w(
    _hdrop: *mut c_void,
    _index: u32,
    _buf: *mut u16,
    _buf_size: u32,
) -> u32 {
    0
}

/// `shell32!DragQueryFileA(hdrop, index, buf, buf_size) -> UINT`. Returns 0 (no files).
pub extern "C" fn drag_query_file_a(
    _hdrop: *mut c_void,
    _index: u32,
    _buf: *mut u8,
    _buf_size: u32,
) -> u32 {
    0
}

// ---------------------------------------------------------------------------
// ShellAbout / ShellExecute
// ---------------------------------------------------------------------------

/// `shell32!ShellAboutW(hwnd, app, other, icon) -> BOOL`. No-op returning TRUE.
pub extern "C" fn shell_about_w(
    _hwnd: *mut c_void,
    _app: *const u16,
    _other: *const u16,
    _icon: *mut c_void,
) -> i32 {
    1
}

/// `shell32!ShellExecuteW(hwnd, verb, file, params, dir, show) -> HINSTANCE`.
/// Returns a fake success handle (> 32); no process is actually launched.
pub extern "C" fn shell_execute_w(
    _hwnd: *mut c_void,
    _verb: *const u16,
    _file: *const u16,
    _params: *const u16,
    _dir: *const u16,
    _show: i32,
) -> *mut c_void {
    FAKE_HINST
}

/// `shell32!ShellExecuteA(hwnd, verb, file, params, dir, show) -> HINSTANCE`.
/// ASCII twin of [`shell_execute_w`].
pub extern "C" fn shell_execute_a(
    _hwnd: *mut c_void,
    _verb: *const u8,
    _file: *const u8,
    _params: *const u8,
    _dir: *const u8,
    _show: i32,
) -> *mut c_void {
    FAKE_HINST
}

// ---------------------------------------------------------------------------
// Special folder paths
// ---------------------------------------------------------------------------

/// `shell32!SHGetFolderPathW(hwnd, csidl, token, flags, path) -> HRESULT`.
/// Fills `path` with the drive root `"C:\"` (UTF-16) and returns `S_OK`.
pub extern "C" fn sh_get_folder_path_w(
    _hwnd: *mut c_void,
    _csidl: i32,
    _token: *mut c_void,
    _flags: u32,
    path: *mut u16,
) -> i32 {
    fill_c_drive_w(path);
    S_OK
}

/// `shell32!SHGetFolderPathA(hwnd, csidl, token, flags, path) -> HRESULT`.
/// ASCII twin of [`sh_get_folder_path_w`].
pub extern "C" fn sh_get_folder_path_a(
    _hwnd: *mut c_void,
    _csidl: i32,
    _token: *mut c_void,
    _flags: u32,
    path: *mut u8,
) -> i32 {
    fill_c_drive_a(path);
    S_OK
}

/// `shell32!SHGetSpecialFolderPathW(hwnd, path, csidl, create) -> BOOL`.
/// Fills `path` with `"C:\"` (UTF-16) and returns TRUE.
pub extern "C" fn sh_get_special_folder_path_w(
    _hwnd: *mut c_void,
    path: *mut u16,
    _csidl: i32,
    _create: i32,
) -> i32 {
    fill_c_drive_w(path);
    1
}

/// Write `"C:\"` as NUL-terminated UTF-16 into the MAX_PATH buffer at `path` (no-op if null).
fn fill_c_drive_w(path: *mut u16) {
    if path.is_null() {
        return;
    }
    let units: [u16; 4] = [b'C' as u16, b':' as u16, b'\\' as u16, 0];
    // SAFETY: `path` is a writable MAX_PATH (260) u16 buffer; we write 4 code units.
    unsafe { std::ptr::copy_nonoverlapping(units.as_ptr(), path, units.len()) };
}

/// Write `b"C:\"` (NUL-terminated) into the MAX_PATH buffer at `path` (no-op if null).
fn fill_c_drive_a(path: *mut u8) {
    if path.is_null() {
        return;
    }
    let bytes: [u8; 4] = [b'C', b':', b'\\', 0];
    // SAFETY: `path` is a writable MAX_PATH (260) byte buffer; we write 4 bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), path, bytes.len()) };
}

// ---------------------------------------------------------------------------
// Shell COM (desktop folder / allocator)
// ---------------------------------------------------------------------------

/// `shell32!SHGetDesktopFolder(ppshf) -> HRESULT`. Returns `E_NOTIMPL` (no shell namespace).
pub extern "C" fn sh_get_desktop_folder(_ppshf: *mut *mut c_void) -> i32 {
    E_NOTIMPL
}

/// `shell32!SHGetMalloc(ppmalloc) -> HRESULT`. Returns `E_NOTIMPL` (no shell allocator).
pub extern "C" fn sh_get_malloc(_ppmalloc: *mut *mut c_void) -> i32 {
    E_NOTIMPL
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full list of `shell32.dll` exports implemented here, with the metadata the PE loader
/// needs to build ABI thunks. Each `dll` is `"shell32.dll"`.
pub fn shell32_exports() -> Vec<ExportSpec> {
    macro_rules! sh {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "shell32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        sh!("DragAcceptFiles", drag_accept_files, 2),
        sh!("DragFinish", drag_finish, 1),
        sh!("DragQueryFileW", drag_query_file_w, 4),
        sh!("DragQueryFileA", drag_query_file_a, 4),
        sh!("ShellAboutW", shell_about_w, 4),
        sh!("ShellExecuteW", shell_execute_w, 6),
        sh!("ShellExecuteA", shell_execute_a, 6),
        sh!("SHGetFolderPathW", sh_get_folder_path_w, 5),
        sh!("SHGetFolderPathA", sh_get_folder_path_a, 5),
        sh!("SHGetSpecialFolderPathW", sh_get_special_folder_path_w, 4),
        sh!("SHGetDesktopFolder", sh_get_desktop_folder, 1),
        sh!("SHGetMalloc", sh_get_malloc, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_path_w_is_c_drive() {
        let mut buf = [0u16; 8];
        sh_get_folder_path_w(
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
        );
        let s: String = buf[..3].iter().map(|&c| c as u8 as char).collect();
        assert_eq!(s, "C:\\");
        assert_eq!(buf[3], 0);
    }

    #[test]
    fn special_folder_path_a_is_c_drive() {
        let mut buf = [0u8; 8];
        sh_get_folder_path_a(
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            buf.as_mut_ptr(),
        );
        assert_eq!(&buf[..3], b"C:\\");
        assert_eq!(buf[3], 0);
    }

    #[test]
    fn shell_execute_returns_success_handle() {
        let h = shell_execute_w(
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        );
        assert!((h as isize) > 32, "ShellExecuteW must return a handle > 32");
        let h2 = shell_execute_a(
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        );
        assert!((h2 as isize) > 32);
    }

    #[test]
    fn not_implemented_folders_return_e_notimpl() {
        assert_eq!(sh_get_desktop_folder(std::ptr::null_mut()), E_NOTIMPL);
        assert_eq!(sh_get_malloc(std::ptr::null_mut()), E_NOTIMPL);
    }

    #[test]
    fn drag_query_returns_zero() {
        assert_eq!(
            drag_query_file_w(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0),
            0
        );
        assert_eq!(
            drag_query_file_a(std::ptr::null_mut(), 0, std::ptr::null_mut(), 0),
            0
        );
    }

    #[test]
    fn export_table_is_complete() {
        let exports = shell32_exports();
        let names: Vec<&str> = exports.iter().map(|e| e.sym).collect();
        assert!(names.contains(&"DragAcceptFiles"));
        assert!(names.contains(&"ShellExecuteW"));
        assert!(names.contains(&"SHGetFolderPathW"));
        assert!(names.contains(&"SHGetDesktopFolder"));
        // Every entry belongs to shell32.dll.
        assert!(exports.iter().all(|e| e.dll == "shell32.dll"));
        assert_eq!(exports.len(), 12);
    }
}
