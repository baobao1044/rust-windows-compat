//! comdlg32.dll reimplementation for the PE loader.
//!
//! Implements the subset of `comdlg32.dll` exports that real Windows PEs (notepad.exe,
//! games, installers) import during startup: the common file-open/save, font, find/replace,
//! and print dialogs. All are best-effort no-ops returning `FALSE` (0) — enough for an app
//! to resolve its imports and proceed; the dialogs are simply never shown. A `FALSE` return
//! from `GetOpenFileNameW`/`GetSaveFileNameW`/`ChooseFontW`/`PrintDlgW` signals "user
//! cancelled", which most callers handle by falling back to a default or doing nothing.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; the exports take raw pointers (called
//! from PE machine code via ABI trampolines), so `clippy::not_unsafe_ptr_arg_deref` is
//! allowed.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::c_void;

use crate::{ExportSpec, FnPtr};

// ---------------------------------------------------------------------------
// Common dialogs (all no-ops returning FALSE / 0)
// ---------------------------------------------------------------------------

/// `comdlg32!GetOpenFileNameW(LPOPENFILENAMEW) -> BOOL`. Returns FALSE (cancelled).
pub extern "C" fn get_open_file_name_w(_ofn: *mut c_void) -> i32 {
    0
}

/// `comdlg32!GetSaveFileNameW(LPOPENFILENAMEW) -> BOOL`. Returns FALSE (cancelled).
pub extern "C" fn get_save_file_name_w(_ofn: *mut c_void) -> i32 {
    0
}

/// `comdlg32!ChooseFontW(LPCHOOSEFONTW) -> BOOL`. Returns FALSE (cancelled).
pub extern "C" fn choose_font_w(_cf: *mut c_void) -> i32 {
    0
}

/// `comdlg32!FindTextW(LPFINDREPLACEW) -> HWND`. Returns NULL (dialog not shown).
pub extern "C" fn find_text_w(_fr: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `comdlg32!ReplaceTextW(LPFINDREPLACEW) -> HWND`. Returns NULL (dialog not shown).
pub extern "C" fn replace_text_w(_fr: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `comdlg32!PrintDlgW(LPPRINTDLGW) -> BOOL`. Returns FALSE (cancelled).
pub extern "C" fn print_dlg_w(_pd: *mut c_void) -> i32 {
    0
}

/// `comdlg32!GetFileTitleW(LPCWSTR, LPWSTR, WORD) -> WORD`. Returns 0 (no title parsed).
pub extern "C" fn get_file_title_w(_file: *const u16, _buf: *mut u16, _buf_size: u16) -> u16 {
    0
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full list of `comdlg32.dll` exports implemented here, with the metadata the PE loader
/// needs to build ABI thunks. Each `dll` is `"comdlg32.dll"`.
pub fn comdlg32_exports() -> Vec<ExportSpec> {
    macro_rules! d {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "comdlg32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        d!("GetOpenFileNameW", get_open_file_name_w, 1),
        d!("GetSaveFileNameW", get_save_file_name_w, 1),
        d!("ChooseFontW", choose_font_w, 1),
        d!("FindTextW", find_text_w, 1),
        d!("ReplaceTextW", replace_text_w, 1),
        d!("PrintDlgW", print_dlg_w, 1),
        d!("GetFileTitleW", get_file_title_w, 3),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_stubs_return_false() {
        assert_eq!(get_open_file_name_w(std::ptr::null_mut()), 0);
        assert_eq!(get_save_file_name_w(std::ptr::null_mut()), 0);
        assert_eq!(choose_font_w(std::ptr::null_mut()), 0);
        assert_eq!(print_dlg_w(std::ptr::null_mut()), 0);
        assert!(find_text_w(std::ptr::null_mut()).is_null());
        assert!(replace_text_w(std::ptr::null_mut()).is_null());
        assert_eq!(
            get_file_title_w(std::ptr::null(), std::ptr::null_mut(), 0),
            0
        );
    }

    #[test]
    fn export_table_is_complete() {
        let exports = comdlg32_exports();
        let names: Vec<&str> = exports.iter().map(|e| e.sym).collect();
        assert!(names.contains(&"GetOpenFileNameW"));
        assert!(names.contains(&"GetSaveFileNameW"));
        assert!(names.contains(&"ChooseFontW"));
        assert!(names.contains(&"FindTextW"));
        assert!(names.contains(&"ReplaceTextW"));
        assert!(names.contains(&"PrintDlgW"));
        assert!(names.contains(&"GetFileTitleW"));
        assert!(exports.iter().all(|e| e.dll == "comdlg32.dll"));
        assert_eq!(exports.len(), 7);
    }
}
