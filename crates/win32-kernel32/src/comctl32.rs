//! comctl32.dll reimplementation for the PE loader.
//!
//! Implements the subset of `comctl32.dll` exports that real Windows PEs (notepad.exe,
//! games, installers) import during startup. `InitCommonControls`/`InitCommonControlsEx` are
//! real (tiny) no-ops that return success; the common-controls classes are not registered,
//! but the call must succeed so CRT init proceeds. The two ordinal imports notepad pulls in
//! (`ORDINAL 410`, `ORDINAL 413` — the `DllGetVersion`/`DllInstall`-style helpers the linker
//! emits as ordinals) are wired up as 0-arg no-ops returning 0 so they resolve to a real
//! thunk instead of the soft-stub trap.
//!
//! `#![deny(unsafe_op_in_unsafe_fn)]` is enforced; the exports take raw pointers (called
//! from PE machine code via ABI trampolines), so `clippy::not_unsafe_ptr_arg_deref` is
//! allowed.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::c_void;

use crate::{ExportSpec, FnPtr};

// ---------------------------------------------------------------------------
// Common controls initialization
// ---------------------------------------------------------------------------

/// `comctl32!InitCommonControls() -> void`. No-op (no control classes registered).
pub extern "C" fn init_common_controls() {}

/// `comctl32!InitCommonControlsEx(const INITCOMMONCONTROLSEX*) -> BOOL`. Returns TRUE
/// (success); no control classes are actually registered.
pub extern "C" fn init_common_controls_ex(_icex: *const c_void) -> i32 {
    1
}

// ---------------------------------------------------------------------------
// Ordinal exports
//
// notepad.exe imports `comctl32.dll` by ordinal 410 and 413 (the linker-emitted helpers the
// import library surfaces as ordinals). The PE loader keys ordinal imports as the string
// `"ORDINAL <n>"` (see `pe-loader::imports::normalize_symbol`), so we register them under
// those exact keys. They are 0-arg no-ops returning 0 — enough to satisfy the call the
// startup sequence makes without hitting the soft-stub trap.
// ---------------------------------------------------------------------------

/// `comctl32!ORDINAL 410` — 0-arg no-op returning 0.
pub extern "C" fn comctl32_ordinal_410() -> u32 {
    0
}

/// `comctl32!ORDINAL 413` — 0-arg no-op returning 0.
pub extern "C" fn comctl32_ordinal_413() -> u32 {
    0
}

// ---------------------------------------------------------------------------
// Export specs
// ---------------------------------------------------------------------------

/// The full list of `comctl32.dll` exports implemented here, with the metadata the PE
/// loader needs to build ABI thunks. Each `dll` is `"comctl32.dll"`. Ordinal imports use the
/// `"ORDINAL <n>"` symbol key the loader normalizes ordinal imports to.
pub fn comctl32_exports() -> Vec<ExportSpec> {
    macro_rules! c {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "comctl32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }

    vec![
        c!("InitCommonControls", init_common_controls, 0),
        c!("InitCommonControlsEx", init_common_controls_ex, 1),
        c!("ORDINAL 410", comctl32_ordinal_410, 0),
        c!("ORDINAL 413", comctl32_ordinal_413, 0),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_stubs_succeed() {
        init_common_controls();
        assert_eq!(init_common_controls_ex(std::ptr::null()), 1);
    }

    #[test]
    fn ordinal_stubs_return_zero() {
        assert_eq!(comctl32_ordinal_410(), 0);
        assert_eq!(comctl32_ordinal_413(), 0);
    }

    #[test]
    fn export_table_is_complete() {
        let exports = comctl32_exports();
        let names: Vec<&str> = exports.iter().map(|e| e.sym).collect();
        assert!(names.contains(&"InitCommonControls"));
        assert!(names.contains(&"InitCommonControlsEx"));
        assert!(names.contains(&"ORDINAL 410"));
        assert!(names.contains(&"ORDINAL 413"));
        assert!(exports.iter().all(|e| e.dll == "comctl32.dll"));
        assert_eq!(exports.len(), 4);
    }
}
