//! gdi32 subset: minimal device-context support for WM_PAINT handling.
//!
//! Most real apps and all D3D games bypass GDI for rendering, so this crate keeps the
//! surface tiny: just enough DC bookkeeping for a Win32 message loop to call
//! `BeginPaint`/`EndPaint`/`ValidateRect` inside `WM_PAINT` without crashing. The DCs are
//! opaque pseudo-handles backed by a small integer id; they carry no real pixel surface.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU32, Ordering};

/// A pseudo device-context handle. We never dereference these; they are opaque ids the
/// caller passes back to `ReleaseDC`/`DeleteDC`/`EndPaint`.
pub type HDC = *mut c_void;

/// A window handle (opaque, owned by user32).
pub type HWND = *mut c_void;

/// `PAINTSTRUCT` — the minimal fields a `WM_PAINT` handler reads. `fErase` and `rcPaint`
/// are zeroed; `hdc` is the DC returned by `BeginPaint`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PaintStruct {
    pub hdc: HDC,
    pub f_erase: c_int,
    pub rc_paint: Rect,
    pub f_restore: c_int,
    pub f_inc_update: c_int,
    _reserved: [u8; 32],
}

/// A Win32 `RECT`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Rect {
    pub left: c_int,
    pub top: c_int,
    pub right: c_int,
    pub bottom: c_int,
}

// ---------------------------------------------------------------------------
// DC allocation — a fresh non-null opaque id per call.
// ---------------------------------------------------------------------------

static NEXT_DC: AtomicU32 = AtomicU32::new(1);

/// Allocate a fresh pseudo-DC handle. The value is non-null and recognizable so callers
/// can distinguish "no DC" (null) from "a DC". We never read or write through it.
fn make_dc() -> HDC {
    let id = NEXT_DC.fetch_add(1, Ordering::Relaxed);
    // Keep it non-null and in a safe-looking range. The value is never dereferenced.
    (id as usize | 0x1_0000_0000) as *mut c_void
}

// ---------------------------------------------------------------------------
// Implemented exports (extern "C"; the ABI thunk in pe-loader wraps them)
// ---------------------------------------------------------------------------

/// `GetDC(HWND) -> HDC`. Returns a pseudo-DC for the window (or the screen if `hwnd`
/// is null).
extern "C" fn get_dc(_hwnd: HWND) -> HDC {
    let dc = make_dc();
    log::trace!("gdi32!GetDC -> {dc:p}");
    dc
}

/// `ReleaseDC(HWND, HDC) -> int`. Always succeeds (returns 1).
extern "C" fn release_dc(_hwnd: HWND, _hdc: HDC) -> c_int {
    log::trace!("gdi32!ReleaseDC");
    1
}

/// `BeginPaint(HWND, LPPAINTSTRUCT) -> HDC`. Fills the `PAINTSTRUCT` with a fresh DC and
/// a zeroed `rcPaint`, returns the DC.
///
/// # Safety
/// `lpps` must be null or point to a writable `PaintStruct` (the guest supplies one per
/// the Win32 contract).
extern "C" fn begin_paint(_hwnd: HWND, lpps: *mut PaintStruct) -> HDC {
    let dc = make_dc();
    log::trace!("gdi32!BeginPaint -> {dc:p}");
    if !lpps.is_null() {
        // SAFETY: the guest provides `lpps` valid for one `PaintStruct` write.
        unsafe {
            lpps.write(PaintStruct {
                hdc: dc,
                ..PaintStruct::default()
            });
        }
    }
    dc
}

/// `EndPaint(HWND, const PAINTSTRUCT*) -> int`. Returns 1 (success).
extern "C" fn end_paint(_hwnd: HWND, _lpps: *const PaintStruct) -> c_int {
    log::trace!("gdi32!EndPaint");
    1
}

/// `CreateCompatibleDC(HDC) -> HDC`. Returns a fresh pseudo-DC (memory DC).
extern "C" fn create_compatible_dc(_hdc: HDC) -> HDC {
    let dc = make_dc();
    log::trace!("gdi32!CreateCompatibleDC -> {dc:p}");
    dc
}

/// `DeleteDC(HDC) -> int`. Returns 1 (success).
extern "C" fn delete_dc(_hdc: HDC) -> c_int {
    log::trace!("gdi32!DeleteDC");
    1
}

/// `ValidateRect(HWND, const RECT*) -> int`. Returns 1.
extern "C" fn validate_rect(_hwnd: HWND, _rect: *const Rect) -> c_int {
    log::trace!("gdi32!ValidateRect");
    1
}

/// `InvalidateRect(HWND, const RECT*, BOOL) -> int`. Returns 1.
extern "C" fn invalidate_rect(_hwnd: HWND, _rect: *const Rect, _erase: c_int) -> c_int {
    log::trace!("gdi32!InvalidateRect");
    1
}

/// `GetClientRect(HWND, LPRECT) -> int`. Returns 1 and zeroes the rect; user32 overrides
/// with the real client size.
extern "C" fn get_client_rect(_hwnd: HWND, lprect: *mut Rect) -> c_int {
    log::trace!("gdi32!GetClientRect (fallback — user32 provides the real size)");
    if !lprect.is_null() {
        // SAFETY: the guest provides `lprect` valid for one `Rect` write.
        unsafe { lprect.write(Rect::default()) };
    }
    1
}

/// `DeleteObject(HGDIOBJ) -> int`. Returns 1. GDI objects are not yet allocated here.
extern "C" fn delete_object(_obj: *mut c_void) -> c_int {
    log::trace!("gdi32!DeleteObject");
    1
}

/// `SetPixel(HDC, int, int, COLORREF) -> COLORREF`. Returns the color set (no real
/// surface).
extern "C" fn set_pixel(_hdc: HDC, _x: c_int, _y: c_int, color: u32) -> u32 {
    color
}

/// The function-pointer type matching `pe-loader`'s `ImplTable`.
pub type FnPtr = *const c_void;

/// Metadata for a single gdi32 export, used by the PE loader to build the ABI thunk for
/// the import. The loader needs the argument count (to size the Win64->SysV trampoline)
/// and the `noreturn` flag (always false here — no gdi32 function diverges).
#[derive(Clone, Copy)]
pub struct ExportSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: FnPtr,
    pub n_args: u8,
    pub noreturn: bool,
}

/// The full list of gdi32 exports with the metadata the PE loader needs to build ABI
/// thunks. Callers that only need `(dll, sym, ptr)` triples should use
/// [`gdi32_imports`] instead.
pub fn gdi32_export_specs() -> Vec<ExportSpec> {
    macro_rules! g {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "gdi32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }
    vec![
        g!("GetDC", get_dc, 1),
        g!("ReleaseDC", release_dc, 2),
        g!("BeginPaint", begin_paint, 2),
        g!("EndPaint", end_paint, 2),
        g!("CreateCompatibleDC", create_compatible_dc, 1),
        g!("DeleteDC", delete_dc, 1),
        g!("ValidateRect", validate_rect, 2),
        g!("InvalidateRect", invalidate_rect, 3),
        g!("GetClientRect", get_client_rect, 2),
        g!("DeleteObject", delete_object, 1),
        g!("SetPixel", set_pixel, 4),
    ]
}

/// The gdi32 export table the PE loader registers. Each tuple is
/// `(dll, symbol, function-pointer)`. Prefer [`gdi32_export_specs`] when the loader needs
/// argument-count metadata for the ABI thunk.
pub fn gdi32_imports() -> Vec<(&'static str, &'static str, FnPtr)> {
    gdi32_export_specs()
        .into_iter()
        .map(|e| (e.dll, e.sym, e.ptr))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdi32_imports_nonempty_and_correct_dll() {
        let imports = gdi32_imports();
        assert!(!imports.is_empty());
        assert!(imports.iter().all(|(dll, _, _)| *dll == "gdi32.dll"));
        assert!(imports.iter().any(|(_, sym, _)| *sym == "BeginPaint"));
        assert!(imports.iter().any(|(_, sym, _)| *sym == "ValidateRect"));
        // Every pointer must be non-null.
        assert!(imports.iter().all(|(_, _, p)| !p.is_null()));
    }

    #[test]
    fn begin_paint_fills_paintstruct() {
        let mut ps = PaintStruct::default();
        let dc = begin_paint(std::ptr::null_mut(), &mut ps as *mut PaintStruct);
        assert!(!dc.is_null());
        assert_eq!(ps.hdc, dc);
        assert_eq!(ps.f_erase, 0);
    }

    #[test]
    fn get_dc_returns_nonnull() {
        let dc = get_dc(std::ptr::null_mut());
        assert!(!dc.is_null());
        assert_eq!(release_dc(std::ptr::null_mut(), dc), 1);
    }

    #[test]
    fn delete_object_succeeds() {
        assert_eq!(delete_object(std::ptr::null_mut()), 1);
    }
}
