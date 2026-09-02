//! gdi32 subset: minimal device-context support for WM_PAINT handling.
//!
//! Most real apps and all D3D games bypass GDI for rendering, so this crate keeps the
//! surface tiny: just enough DC bookkeeping for a Win32 message loop to call
//! `BeginPaint`/`EndPaint`/`ValidateRect` inside `WM_PAINT` without crashing. The DCs are
//! opaque pseudo-handles backed by a small integer id; they carry no real pixel surface.

#![deny(unsafe_op_in_unsafe_fn)]
// `FAKE_HGDI` below is a small non-null integer *handle* sentinel (HGDIOBJ/HFONT), cast from
// `1` — the intended spelling for an opaque handle, not a pointer to memory. The
// `manual_dangling_ptr` lint misreads it as a dangling-pointer construction.
#![allow(clippy::manual_dangling_ptr)]

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
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rect {
    pub left: c_int,
    pub top: c_int,
    pub right: c_int,
    pub bottom: c_int,
}

/// Win32 `SIZE` (8 bytes): `{ cx, cy }`.
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Size {
    pub cx: c_int,
    pub cy: c_int,
}

/// Win32 `TEXTMETRICW` (60 bytes on x64, including 3 bytes of trailing padding). We mirror
/// the full field layout so a PE's `&TEXTMETRICW` pointer is written at the right offsets.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct TextMetricW {
    pub tm_height: c_int,
    pub tm_ascent: c_int,
    pub tm_descent: c_int,
    pub tm_internal_leading: c_int,
    pub tm_external_leading: c_int,
    pub tm_ave_char_width: c_int,
    pub tm_max_char_width: c_int,
    pub tm_weight: c_int,
    pub tm_overhang: c_int,
    pub tm_digitized_aspect_x: c_int,
    pub tm_digitized_aspect_y: c_int,
    pub tm_first_char: u16,
    pub tm_last_char: u16,
    pub tm_default_char: u16,
    pub tm_break_char: u16,
    pub tm_italic: u8,
    pub tm_underlined: u8,
    pub tm_struck_out: u8,
    pub tm_pitch_and_family: u8,
    pub tm_char_set: u8,
}

// `GetDeviceCaps` indices we answer with a non-zero default.
/// `HORZRES` — pixel width of the screen.
const HORZRES: c_int = 8;
/// `VERTRES` — pixel height of the screen.
const VERTRES: c_int = 10;
/// `LOGPIXELSX` — horizontal dots-per-inch.
const LOGPIXELSX: c_int = 88;
/// `LOGPIXELSY` — vertical dots-per-inch.
const LOGPIXELSY: c_int = 90;
/// Default screen width returned by `GetDeviceCaps(HORZRES)`.
const DEFAULT_CXSCREEN: c_int = 640;
/// Default screen height returned by `GetDeviceCaps(VERTRES)`.
const DEFAULT_CYSCREEN: c_int = 480;
/// Standard 96 DPI returned by `GetDeviceCaps(LOGPIXELS*)`.
const STANDARD_DPI: c_int = 96;
/// `MM_TEXT` — the default mapping mode (1 logical unit == 1 pixel).
const MM_TEXT: c_int = 1;
/// Fake non-null GDI object handle returned by `SelectObject` (the "previous object") and
/// `CreateFontIndirectW` (the new font). A small integer keeps PEs that test for NULL happy.
const FAKE_HGDI: *mut c_void = 1 as *mut c_void;

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

// ---------------------------------------------------------------------------
// Additional gdi32 exports — simple no-op stubs real PEs (notepad.exe) import.
// ---------------------------------------------------------------------------

/// `SelectObject(HDC, HGDIOBJ) -> HGDIOBJ`. Returns a fake non-null handle (the "previous
/// object"); GDI objects are not really tracked here.
extern "C" fn select_object(_hdc: HDC, _obj: *mut c_void) -> *mut c_void {
    FAKE_HGDI
}

/// `CreateFontIndirectW(const LOGFONTW*) -> HFONT`. Returns a fake non-null font handle.
/// The `LOGFONTW` is not inspected.
extern "C" fn create_font_indirect_w(_logfont: *const c_void) -> *mut c_void {
    FAKE_HGDI
}

/// `GetDeviceCaps(HDC, int) -> int`. Returns reasonable defaults for the metrics notepad
/// probes (screen size, DPI); 0 for everything else.
extern "C" fn get_device_caps(_hdc: HDC, index: c_int) -> c_int {
    match index {
        HORZRES => DEFAULT_CXSCREEN,
        VERTRES => DEFAULT_CYSCREEN,
        LOGPIXELSX => STANDARD_DPI,
        LOGPIXELSY => STANDARD_DPI,
        _ => 0,
    }
}

/// `GetTextMetricsW(HDC, TEXTMETRICW*) -> BOOL`. Zeroes the struct and returns TRUE.
extern "C" fn get_text_metrics_w(_hdc: HDC, tm: *mut TextMetricW) -> c_int {
    if tm.is_null() {
        return 0;
    }
    // SAFETY: the guest provides `tm` valid for one `TextMetricW` write.
    unsafe { tm.write(TextMetricW::default()) };
    1
}

/// `GetTextExtentPoint32W(HDC, LPCWSTR, int, LPSIZE) -> BOOL`. Sets the size to
/// `{8*len, 16}` (a fixed-width-ish default) and returns TRUE.
extern "C" fn get_text_extent_point32_w(
    _hdc: HDC,
    _str: *const u16,
    len: c_int,
    size: *mut Size,
) -> c_int {
    if size.is_null() {
        return 0;
    }
    let n = len.max(0);
    // SAFETY: the guest provides `size` valid for one `Size` write.
    unsafe {
        size.write(Size { cx: 8 * n, cy: 16 });
    }
    1
}

/// `GetTextExtentExPointW(HDC, LPCWSTR, int, int, LPINT, LPINT, LPSIZE) -> BOOL`. Returns
/// TRUE without computing per-char extents.
extern "C" fn get_text_extent_ex_point_w(
    _hdc: HDC,
    _str: *const u16,
    _len: c_int,
    _max_extent: c_int,
    fit: *mut c_int,
    _dx: *mut c_int,
    size: *mut Size,
) -> c_int {
    if !fit.is_null() {
        // SAFETY: the guest provides `fit` valid for one `c_int` write.
        unsafe { *fit = 0 };
    }
    if !size.is_null() {
        // SAFETY: the guest provides `size` valid for one `Size` write.
        unsafe { size.write(Size::default()) };
    }
    1
}

/// `ExtTextOutW(HDC, int, int, UINT, const RECT*, LPCWSTR, UINT, const INT*) -> BOOL`.
/// Returns TRUE (text "drawn" to the no-op surface).
extern "C" fn ext_text_out_w(
    _hdc: HDC,
    _x: c_int,
    _y: c_int,
    _flags: u32,
    _rect: *const Rect,
    _str: *const u16,
    _count: u32,
    _dx: *const c_int,
) -> c_int {
    1
}

/// `SetMapMode(HDC, int) -> int`. Returns `MM_TEXT` (the previous/only mode we honor).
extern "C" fn set_map_mode(_hdc: HDC, _mode: c_int) -> c_int {
    MM_TEXT
}

/// `StartDocW(HDC, const DOCINFOW*) -> int`. Returns 1 (a positive job id).
extern "C" fn start_doc_w(_hdc: HDC, _docinfo: *const c_void) -> c_int {
    1
}

/// `EndDoc(HDC) -> int`. Returns TRUE (print job ended).
extern "C" fn end_doc(_hdc: HDC) -> c_int {
    1
}

/// `StartPage(HDC) -> int`. Returns TRUE.
extern "C" fn start_page(_hdc: HDC) -> c_int {
    1
}

/// `EndPage(HDC) -> int`. Returns TRUE.
extern "C" fn end_page(_hdc: HDC) -> c_int {
    1
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
        // --- additional stubs real PEs (notepad.exe) import ---
        g!("SelectObject", select_object, 2),
        g!("CreateFontIndirectW", create_font_indirect_w, 1),
        g!("GetDeviceCaps", get_device_caps, 2),
        g!("GetTextMetricsW", get_text_metrics_w, 2),
        g!("GetTextExtentPoint32W", get_text_extent_point32_w, 4),
        g!("GetTextExtentExPointW", get_text_extent_ex_point_w, 7),
        g!("ExtTextOutW", ext_text_out_w, 8),
        g!("SetMapMode", set_map_mode, 2),
        g!("StartDocW", start_doc_w, 2),
        g!("EndDoc", end_doc, 1),
        g!("StartPage", start_page, 1),
        g!("EndPage", end_page, 1),
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

    #[test]
    fn additional_stubs_are_registered() {
        let specs = gdi32_export_specs();
        let names: Vec<&str> = specs.iter().map(|e| e.sym).collect();
        for required in [
            "SelectObject",
            "CreateFontIndirectW",
            "GetDeviceCaps",
            "GetTextMetricsW",
            "GetTextExtentPoint32W",
            "GetTextExtentExPointW",
            "ExtTextOutW",
            "SetMapMode",
            "StartDocW",
            "EndDoc",
            "StartPage",
            "EndPage",
        ] {
            assert!(
                names.contains(&required),
                "gdi32 export {required} missing from gdi32_export_specs"
            );
        }
        assert!(specs.iter().all(|e| e.dll == "gdi32.dll"));
    }

    #[test]
    fn get_device_caps_returns_defaults() {
        assert_eq!(get_device_caps(std::ptr::null_mut(), 8), 640); // HORZRES
        assert_eq!(get_device_caps(std::ptr::null_mut(), 10), 480); // VERTRES
        assert_eq!(get_device_caps(std::ptr::null_mut(), 88), 96); // LOGPIXELSX
        assert_eq!(get_device_caps(std::ptr::null_mut(), 90), 96); // LOGPIXELSY
        assert_eq!(get_device_caps(std::ptr::null_mut(), 999), 0); // unknown
    }

    #[test]
    fn text_extent_and_metrics_stubs() {
        let mut tm = TextMetricW::default();
        assert_eq!(
            get_text_metrics_w(std::ptr::null_mut(), &mut tm as *mut TextMetricW),
            1
        );
        assert_eq!(tm.tm_height, 0);

        let mut size = Size { cx: 1, cy: 1 };
        assert_eq!(
            get_text_extent_point32_w(
                std::ptr::null_mut(),
                std::ptr::null(),
                4,
                &mut size as *mut Size
            ),
            1
        );
        assert_eq!(size, Size { cx: 32, cy: 16 });
    }

    #[test]
    fn select_object_and_font_stubs_return_nonnull() {
        assert!(!select_object(std::ptr::null_mut(), std::ptr::null_mut()).is_null());
        assert!(!create_font_indirect_w(std::ptr::null()).is_null());
    }

    #[test]
    fn map_mode_and_print_stubs() {
        assert_eq!(set_map_mode(std::ptr::null_mut(), 0), 1); // MM_TEXT
        assert_eq!(start_doc_w(std::ptr::null_mut(), std::ptr::null()), 1);
        assert_eq!(end_doc(std::ptr::null_mut()), 1);
        assert_eq!(start_page(std::ptr::null_mut()), 1);
        assert_eq!(end_page(std::ptr::null_mut()), 1);
    }
}
