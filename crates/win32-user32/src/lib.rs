//! user32 subset: Win32 windowing and message loop, backed by `nigg-wsi`.
//!
//! Implements the core of a Win32 message loop: `RegisterClassExW`, `CreateWindowExW`,
//! `GetMessageW`/`PeekMessageW`/`DispatchMessageW`, `PostQuitMessage`,
//! `SendMessageW`/`PostMessageW`, and `DefWindowProcW`. Window events from the host
//! (`nigg_wsi::WindowEvent`) are translated into Win32 `MSG` records; `DispatchMessageW`
//! calls the PE-supplied window procedure through a Win64→SysV ABI thunk.
//!
//! The window and class tables are thread-local because `wsi::Window` (the X11
//! connection) is not `Send` — matching Win32's single-threaded message-loop model.
//! All exports are `extern "C"`; the PE loader's ABI thunk wraps them before they land
//! in the IAT.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
// The `FAKE_*` constants below are small non-null integer *handle* sentinels (HMENU, HICON,
// HMONITOR, ...), not pointers to memory. Casting `1 as *mut c_void` is the intended way to
// spell "a non-null opaque handle"; the `manual_dangling_ptr` lint misreads these as attempts
// to build a dangling pointer for `NonNull` purposes.
#![allow(clippy::manual_dangling_ptr)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Opaque window handle. A small non-null integer encoded as a pointer.
pub type HWND = *mut c_void;
/// Opaque handle to a window class atom (small integer).
pub type ATOM = u16;

/// Win32 `POINT`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Point {
    pub x: c_int,
    pub y: c_int,
}

/// Win32 `RECT`.
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rect {
    pub left: c_int,
    pub top: c_int,
    pub right: c_int,
    pub bottom: c_int,
}

/// Win32 `MSG`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Msg {
    pub hwnd: HWND,
    pub message: u32,
    pub w_param: usize,
    pub l_param: isize,
    pub time: u32,
    pub pt: Point,
}

/// A window-procedure function pointer supplied by the PE image (Win64 ABI):
/// `LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM)`.
pub type WndProc = *const c_void;

/// The Windows `WNDCLASSEXW` structure as a PE lays it out (80 bytes on x64).
/// We mirror the full field layout so a PE's `&WNDCLASSEXW` pointer is read
/// correctly — a partial struct would misalign every field after the first
/// gap, and `lpszClassName` (at offset 64) would read from the wrong place.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WndClassEx {
    pub cb_size: u32,
    pub style: u32,
    pub lpfn_wnd_proc: WndProc,
    pub cb_cls_extra: c_int,
    pub cb_wnd_extra: c_int,
    pub h_instance: *mut c_void,
    pub h_icon: *mut c_void,
    pub h_cursor: *mut c_void,
    pub hbr_background: *mut c_void,
    pub lpsz_menu_name: *const u16,
    pub lpsz_class_name: *const u16,
    pub h_icon_sm: *mut c_void,
}

/// Win32 `WINDOWPLACEMENT` (44 bytes on x64). We mirror the full layout so a PE's
/// `&WINDOWPLACEMENT` pointer is read/written at the right offsets.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WindowPlacement {
    pub length: u32,
    pub flags: u32,
    pub show_cmd: u32,
    pub pt_min_position: Point,
    pub pt_max_position: Point,
    pub rc_normal_position: Rect,
}

/// Win32 `MONITORINFO` (40 bytes on x64).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MonitorInfo {
    pub cb_size: u32,
    pub rc_monitor: Rect,
    pub rc_work: Rect,
    pub dw_flags: u32,
}

// ---------------------------------------------------------------------------
// Window-message constants
// ---------------------------------------------------------------------------

pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;

/// `SW_SHOW`
pub const SW_SHOW: c_int = 5;
/// `SW_HIDE`
pub const SW_HIDE: c_int = 0;

// `GetSystemMetrics` indices we answer with a non-zero default.
/// `SM_CXSCREEN` (primary screen width in pixels).
const SM_CXSCREEN: c_int = 0;
/// `SM_CYSCREEN` (primary screen height in pixels).
const SM_CYSCREEN: c_int = 1;
/// Default primary screen width returned by `GetSystemMetrics(SM_CXSCREEN)`.
const DEFAULT_CXSCREEN: c_int = 640;
/// Default primary screen height returned by `GetSystemMetrics(SM_CYSCREEN)`.
const DEFAULT_CYSCREEN: c_int = 480;
/// `MONITOR_DEFAULTTOPRIMARY`-ish fake monitor handle returned by `MonitorFromRect`.
const FAKE_HMONITOR: *mut c_void = 1 as *mut c_void;
/// Fake non-null `HMENU` returned by `GetMenu`/`LoadMenu`-family stubs (we never deliver a
/// real menu). Stays a small integer so PEs treat it as a valid (empty) menu handle.
const FAKE_HMENU: *mut c_void = 1 as *mut c_void;
/// Fake non-null `HICON`/`HCURSOR`/`HIMAGE` handle returned by the `Load*`-family stubs.
const FAKE_HICON: *mut c_void = 1 as *mut c_void;
/// Fake non-null `HACCEL` handle returned by `LoadAcceleratorsW`.
const FAKE_HACCEL: *mut c_void = 1 as *mut c_void;
/// `RegisterWindowMessageW` returns values in the range `0xC000..=0xFFFF` on Windows; we
/// hand out a stable high-range id so callers that compare against a registered message id
/// keep working.
const FAKE_REGISTERED_MSG: u32 = 0x8000;
/// Standard 96 DPI returned by `GetDpiForWindow` (user has no DPI override).
const STANDARD_DPI: u32 = 96;

// ---------------------------------------------------------------------------
// Thread-local state (wsi::Window is not Send; Win32 message loops are single-thread)
// ---------------------------------------------------------------------------

/// One registered window class.
struct ClassEntry {
    atom: ATOM,
    class: WndClassEx,
    name: String,
}

/// One live window.
struct WindowEntry {
    /// The host window. `None` on a headless host or after `DestroyWindow`.
    window: Option<nigg_wsi::Window>,
    class_atom: ATOM,
    wnd_proc: WndProc,
    title: String,
    width: u32,
    height: u32,
    visible: bool,
    /// Pending paint flag (set by `InvalidateRect`, cleared by `ValidateRect`/`BeginPaint`).
    paint_pending: bool,
}

#[derive(Default)]
struct State {
    classes: Vec<ClassEntry>,
    windows: Vec<(HWND, WindowEntry)>,
    /// The per-thread posted-message queue (`PostMessage`/`PostQuitMessage`).
    queue: VecDeque<Msg>,
    /// Nonzero once `PostQuitMessage` has been called; `GetMessage` then returns 0.
    quit_code: Option<isize>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

static NEXT_HWND: AtomicU32 = AtomicU32::new(1);

/// Allocate a fresh non-null `HWND`.
fn make_hwnd() -> HWND {
    let id = NEXT_HWND.fetch_add(1, Ordering::Relaxed);
    (id as usize | 0x2_0000_0000) as *mut c_void
}

fn find_class_by_name(name: &str) -> Option<ATOM> {
    STATE.with(|s| {
        s.borrow()
            .classes
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.atom)
    })
}

fn clear_paint_flag(hwnd: HWND) {
    STATE.with(|s| {
        if let Some((_, w)) = s.borrow_mut().windows.iter_mut().find(|(h, _)| *h == hwnd) {
            w.paint_pending = false;
        }
    });
}

// ---------------------------------------------------------------------------
// Win64→SysV window-procedure thunk
// ---------------------------------------------------------------------------

/// Call a PE window procedure `proc` (Win64 ABI) with four integer arguments, returning
/// the `LRESULT` in `rax`. The thunk sets up the Win64 register arguments
/// (RCX=`hwnd`, RDX=`msg`, R8=`wparam`, R9=`lparam`) and a 32-byte shadow space on a
/// scratch stack, then tail-calls the procedure.
///
/// # Safety
/// `proc` must be a valid, executable Win64 function pointer (a PE `lpfnWndProc` with
/// relocations applied). The four arguments must match the `WndProc` contract.
pub unsafe fn call_win64_wndproc(
    proc_: *const c_void,
    hwnd: u64,
    msg: u32,
    w_param: u64,
    l_param: isize,
) -> isize {
    let mut result: isize;
    // We allocate a 64-byte scratch region (32-byte Win64 shadow space + alignment) on
    // the Rust stack and hand the *top* of it to the callee as its initial RSP. Win64
    // requires 32 bytes of shadow space below the return address at the call site and
    // 16-byte alignment *after* the implicit push of the return address — i.e. RSP
    // entering the callee must be `(rsp - 8) % 16 == 0`. We reserve 64 bytes, align the
    // handoff pointer down to 16 and leave 32 bytes of shadow below it.
    let mut scratch = [0u8; 64];
    let base = scratch.as_mut_ptr();
    // Align up to 16 and leave 32 bytes of shadow space below the callee's RSP.
    let handoff = ((base as usize + 48) & !0xF) as *mut u8;
    // Pack the four Win64 arguments into a small array on the stack and load them with
    // a single `in(reg)` pointer, avoiding the "too many registers" limit. We then move
    // each argument into the correct Win64 register inline.
    let args = [hwnd, msg as u64, w_param, l_param as u64];
    let args_ptr = args.as_ptr();
    unsafe {
        core::arch::asm!(
            "mov r12, rsp",
            "mov rsp, {sp}",
            "mov rax, {args}",
            "mov rcx, [rax]",
            "mov rdx, [rax+8]",
            "mov r8, [rax+16]",
            "mov r9, [rax+24]",
            "call {proc}",
            "mov rsp, r12",
            sp = in(reg) handoff,
            args = in(reg) args_ptr,
            proc = in(reg) proc_,
            out("r12") _,
            out("rax") result,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }
    result
}

// ---------------------------------------------------------------------------
// Implemented exports (extern "C"; the ABI thunk in pe-loader wraps them)
// ---------------------------------------------------------------------------

/// `RegisterClassExW(const WNDCLASSEXW*) -> ATOM`. Stores the class and returns a fresh
/// atom (nonzero). Returns 0 on null input.
extern "C" fn register_class_ex_w(lpwcx: *const WndClassEx) -> ATOM {
    if lpwcx.is_null() {
        return 0;
    }
    // SAFETY: the guest provides `lpwcx` valid for one `WndClassEx` read.
    let wcx = unsafe { *lpwcx };
    let name = widestring_to_string(wcx.lpsz_class_name);
    let atom = NEXT_HWND.fetch_add(1, Ordering::Relaxed) as u16 | 0x8000;
    STATE.with(|s| {
        s.borrow_mut().classes.push(ClassEntry {
            atom,
            class: wcx,
            name,
        });
    });
    log::trace!("user32!RegisterClassExW -> atom {atom}");
    atom
}

/// `UnregisterClassW(LPCWSTR, HINSTANCE) -> int`. Removes the named class. Returns 1
/// on success.
extern "C" fn unregister_class_w(name: *const u16, _instance: *mut c_void) -> c_int {
    if name.is_null() {
        return 0;
    }
    let n = widestring_to_string(name);
    let removed = STATE.with(|s| {
        let mut st = s.borrow_mut();
        if let Some(pos) = st.classes.iter().position(|c| c.name == n) {
            st.classes.remove(pos);
            true
        } else {
            false
        }
    });
    if removed {
        1
    } else {
        0
    }
}

/// `CreateWindowExW(...) -> HWND`. Opens a `wsi::Window` and records it under a fresh
/// HWND. On a headless host (no display) the `wsi::Window` is `None` but the HWND is
/// still valid for message-loop bookkeeping, so headless tests can exercise the loop.
extern "C" fn create_window_ex_w(
    _ex_style: u32,
    class_name: *const u16,
    _window_name: *const u16,
    _style: u32,
    _x: c_int,
    _y: c_int,
    width: c_int,
    height: c_int,
    _parent: HWND,
    _menu: *mut c_void,
    _instance: *mut c_void,
    _param: *mut c_void,
) -> HWND {
    let cname = widestring_to_string(class_name);
    let atom = match find_class_by_name(&cname) {
        Some(a) => a,
        None => {
            log::warn!("user32!CreateWindowExW: class '{cname}' not registered");
            return std::ptr::null_mut();
        }
    };
    let (wnd_proc, w, h) = STATE
        .with(|s| {
            let st = s.borrow();
            let cls = st.classes.iter().find(|c| c.atom == atom)?;
            Some((
                cls.class.lpfn_wnd_proc,
                width.max(1) as u32,
                height.max(1) as u32,
            ))
        })
        .unwrap_or((std::ptr::null(), 1, 1));

    let title = cname.clone();
    // Try to open a real host window; degrade to None on a headless host.
    let host_window = nigg_wsi::Window::new(&title, w, h).ok();

    let hwnd = make_hwnd();
    STATE.with(|s| {
        s.borrow_mut().windows.push((
            hwnd,
            WindowEntry {
                window: host_window,
                class_atom: atom,
                wnd_proc,
                title,
                width: w,
                height: h,
                visible: false,
                paint_pending: false,
            },
        ));
    });
    log::trace!("user32!CreateWindowExW('{cname}') -> {hwnd:p}");

    // Windows sends WM_CREATE, WM_SIZE, WM_MOVE, and WM_SHOWWINDOW to the
    // window procedure during CreateWindowExW. Without WM_CREATE, the game's
    // WndProc never initializes its state and crashes on the first message.
    if !wnd_proc.is_null() {
        send_message_internal(hwnd, WM_CREATE, 0, 0);
        send_message_internal(hwnd, 0x0005, 0, 0); // WM_SIZE
        send_message_internal(hwnd, 0x0003, 0, 0); // WM_MOVE
        send_message_internal(hwnd, 0x0018, 1, 0); // WM_SHOWWINDOW (TRUE)
    }

    hwnd
}

/// `DestroyWindow(HWND) -> int`. Marks the window closed and posts `WM_DESTROY`.
extern "C" fn destroy_window(hwnd: HWND) -> c_int {
    let removed = STATE.with(|s| {
        let mut st = s.borrow_mut();
        if let Some(pos) = st.windows.iter().position(|(h, _)| *h == hwnd) {
            st.windows.remove(pos);
            true
        } else {
            false
        }
    });
    if removed {
        // Mirror Win32: DestroyWindow sends WM_DESTROY to the window proc.
        post_message_internal(hwnd, WM_DESTROY, 0, 0);
        1
    } else {
        0
    }
}

/// `ShowWindow(HWND, int) -> int`. Records visibility; on a real host maps/unmaps the
/// window.
extern "C" fn show_window(hwnd: HWND, cmd: c_int) -> c_int {
    let was_visible = STATE.with(|s| {
        let mut st = s.borrow_mut();
        if let Some((_, w)) = st.windows.iter_mut().find(|(h, _)| *h == hwnd) {
            let prev = w.visible;
            w.visible = cmd != SW_HIDE;
            prev
        } else {
            false
        }
    });
    if was_visible {
        1
    } else {
        0
    }
}

/// `UpdateWindow(HWND) -> int`. Sends a synchronous `WM_PAINT`. Returns 1.
extern "C" fn update_window(hwnd: HWND) -> c_int {
    send_message_internal(hwnd, WM_PAINT, 0, 0);
    1
}

/// `GetClientRect(HWND, LPRECT) -> int`. Returns 1 and fills the rect with the client
/// size.
extern "C" fn get_client_rect(hwnd: HWND, lprect: *mut Rect) -> c_int {
    if lprect.is_null() {
        return 0;
    }
    let (w, h) = window_size(hwnd);
    // SAFETY: the guest provides `lprect` valid for one `Rect` write.
    unsafe {
        lprect.write(Rect {
            left: 0,
            top: 0,
            right: w as c_int,
            bottom: h as c_int,
        });
    }
    1
}

/// `GetWindowRect(HWND, LPRECT) -> int`.
extern "C" fn get_window_rect(hwnd: HWND, lprect: *mut Rect) -> c_int {
    get_client_rect(hwnd, lprect)
}

/// `SetWindowPos(HWND, HWND, int, int, int, int, u32) -> int`. Updates cached size.
extern "C" fn set_window_pos(
    _hwnd: HWND,
    _insert_after: HWND,
    _x: c_int,
    _y: c_int,
    cx: c_int,
    cy: c_int,
    _flags: u32,
) -> c_int {
    update_size(_hwnd, cx.max(1) as u32, cy.max(1) as u32)
}

/// `MoveWindow(HWND, int, int, int, int, BOOL) -> int`. Updates cached size.
extern "C" fn move_window(
    hwnd: HWND,
    _x: c_int,
    _y: c_int,
    cx: c_int,
    cy: c_int,
    _repaint: c_int,
) -> c_int {
    update_size(hwnd, cx.max(1) as u32, cy.max(1) as u32)
}

/// `GetWindowTextW(HWND, LPWSTR, int) -> int`. Copies the cached title. Returns the
/// length (in wide chars, excluding the NUL).
extern "C" fn get_window_text_w(hwnd: HWND, buf: *mut u16, max: c_int) -> c_int {
    if buf.is_null() || max <= 0 {
        return 0;
    }
    let title = window_title(hwnd);
    let mut len = 0i32;
    for (i, unit) in title.encode_utf16().enumerate() {
        if i as i32 >= max - 1 {
            break;
        }
        // SAFETY: `buf` is valid for `max` u16s per the guest; we stop at `max-1`.
        unsafe { buf.add(i).write(unit) };
        len = (i as i32) + 1;
    }
    // SAFETY: NUL-terminate within the `max` bound.
    if len < max {
        unsafe { buf.add(len as usize).write(0) };
    }
    len
}

/// `SetWindowTextW(HWND, LPCWSTR) -> int`. Updates the cached title.
extern "C" fn set_window_text_w(hwnd: HWND, title: *const u16) -> c_int {
    let t = widestring_to_string(title);
    STATE.with(|s| {
        if let Some((_, w)) = s.borrow_mut().windows.iter_mut().find(|(h, _)| *h == hwnd) {
            w.title = t;
        }
    });
    1
}

/// `GetMessageW(LPMSG, HWND, u32, u32) -> int`. Blocks for a message: first drains the
/// posted-message queue, then polls the host window for events and translates them.
/// Returns 0 on `WM_QUIT`, nonzero otherwise. This implementation does not truly block
/// (it polls once); a blocking variant can come later. It never returns -1 in M3.
extern "C" fn get_message_w(lpmsg: *mut Msg, _hwnd: HWND, _min: u32, _max: u32) -> c_int {
    if lpmsg.is_null() {
        return -1;
    }
    // 1. Drain the posted queue first.
    if let Some(m) = STATE.with(|s| s.borrow_mut().queue.pop_front()) {
        // SAFETY: the guest provides `lpmsg` valid for one `Msg` write.
        unsafe { lpmsg.write(m) };
        // Re-read to check for WM_QUIT (the borrowed value was moved into the write).
        // SAFETY: we just wrote it; reading it back is sound.
        let msg = unsafe { *lpmsg };
        return if msg.message == WM_QUIT { 0 } else { 1 };
    }
    // 2. Check for a pending quit.
    if let Some(code) = STATE.with(|s| s.borrow().quit_code) {
        // SAFETY: same as above.
        unsafe {
            lpmsg.write(Msg {
                message: WM_QUIT,
                w_param: code as usize,
                ..Msg::default()
            })
        };
        return 0;
    }
    // 3. Poll the host window for an event.
    if let Some(m) = poll_host_event() {
        // SAFETY: same as above.
        unsafe { lpmsg.write(m) };
        return 1;
    }
    // 4. Nothing ready: in a real blocking `GetMessage` we would wait. To stay
    //    CI-safe and non-hanging, return a synthetic `WM_NULL` so the caller can
    //    decide to retry or exit. A future blocking variant sleeps here.
    // SAFETY: same as above.
    unsafe {
        lpmsg.write(Msg {
            message: 0x0000, // WM_NULL
            ..Msg::default()
        })
    };
    1
}

/// `PeekMessageW(LPMSG, HWND, u32, u32, u32) -> int`. Non-blocking: returns 1 if a
/// message was available, 0 otherwise.
extern "C" fn peek_message_w(
    lpmsg: *mut Msg,
    _hwnd: HWND,
    _min: u32,
    _max: u32,
    _remove: u32,
) -> c_int {
    if lpmsg.is_null() {
        return 0;
    }
    let queued = STATE.with(|s| s.borrow_mut().queue.pop_front());
    if let Some(m) = queued {
        // SAFETY: the guest provides `lpmsg` valid for one `Msg` write.
        unsafe { lpmsg.write(m) };
        return 1;
    }
    if let Some(m) = poll_host_event() {
        // SAFETY: same as above.
        unsafe { lpmsg.write(m) };
        return 1;
    }
    0
}

/// `TranslateMessage(const MSG*) -> int`. Stub: returns 0 (no char translation).
extern "C" fn translate_message(_lpmsg: *const Msg) -> c_int {
    0
}

/// `DispatchMessageW(const MSG*) -> LRESULT`. Calls the target window's procedure
/// through the Win64→SysV thunk. If the window has no proc (e.g. headless test), calls
/// `DefWindowProcW`.
extern "C" fn dispatch_message_w(lpmsg: *const Msg) -> isize {
    if lpmsg.is_null() {
        return 0;
    }
    // SAFETY: the guest provides `lpmsg` valid for one `Msg` read.
    let msg = unsafe { *lpmsg };
    let (wnd_proc, _atom) = STATE
        .with(|s| {
            let st = s.borrow();
            st.windows
                .iter()
                .find(|(h, _)| *h == msg.hwnd)
                .map(|(_, w)| (w.wnd_proc, w.class_atom))
        })
        .unwrap_or((std::ptr::null(), 0));
    if !wnd_proc.is_null() {
        // SAFETY: `wnd_proc` is a PE-supplied Win64 function pointer with relocations
        // applied by the loader; `msg` fields match the WndProc contract.
        return unsafe {
            call_win64_wndproc(
                wnd_proc,
                msg.hwnd as u64,
                msg.message,
                msg.w_param as u64,
                msg.l_param,
            )
        };
    }
    // No PE proc: defer to DefWindowProcW.
    def_window_proc_w_impl(msg.hwnd, msg.message, msg.w_param, msg.l_param)
}

/// `PostQuitMessage(int) -> void`. Sets the quit code so the next `GetMessage` returns
/// 0.
extern "C" fn post_quit_message(exit_code: c_int) {
    STATE.with(|s| {
        s.borrow_mut().quit_code = Some(exit_code as isize);
    });
}

/// `PostMessageW(HWND, u32, WPARAM, LPARAM) -> int`. Queues a message.
extern "C" fn post_message_w(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) -> c_int {
    post_message_internal(hwnd, msg, w_param, l_param);
    1
}

/// `SendMessageW(HWND, u32, WPARAM, LPARAM) -> LRESULT`. Calls the window proc directly
/// (no queue). Falls back to `DefWindowProcW` if the window has no proc.
extern "C" fn send_message_w(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) -> isize {
    send_message_internal(hwnd, msg, w_param, l_param)
}

/// `DefWindowProcW(HWND, u32, WPARAM, LPARAM) -> LRESULT`. Default handling:
/// `WM_DESTROY`→`PostQuitMessage(0)`, `WM_CLOSE`→`DestroyWindow`, `WM_PAINT`→
/// `ValidateRect`, else 0.
extern "C" fn def_window_proc_w(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) -> isize {
    def_window_proc_w_impl(hwnd, msg, w_param, l_param)
}

/// `GetParent(HWND) -> HWND`. Stub: returns null.
extern "C" fn get_parent(_hwnd: HWND) -> HWND {
    std::ptr::null_mut()
}

/// `SetParent(HWND, HWND) -> HWND`. Stub.
extern "C" fn set_parent(_hwnd: HWND, _parent: HWND) -> HWND {
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Additional user32 exports — simple no-op stubs real PEs (notepad.exe) import.
// Most return a fixed value (0/TRUE/1) just to satisfy import resolution and CRT init.
// ---------------------------------------------------------------------------

/// `GetSystemMetrics(int) -> int`. Returns reasonable defaults for the handful of
/// metrics notepad probes (screen size); 0 for everything else.
extern "C" fn get_system_metrics(index: c_int) -> c_int {
    match index {
        SM_CXSCREEN => DEFAULT_CXSCREEN,
        SM_CYSCREEN => DEFAULT_CYSCREEN,
        _ => 0,
    }
}

/// `GetDesktopWindow() -> HWND`. Returns a fake non-null desktop HWND.
extern "C" fn get_desktop_window() -> HWND {
    1 as *mut c_void
}

/// `GetMenu(HWND) -> HMENU`. Returns a fake non-null (empty) menu handle.
extern "C" fn get_menu(_hwnd: HWND) -> *mut c_void {
    FAKE_HMENU
}

/// `GetWindowTextLengthW(HWND) -> int`. Returns 0 (empty title length).
extern "C" fn get_window_text_length_w(_hwnd: HWND) -> c_int {
    0
}

/// `GetWindowPlacement(HWND, WINDOWPLACEMENT*) -> BOOL`. Zeroes the struct (preserving
/// the caller's `length` field, which identifies the struct size on Windows) and returns
/// TRUE.
extern "C" fn get_window_placement(_hwnd: HWND, wp: *mut WindowPlacement) -> c_int {
    if wp.is_null() {
        return 0;
    }
    // SAFETY: the guest provides `wp` valid for one `WindowPlacement` write; we read the
    // caller's `length` first so the struct size is preserved.
    unsafe {
        let length = (*wp).length;
        wp.write(WindowPlacement {
            length,
            flags: 0,
            show_cmd: 0,
            pt_min_position: Point::default(),
            pt_max_position: Point::default(),
            rc_normal_position: Rect::default(),
        });
    }
    1
}

/// `GetDlgItem(HWND, int) -> HWND`. Returns NULL (no dialog item).
extern "C" fn get_dlg_item(_hwnd: HWND, _id: c_int) -> HWND {
    std::ptr::null_mut()
}

/// `GetDlgItemTextW(HWND, int, LPWSTR, int) -> UINT`. Returns 0 (no text).
extern "C" fn get_dlg_item_text_w(_hwnd: HWND, _id: c_int, _buf: *mut u16, _max: c_int) -> u32 {
    0
}

/// `GetDlgItemInt(HWND, int, BOOL*, BOOL) -> UINT`. Returns 0 (no value).
extern "C" fn get_dlg_item_int(
    _hwnd: HWND,
    _id: c_int,
    translated: *mut c_int,
    _signed: c_int,
) -> u32 {
    if !translated.is_null() {
        // SAFETY: the guest provides `translated` valid for one `c_int` write.
        unsafe { *translated = 0 };
    }
    0
}

/// `SetDlgItemTextW(HWND, int, LPCWSTR) -> BOOL`. Returns TRUE (text accepted).
extern "C" fn set_dlg_item_text_w(_hwnd: HWND, _id: c_int, _text: *const u16) -> c_int {
    1
}

/// `SetDlgItemInt(HWND, int, UINT, BOOL) -> BOOL`. Returns TRUE.
extern "C" fn set_dlg_item_int(_hwnd: HWND, _id: c_int, _value: u32, _signed: c_int) -> c_int {
    1
}

/// `SetActiveWindow(HWND) -> HWND`. Returns 0 (no previously active window).
extern "C" fn set_active_window(_hwnd: HWND) -> HWND {
    std::ptr::null_mut()
}

/// `SetFocus(HWND) -> HWND`. Returns 0 (no previously focused window).
extern "C" fn set_focus(_hwnd: HWND) -> HWND {
    std::ptr::null_mut()
}

/// `EnableMenuItem(HMENU, UINT, UINT) -> BOOL`. Returns 0 (no previous state).
extern "C" fn enable_menu_item(_menu: *mut c_void, _id: u32, _flags: u32) -> c_int {
    0
}

/// `CheckMenuItem(HMENU, UINT, UINT) -> BOOL`. Returns 0 (no previous state).
extern "C" fn check_menu_item(_menu: *mut c_void, _id: u32, _flags: u32) -> c_int {
    0
}

/// `MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT) -> int`. Returns `IDOK` (1) without showing
/// a dialog.
extern "C" fn message_box_w(
    _hwnd: HWND,
    _text: *const u16,
    _caption: *const u16,
    _flags: u32,
) -> c_int {
    1
}

/// `LoadIconW(HINSTANCE, LPCWSTR) -> HICON`. Returns a fake non-null icon handle.
extern "C" fn load_icon_w(_instance: *mut c_void, _name: *const u16) -> *mut c_void {
    FAKE_HICON
}

/// `LoadCursorW(HINSTANCE, LPCWSTR) -> HCURSOR`. Returns a fake non-null cursor handle.
extern "C" fn load_cursor_w(_instance: *mut c_void, _name: *const u16) -> *mut c_void {
    FAKE_HICON
}

/// `LoadImageW(HINSTANCE, LPCWSTR, UINT, int, int, UINT) -> HANDLE`. Returns a fake
/// non-null image handle.
extern "C" fn load_image_w(
    _instance: *mut c_void,
    _name: *const u16,
    _type: u32,
    _cx: c_int,
    _cy: c_int,
    _flags: u32,
) -> *mut c_void {
    FAKE_HICON
}

/// `LoadStringW(HINSTANCE, UINT, LPWSTR, int) -> int`. Returns 0 (string not found).
extern "C" fn load_string_w(
    _instance: *mut c_void,
    _id: u32,
    _buf: *mut u16,
    _max: c_int,
) -> c_int {
    0
}

/// `LoadAcceleratorsW(HINSTANCE, LPCWSTR) -> HACCEL`. Returns a fake non-null handle.
extern "C" fn load_accelerators_w(_instance: *mut c_void, _name: *const u16) -> *mut c_void {
    FAKE_HACCEL
}

/// `TranslateAcceleratorW(HWND, HACCEL, LPMSG) -> int`. Returns 0 (no key translated).
extern "C" fn translate_accelerator_w(_hwnd: HWND, _accel: *mut c_void, _msg: *const Msg) -> c_int {
    0
}

/// `RegisterWindowMessageW(LPCWSTR) -> UINT`. Returns a stable high-range id so callers
/// comparing against a registered message id keep working.
extern "C" fn register_window_message_w(_name: *const u16) -> u32 {
    FAKE_REGISTERED_MSG
}

/// `IsDialogMessageW(HWND, LPMSG) -> BOOL`. Returns FALSE (not a dialog message).
extern "C" fn is_dialog_message_w(_hwnd: HWND, _msg: *const Msg) -> c_int {
    0
}

/// `IsClipboardFormatAvailable(UINT) -> BOOL`. Returns FALSE (no formats available).
extern "C" fn is_clipboard_format_available(_format: u32) -> c_int {
    0
}

/// `InvalidateRect(HWND, const RECT*, BOOL) -> BOOL`. Marks the window's pending-paint
/// flag and returns TRUE.
extern "C" fn invalidate_rect(hwnd: HWND, _rect: *const Rect, _erase: c_int) -> c_int {
    STATE.with(|s| {
        if let Some((_, w)) = s.borrow_mut().windows.iter_mut().find(|(h, _)| *h == hwnd) {
            w.paint_pending = true;
        }
    });
    1
}

/// `GetDpiForWindow(HWND) -> UINT`. Returns 96 (standard DPI).
extern "C" fn get_dpi_for_window(_hwnd: HWND) -> u32 {
    STANDARD_DPI
}

/// `GetMonitorInfoW(HMONITOR, MONITORINFO*) -> BOOL`. Fills the struct with the primary
/// screen rect (both `rcMonitor` and `rcWork`) and returns TRUE.
extern "C" fn get_monitor_info_w(_monitor: *mut c_void, info: *mut MonitorInfo) -> c_int {
    if info.is_null() {
        return 0;
    }
    let screen = Rect {
        left: 0,
        top: 0,
        right: DEFAULT_CXSCREEN,
        bottom: DEFAULT_CYSCREEN,
    };
    // SAFETY: the guest provides `info` valid for one `MonitorInfo` write; we preserve the
    // caller's `cb_size` so they can identify the struct variant.
    unsafe {
        let cb = (*info).cb_size;
        info.write(MonitorInfo {
            cb_size: cb,
            rc_monitor: screen,
            rc_work: screen,
            dw_flags: 0,
        });
    }
    1
}

/// `MonitorFromRect(const RECT*, DWORD) -> HMONITOR`. Returns a fake non-null monitor
/// handle.
extern "C" fn monitor_from_rect(_rect: *const Rect, _flags: u32) -> *mut c_void {
    FAKE_HMONITOR
}

/// `DialogBoxParamW(HINSTANCE, LPCWSTR, HWND, DLGPROC, LPARAM) -> int`. Returns -1
/// (dialog failed to create) so the caller takes its error/fallback path.
extern "C" fn dialog_box_param_w(
    _instance: *mut c_void,
    _name: *const u16,
    _parent: HWND,
    _dlg_proc: *mut c_void,
    _param: isize,
) -> isize {
    -1
}

/// `EndDialog(HWND, INT_PTR) -> BOOL`. Returns TRUE.
extern "C" fn end_dialog(_hwnd: HWND, _result: isize) -> c_int {
    1
}

/// `WinHelpW(HWND, LPCWSTR, UINT, ULONG_PTR) -> BOOL`. Returns FALSE (no help available).
extern "C" fn win_help_w(_hwnd: HWND, _file: *const u16, _cmd: u32, _data: usize) -> c_int {
    0
}

/// `wsprintfW(LPWSTR, LPCWSTR, ...) -> int`. On Windows this is C-variadic; we cannot
/// express that stably in `extern "C"` Rust, so we model only the two fixed pointer args.
/// The thunk (n_args=2) shuffles the two register args; the variadic stack args are left
/// untouched and ignored by this no-op, which returns 0 (no formatting done).
extern "C" fn wsprintf_w(_buf: *mut u16, _fmt: *const u16) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn def_window_proc_w_impl(hwnd: HWND, msg: u32, _w_param: usize, _l_param: isize) -> isize {
    match msg {
        WM_DESTROY => {
            post_quit_message(0);
            0
        }
        WM_CLOSE => {
            destroy_window(hwnd);
            0
        }
        WM_PAINT => {
            // ValidateRect clears the pending paint; clear our local flag too.
            clear_paint_flag(hwnd);
            0
        }
        WM_SIZE => 0,
        _ => 0,
    }
}

fn post_message_internal(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) {
    STATE.with(|s| {
        s.borrow_mut().queue.push_back(Msg {
            hwnd,
            message: msg,
            w_param,
            l_param,
            time: 0,
            pt: Point::default(),
        });
    });
}

fn send_message_internal(hwnd: HWND, msg: u32, w_param: usize, l_param: isize) -> isize {
    let (wnd_proc, _atom) = STATE
        .with(|s| {
            let st = s.borrow();
            st.windows
                .iter()
                .find(|(h, _)| *h == hwnd)
                .map(|(_, w)| (w.wnd_proc, w.class_atom))
        })
        .unwrap_or((std::ptr::null(), 0));
    if !wnd_proc.is_null() {
        // SAFETY: PE-supplied Win64 function pointer; args match WndProc contract.
        unsafe { call_win64_wndproc(wnd_proc, hwnd as u64, msg, w_param as u64, l_param) }
    } else {
        def_window_proc_w_impl(hwnd, msg, w_param, l_param)
    }
}

fn window_size(hwnd: HWND) -> (u32, u32) {
    STATE.with(|s| {
        s.borrow()
            .windows
            .iter()
            .find(|(h, _)| *h == hwnd)
            .map(|(_, w)| (w.width, w.height))
            .unwrap_or((0, 0))
    })
}

fn window_title(hwnd: HWND) -> String {
    STATE.with(|s| {
        s.borrow()
            .windows
            .iter()
            .find(|(h, _)| *h == hwnd)
            .map(|(_, w)| w.title.clone())
            .unwrap_or_default()
    })
}

fn update_size(hwnd: HWND, cx: u32, cy: u32) -> c_int {
    STATE.with(|s| {
        if let Some((_, w)) = s.borrow_mut().windows.iter_mut().find(|(h, _)| *h == hwnd) {
            w.width = cx;
            w.height = cy;
            1
        } else {
            0
        }
    })
}

/// Drain one event from the host window (if any) and translate it to a `MSG`.
fn poll_host_event() -> Option<Msg> {
    // We poll the first window that owns a real host window. `wsi::Window` is not `Send`
    // and must be driven from the thread that owns it, so the whole table is thread-local.
    let hwnd = STATE.with(|s| {
        s.borrow()
            .windows
            .iter()
            .find(|(_, w)| w.window.is_some())
            .map(|(h, _)| *h)
    })?;
    // Now poll that window's event queue. We re-borrow mutably to reach the Window.
    let ev = STATE.with(|s| {
        let mut st = s.borrow_mut();
        let entry = st.windows.iter_mut().find(|(h, _)| *h == hwnd)?;
        let win = entry.1.window.as_mut()?;
        win.poll_event().ok().flatten()
    })?;
    Some(translate_event_to_msg(hwnd, ev))
}

/// Translate a `wsi::WindowEvent` into a Win32 `MSG`.
fn translate_event_to_msg(hwnd: HWND, ev: nigg_wsi::WindowEvent) -> Msg {
    use nigg_wsi::WindowEvent as E;
    let (message, w, l) = match ev {
        E::Resize { width, height } => {
            update_size(hwnd, width, height);
            (
                WM_SIZE,
                0,
                ((width & 0xFFFF) | ((height & 0xFFFF) << 16)) as isize,
            )
        }
        E::Close => (WM_CLOSE, 0, 0),
        E::Key { code, pressed } => {
            if pressed {
                (WM_KEYDOWN, code as usize, 0)
            } else {
                (WM_KEYUP, code as usize, 0)
            }
        }
        E::MouseMove { x, y } => (
            WM_MOUSEMOVE,
            0,
            ((x & 0xFFFF) as isize) | ((y & 0xFFFF) as isize) << 16,
        ),
        E::MouseButton { button, pressed } => {
            let mk = (1u16 << (button as u8)) as usize;
            if pressed {
                (WM_LBUTTONDOWN, mk, 0)
            } else {
                (WM_LBUTTONUP, mk, 0)
            }
        }
    };
    Msg {
        hwnd,
        message,
        w_param: w,
        l_param: l,
        time: 0,
        pt: Point::default(),
    }
}

/// Decode a NUL-terminated UTF-16 (`LPCWSTR`) into a Rust `String`. Handles null and
/// empty strings.
fn widestring_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut units = Vec::new();
    let mut i = 0usize;
    loop {
        // SAFETY: the guest provides a NUL-terminated wide string; we read one u16 at a
        // time and stop at the NUL.
        let unit = unsafe { *ptr.add(i) };
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 1;
    }
    String::from_utf16_lossy(&units)
}

// ---------------------------------------------------------------------------
// Exports for the PE loader
// ---------------------------------------------------------------------------

/// The function-pointer type matching `pe-loader`'s `ImplTable`.
pub type FnPtr = *const c_void;

/// Metadata for a single user32 export, used by the PE loader to build the ABI thunk for
/// the import. The loader needs the argument count (to size the Win64->SysV trampoline).
/// No user32 function diverges, so `noreturn` is always false.
#[derive(Clone, Copy)]
pub struct ExportSpec {
    pub dll: &'static str,
    pub sym: &'static str,
    pub ptr: FnPtr,
    pub n_args: u8,
    pub noreturn: bool,
}

/// The full list of user32 exports with the metadata the PE loader needs to build ABI
/// thunks. `CreateWindowExW` takes 12 args — the loader's thunk layer must support
/// more than 8 stack args (it does after the M3-integration extension). Callers that
/// only need `(dll, sym, ptr)` triples should use [`user32_imports`] instead.
pub fn user32_export_specs() -> Vec<ExportSpec> {
    macro_rules! u {
        ($sym:literal, $f:expr, $n:literal) => {
            ExportSpec {
                dll: "user32.dll",
                sym: $sym,
                ptr: $f as FnPtr,
                n_args: $n,
                noreturn: false,
            }
        };
    }
    vec![
        u!("RegisterClassExW", register_class_ex_w, 1),
        u!("UnregisterClassW", unregister_class_w, 2),
        u!("CreateWindowExW", create_window_ex_w, 12),
        u!("DestroyWindow", destroy_window, 1),
        u!("ShowWindow", show_window, 2),
        u!("UpdateWindow", update_window, 1),
        u!("GetClientRect", get_client_rect, 2),
        u!("GetWindowRect", get_window_rect, 2),
        u!("SetWindowPos", set_window_pos, 7),
        u!("MoveWindow", move_window, 6),
        u!("GetWindowTextW", get_window_text_w, 3),
        u!("SetWindowTextW", set_window_text_w, 2),
        u!("GetMessageW", get_message_w, 4),
        u!("PeekMessageW", peek_message_w, 5),
        u!("TranslateMessage", translate_message, 1),
        u!("DispatchMessageW", dispatch_message_w, 1),
        u!("PostQuitMessage", post_quit_message, 1),
        u!("PostMessageW", post_message_w, 4),
        u!("SendMessageW", send_message_w, 4),
        u!("DefWindowProcW", def_window_proc_w, 4),
        u!("GetParent", get_parent, 1),
        u!("SetParent", set_parent, 2),
        // --- additional stubs real PEs (notepad.exe) import ---
        u!("GetSystemMetrics", get_system_metrics, 1),
        u!("GetDesktopWindow", get_desktop_window, 0),
        u!("GetMenu", get_menu, 1),
        u!("GetWindowTextLengthW", get_window_text_length_w, 1),
        u!("GetWindowPlacement", get_window_placement, 2),
        u!("GetDlgItem", get_dlg_item, 2),
        u!("GetDlgItemTextW", get_dlg_item_text_w, 4),
        u!("GetDlgItemInt", get_dlg_item_int, 4),
        u!("SetDlgItemTextW", set_dlg_item_text_w, 3),
        u!("SetDlgItemInt", set_dlg_item_int, 4),
        u!("SetActiveWindow", set_active_window, 1),
        u!("SetFocus", set_focus, 1),
        u!("EnableMenuItem", enable_menu_item, 3),
        u!("CheckMenuItem", check_menu_item, 3),
        u!("MessageBoxW", message_box_w, 4),
        u!("LoadIconW", load_icon_w, 2),
        u!("LoadCursorW", load_cursor_w, 2),
        u!("LoadImageW", load_image_w, 6),
        u!("LoadStringW", load_string_w, 4),
        u!("LoadAcceleratorsW", load_accelerators_w, 2),
        u!("TranslateAcceleratorW", translate_accelerator_w, 3),
        u!("RegisterWindowMessageW", register_window_message_w, 1),
        u!("IsDialogMessageW", is_dialog_message_w, 2),
        u!(
            "IsClipboardFormatAvailable",
            is_clipboard_format_available,
            1
        ),
        u!("InvalidateRect", invalidate_rect, 3),
        u!("GetDpiForWindow", get_dpi_for_window, 1),
        u!("GetMonitorInfoW", get_monitor_info_w, 2),
        u!("MonitorFromRect", monitor_from_rect, 2),
        u!("DialogBoxParamW", dialog_box_param_w, 5),
        u!("EndDialog", end_dialog, 2),
        u!("WinHelpW", win_help_w, 4),
        u!("wsprintfW", wsprintf_w, 2),
    ]
}

/// The user32 export table the PE loader registers (without arg-count metadata). Prefer
/// [`user32_export_specs`] when the loader needs argument counts for the ABI thunk.
pub fn user32_imports() -> Vec<(&'static str, &'static str, FnPtr)> {
    user32_export_specs()
        .into_iter()
        .map(|e| (e.dll, e.sym, e.ptr))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests (headless-safe)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user32_imports_nonempty_and_correct_dll() {
        let imports = user32_imports();
        assert!(!imports.is_empty());
        assert!(imports.iter().all(|(dll, _, _)| *dll == "user32.dll"));
        assert!(imports.iter().any(|(_, sym, _)| *sym == "CreateWindowExW"));
        assert!(imports.iter().any(|(_, sym, _)| *sym == "GetMessageW"));
        assert!(imports.iter().any(|(_, sym, _)| *sym == "DispatchMessageW"));
        assert!(imports.iter().all(|(_, _, p)| !p.is_null()));
    }

    #[test]
    fn additional_stubs_are_registered() {
        // The no-op stubs notepad.exe imports must resolve (otherwise the loader falls back to
        // the soft-stub trap). Verify each is present in the export spec list.
        let specs = user32_export_specs();
        let names: Vec<&str> = specs.iter().map(|e| e.sym).collect();
        for required in [
            "GetSystemMetrics",
            "GetDesktopWindow",
            "GetMenu",
            "GetWindowTextLengthW",
            "GetWindowPlacement",
            "GetDlgItem",
            "GetDlgItemTextW",
            "GetDlgItemInt",
            "SetDlgItemTextW",
            "SetDlgItemInt",
            "SetActiveWindow",
            "SetFocus",
            "EnableMenuItem",
            "CheckMenuItem",
            "MessageBoxW",
            "LoadIconW",
            "LoadCursorW",
            "LoadImageW",
            "LoadStringW",
            "LoadAcceleratorsW",
            "TranslateAcceleratorW",
            "RegisterWindowMessageW",
            "IsDialogMessageW",
            "IsClipboardFormatAvailable",
            "InvalidateRect",
            "GetDpiForWindow",
            "GetMonitorInfoW",
            "MonitorFromRect",
            "DialogBoxParamW",
            "EndDialog",
            "WinHelpW",
            "wsprintfW",
        ] {
            assert!(
                names.contains(&required),
                "user32 export {required} missing from user32_export_specs"
            );
        }
    }

    #[test]
    fn get_system_metrics_returns_screen_defaults() {
        assert_eq!(get_system_metrics(0), 640); // SM_CXSCREEN
        assert_eq!(get_system_metrics(1), 480); // SM_CYSCREEN
        assert_eq!(get_system_metrics(999), 0); // unknown index
    }

    #[test]
    fn desktop_window_and_dpi_stubs() {
        assert!(!get_desktop_window().is_null());
        assert_eq!(get_dpi_for_window(std::ptr::null_mut()), 96);
        assert!(!monitor_from_rect(std::ptr::null(), 0).is_null());
        assert_eq!(
            message_box_w(std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), 0),
            1
        );
        assert_eq!(register_window_message_w(std::ptr::null()), 0x8000);
    }

    #[test]
    fn get_window_placement_preserves_length() {
        let mut wp = WindowPlacement {
            length: 44,
            flags: 99,
            show_cmd: 99,
            pt_min_position: Point { x: 1, y: 2 },
            pt_max_position: Point { x: 3, y: 4 },
            rc_normal_position: Rect {
                left: 1,
                top: 2,
                right: 3,
                bottom: 4,
            },
        };
        assert_eq!(
            get_window_placement(std::ptr::null_mut(), &mut wp as *mut WindowPlacement),
            1
        );
        assert_eq!(wp.length, 44, "length field must be preserved");
        assert_eq!(wp.flags, 0);
        assert_eq!(wp.show_cmd, 0);
        assert_eq!(wp.rc_normal_position, Rect::default());
        // Null pointer must return FALSE without writing.
        assert_eq!(
            get_window_placement(std::ptr::null_mut(), std::ptr::null_mut()),
            0
        );
    }

    #[test]
    fn get_monitor_info_fills_screen_rect() {
        let mut info = MonitorInfo {
            cb_size: 40,
            rc_monitor: Rect::default(),
            rc_work: Rect::default(),
            dw_flags: 0,
        };
        assert_eq!(
            get_monitor_info_w(std::ptr::null_mut(), &mut info as *mut MonitorInfo),
            1
        );
        assert_eq!(
            info.rc_monitor,
            Rect {
                left: 0,
                top: 0,
                right: 640,
                bottom: 480
            }
        );
        assert_eq!(info.rc_work, info.rc_monitor);
        assert_eq!(info.cb_size, 40, "cb_size must be preserved");
    }

    #[test]
    fn register_and_lookup_class() {
        // A class name as a NUL-terminated wide string on the stack.
        let name: Vec<u16> = "TestWnd\0".encode_utf16().collect();
        let wcx = WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style: 0,
            lpfn_wnd_proc: std::ptr::null(),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: std::ptr::null_mut(),
            h_icon: std::ptr::null_mut(),
            h_cursor: std::ptr::null_mut(),
            hbr_background: std::ptr::null_mut(),
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: name.as_ptr(),
            h_icon_sm: std::ptr::null_mut(),
        };
        let atom = register_class_ex_w(&wcx);
        assert_ne!(atom, 0, "RegisterClassExW must return a nonzero atom");
        let found = find_class_by_name("TestWnd");
        assert_eq!(found, Some(atom));
        assert_eq!(unregister_class_w(name.as_ptr(), std::ptr::null_mut()), 1);
    }

    /// Simulate the core message-loop flow without any PE code or display: register a
    /// class (with a null wndproc so DispatchMessageW defers to DefWindowProcW), create
    /// a window (degrades to headless), post WM_CLOSE, run the loop, and assert it
    /// exits via WM_QUIT.

    #[test]
    fn message_loop_simulated_close() {
        // Register a class pointing at our Rust wndproc (treated as a SysV fn; the thunk
        // would translate in a real PE, but here we call dispatch's DefWindowProc path
        // by setting wnd_proc to null so DispatchMessageW defers to DefWindowProcW).
        let name: Vec<u16> = "LoopWnd\0".encode_utf16().collect();
        let wcx = WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style: 0,
            lpfn_wnd_proc: std::ptr::null(), // DefWindowProc path
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: std::ptr::null_mut(),
            h_icon: std::ptr::null_mut(),
            h_cursor: std::ptr::null_mut(),
            hbr_background: std::ptr::null_mut(),
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: name.as_ptr(),
            h_icon_sm: std::ptr::null_mut(),
        };
        let atom = register_class_ex_w(&wcx);
        assert_ne!(atom, 0);

        let hwnd = create_window_ex_w(
            0,
            name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            100,
            100,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert!(!hwnd.is_null());

        // Post a WM_CLOSE; DefWindowProcW(WM_CLOSE) calls DestroyWindow, which posts
        // WM_DESTROY; DefWindowProcW(WM_DESTROY) calls PostQuitMessage(0).
        post_message_w(hwnd, WM_CLOSE, 0, 0);

        // Run the message loop.
        let mut msg = Msg::default();
        loop {
            let r = get_message_w(&mut msg as *mut Msg, std::ptr::null_mut(), 0, 0);
            if r == 0 {
                break; // WM_QUIT
            }
            translate_message(&msg as *const Msg);
            dispatch_message_w(&msg as *const Msg);
        }
        // The loop exited (GetMessage returned 0 for WM_QUIT).
        assert_eq!(
            get_message_w(&mut msg as *mut Msg, std::ptr::null_mut(), 0, 0),
            0
        );

        // Cleanup: remove the class so it doesn't leak into other tests on the same
        // thread. The window entry was already removed by DestroyWindow.
        unregister_class_w(name.as_ptr(), std::ptr::null_mut());
    }

    #[test]
    fn post_and_peek_message() {
        let hwnd = make_hwnd();
        post_message_internal(hwnd, 0x1234, 56, 78);
        let mut msg = Msg::default();
        let got = peek_message_w(&mut msg as *mut Msg, std::ptr::null_mut(), 0, 0xFFFF, 0);
        assert_eq!(got, 1);
        assert_eq!(msg.message, 0x1234);
        assert_eq!(msg.w_param, 56);
        assert_eq!(msg.l_param, 78);
    }

    #[test]
    fn get_client_rect_reflects_cached_size() {
        let name: Vec<u16> = "RectWnd\0".encode_utf16().collect();
        let wcx = WndClassEx {
            cb_size: core::mem::size_of::<WndClassEx>() as u32,
            style: 0,
            lpfn_wnd_proc: std::ptr::null(),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: std::ptr::null_mut(),
            h_icon: std::ptr::null_mut(),
            h_cursor: std::ptr::null_mut(),
            hbr_background: std::ptr::null_mut(),
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: name.as_ptr(),
            h_icon_sm: std::ptr::null_mut(),
        };
        let _atom = register_class_ex_w(&wcx);
        let hwnd = create_window_ex_w(
            0,
            name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            320,
            200,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let mut rect = Rect::default();
        assert_eq!(get_client_rect(hwnd, &mut rect as *mut Rect), 1);
        assert_eq!(rect.right, 320);
        assert_eq!(rect.bottom, 200);
        unregister_class_w(name.as_ptr(), std::ptr::null_mut());
    }
}
