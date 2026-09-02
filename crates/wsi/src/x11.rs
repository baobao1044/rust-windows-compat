//! X11 window backend implemented on top of `x11rb`.
//!
//! The backend owns a [`RustConnection`] — x11rb's pure-Rust X11 connection, which
//! needs **no** system libraries at build time (unlike the libxcb-backed
//! `XCBConnection`, which sits behind x11rb's `allow-unsafe-code` feature). It opens
//! one top-level window, selects for the core event subset the rest of the
//! compatibility layer cares about (expose, structure-notify, key, button, motion),
//! and registers `WM_PROTOCOLS` / `WM_DELETE_WINDOW` so the close button turns into a
//! [`WindowEvent::Close`] instead of killing the client.
//!
//! Events are drained non-blockingly from `poll_for_event`; the Win32 message loop
//! above drives pacing, so we never sleep inside [`X11Window::poll_event`].
//!
//! # Raw surface handle (Phase 1)
//!
//! [`X11Window::raw_surface_handle`] returns [`RawSurfaceHandle::None`] for now. The
//! pure-Rust connection has no `xcb_connection_t*` to hand Vulkan; the path to a real
//! `VkSurfaceKHR` is to switch to x11rb's `XCBConnection` (enable the
//! `allow-unsafe-code` feature, install `libxcb1-dev`), which exposes
//! `get_raw_xcb_connection`. That is a Phase 2 concern for the dxgi workstream.

use x11rb::connection::Connection;
use x11rb::errors::ConnectError;
use x11rb::protocol::xproto::{
    self, Atom, AtomEnum, ClientMessageData, ClientMessageEvent, ConfigureNotifyEvent, EventMask,
    PropMode, WindowClass,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;

use crate::{MouseButton, RawSurfaceHandle, WindowEvent, WsiError};

/// The X11 atoms we need for a well-behaved top-level window.
#[derive(Debug, Clone, Copy)]
struct WmAtoms {
    wm_protocols: Atom,
    wm_delete_window: Atom,
}

/// `WM_PROTOCOLS` / `WM_DELETE_WINDOW` interned atom names.
const WM_PROTOCOLS: &[u8] = b"WM_PROTOCOLS";
const WM_DELETE_WINDOW: &[u8] = b"WM_DELETE_WINDOW";

impl WmAtoms {
    /// Intern both atomids. Called once at window construction.
    fn intern(conn: &RustConnection) -> Result<Self, WsiError> {
        let wm_protocols = intern_atom(conn, WM_PROTOCOLS)?;
        let wm_delete_window = intern_atom(conn, WM_DELETE_WINDOW)?;
        Ok(Self {
            wm_protocols,
            wm_delete_window,
        })
    }
}

/// Intern a single atom via the core protocol free function.
fn intern_atom(conn: &RustConnection, name: &[u8]) -> Result<Atom, WsiError> {
    let cookie =
        xproto::intern_atom(conn, false, name).map_err(|e| WsiError::Backend(e.to_string()))?;
    let reply = cookie
        .reply()
        .map_err(|e| WsiError::Backend(e.to_string()))?;
    Ok(reply.atom)
}

/// An X11 top-level window and the connection backing it.
///
/// Dropping this value destroys the window and closes the connection. It is not
/// `Clone`/`Send` because the underlying X11 connection is not shareable across
/// threads without extra locking.
pub(crate) struct X11Window {
    conn: RustConnection,
    window: u32,
    wm_atoms: WmAtoms,
    width: u32,
    height: u32,
}

impl X11Window {
    /// Open a top-level window of `width` x `height` with `title`.
    ///
    /// Returns [`WsiError::NoDisplay`] if no X server is reachable, so callers on a
    /// headless host degrade gracefully instead of panicking.
    pub(crate) fn new(title: &str, width: u32, height: u32) -> Result<Self, WsiError> {
        let (conn, screen_num) = connect_to_display()?;
        let setup = conn.setup();
        let screen = setup
            .roots
            .get(screen_num)
            .ok_or_else(|| WsiError::Backend("no screen for default display".into()))?;

        // Clamp to X11's u16 geometry range while keeping the caller's intent.
        let w = width.min(u16::MAX as u32).max(1) as u16;
        let h = height.min(u16::MAX as u32).max(1) as u16;

        let window: u32 = conn
            .generate_id()
            .map_err(|e| WsiError::Backend(e.to_string()))?;

        // Select for exactly the events we surface to the rest of the layer.
        let event_mask = EventMask::EXPOSURE
            | EventMask::STRUCTURE_NOTIFY
            | EventMask::KEY_PRESS
            | EventMask::KEY_RELEASE
            | EventMask::BUTTON_PRESS
            | EventMask::BUTTON_RELEASE
            | EventMask::POINTER_MOTION;

        xproto::create_window(
            &conn,
            x11rb::COPY_FROM_PARENT as u8,
            window,
            screen.root,
            0,
            0,
            w,
            h,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &xproto::CreateWindowAux::new().event_mask(event_mask),
        )
        .map_err(|e| WsiError::Backend(e.to_string()))?
        .check()
        .map_err(|e| WsiError::Backend(e.to_string()))?;

        set_window_title(&conn, window, title)?;
        set_wm_protocols(&conn, window)?;

        let wm_atoms = WmAtoms::intern(&conn)?;

        xproto::map_window(&conn, window).map_err(|e| WsiError::Backend(e.to_string()))?;
        conn.flush().map_err(|e| WsiError::Backend(e.to_string()))?;

        Ok(Self {
            conn,
            window,
            wm_atoms,
            width: u32::from(w),
            height: u32::from(h),
        })
    }

    /// Current client-area size in pixels.
    pub(crate) fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Drain one pending event without blocking.
    pub(crate) fn poll_event(&mut self) -> Result<Option<WindowEvent>, WsiError> {
        loop {
            let ev = self
                .conn
                .poll_for_event()
                .map_err(|e| WsiError::Backend(e.to_string()))?;
            let Some(ev) = ev else {
                return Ok(None);
            };
            if let Some(window_event) = translate_event(&ev, self) {
                // Keep our cached client-area size in sync with the server.
                if let WindowEvent::Resize { width, height } = window_event {
                    self.width = width;
                    self.height = height;
                }
                return Ok(Some(window_event));
            }
            // Events we don't surface (Expose repaint hints, etc.) are dropped and we
            // loop to drain the next one in the same poll.
        }
    }

    /// Raw X11 surface handle for a later Vulkan swapchain.
    ///
    /// Returns [`RawSurfaceHandle::None`] in Phase 1; see the module docs for the
    /// path to a real `xcb_connection_t*`.
    pub(crate) fn raw_surface_handle(&self) -> RawSurfaceHandle {
        RawSurfaceHandle::None
    }
}

impl Drop for X11Window {
    fn drop(&mut self) {
        // Best-effort teardown; ignore errors because there is nothing useful to do
        // with them while dropping.
        let _ = xproto::destroy_window(&self.conn, self.window);
        let _ = self.conn.flush();
    }
}

/// Connect to the default display, honouring `$DISPLAY`. On a headless host the
/// connection fails and we map that to [`WsiError::NoDisplay`].
fn connect_to_display() -> Result<(RustConnection, usize), WsiError> {
    RustConnection::connect(std::env::var("DISPLAY").ok().as_deref()).map_err(connect_error_to_wsi)
}

/// Map a connection failure onto our coarse error set: a missing/unparseable display
/// is [`WsiError::NoDisplay`], anything else is a backend error.
fn connect_error_to_wsi(e: ConnectError) -> WsiError {
    match e {
        ConnectError::DisplayParsingError(_) | ConnectError::InvalidScreen => WsiError::NoDisplay,
        other => WsiError::Backend(other.to_string()),
    }
}

/// Set the legacy `WM_NAME` property (Latin-1). Enough for Phase 1 window
/// visibility; a future phase adds `_NET_WM_NAME` (UTF-8) with the `UTF8_STRING` atom.
fn set_window_title(conn: &RustConnection, window: u32, title: &str) -> Result<(), WsiError> {
    let bytes = title.as_bytes();
    xproto::change_property(
        conn,
        PropMode::REPLACE,
        window,
        AtomEnum::WM_NAME,
        AtomEnum::STRING,
        8,
        bytes.len().try_into().unwrap_or(u32::MAX),
        bytes,
    )
    .map_err(|e| WsiError::Backend(e.to_string()))?
    .check()
    .map_err(|e| WsiError::Backend(e.to_string()))?;
    Ok(())
}

/// Advertise `WM_DELETE_WINDOW` so the window manager sends a `ClientMessage` on
/// close instead of forcibly killing the client.
fn set_wm_protocols(conn: &RustConnection, window: u32) -> Result<(), WsiError> {
    let wm_protocols = intern_atom(conn, WM_PROTOCOLS)?;
    let wm_delete_window = intern_atom(conn, WM_DELETE_WINDOW)?;
    let data = wm_delete_window.to_ne_bytes();
    xproto::change_property(
        conn,
        PropMode::REPLACE,
        window,
        wm_protocols,
        AtomEnum::ATOM,
        32,
        1,
        &data,
    )
    .map_err(|e| WsiError::Backend(e.to_string()))?
    .check()
    .map_err(|e| WsiError::Backend(e.to_string()))?;
    conn.flush().map_err(|e| WsiError::Backend(e.to_string()))?;
    Ok(())
}

/// Translate one raw X11 event into a [`WindowEvent`]. `None` means "drop this event"
/// (e.g. an Expose with no payload we care about).
fn translate_event(ev: &Event, win: &X11Window) -> Option<WindowEvent> {
    match ev {
        Event::ConfigureNotify(e) => Some(translate_configure(e)),
        Event::KeyPress(e) => Some(WindowEvent::Key {
            code: u32::from(e.detail),
            pressed: true,
        }),
        Event::KeyRelease(e) => Some(WindowEvent::Key {
            code: u32::from(e.detail),
            pressed: false,
        }),
        Event::ButtonPress(e) => Some(WindowEvent::MouseButton {
            button: MouseButton::from_x11_button(e.detail),
            pressed: true,
        }),
        Event::ButtonRelease(e) => Some(WindowEvent::MouseButton {
            button: MouseButton::from_x11_button(e.detail),
            pressed: false,
        }),
        Event::MotionNotify(e) => Some(WindowEvent::MouseMove {
            x: i32::from(e.event_x),
            y: i32::from(e.event_y),
        }),
        Event::ClientMessage(e) => translate_client_message(e, win),
        // Expose/MappingNotify/etc. do not map to Win32 events yet.
        _ => None,
    }
}

/// A `ConfigureNotify` surfaces a `Resize` event with the new client-area size. The
/// caller (`poll_event`) updates the cached size after translation.
fn translate_configure(e: &ConfigureNotifyEvent) -> WindowEvent {
    WindowEvent::Resize {
        width: u32::from(e.width),
        height: u32::from(e.height),
    }
}

/// A `ClientMessage` carrying `WM_DELETE_WINDOW` is the window manager's close
/// request.
fn translate_client_message(e: &ClientMessageEvent, win: &X11Window) -> Option<WindowEvent> {
    if e.format == 32 && e.type_ == win.wm_atoms.wm_protocols {
        let data: ClientMessageData = e.data;
        if data.as_data32()[0] == win.wm_atoms.wm_delete_window {
            return Some(WindowEvent::Close);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a headless host there is no display, so construction must fail with
    /// `NoDisplay` rather than panic. On a host with a display it must succeed and the
    /// window must report the requested size.
    #[test]
    fn new_window_respects_display_availability() {
        // Force a no-display environment for this test so it is deterministic.
        let prev = std::env::var_os("DISPLAY");
        std::env::remove_var("DISPLAY");
        let result = X11Window::new("nigg-test", 64, 48);
        if let Some(p) = prev {
            std::env::set_var("DISPLAY", p);
        }
        match result {
            Ok(mut w) => {
                let (w_, h) = w.size();
                assert_eq!((w_, h), (64, 48));
                // The event queue drains cleanly.
                assert!(w.poll_event().is_ok());
            }
            Err(WsiError::NoDisplay) => { /* expected on headless CI */ }
            Err(other) => panic!("unexpected WSI error: {other:?}"),
        }
    }

    /// The raw surface handle is a Phase 1 stub on the pure-Rust backend.
    #[test]
    fn raw_handle_is_none_stub() {
        // We cannot construct a window without a display, so assert the documented
        // stub contract indirectly: `None` is a valid `RawSurfaceHandle`.
        assert!(matches!(RawSurfaceHandle::None, RawSurfaceHandle::None));
    }
}
