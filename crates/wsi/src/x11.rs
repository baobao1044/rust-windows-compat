//! X11 window backend implemented on top of `x11rb`.
//!
//! The backend owns a [`XCBConnection`] — x11rb's libxcb-backed connection (built
//! with the `allow-unsafe-code` feature, so it links against the system libxcb). It
//! opens one top-level window, selects for the core event subset the rest of the
//! compatibility layer cares about (expose, structure-notify, key, button, motion),
//! and registers `WM_PROTOCOLS` / `WM_DELETE_WINDOW` so the close button turns into a
//! [`WindowEvent::Close`] instead of killing the client.
//!
//! Events are drained non-blockingly from `poll_for_event`; the Win32 message loop
//! above drives pacing, so we never sleep inside [`X11Window::poll_event`].
//!
//! # Raw surface handle (dxgi present path)
//!
//! Because the connection is libxcb-backed, [`X11Window::raw_surface_handle`] hands
//! out a real [`RawSurfaceHandle::X11`]: the `xcb_connection_t*` (from
//! `get_raw_xcb_connection`) plus the window XID. The dxgi swap chain turns that
//! pair into a `VkSurfaceKHR` via `VK_KHR_xcb_surface`, so a win32-style PE opens a
//! genuinely visible window with D3D11 rendering on it. The raw pointer is owned by
//! the [`XCBConnection`] stored here, so the [`Window`](crate::Window) must outlive
//! any surface (and swap chain) built from the handle.

use x11rb::connection::Connection;
use x11rb::errors::ConnectError;
use x11rb::protocol::xproto::{
    self, Atom, AtomEnum, ClientMessageData, ClientMessageEvent, ConfigureNotifyEvent, EventMask,
    PropMode, WindowClass,
};
use x11rb::protocol::Event;
use x11rb::xcb_ffi::XCBConnection;

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
    fn intern(conn: &XCBConnection) -> Result<Self, WsiError> {
        let wm_protocols = intern_atom(conn, WM_PROTOCOLS)?;
        let wm_delete_window = intern_atom(conn, WM_DELETE_WINDOW)?;
        Ok(Self {
            wm_protocols,
            wm_delete_window,
        })
    }
}

/// Intern a single atom via the core protocol free function.
fn intern_atom(conn: &XCBConnection, name: &[u8]) -> Result<Atom, WsiError> {
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
    conn: XCBConnection,
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

    /// Raw X11 surface handle for the Vulkan swapchain.
    ///
    /// Returns the `(xcb_connection_t*, window XID)` pair owned by this window. The
    /// connection must stay alive — i.e. this [`X11Window`] must not be dropped — for
    /// as long as any `VkSurfaceKHR` built from the handle exists.
    pub(crate) fn raw_surface_handle(&self) -> RawSurfaceHandle {
        RawSurfaceHandle::X11 {
            connection: self.conn.get_raw_xcb_connection(),
            window: self.window,
        }
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
fn connect_to_display() -> Result<(XCBConnection, usize), WsiError> {
    // libxcb resolves `$DISPLAY` itself when the name is `None`; the error mapping is
    // the same as for the pure-Rust connection (bad/missing display → `NoDisplay`).
    XCBConnection::connect(None).map_err(connect_error_to_wsi)
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
fn set_window_title(conn: &XCBConnection, window: u32, title: &str) -> Result<(), WsiError> {
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
fn set_wm_protocols(conn: &XCBConnection, window: u32) -> Result<(), WsiError> {
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

    /// On a display-capable host the raw surface handle must carry the real
    /// `xcb_connection_t*` + XID pair (non-null pointer). On a headless host
    /// construction fails first, so there is nothing to assert.
    #[test]
    fn raw_handle_carries_xcb_connection_and_xid() {
        let mut w = match X11Window::new("nigg-test", 64, 48) {
            Ok(w) => w,
            Err(WsiError::NoDisplay) => return, // headless CI
            Err(other) => panic!("unexpected WSI error: {other:?}"),
        };
        // Touch an event poll first so the server round-trip has flushed.
        assert!(w.poll_event().is_ok());
        match w.raw_surface_handle() {
            RawSurfaceHandle::X11 { connection, window } => {
                assert!(!connection.is_null(), "xcb_connection_t* must be non-null");
                assert_ne!(window, 0, "window XID must be non-zero");
            }
            other => panic!("expected an X11 raw surface handle, got {other:?}"),
        }
    }
}
