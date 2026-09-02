//! Window-system integration: an X11/Wayland surface for the compatibility layer.
//!
//! Workstream D — host-facing crate. Talks to the Linux display server directly and
//! exposes a small surface/window abstraction that the graphics workstream (dxgi) and
//! the Win32 windowing workstream (user32) build on top of.
//!
//! # Backends
//!
//! - **X11** (feature `x11`, **on by default**): implemented via `x11rb`. Needs
//!   `libxcb1-dev` at build time and a running X server at runtime.
//! - **Wayland** (feature `wayland`, **off by default**): a documented stub. The
//!   real `smithay-client-toolkit` backend is left out of the default build because
//!   it requires `libxkbcommon-dev` / `libwayland-dev`, which are not guaranteed to be
//!   installed on every build host. See [`WaylandWindow`].
//!
//! With the default feature set the crate compiles to a working X11 backend. On a
//! headless host without a display, [`Window::new`] returns an error instead of
//! panicking, so examples and tests stay CI-friendly.

#[cfg(feature = "x11")]
mod x11;

use thiserror::Error;

/// A logical button on a mouse / pointer device.
///
/// Buttons are 1-indexed to match X11 / evdev conventions (1 = left, 2 = middle,
/// 3 = right, 4/5 = wheel up/down).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MouseButton {
    Left = 1,
    Middle = 2,
    Right = 3,
    /// Wheel tilt / extra button 4.
    Other = 4,
}

impl MouseButton {
    /// Build a [`MouseButton`] from an X11/evdev 1-indexed button code.
    ///
    /// Codes outside the known set collapse to [`MouseButton::Other`] so callers do
    /// not have to handle a fallible conversion at every event site.
    pub fn from_x11_button(code: u8) -> Self {
        match code {
            1 => MouseButton::Left,
            2 => MouseButton::Middle,
            3 => MouseButton::Right,
            _ => MouseButton::Other,
        }
    }
}

/// A window-system event surfaced to the rest of the compatibility layer.
///
/// The set is intentionally small — it covers exactly what user32 needs to drive a
/// Win32 message loop and what dxgi needs to react to resizes. Pointer coordinates
/// are in window-relative pixels with the origin at the top-left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEvent {
    /// The client area changed size.
    Resize { width: u32, height: u32 },
    /// The user asked the window to close (WM_DELETE_WINDOW / close button).
    Close,
    /// A keyboard key transition.
    ///
    /// `code` is the raw X11 keycode (offset by 8 to get the Linux evdev keycode).
    Key { code: u32, pressed: bool },
    /// The pointer moved inside the window.
    MouseMove { x: i32, y: i32 },
    /// A mouse button transition.
    MouseButton { button: MouseButton, pressed: bool },
}

/// Opaque handle to a host window surface that a Vulkan swapchain can target.
///
/// Phase 1 returns a small enum that the dxgi workstream can match on later to build
/// a `VkSurfaceKHR` (via `ash`'s platform surface extensions). It does **not** hand
/// out raw pointers directly; those are produced on demand by methods on the
/// concrete backend so that `unsafe` stays local to the backend module.
#[derive(Debug, Clone, Copy)]
pub enum RawSurfaceHandle {
    /// No backend is available (e.g. a stub window).
    None,
    /// X11: the `(connection, window)` pair. `connection` is an `xcb_connection_t*`
    /// obtained from `x11rb`'s `get_raw_xcb_connection`; `window` is the XID. Both
    /// are owned by the [`Window`] that produced this handle and must outlive any
    /// surface created from them.
    #[cfg(feature = "x11")]
    X11 {
        connection: *mut std::ffi::c_void,
        window: u32,
    },
    /// Wayland: `(wl_display*, wl_surface*)`. Phase 1 stub — both are null until the
    /// real Wayland backend lands.
    #[cfg(feature = "wayland")]
    Wayland {
        display: *mut std::ffi::c_void,
        surface: *mut std::ffi::c_void,
    },
}

/// A drawable surface backed by a host window.
///
/// `present` is a stub for now: the dxgi workstream fills it in once a Vulkan
/// swapchain exists. The other methods are the minimum user32 / dxgi need to drive
/// a Win32 window and resize a swapchain.
pub trait Surface {
    /// Fetch the current client-area size, in pixels.
    fn size(&self) -> (u32, u32);

    /// Poll for one pending window event without blocking.
    ///
    /// Returns `Ok(None)` when the event queue is empty. Implementations must never
    /// sleep — the Win32 message loop drives pacing from above.
    fn poll_event(&mut self) -> Result<Option<WindowEvent>, WsiError>;

    /// Return a raw handle the Vulkan swapchain can build a surface from.
    fn raw_surface_handle(&self) -> RawSurfaceHandle;

    /// Present the current back buffer to the window.
    ///
    /// Phase 1 stub: dxgi replaces this with a real Vulkan present once the swapchain
    /// exists. Returning [`WsiError::PresentUnimplemented`] is the contract for "not
    /// yet wired up".
    fn present(&mut self) -> Result<(), WsiError> {
        Err(WsiError::PresentUnimplemented)
    }
}

/// Errors that can come out of the WSI layer.
#[derive(Debug, Error)]
pub enum WsiError {
    /// No display server is reachable (no `DISPLAY`, no Wayland, etc.).
    #[error("no display server available")]
    NoDisplay,
    /// The host window backend returned a low-level error.
    #[error("backend error: {0}")]
    Backend(String),
    /// `present()` was called before the dxgi swapchain was wired up.
    #[error("present is not implemented in this phase")]
    PresentUnimplemented,
}

/// A host window owning one [`Surface`].
///
/// Constructing a [`Window`] opens a real OS window on the active backend. With the
/// default feature set that backend is X11; on a headless host construction fails
/// with [`WsiError::NoDisplay`] instead of panicking, so callers can degrade
/// gracefully.
///
/// [`Window`] owns the backend connection and the window resource; dropping it
/// destroys the window.
pub struct Window {
    #[cfg(feature = "x11")]
    inner: x11::X11Window,
}

impl Window {
    /// Open a new window titled `title` with a client area of `width` x `height`
    /// pixels.
    pub fn new(title: &str, width: u32, height: u32) -> Result<Self, WsiError> {
        let title = if title.is_empty() { "nigg" } else { title };

        #[cfg(feature = "x11")]
        {
            let inner = x11::X11Window::new(title, width, height)?;
            return Ok(Self { inner });
        }

        // No backend compiled in.
        #[allow(unreachable_code)]
        Err(WsiError::NoDisplay)
    }

    /// Current client-area size in pixels.
    pub fn size(&self) -> (u32, u32) {
        #[cfg(feature = "x11")]
        {
            self.inner.size()
        }
        #[cfg(not(feature = "x11"))]
        {
            (0, 0)
        }
    }

    /// Poll for one pending window event without blocking. `Ok(None)` if the queue
    /// is empty.
    pub fn poll_event(&mut self) -> Result<Option<WindowEvent>, WsiError> {
        #[cfg(feature = "x11")]
        {
            self.inner.poll_event()
        }
        #[cfg(not(feature = "x11"))]
        {
            Ok(None)
        }
    }

    /// Raw handle a Vulkan swapchain can build a surface from.
    pub fn raw_surface_handle(&self) -> RawSurfaceHandle {
        #[cfg(feature = "x11")]
        {
            self.inner.raw_surface_handle()
        }
        #[cfg(not(feature = "x11"))]
        {
            RawSurfaceHandle::None
        }
    }

    /// Present the current back buffer. Phase 1 stub; see [`Surface::present`].
    pub fn present(&mut self) -> Result<(), WsiError> {
        Err(WsiError::PresentUnimplemented)
    }
}

/// Wayland window stub.
///
/// The real Wayland backend (xdg_toplevel via `smithay-client-toolkit`) is gated
/// behind the `wayland` feature and not wired up in Phase 1 because
/// `smithay-client-toolkit` needs `libxkbcommon-dev` / `libwayland-dev` system
/// headers. This type exists so that downstream code can be written against a stable
/// name; constructing it always fails with [`WsiError::NoDisplay`] until the backend
/// lands. To enable it: install the system headers, flip `wayland` on, and replace
/// this stub with a real `smithay-client-toolkit` implementation.
#[derive(Debug)]
pub struct WaylandWindow;

impl WaylandWindow {
    /// Always returns [`WsiError::NoDisplay`] in Phase 1.
    pub fn new(_title: &str, _width: u32, _height: u32) -> Result<Self, WsiError> {
        Err(WsiError::NoDisplay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_button_from_x11_known_codes() {
        assert_eq!(MouseButton::from_x11_button(1), MouseButton::Left);
        assert_eq!(MouseButton::from_x11_button(2), MouseButton::Middle);
        assert_eq!(MouseButton::from_x11_button(3), MouseButton::Right);
        assert_eq!(MouseButton::from_x11_button(8), MouseButton::Other);
    }

    #[test]
    fn raw_handle_none_roundtrips() {
        let h = RawSurfaceHandle::None;
        assert!(matches!(h, RawSurfaceHandle::None));
    }

    #[test]
    fn window_event_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<WindowEvent>();
    }
}
