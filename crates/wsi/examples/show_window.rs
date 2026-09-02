//! Open a 640x480 window titled "nigg" and print events until the window is closed.
//!
//! Headless-safe: if there is no display server reachable (`$DISPLAY` unset or the X
//! server refusing connections), the example prints a message and exits 0 instead of
//! panicking, so it can run in CI without a virtual framebuffer.

use std::time::{Duration, Instant};

use nigg_wsi::{Window, WindowEvent};

fn main() {
    // A 3s ceiling so the example never blocks a CI runner forever.
    let deadline = Instant::now() + Duration::from_secs(3);

    let mut window = match Window::new("nigg", 640, 480) {
        Ok(w) => w,
        Err(e) => {
            println!("[wsi example] no display server available, skipping: {e}");
            return;
        }
    };

    let (w, h) = window.size();
    println!("[wsi example] opened window {}x{}", w, h);

    let mut closed = false;
    while !closed && Instant::now() < deadline {
        while let Ok(Some(event)) = window.poll_event() {
            match event {
                WindowEvent::Resize { width, height } => {
                    println!("[wsi example] resize {width}x{height}");
                }
                WindowEvent::Close => {
                    println!("[wsi example] close");
                    closed = true;
                }
                WindowEvent::Key { code, pressed } => {
                    println!(
                        "[wsi example] key {code} {}",
                        if pressed { "down" } else { "up" }
                    );
                }
                WindowEvent::MouseMove { x, y } => {
                    println!("[wsi example] mouse move ({x}, {y})");
                }
                WindowEvent::MouseButton { button, pressed } => {
                    println!(
                        "[wsi example] mouse button {:?} {}",
                        button,
                        if pressed { "down" } else { "up" }
                    );
                }
            }
        }
        // Drain the queue at a gentle pace; the example is event-driven, not busy.
        std::thread::sleep(Duration::from_millis(16));
    }

    println!("[wsi example] done");
}
