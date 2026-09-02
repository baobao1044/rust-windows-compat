//! Print input events from all sources for ~3 seconds, then exit.
//!
//! Headless-safe: if no evdev devices are openable (no `/dev/input`, permission
//! denied) and no gamepads are connected, the example prints a message and exits 0
//! instead of blocking or panicking, so it can run in CI without input devices.

use std::time::{Duration, Instant};

use nigg_input::InputContext;

fn main() {
    let deadline = Instant::now() + Duration::from_secs(3);

    let mut ctx = InputContext::new();
    println!("[input example] context created, polling for 3s...");

    let mut count = 0usize;
    while Instant::now() < deadline {
        match ctx.poll() {
            Ok(Some(event)) => {
                println!("[input example] {event:?}");
                count += 1;
            }
            Ok(None) => {
                // No events pending; pace the loop.
                std::thread::sleep(Duration::from_millis(16));
            }
            Err(e) => {
                eprintln!("[input example] poll error: {e}");
                break;
            }
        }
    }

    println!("[input example] done, saw {count} event(s)");
}
