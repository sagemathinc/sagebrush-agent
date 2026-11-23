//! The library's log, kept off stdout (which carries only the one JSON result): warnings and errors go to stderr,
//! bounded, and a cache-write failure is noticed so the result can report `cache_full` (host backup design r3.3 §6: a full cache
//! is a warning, not an abort; read-back still decides success).

use std::{
    io::Write,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use log::{Level, LevelFilter, Log, Metadata, Record};

static CACHE_FULL: AtomicBool = AtomicBool::new(false);
static LINES: AtomicUsize = AtomicUsize::new(0);
/// Lines of library log written to stderr, at most.
const MAX_LINES: usize = 200;

struct Capture;

impl Log for Capture {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        m.level() <= Level::Warn
    }

    fn log(&self, r: &Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let text = r.args().to_string();
        if text.contains("cache backend") {
            CACHE_FULL.store(true, Ordering::Relaxed);
        }
        if LINES.fetch_add(1, Ordering::Relaxed) < MAX_LINES {
            let line: String = text.chars().take(400).collect();
            let _ = writeln!(std::io::stderr(), "[{}] {}", r.level(), line);
        }
    }

    fn flush(&self) {}
}

pub fn init() {
    static LOGGER: Capture = Capture;
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Warn);
    }
}

/// Record that the cache can't be used (an unwritable or full cache directory is noticed before opening, since the
/// library drops an unusable cache silently).
pub fn mark_cache_full() {
    CACHE_FULL.store(true, Ordering::Relaxed);
}

pub fn cache_full() -> bool {
    CACHE_FULL.load(Ordering::Relaxed)
}
