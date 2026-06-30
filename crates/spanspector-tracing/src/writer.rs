//! The [`RecordWriter`] sink abstraction the layer writes serialized records to.
//!
//! Decoupling the layer from a concrete `Write` lets the same layer drive either
//! a synchronous, inline sink (an `Arc<Mutex<W>>`, ordered and simple) or the
//! non-blocking, background-thread sink in [`crate::nonblocking`] without the
//! layer knowing which.

use std::io::Write;
use std::sync::{Arc, Mutex};

/// A sink for already-serialized `spanspector-trace/v1` JSONL lines.
///
/// Implementations receive one complete line (terminated by `\n`) per call and
/// must be cheap and panic-free: the layer calls [`write_line`] from inside
/// `tracing` callbacks on arbitrary threads, so a sink that fails should drop the
/// line (and ideally count it) rather than block indefinitely or unwind.
///
/// [`write_line`]: RecordWriter::write_line
pub trait RecordWriter: Send + Sync + 'static {
    /// Write one serialized JSONL line, best-effort.
    fn write_line(&self, line: &str);
}

/// A synchronous, ordered sink: every line is written inline under the mutex.
///
/// Simple and correct for tests, CLIs, and low-volume paths. Because the write
/// happens while the lock is held, this **can block the calling thread** on a
/// slow sink — do not use it on async request, consensus, or recovery paths;
/// reach for [`crate::NonBlockingWriter`] there instead.
impl<W: Write + Send + 'static> RecordWriter for Arc<Mutex<W>> {
    fn write_line(&self, line: &str) {
        if let Ok(mut writer) = self.lock() {
            let _ = writer.write_all(line.as_bytes());
        }
    }
}
