//! A non-blocking [`RecordWriter`] backed by a bounded channel and a background
//! writer thread, plus the [`SpanSpectorGuard`] that flushes and drains it.
//!
//! On a server, evidence must never block a request, consensus, or recovery path
//! on a filesystem write. [`NonBlockingWriter`] serializes nothing inline: it
//! hands each line to a bounded channel and returns immediately. A dedicated
//! thread owns the underlying [`Write`] and drains the channel. When the channel
//! is full, the configured [`Overflow`] policy decides whether to drop the newest
//! record (the default — never block) or to block the caller until space frees.
//!
//! Dropped records and writer errors are counted, and the [`SpanSpectorGuard`]
//! exposes those counts plus `flush()`/`shutdown()` so a process can report or
//! drain evidence deterministically on the way down.

use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, sync_channel};
use std::thread::JoinHandle;

use crate::writer::RecordWriter;

/// Default bounded-channel capacity (records buffered before overflow applies).
pub const DEFAULT_CAPACITY: usize = 8192;

/// What a [`NonBlockingWriter`] does when its bounded channel is full.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Overflow {
    /// Drop the newest record and increment the dropped counter. Never blocks the
    /// calling thread — the safe default for async and latency-sensitive paths.
    #[default]
    DropNewest,
    /// Block the calling thread until the writer thread frees a slot. Loses no
    /// records, but can stall the caller — only safe off hot paths.
    Block,
}

/// A callback invoked on the writer thread when an underlying write fails.
pub type ErrorCallback = Arc<dyn Fn(&io::Error) + Send + Sync>;

/// Configuration for [`NonBlockingWriter::new`] and [`non_blocking_jsonl`].
#[derive(Clone)]
pub struct NonBlockingOptions {
    capacity: usize,
    overflow: Overflow,
    on_error: Option<ErrorCallback>,
}

impl Default for NonBlockingOptions {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            overflow: Overflow::default(),
            on_error: None,
        }
    }
}

impl std::fmt::Debug for NonBlockingOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonBlockingOptions")
            .field("capacity", &self.capacity)
            .field("overflow", &self.overflow)
            .field("on_error", &self.on_error.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl NonBlockingOptions {
    /// Start from the defaults: [`DEFAULT_CAPACITY`] and [`Overflow::DropNewest`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bounded-channel capacity in records. A capacity of `0` is treated
    /// as `1` so the channel always has at least one slot.
    #[must_use]
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Set the overflow policy applied when the channel is full.
    #[must_use]
    pub fn overflow(mut self, overflow: Overflow) -> Self {
        self.overflow = overflow;
        self
    }

    /// Register a callback invoked on the writer thread for each write error.
    ///
    /// Errors are always counted regardless; this is for surfacing them (logging,
    /// metrics) without polling [`SpanSpectorGuard::write_errors`].
    #[must_use]
    pub fn on_error(mut self, callback: ErrorCallback) -> Self {
        self.on_error = Some(callback);
        self
    }
}

/// Counters shared between a [`NonBlockingWriter`] and its [`SpanSpectorGuard`].
#[derive(Debug, Default)]
struct WriterMetrics {
    dropped: AtomicU64,
    write_errors: AtomicU64,
}

/// A message handed to the background writer thread.
enum Message {
    /// One serialized JSONL line to write.
    Line(String),
    /// Flush the underlying writer, then acknowledge on the channel.
    Flush(Sender<()>),
    /// Stop: drain anything still queued, do a final flush, and exit the thread.
    Shutdown,
}

/// A cloneable, non-blocking [`RecordWriter`] that offloads writes to a thread.
///
/// Create it with [`NonBlockingWriter::new`] (any [`Write`]) or
/// [`non_blocking_jsonl`] (a file path). Both return the writer **and** a
/// [`SpanSpectorGuard`]; keep the guard alive until shutdown so the thread is
/// joined and the final flush runs.
#[derive(Clone)]
pub struct NonBlockingWriter {
    tx: SyncSender<Message>,
    overflow: Overflow,
    metrics: Arc<WriterMetrics>,
}

impl NonBlockingWriter {
    /// Wrap any [`Write`] in a background writer thread.
    ///
    /// Returns the writer to hand to [`SpanSpectorLayer::new`] and a
    /// [`SpanSpectorGuard`] to keep alive until shutdown.
    ///
    /// [`SpanSpectorLayer::new`]: crate::SpanSpectorLayer::new
    pub fn new<W: Write + Send + 'static>(
        writer: W,
        options: NonBlockingOptions,
    ) -> io::Result<(Self, SpanSpectorGuard)> {
        let capacity = options.capacity.max(1);
        let (tx, rx) = sync_channel::<Message>(capacity);
        let metrics = Arc::new(WriterMetrics::default());
        let worker_metrics = Arc::clone(&metrics);
        let on_error = options.on_error.clone();

        let worker = std::thread::Builder::new()
            .name("spanspector-writer".to_owned())
            .spawn(move || worker_loop(writer, &rx, &worker_metrics, on_error.as_ref()))?;

        let handle = NonBlockingWriter {
            tx: tx.clone(),
            overflow: options.overflow,
            metrics: Arc::clone(&metrics),
        };
        let guard = SpanSpectorGuard {
            tx: Some(tx),
            worker: Some(worker),
            metrics,
        };
        Ok((handle, guard))
    }

    fn record_dropped(&self) {
        self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for NonBlockingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonBlockingWriter")
            .field("overflow", &self.overflow)
            .field("dropped", &self.metrics.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RecordWriter for NonBlockingWriter {
    fn write_line(&self, line: &str) {
        let message = Message::Line(line.to_owned());
        match self.overflow {
            // Both a full and a disconnected channel mean the line is not written;
            // count it as dropped rather than blocking or panicking.
            Overflow::DropNewest => {
                if self.tx.try_send(message).is_err() {
                    self.record_dropped();
                }
            }
            Overflow::Block => {
                if self.tx.send(message).is_err() {
                    self.record_dropped();
                }
            }
        }
    }
}

/// Drains and flushes a [`NonBlockingWriter`]'s background thread.
///
/// Keep it alive for the lifetime of the process (or the scope that should emit
/// evidence). On `flush()` it waits until everything queued so far is written;
/// on `shutdown()` — or on drop — it closes the channel, lets the thread drain
/// and flush, and joins it. After shutdown, query [`dropped`] and
/// [`write_errors`] to report lost evidence.
///
/// [`dropped`]: SpanSpectorGuard::dropped
/// [`write_errors`]: SpanSpectorGuard::write_errors
pub struct SpanSpectorGuard {
    tx: Option<SyncSender<Message>>,
    worker: Option<JoinHandle<()>>,
    metrics: Arc<WriterMetrics>,
}

impl SpanSpectorGuard {
    /// Block until every record queued before this call has been written and the
    /// underlying writer is flushed.
    ///
    /// Returns an error only if the writer thread has already stopped.
    pub fn flush(&self) -> io::Result<()> {
        let Some(tx) = &self.tx else {
            return Ok(());
        };
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        tx.send(Message::Flush(ack_tx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer thread stopped"))?;
        ack_rx.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer thread stopped during flush",
            )
        })
    }

    /// Close the channel, drain and flush remaining records, and join the thread.
    ///
    /// Consumes the guard. [`Drop`] performs the same drain best-effort if you do
    /// not call this explicitly.
    pub fn shutdown(mut self) -> io::Result<()> {
        self.shutdown_inner()
    }

    /// Number of records dropped because the channel was full (or disconnected).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.metrics.dropped.load(Ordering::Relaxed)
    }

    /// Number of underlying write errors observed by the writer thread.
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.metrics.write_errors.load(Ordering::Relaxed)
    }

    fn shutdown_inner(&mut self) -> io::Result<()> {
        // Signal the worker explicitly rather than relying on every sender being
        // dropped: when the layer lives in a global subscriber, its writer holds
        // a sender for the life of the process, so dropping only this guard's
        // sender would never disconnect the channel and `join` would hang.
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Message::Shutdown);
        }
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("writer thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for SpanSpectorGuard {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

impl std::fmt::Debug for SpanSpectorGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpanSpectorGuard")
            .field("dropped", &self.dropped())
            .field("write_errors", &self.write_errors())
            .field("active", &self.tx.is_some())
            .finish()
    }
}

/// Open `path` (creating parent directories) and wrap it in a non-blocking writer.
///
/// The file is created if missing and appended to otherwise, so re-running a
/// process does not truncate prior evidence. Writes are buffered and flushed by
/// the background thread; the returned [`SpanSpectorGuard`] flushes on shutdown.
///
/// ```no_run
/// use spanspector_schema::RunMetadata;
/// use spanspector_tracing::{NonBlockingOptions, SpanSpectorLayer, non_blocking_jsonl};
/// use tracing_subscriber::layer::SubscriberExt;
/// use tracing_subscriber::util::SubscriberInitExt;
///
/// let (writer, guard) =
///     non_blocking_jsonl("target/spanspector/run-1/trace.jsonl", NonBlockingOptions::new())?;
/// let layer = SpanSpectorLayer::new(RunMetadata::new("run-1"), writer);
/// tracing_subscriber::registry().with(layer).init();
/// // ... run the program ...
/// guard.shutdown()?; // flush and join before exit
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn non_blocking_jsonl(
    path: impl AsRef<Path>,
    options: NonBlockingOptions,
) -> io::Result<(NonBlockingWriter, SpanSpectorGuard)> {
    let file = open_append(path.as_ref())?;
    NonBlockingWriter::new(BufWriter::new(file), options)
}

/// Create `path`'s parent directories and open it for create-or-append writing.
pub(crate) fn open_append(path: &Path) -> io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// The background thread body: drain the channel, writing and flushing.
fn worker_loop<W: Write>(
    mut writer: W,
    rx: &Receiver<Message>,
    metrics: &WriterMetrics,
    on_error: Option<&ErrorCallback>,
) {
    loop {
        match rx.recv() {
            Ok(Message::Line(line)) => write_line(&mut writer, &line, metrics, on_error),
            Ok(Message::Flush(ack)) => {
                flush_writer(&mut writer, metrics, on_error);
                // The receiver may already be gone if the caller stopped waiting.
                let _ = ack.send(());
            }
            // Explicit shutdown, or every sender dropped: stop the loop.
            Ok(Message::Shutdown) | Err(_) => break,
        }
    }

    // Drain records queued before shutdown so evidence is not lost on the way out,
    // then do a final flush.
    while let Ok(message) = rx.try_recv() {
        if let Message::Line(line) = message {
            write_line(&mut writer, &line, metrics, on_error);
        }
    }
    flush_writer(&mut writer, metrics, on_error);
}

fn write_line<W: Write>(
    writer: &mut W,
    line: &str,
    metrics: &WriterMetrics,
    on_error: Option<&ErrorCallback>,
) {
    if let Err(error) = writer.write_all(line.as_bytes()) {
        metrics.write_errors.fetch_add(1, Ordering::Relaxed);
        if let Some(callback) = on_error {
            callback(&error);
        }
    }
}

fn flush_writer<W: Write>(
    writer: &mut W,
    metrics: &WriterMetrics,
    on_error: Option<&ErrorCallback>,
) {
    if let Err(error) = writer.flush() {
        metrics.write_errors.fetch_add(1, Ordering::Relaxed);
        if let Some(callback) = on_error {
            callback(&error);
        }
    }
}
