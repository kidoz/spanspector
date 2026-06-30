//! [`EvidenceBuilder`]: one call from configuration to a ready-to-install layer.
//!
//! Consumers should not hand-roll path conventions, run-id generation, or writer
//! wiring. The builder takes a runs directory (or an exact trace-file path) plus
//! optional run context, creates the parent directories, opens `trace.jsonl`,
//! builds [`RunMetadata`], wraps the file in a [`NonBlockingWriter`], and returns
//! the [`SpanSpectorLayer`] together with the [`SpanSpectorGuard`] to flush on
//! shutdown.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use spanspector_core::{RedactionPolicy, RunMetadata};

use crate::layer::SpanSpectorLayer;
use crate::nonblocking::{
    NonBlockingOptions, NonBlockingWriter, SpanSpectorGuard, non_blocking_jsonl,
};

/// File name written inside a per-run directory when a runs directory is used.
const TRACE_FILE_NAME: &str = "trace.jsonl";

/// A fully wired evidence sink: an installable layer plus its lifecycle guard.
///
/// Move `layer` into a subscriber (optionally after `.with_filter(...)`), keep
/// `guard` alive until shutdown, and use `run`/`path` for logging or to point a
/// reader at the file.
pub struct Evidence {
    /// The layer to compose onto a [`tracing_subscriber::registry()`].
    ///
    /// [`tracing_subscriber::registry()`]: mod@tracing_subscriber::registry
    pub layer: SpanSpectorLayer<NonBlockingWriter>,
    /// Flushes and joins the background writer; keep alive until process exit.
    pub guard: SpanSpectorGuard,
    /// The run metadata embedded in every emitted record.
    pub run: RunMetadata,
    /// The trace file the evidence is written to.
    pub path: PathBuf,
}

impl std::fmt::Debug for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Evidence")
            .field("run", &self.run)
            .field("path", &self.path)
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

/// Builder that turns evidence configuration into an [`Evidence`] bundle.
///
/// Provide exactly one output location: a [`runs_dir`] (the run id becomes a
/// subdirectory holding `trace.jsonl`) or an exact [`trace_file`]. Everything
/// else is optional.
///
/// ```no_run
/// use spanspector_tracing::EvidenceBuilder;
/// use tracing_subscriber::layer::SubscriberExt;
/// use tracing_subscriber::util::SubscriberInitExt;
///
/// let evidence = EvidenceBuilder::new()
///     .runs_dir("target/spanspector")
///     .profile("ci")
///     .crate_name("nodus_server")
///     .git_sha("abc1234")
///     .build()?;
///
/// tracing_subscriber::registry().with(evidence.layer).init();
/// // ... run the program ...
/// evidence.guard.shutdown()?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// [`runs_dir`]: EvidenceBuilder::runs_dir
/// [`trace_file`]: EvidenceBuilder::trace_file
#[derive(Debug, Default)]
pub struct EvidenceBuilder {
    runs_dir: Option<PathBuf>,
    trace_file: Option<PathBuf>,
    run_id: Option<String>,
    git_sha: Option<String>,
    profile: Option<String>,
    crate_name: Option<String>,
    emit_span_started: bool,
    redaction: Option<RedactionPolicy>,
    writer_options: NonBlockingOptions,
}

impl EvidenceBuilder {
    /// Start a builder with no output location set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Write under `dir/<run_id>/trace.jsonl`, generating the run id if unset.
    ///
    /// Mutually exclusive with [`trace_file`]; if both are set, `trace_file` wins.
    ///
    /// [`trace_file`]: EvidenceBuilder::trace_file
    #[must_use]
    pub fn runs_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.runs_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Write to this exact trace-file path. Takes precedence over [`runs_dir`].
    ///
    /// [`runs_dir`]: EvidenceBuilder::runs_dir
    #[must_use]
    pub fn trace_file(mut self, path: impl AsRef<Path>) -> Self {
        self.trace_file = Some(path.as_ref().to_path_buf());
        self
    }

    /// Override the run id. When unset, a unique id is generated at [`build`].
    ///
    /// [`build`]: EvidenceBuilder::build
    #[must_use]
    pub fn run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Set the git revision recorded in [`RunMetadata`].
    #[must_use]
    pub fn git_sha(mut self, git_sha: impl Into<String>) -> Self {
        self.git_sha = Some(git_sha.into());
        self
    }

    /// Set the execution profile (for example `dev`, `ci`, `test`).
    #[must_use]
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the emitting crate or application name.
    #[must_use]
    pub fn crate_name(mut self, crate_name: impl Into<String>) -> Self {
        self.crate_name = Some(crate_name.into());
        self
    }

    /// Emit a `span_started` record when each span opens (off by default).
    #[must_use]
    pub fn emit_span_started(mut self, enabled: bool) -> Self {
        self.emit_span_started = enabled;
        self
    }

    /// Use a custom [`RedactionPolicy`] (built-in sensitive keys stay active).
    #[must_use]
    pub fn redaction(mut self, policy: RedactionPolicy) -> Self {
        self.redaction = Some(policy);
        self
    }

    /// Configure the non-blocking writer (capacity, overflow, error callback).
    #[must_use]
    pub fn writer_options(mut self, options: NonBlockingOptions) -> Self {
        self.writer_options = options;
        self
    }

    /// Resolve the output path, open it, and build the layer, guard, and metadata.
    ///
    /// Errors if no output location was set, or if the file or its parent
    /// directories cannot be created.
    pub fn build(self) -> io::Result<Evidence> {
        let run_id = self.run_id.unwrap_or_else(generate_run_id);
        let path = resolve_path(self.trace_file, self.runs_dir, &run_id)?;
        let (writer, guard) = non_blocking_jsonl(&path, self.writer_options)?;

        let mut run = RunMetadata::new(run_id);
        run.git_sha = self.git_sha;
        run.profile = self.profile;
        run.crate_name = self.crate_name;

        let mut layer =
            SpanSpectorLayer::new(run.clone(), writer).with_span_started(self.emit_span_started);
        if let Some(policy) = self.redaction {
            layer = layer.with_redaction(policy);
        }

        Ok(Evidence {
            layer,
            guard,
            run,
            path,
        })
    }
}

/// Pick the trace-file path: an exact file wins, else `runs_dir/<run_id>/trace.jsonl`.
fn resolve_path(
    trace_file: Option<PathBuf>,
    runs_dir: Option<PathBuf>,
    run_id: &str,
) -> io::Result<PathBuf> {
    if let Some(file) = trace_file {
        return Ok(file);
    }
    if let Some(dir) = runs_dir {
        return Ok(dir.join(run_id).join(TRACE_FILE_NAME));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "EvidenceBuilder requires runs_dir or trace_file",
    ))
}

/// Generate a unique-enough run id from wall-clock millis and the process id.
///
/// Stable within a process and ordered across runs; not a UUID. Callers that
/// need a specific scheme (an ISO timestamp, a CI build id) pass
/// [`EvidenceBuilder::run_id`].
fn generate_run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    format!("run-{millis}-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_dir_places_trace_under_run_id() {
        let path = resolve_path(None, Some(PathBuf::from("/runs")), "abc").unwrap();
        assert_eq!(path, PathBuf::from("/runs/abc/trace.jsonl"));
    }

    #[test]
    fn trace_file_takes_precedence_over_runs_dir() {
        let path = resolve_path(
            Some(PathBuf::from("/exact/trace.jsonl")),
            Some(PathBuf::from("/runs")),
            "abc",
        )
        .unwrap();
        assert_eq!(path, PathBuf::from("/exact/trace.jsonl"));
    }

    #[test]
    fn missing_output_location_is_an_error() {
        let error = resolve_path(None, None, "abc").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn generated_run_id_has_run_prefix() {
        assert!(generate_run_id().starts_with("run-"));
    }
}
