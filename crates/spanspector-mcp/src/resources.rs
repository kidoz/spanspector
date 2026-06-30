//! Read-only evidence resources.
//!
//! The registry maps `trace://` and `source://` URIs to bounded, structured
//! content read from a runs directory and the workspace. Everything is read-only
//! and every path is resolved through [`crate::path`], so resources cannot mutate
//! state or escape the workspace.
//!
//! Runs are stored as `<runs_dir>/<run_id>/trace.jsonl`.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde::Serialize;
use spanspector_schema::{
    DEFAULT_SLOWEST_SPANS, JsonlLine, RunSummary, TraceRecord, from_jsonl_line, read_jsonl,
};

use crate::error::{McpError, Result};
use crate::path::{canonical_within, validate_segment};

/// The file name holding a run's JSONL evidence inside its run directory.
const TRACE_FILE_NAME: &str = "trace.jsonl";

/// A read-only registry of SpanSpector evidence resources.
pub struct ResourceRegistry {
    runs_dir: PathBuf,
    workspace_root: PathBuf,
    max_bytes: usize,
    max_source_lines: u32,
}

/// The content returned for a resource read.
#[derive(Clone, Debug, Serialize)]
pub struct ResourceContents {
    /// The URI that was read.
    pub uri: String,
    /// MIME type of [`ResourceContents::text`].
    pub mime_type: String,
    /// The resource body.
    pub text: String,
    /// Whether the body was truncated to fit the size limit.
    pub truncated: bool,
}

impl ResourceRegistry {
    /// Create a registry over `runs_dir`, resolving `source://` paths under
    /// `workspace_root`. Bodies are capped at 1 MiB and source slices at 2000
    /// lines.
    pub fn new(runs_dir: impl Into<PathBuf>, workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            runs_dir: runs_dir.into(),
            workspace_root: workspace_root.into(),
            max_bytes: 1024 * 1024,
            max_source_lines: 2000,
        }
    }

    /// List available run identifiers (directories containing a trace file),
    /// sorted for deterministic output.
    pub fn list_runs(&self) -> Result<Vec<String>> {
        let mut runs = Vec::new();
        let entries = std::fs::read_dir(&self.runs_dir)?;
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if validate_segment(&name).is_ok() && entry.path().join(TRACE_FILE_NAME).is_file() {
                runs.push(name);
            }
        }
        runs.sort();
        Ok(runs)
    }

    /// Resolve and read a resource URI.
    pub fn read(&self, uri: &str) -> Result<ResourceContents> {
        if let Some(rest) = uri.strip_prefix("trace://runs") {
            self.read_trace(uri, rest)
        } else if let Some(rest) = uri.strip_prefix("source://") {
            self.read_source(uri, rest)
        } else {
            Err(McpError::InvalidResourceUri {
                uri: uri.to_owned(),
            })
        }
    }

    /// Compute a run summary by streaming the run's trace file.
    pub fn summarize(&self, run_id: &str) -> Result<RunSummary> {
        let path = self.trace_path(run_id)?;
        let file = File::open(&path)?;
        let mut summary = RunSummary::with_capacity(DEFAULT_SLOWEST_SPANS);
        for line in read_jsonl(BufReader::new(file)) {
            match line {
                JsonlLine::Record(record) => summary.ingest(&record),
                JsonlLine::Fault { .. } => summary.note_malformed(),
            }
        }
        Ok(summary)
    }

    /// Load every valid record for a run (used by tools that filter events).
    pub fn records(&self, run_id: &str) -> Result<Vec<TraceRecord>> {
        let path = self.trace_path(run_id)?;
        let file = File::open(&path)?;
        let records = read_jsonl(BufReader::new(file))
            .into_iter()
            .filter_map(|line| match line {
                JsonlLine::Record(record) => Some(*record),
                JsonlLine::Fault { .. } => None,
            })
            .collect();
        Ok(records)
    }

    /// Resolve `<runs_dir>/<run_id>/trace.jsonl`, rejecting unsafe run ids.
    fn trace_path(&self, run_id: &str) -> Result<PathBuf> {
        validate_segment(run_id)?;
        let relative = Path::new(run_id).join(TRACE_FILE_NAME);
        canonical_within(&self.runs_dir, &relative)
    }

    fn read_trace(&self, uri: &str, rest: &str) -> Result<ResourceContents> {
        // `rest` is the portion after `trace://runs`.
        if rest.is_empty() || rest == "/" {
            let runs = self.list_runs()?;
            return Ok(ResourceContents {
                uri: uri.to_owned(),
                mime_type: "application/json".to_owned(),
                text: serde_json::to_string_pretty(&runs)?,
                truncated: false,
            });
        }

        let segments: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
        match segments.as_slice() {
            [run_id, "summary"] => {
                let summary = self.summarize(run_id)?;
                Ok(ResourceContents {
                    uri: uri.to_owned(),
                    mime_type: "application/json".to_owned(),
                    text: serde_json::to_string_pretty(&summary)?,
                    truncated: false,
                })
            }
            [run_id, "events"] => self.read_events(uri, run_id),
            [run_id, "span", span_id] => {
                let records: Vec<TraceRecord> = self
                    .records(run_id)?
                    .into_iter()
                    .filter(|record| record.event.span_id == *span_id)
                    .collect();
                if records.is_empty() {
                    return Err(McpError::NotFound {
                        what: format!("span {span_id} in run {run_id}"),
                    });
                }
                Ok(ResourceContents {
                    uri: uri.to_owned(),
                    mime_type: "application/json".to_owned(),
                    text: serde_json::to_string_pretty(&records)?,
                    truncated: false,
                })
            }
            _ => Err(McpError::InvalidResourceUri {
                uri: uri.to_owned(),
            }),
        }
    }

    /// Read a run's events as JSONL, re-serializing only valid records and
    /// stopping at the byte cap on a whole-line boundary.
    fn read_events(&self, uri: &str, run_id: &str) -> Result<ResourceContents> {
        let path = self.trace_path(run_id)?;
        let file = File::open(&path)?;
        let mut text = String::new();
        let mut truncated = false;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // Validate before echoing so the events resource never emits a line
            // that would fail the schema (including unredacted sensitive fields).
            let Ok(record) = from_jsonl_line(&line) else {
                continue;
            };
            let serialized = serde_json::to_string(&record)?;
            if text.len() + serialized.len() + 1 > self.max_bytes {
                truncated = true;
                break;
            }
            text.push_str(&serialized);
            text.push('\n');
        }
        Ok(ResourceContents {
            uri: uri.to_owned(),
            mime_type: "application/x-ndjson".to_owned(),
            text,
            truncated,
        })
    }

    /// Read a source slice: `source://<path>#L<start>-L<end>`.
    fn read_source(&self, uri: &str, rest: &str) -> Result<ResourceContents> {
        let (path_part, range) = match rest.split_once('#') {
            Some((path, fragment)) => (path, parse_line_range(fragment)),
            None => (rest, None),
        };

        let resolved = canonical_within(&self.workspace_root, Path::new(path_part))?;
        let file = File::open(&resolved)?;
        let (start, end) = range.unwrap_or((1, u32::MAX));
        let mut text = String::new();
        let mut truncated = false;
        let mut emitted = 0u32;

        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            if line_number < start {
                continue;
            }
            if line_number > end {
                break;
            }
            if emitted >= self.max_source_lines {
                truncated = true;
                break;
            }
            text.push_str(&line?);
            text.push('\n');
            emitted += 1;
        }

        Ok(ResourceContents {
            uri: uri.to_owned(),
            mime_type: "text/plain".to_owned(),
            text,
            truncated,
        })
    }
}

/// Parse a `L<start>-L<end>` or `L<start>` fragment into an inclusive range.
fn parse_line_range(fragment: &str) -> Option<(u32, u32)> {
    let fragment = fragment.trim();
    match fragment.split_once('-') {
        Some((start, end)) => {
            let start = start.trim_start_matches('L').parse().ok()?;
            let end = end.trim_start_matches('L').parse().ok()?;
            Some((start, end))
        }
        None => {
            let start = fragment.trim_start_matches('L').parse().ok()?;
            Some((start, start))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique() -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn fixture_run(text: &str) -> (PathBuf, String) {
        let base = std::env::temp_dir().join(format!(
            "spanspector-res-{}-{}",
            std::process::id(),
            unique()
        ));
        let run_dir = base.join("runs").join("run-1");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join(TRACE_FILE_NAME), text).unwrap();
        (base, "run-1".to_owned())
    }

    fn sample_jsonl() -> String {
        // Two valid records (one error span) plus a malformed line.
        let ok = r#"{"schema":"spanspector-trace/v1","run":{"id":"run-1"},"event":{"kind":"span_closed","trace_id":"t","span_id":"s1","name":"ok","target":"app","level":"INFO","duration_ms":5,"status":"ok"}}"#;
        let err = r#"{"schema":"spanspector-trace/v1","run":{"id":"run-1"},"event":{"kind":"span_closed","trace_id":"t","span_id":"s2","name":"boom","target":"app","level":"ERROR","duration_ms":200,"status":"error","fields":{"error.kind":"validation_error"}}}"#;
        format!("{ok}\n{{ bad }}\n{err}\n")
    }

    #[test]
    fn summary_counts_records_and_malformed_lines() {
        let (base, run) = fixture_run(&sample_jsonl());
        let registry = ResourceRegistry::new(base.join("runs"), &base);

        let summary = registry.summarize(&run).unwrap();
        assert_eq!(summary.total_events, 2);
        assert_eq!(summary.malformed_lines, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.error_kinds["validation_error"], 1);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn list_runs_and_read_trace_uris() {
        let (base, _run) = fixture_run(&sample_jsonl());
        let registry = ResourceRegistry::new(base.join("runs"), &base);

        let listing = registry.read("trace://runs").unwrap();
        assert!(listing.text.contains("run-1"));

        let span = registry.read("trace://runs/run-1/span/s2").unwrap();
        assert!(span.text.contains("boom"));

        let events = registry.read("trace://runs/run-1/events").unwrap();
        // Malformed line is dropped; both valid records survive.
        assert_eq!(events.text.lines().count(), 2);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn rejects_run_id_traversal() {
        let (base, _run) = fixture_run(&sample_jsonl());
        let registry = ResourceRegistry::new(base.join("runs"), &base);

        let error = registry.read("trace://runs/..%2f/summary");
        assert!(error.is_err());
        let error = registry.summarize("../../etc").unwrap_err();
        assert!(matches!(error, McpError::InvalidRunId { .. }));

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let registry = ResourceRegistry::new(std::env::temp_dir(), std::env::temp_dir());
        assert!(matches!(
            registry.read("file:///etc/passwd").unwrap_err(),
            McpError::InvalidResourceUri { .. }
        ));
    }
}
