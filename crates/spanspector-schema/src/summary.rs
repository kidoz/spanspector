//! Incremental, deterministic aggregation of a run's trace records.
//!
//! [`RunSummary`] answers the first triage questions an agent asks — what failed,
//! how often, where the slow spans are, which security boundaries fired — without
//! re-reading the raw events. It is built incrementally with [`RunSummary::ingest`]
//! so a large run never has to be held in memory at once, and every aggregate is
//! ordered deterministically so the same input yields byte-identical output.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::event::{EventKind, EventStatus};
use crate::record::TraceRecord;

/// Default number of slowest spans retained in a summary.
pub const DEFAULT_SLOWEST_SPANS: usize = 10;

/// A deterministic aggregate view of one run's evidence.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunSummary {
    /// Run identifier, taken from the first ingested record.
    pub run_id: String,
    /// Total records ingested (excludes malformed lines).
    pub total_events: usize,
    /// Count of `span_closed` records.
    pub spans_closed: usize,
    /// Count of records with `status == error`.
    pub errors: usize,
    /// Malformed JSONL lines skipped while building the summary.
    pub malformed_lines: usize,
    /// Number of `perf.suspect == true` records.
    pub perf_suspects: usize,
    /// Count of each `error.kind`, keyed for stable ordering.
    pub error_kinds: BTreeMap<String, usize>,
    /// Count of each `security.boundary:security.decision` pair.
    pub security_decisions: BTreeMap<String, usize>,
    /// The slowest closed spans, descending by duration then by span id.
    pub slowest_spans: Vec<SpanTiming>,
    /// Maximum number of entries kept in [`RunSummary::slowest_spans`].
    pub slowest_capacity: usize,
}

/// A single timed span retained in [`RunSummary::slowest_spans`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpanTiming {
    /// Span identifier.
    pub span_id: String,
    /// Span name.
    pub name: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether the span was flagged as a performance suspect.
    pub perf_suspect: bool,
}

impl RunSummary {
    /// Create an empty summary that keeps up to `slowest_capacity` slow spans.
    pub fn with_capacity(slowest_capacity: usize) -> Self {
        Self {
            slowest_capacity,
            ..Self::default()
        }
    }

    /// Fold one record into the summary.
    pub fn ingest(&mut self, record: &TraceRecord) {
        if self.total_events == 0 && self.run_id.is_empty() {
            self.run_id = record.run.id.clone();
        }
        self.total_events += 1;

        let event = &record.event;
        if event.kind == EventKind::SpanClosed {
            self.spans_closed += 1;
        }
        if event.status == EventStatus::Error {
            self.errors += 1;
        }
        if event.is_perf_suspect() {
            self.perf_suspects += 1;
        }
        if let Some(kind) = event.error_kind() {
            *self.error_kinds.entry(kind.to_owned()).or_insert(0) += 1;
        }
        if let Some((boundary, decision)) = event.security_decision() {
            *self
                .security_decisions
                .entry(format!("{boundary}:{decision}"))
                .or_insert(0) += 1;
        }
        if let Some(duration_ms) = event.duration_ms {
            self.record_timing(SpanTiming {
                span_id: event.span_id.clone(),
                name: event.name.clone(),
                duration_ms,
                perf_suspect: event.is_perf_suspect(),
            });
        }
    }

    /// Note a malformed line so the count is visible in the summary.
    pub fn note_malformed(&mut self) {
        self.malformed_lines += 1;
    }

    /// Insert a timing, keeping the list sorted and bounded to capacity.
    fn record_timing(&mut self, timing: SpanTiming) {
        self.slowest_spans.push(timing);
        // Sort descending by duration; break ties by span id for determinism.
        self.slowest_spans.sort_by(|a, b| {
            b.duration_ms
                .cmp(&a.duration_ms)
                .then_with(|| a.span_id.cmp(&b.span_id))
        });
        if self.slowest_capacity > 0 {
            self.slowest_spans.truncate(self.slowest_capacity);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, EventStatus, FieldValue, Level, TraceEvent};
    use spanspector_core::RunMetadata;

    fn closed(span_id: &str, duration_ms: u64, status: EventStatus) -> TraceRecord {
        let mut event = TraceEvent::new(
            EventKind::SpanClosed,
            "trace-1",
            span_id,
            "op",
            "app",
            Level::Info,
        );
        event.duration_ms = Some(duration_ms);
        event.status = status;
        TraceRecord::new(RunMetadata::new("run-1"), event)
    }

    #[test]
    fn aggregates_counts_and_keeps_slowest_bounded() {
        let mut summary = RunSummary::with_capacity(2);
        summary.ingest(&closed("a", 10, EventStatus::Ok));
        summary.ingest(&closed("b", 300, EventStatus::Error));
        summary.ingest(&closed("c", 200, EventStatus::Ok));

        assert_eq!(summary.run_id, "run-1");
        assert_eq!(summary.total_events, 3);
        assert_eq!(summary.spans_closed, 3);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.slowest_spans.len(), 2);
        // Bounded to the two slowest, ordered descending.
        assert_eq!(summary.slowest_spans[0].span_id, "b");
        assert_eq!(summary.slowest_spans[1].span_id, "c");
    }

    #[test]
    fn slowest_ordering_is_deterministic_on_ties() {
        let mut a = RunSummary::with_capacity(10);
        a.ingest(&closed("y", 100, EventStatus::Ok));
        a.ingest(&closed("x", 100, EventStatus::Ok));

        let mut b = RunSummary::with_capacity(10);
        b.ingest(&closed("x", 100, EventStatus::Ok));
        b.ingest(&closed("y", 100, EventStatus::Ok));

        assert_eq!(a.slowest_spans, b.slowest_spans);
        assert_eq!(a.slowest_spans[0].span_id, "x");
    }

    #[test]
    fn tallies_error_kinds_security_and_perf() {
        let mut event = TraceEvent::new(
            EventKind::Event,
            "trace-1",
            "s",
            "validate",
            "app",
            Level::Error,
        );
        event.status = EventStatus::Error;
        event.fields.insert(
            "error.kind".to_owned(),
            FieldValue::Text("validation_error".to_owned()),
        );
        event.fields.insert(
            "security.boundary".to_owned(),
            FieldValue::Text("validation".to_owned()),
        );
        event.fields.insert(
            "security.decision".to_owned(),
            FieldValue::Text("reject".to_owned()),
        );
        event
            .fields
            .insert("perf.suspect".to_owned(), FieldValue::Bool(true));
        let record = TraceRecord::new(RunMetadata::new("run-1"), event);

        let mut summary = RunSummary::with_capacity(10);
        summary.ingest(&record);

        assert_eq!(summary.error_kinds["validation_error"], 1);
        assert_eq!(summary.security_decisions["validation:reject"], 1);
        assert_eq!(summary.perf_suspects, 1);
    }
}
