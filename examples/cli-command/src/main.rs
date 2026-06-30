//! Example command instrumented with SpanSpector.
//!
//! Run it to print `spanspector-trace/v1` JSONL evidence to stdout:
//!
//! ```text
//! cargo run -p spanspector-example-cli > tests/fixtures/example-run/trace.jsonl
//! ```
//!
//! It models a tiny "create order" command: a parent span plus a validation
//! event that fails for a bad total. A sensitive `auth.token` field is included
//! to show that it is redacted on the way out.

use std::io::{Stdout, stdout};
use std::sync::{Arc, Mutex};

use spanspector_schema::RunMetadata;
use spanspector_tracing::SpanSpectorLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    let writer: Arc<Mutex<Stdout>> = Arc::new(Mutex::new(stdout()));
    let run = RunMetadata::new("2026-06-27T10-15-32Z-local")
        .with_git_sha("abc1234")
        .with_profile("dev")
        .with_crate("spanspector-example-cli");

    let layer = SpanSpectorLayer::new(run, writer).with_span_started(false);
    tracing_subscriber::registry().with(layer).init();

    create_order("invalid-total");
}

/// A toy command. The `auth.token` field is intentionally sensitive to show
/// redaction; the raw value never reaches the emitted JSONL.
fn create_order(input_class: &str) {
    let span = tracing::info_span!(
        "order.create",
        ai.kind = "command",
        ai.contract = "order_total_equals_sum_of_lines",
        input.class = input_class,
        auth.token = "do-not-log-me",
        perf.suspect = true,
        perf.duration_ms = 312_i64,
    );
    let _guard = span.enter();

    tracing::error!(
        error.kind = "validation_error",
        security.boundary = "validation",
        security.decision = "reject",
        "order total does not equal sum of lines"
    );
}
