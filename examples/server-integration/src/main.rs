//! Compose SpanSpector the way a server (for example NodusDB) would.
//!
//! It mirrors the target topology:
//!
//! ```text
//! tracing registry
//!   fmt/log layer            (always on)
//!   optional OTLP exporter   (composes as one more `.with(...)` layer)
//!   optional SpanSpector     (non-blocking JSONL evidence, off by default)
//! ```
//!
//! Run it:
//!
//! ```text
//! cargo run -p spanspector-example-server
//! # then inspect the evidence the run prints the path to:
//! cargo run -p spanspector-cli -- validate <printed trace.jsonl>
//! ```
//!
//! Key properties demonstrated:
//! - the formatted log layer stays active and unaffected;
//! - the SpanSpector layer is **optional** and gated by a flag;
//! - a per-layer filter bounds evidence to a few targets, not the whole process;
//! - evidence writes never block the request path (non-blocking writer);
//! - the guard is flushed on shutdown and dropped records are reported.

use spanspector_tracing::{EvidenceBuilder, RedactionPolicy, SensitiveClass};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In a real server this comes from `observability.spanspector_enabled`, which
    // is `false` by default. Here we force it on so the example produces evidence.
    let spanspector_enabled = true;

    // The formatted log layer a server already installs — always present.
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(true);

    // Build the optional evidence layer only when enabled. `Option<Layer>` is
    // itself a `Layer`, so `None` composes to a no-op.
    let evidence = if spanspector_enabled {
        Some(
            EvidenceBuilder::new()
                .runs_dir("target/spanspector")
                .profile("dev")
                .crate_name("nodus_server")
                // Database-specific sensitive keys, on top of the built-ins.
                .redaction(
                    RedactionPolicy::new()
                        .with_key("sql.literal", SensitiveClass::Secret)
                        .with_key("connection_string", SensitiveClass::ConnectionString)
                        .with_key("admin_token", SensitiveClass::Token),
                )
                .build()?,
        )
    } else {
        None
    };

    // Keep evidence volume bounded: capture only the targets that matter for
    // diagnosis, at the levels that matter — without touching the fmt layer.
    let evidence_filter = Targets::new()
        .with_target("spanspector_example_server", LevelFilter::INFO)
        .with_target("nodus_pgwire", LevelFilter::INFO)
        .with_target("nodus_server::raft", LevelFilter::INFO)
        .with_default(LevelFilter::ERROR);

    // Split the bundle: the layer goes into the registry, the guard stays here so
    // we can flush it on the way out.
    let (spanspector_layer, guard, trace_path) = match evidence {
        Some(evidence) => (
            Some(evidence.layer.with_filter(evidence_filter)),
            Some(evidence.guard),
            Some(evidence.path),
        ),
        None => (None, None, None),
    };

    tracing_subscriber::registry()
        .with(fmt_layer)
        // An OTLP exporter, when configured, would be one more `.with(otlp)` here
        // and is unaffected by the SpanSpector layer.
        .with(spanspector_layer)
        .init();

    // Simulate a unit of server work.
    handle_request("json.order.v1");

    // Shutdown: flush evidence and report anything dropped.
    if let Some(guard) = guard {
        if let Err(error) = guard.flush() {
            eprintln!("spanspector flush failed: {error}");
        }
        let dropped = guard.dropped();
        let write_errors = guard.write_errors();
        if dropped > 0 || write_errors > 0 {
            eprintln!("spanspector dropped {dropped} record(s), {write_errors} write error(s)");
        }
        guard.shutdown()?;
    }
    if let Some(path) = trace_path {
        eprintln!("spanspector evidence written to {}", path.display());
    }
    Ok(())
}

/// A toy request handler. The `auth.token` and `sql.literal` fields are sensitive
/// and never reach the evidence as raw values.
fn handle_request(input_class: &str) {
    let span = tracing::info_span!(
        target: "nodus_pgwire",
        "pgwire.query",
        input.class = input_class,
        auth.token = "do-not-log-me",
        sql.literal = "WHERE ssn = '123-45-6789'",
    );
    let _entered = span.enter();

    // The event inherits this module's target; at ERROR it passes the filter.
    tracing::error!(
        error.kind = "constraint_violation",
        "unique constraint violated"
    );
}
