# Integrating SpanSpector into a server

This guide is for services (for example a database server such as NodusDB) that
want SpanSpector as an **optional** diagnostic evidence sink next to their
existing formatted logs and OpenTelemetry export. It covers dependency
consumption, the production-safe writer, run/file configuration, per-layer
filtering, redaction extension, and the shutdown contract.

```text
tracing registry
  fmt/log layer            (always on)
  optional OTLP exporter   (composes as one more `.with(...)` layer)
  optional SpanSpector     (non-blocking JSONL evidence, off by default)
```

A complete, runnable version of everything below is
[`examples/server-integration`](../examples/server-integration/src/main.rs):

```bash
cargo run -p spanspector-example-server
```

## 1. Consuming the crates

The workspace crates are `publish = false` **by design** — SpanSpector is
consumed as a git dependency, not from crates.io. Pin an exact revision:

```toml
[dependencies]
spanspector-tracing = { git = "https://github.com/kidoz/spanspector.git", rev = "<commit>", package = "spanspector-tracing" }
spanspector-schema  = { git = "https://github.com/kidoz/spanspector.git", rev = "<commit>", package = "spanspector-schema" }
```

`spanspector-tracing` re-exports the run-metadata and redaction types you need
(`RunMetadata`, `RedactionPolicy`, `SensitiveClass`), so most consumers depend on
the one crate. Add `spanspector-schema` only if you also parse or summarize the
JSONL in-process; add `spanspector-cli`/`spanspector-mcp` only for tooling.

Git-consumer compatibility is covered in CI (the `just git-consumer-smoke`
recipe in the [`justfile`](../justfile)); if you keep the crates
`publish = false`, that smoke build is the contract that keeps git consumption
working.

## 2. Pick a writer: never block the request path

The layer writes serialized lines to any
[`RecordWriter`](../crates/spanspector-tracing/src/writer.rs) sink:

- **Synchronous** — an `Arc<Mutex<W>>` over any `std::io::Write`. Simple and
  ordered, but it writes **inline under the lock**, so it can block the calling
  thread. Fine for tests, CLIs, and low-volume paths; **not** for async request,
  pgwire, Raft, compaction, recovery, or backup paths.
- **Non-blocking** — `NonBlockingWriter` hands each line to a bounded channel
  drained by a background thread. The calling thread never does filesystem I/O.

```rust
use spanspector_tracing::{non_blocking_jsonl, NonBlockingOptions, Overflow, SpanSpectorLayer};
use spanspector_schema::RunMetadata;

let (writer, guard) = non_blocking_jsonl(
    "var/spanspector/run-1/trace.jsonl",
    NonBlockingOptions::new()
        .capacity(8192)             // records buffered before overflow applies
        .overflow(Overflow::DropNewest), // never block; default
)?;
let layer = SpanSpectorLayer::new(RunMetadata::new("run-1"), writer);
// keep `guard` alive until shutdown
# Ok::<(), std::io::Error>(())
```

**Backpressure / drop behavior is explicit.** When the bounded channel is full:

- `Overflow::DropNewest` (default) drops the record and increments a counter —
  the caller never blocks. Use this on hot paths.
- `Overflow::Block` blocks the caller until a slot frees — loses nothing, but can
  stall. Use only off hot paths.

## 3. Configure output with `EvidenceBuilder`

Rather than hand-rolling path conventions, use the builder. It creates parent
directories, opens `trace.jsonl`, generates or accepts a run id, builds
`RunMetadata`, and wires a non-blocking writer:

```rust
use spanspector_tracing::EvidenceBuilder;

let evidence = EvidenceBuilder::new()
    .runs_dir("var/spanspector")     // -> var/spanspector/<run_id>/trace.jsonl
    // .trace_file("var/spanspector/custom.jsonl") // ...or an exact path
    .run_id("2026-06-30T18-00-00Z-ci")           // optional; generated if unset
    .profile("ci")
    .crate_name("nodus_server")
    .git_sha("abc1234")
    .emit_span_started(false)
    .build()?;

// evidence.layer  -> compose into the registry (optionally with a filter)
// evidence.guard  -> keep alive; flush on shutdown
// evidence.run    -> the RunMetadata embedded in every record
// evidence.path   -> the trace file path
# Ok::<(), std::io::Error>(())
```

## 4. Compose with fmt and OTLP

The layer is a plain `tracing_subscriber::Layer`. `Option<Layer>` is itself a
`Layer`, so a disabled SpanSpector composes to a no-op and your fmt/OTLP layers
are unaffected:

```rust
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

let spanspector = spanspector_enabled.then(|| evidence.layer); // Option<Layer>

tracing_subscriber::registry()
    .with(fmt_layer)        // existing formatted logs, always on
    .with(otlp_layer)       // optional OTLP exporter, unaffected
    .with(spanspector)      // optional evidence, off by default
    .init();
```

> Note: redaction applies to SpanSpector evidence only. Your fmt and OTLP layers
> emit whatever fields you record — do not log raw secrets to them.

## 5. Bound evidence volume with a per-layer filter

Attach a filter to the **SpanSpector layer only**, so capturing a narrow set of
targets does not change what fmt or OTLP see:

```rust
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::Layer;

let filter = Targets::new()
    .with_target("nodus_pgwire", LevelFilter::INFO)
    .with_target("nodus_server::raft", LevelFilter::INFO)
    .with_target("nodus_server::recovery", LevelFilter::INFO)
    .with_target("nodus_server::backup", LevelFilter::INFO)
    .with_default(LevelFilter::ERROR); // everything else: errors only

let layer = evidence.layer.with_filter(filter);
```

`Targets` needs no extra crate features. If you prefer `RUST_LOG`-style strings,
enable `tracing-subscriber`'s `env-filter` feature and use `EnvFilter` the same
way via `.with_filter(...)`.

## 6. Extend redaction for domain-specific secrets

Built-in keys (`password`, `auth.token`, `api_key`, `db_url`, …) always redact.
Add database-specific keys on top with a `RedactionPolicy` — extensions can only
**widen** what is redacted, never narrow it:

```rust
use spanspector_tracing::{RedactionPolicy, SensitiveClass};

let policy = RedactionPolicy::new()
    .with_key("sql.literal", SensitiveClass::Secret)
    .with_key("connection_string", SensitiveClass::ConnectionString)
    .with_key("admin_token", SensitiveClass::Token)
    .with_key("encryption_key_alias", SensitiveClass::Secret);

// On the builder:
let evidence = EvidenceBuilder::new().runs_dir("var/spanspector").redaction(policy).build()?;
// ...or directly on a layer: SpanSpectorLayer::new(run, writer).with_redaction(policy)
# Ok::<(), std::io::Error>(())
```

Matching is on a normalized key, so `sql.literal`, `sql-literal`, and `SqlLiteral`
all match.

## 7. Shutdown: flush and report dropped evidence

Keep the `SpanSpectorGuard` alive for the life of the process. On shutdown:

```rust
guard.flush()?;                  // wait until everything queued so far is written
let dropped = guard.dropped();   // records dropped due to a full channel
let errors = guard.write_errors(); // underlying write failures
if dropped > 0 || errors > 0 {
    tracing::warn!(dropped, errors, "spanspector lost evidence");
}
guard.shutdown()?;               // drain, final flush, join the writer thread
# Ok::<(), std::io::Error>(())
```

`shutdown()` (and `Drop`, best-effort) signal the writer thread **explicitly** —
they do not wait for every layer to be dropped. This matters because a globally
installed subscriber holds the layer (and a writer handle) for the life of the
process; relying on sender-drop alone would hang the join. You can also register
an `on_error` callback in `NonBlockingOptions` to surface write failures as they
happen instead of polling `write_errors()`.

## 8. Output rotation

SpanSpector does not rotate output itself. Hand off to application-managed
rotation by pointing each run at a fresh trace file — typically one directory per
run id, which `EvidenceBuilder::runs_dir` does for you. The non-blocking file
writer opens in create-or-append mode, so re-running a process with the same run
id appends rather than truncating. Prune old run directories with whatever
retention policy the host already uses for logs.

## 9. Acceptance checklist

- [ ] `observability.spanspector_enabled = false` is the default; the layer is
      `None` and composes to a no-op when disabled.
- [ ] Enabling it writes valid JSONL under the configured run path
      (`spanspector validate <path>` passes).
- [ ] fmt logs and OTLP export still work with SpanSpector enabled.
- [ ] No blocking filesystem writes on async paths (use `NonBlockingWriter` /
      `EvidenceBuilder`).
- [ ] Shutdown flushes and reports `dropped()` / `write_errors()`.
- [ ] Tests cover config parsing, subscriber composition, JSONL emission, and
      redaction of your domain-specific sensitive fields (see
      [`crates/spanspector-tracing/tests/nonblocking.rs`](../crates/spanspector-tracing/tests/nonblocking.rs)).
