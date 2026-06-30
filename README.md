# SpanSpector

**AI-ready tracing diagnostics for Rust.**

[![Language: Rust](https://img.shields.io/badge/language-Rust-CE422B.svg?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Edition: 2024](https://img.shields.io/badge/edition-2024-CE422B.svg?logo=rust&logoColor=white)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

SpanSpector turns Rust [`tracing`](https://docs.rs/tracing) spans and events into
structured, deterministic, **redacted** JSONL evidence that AI agents and
developers can use to generate focused tests, reproduce bugs, inspect security
boundaries, and find slow spans — faster.

It complements existing observability tools; it is **not** an OpenTelemetry,
Jaeger, Datadog, or Grafana replacement, and it does not prove the absence of
bugs or vulnerabilities.

## Workspace layout

| Crate | Responsibility |
| --- | --- |
| `spanspector-core` | Redaction primitives, run metadata, sha256 digest. |
| `spanspector-schema` | `spanspector-trace/v1` types, JSONL read/write, validation, run summaries. |
| `spanspector-tracing` | A `tracing-subscriber` layer that emits redacted JSONL. |
| `spanspector-mcp` | A safe, local MCP-style server: read-only resources and allowlisted tools. |
| `spanspector-cli` | The `spanspector` CLI: `validate`, `summarize`, `search`, `serve`. |
| `examples/cli-command` | A tiny instrumented command that emits example evidence. |

Docs: [`docs/trace-schema.md`](docs/trace-schema.md),
[`docs/mcp-tools.md`](docs/mcp-tools.md), [`docs/security.md`](docs/security.md),
[`docs/performance.md`](docs/performance.md).

## Quick start

### 1. Emit JSONL from your tracing spans

```rust
use std::sync::{Arc, Mutex};
use spanspector_schema::RunMetadata;
use spanspector_tracing::SpanSpectorLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    // Write JSONL evidence to any `Write` sink (a file, a buffer, stdout).
    let writer = Arc::new(Mutex::new(std::io::stdout()));
    let run = RunMetadata::new("2026-06-27T10-15-32Z-local")
        .with_git_sha("abc1234")
        .with_profile("test")
        .with_crate("example-app");

    tracing_subscriber::registry()
        .with(SpanSpectorLayer::new(run, writer))
        .init();

    let span = tracing::info_span!("order.create", input.class = "json.order.v1");
    let _guard = span.enter();
    tracing::error!(error.kind = "validation_error", "rejected");
}
```

Each closed span and each event becomes one JSONL line. Sensitive field keys
(`auth.token`, `password`, `api_key`, …) are redacted to a class + digest before
they are ever written. See [`docs/trace-schema.md`](docs/trace-schema.md) for the
full event shape.

### 2. Run the example

```bash
cargo run -p spanspector-example-cli > /tmp/runs/2026-06-27T10-15-32Z-local/trace.jsonl
```

### 3. Use the CLI

```bash
# Validate JSONL (exits non-zero if any line is malformed).
spanspector validate tests/fixtures/example-run/trace.jsonl

# Deterministic run summary as JSON.
spanspector summarize tests/fixtures/example-run/trace.jsonl

# Find events by field.
spanspector search --field error.kind --value validation_error \
  tests/fixtures/example-run/trace.jsonl

# Serve evidence over the local MCP stdio protocol (read-only by default).
spanspector serve --runs-dir /tmp/runs --workspace .
```

### 4. Wire up the MCP server

The MCP server is **local-only, read-only by default**, and exposes resources
like `trace://runs/{id}/summary` plus opt-in allowlisted tools. See
[`docs/mcp-tools.md`](docs/mcp-tools.md).

## CI integration

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Generate evidence in CI by setting `RUST_LOG` and pointing the layer at a file
per run id, then run `spanspector validate` and `spanspector summarize` as a gate.

## Schema versioning

The schema identifier is `spanspector-trace/v1`. Additive fields stay on `v1`;
any breaking change bumps the version, and readers reject unknown schema strings
rather than guessing. See [`docs/trace-schema.md`](docs/trace-schema.md#versioning).

## Safety, in one breath

- Redaction is a hard validation invariant, not a best effort.
- The MCP server has no network listener and no `run_shell`.
- Commands are restricted to a fixed cargo allowlist with timeout, output, and
  environment limits. See [`docs/security.md`](docs/security.md).
