# Trace schema: `spanspector-trace/v1`

SpanSpector evidence is **JSONL**: one complete JSON object per line, each a
`TraceRecord`. The format is deterministic — fields are ordered, maps are sorted,
and the same input always serializes identically — so output is safe to snapshot
and diff.

## Record shape

```json
{
  "schema": "spanspector-trace/v1",
  "run": {
    "id": "2026-06-27T10-15-32Z-local",
    "git_sha": "abc1234",
    "profile": "test",
    "crate": "example-app"
  },
  "event": {
    "kind": "span_closed",
    "trace_id": "trace-id",
    "span_id": "span-id",
    "parent_span_id": "parent-span-id",
    "name": "order.create",
    "target": "example_app::orders",
    "level": "INFO",
    "duration_ms": 312,
    "status": "error",
    "source": {
      "file": "src/orders.rs",
      "line": 42,
      "function": "example_app::orders::create_order"
    },
    "fields": {
      "ai.kind": "command",
      "ai.contract": "order_total_equals_sum_of_lines",
      "input.class": "json.order.v1",
      "input.digest": "sha256:…",
      "security.boundary": "validation",
      "security.decision": "reject",
      "perf.suspect": true,
      "error.kind": "validation_error"
    },
    "test_hints": [
      {
        "kind": "regression",
        "suggested_name": "rejects_order_with_invalid_total",
        "fixture": "tests/fixtures/orders/invalid-total.json",
        "assert": "returns validation error and does not persist order"
      }
    ],
    "repro": {
      "command": "cargo nextest run rejects_order_with_invalid_total",
      "env": { "RUST_LOG": "example_app=debug" }
    }
  }
}
```

## Fields

| Path | Type | Notes |
| --- | --- | --- |
| `schema` | string | Always `spanspector-trace/v1`; defaults in on read. |
| `run.id` | string | Required, stable per run. |
| `run.git_sha`, `run.profile`, `run.crate` | string | Optional context; omitted when unset. |
| `event.kind` | enum | `span_started` \| `span_closed` \| `event`. |
| `event.trace_id`, `event.span_id` | string | Required, non-empty. |
| `event.parent_span_id` | string | Omitted for roots. |
| `event.name`, `event.target` | string | Required. |
| `event.level` | enum | `TRACE` \| `DEBUG` \| `INFO` \| `WARN` \| `ERROR`. |
| `event.duration_ms` | integer | Present for closed spans. |
| `event.status` | enum | `ok` \| `error` \| `unknown`. |
| `event.source` | object | `file`, `line`, optional `function`. |
| `event.fields` | map | Semantic fields; sorted; sensitive keys redacted. |
| `event.test_hints` | array | Deterministic test-generation hints. |
| `event.repro` | object | Safe reproduction command + env. |

### Field value types

A field value is one of: `bool`, integer (`i64`), string, or a **redacted
object** (`{class, present, redacted, size_bytes, digest}`). See
[`security.md`](security.md) for which keys are redacted.

## Recommended field namespaces

```text
ai.kind            request | command | query | job | parser | authz | db | cache | external
ai.contract        stable invariant or business-rule identifier
input.class        shape of input, never raw sensitive data
input.digest       sha256 hash for correlation
security.boundary  authn | authz | validation | crypto | deserialization | ffi | filesystem | network | unsafe
security.decision  allow | deny | sanitize | reject
perf.suspect       boolean
perf.duration_ms   integer
error.kind         stable error class
```

Prefer stable semantic fields over prose; avoid high-cardinality raw values.

## Parsing and fault tolerance

`spanspector_schema::read_jsonl` parses a stream one line at a time. A single
malformed line is reported as a `JsonlLine::Fault { line_number, error }` and does
**not** abort the stream or corrupt a run summary. Error values never contain the
offending bytes, so malformed input cannot leak data through diagnostics.

## Versioning

- Additive, backward-compatible field changes keep `spanspector-trace/v1`.
- Any change that would break a `v1` reader bumps the version (`/v2`).
- Readers reject unknown schema strings (`UnsupportedSchema`) rather than guessing.
