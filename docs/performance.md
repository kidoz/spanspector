# Performance and overhead

SpanSpector aims for **predictable, documented** overhead rather than the lowest
possible cost. This document describes where time and allocation go, and how to
keep them bounded.

## Tracing layer overhead

The `SpanSpectorLayer` does the following per event:

- **Span open:** capture fields once via a single `Visit` pass into a
  `BTreeMap`, plus an `Instant::now()`; cache the state in the span's registry
  extensions. No serialization happens at open time by default.
- **Span close / event:** clone the small `RunMetadata`, serialize one record to
  JSON, and write it while holding a single `Mutex` around the writer.

Implications and guidance:

- Emission is **synchronous and serialized** through one mutex. This keeps output
  ordered and simple. On very hot paths with many threads, the mutex is the main
  contention point — write to a buffered sink and, if needed, restrict the layer
  with a level/target filter so trace-heavy paths do not emit.
- `with_span_started(false)` (the default) avoids an extra record per span; enable
  it only when you need open/close correlation for long-lived spans.
- Writes are **best-effort**: a failing writer drops the record rather than
  panicking inside the tracing callback.

## Parsing and summarization

- `read_jsonl` is **streaming** (`BufRead`, one line at a time); it never loads a
  whole file into memory.
- `RunSummary` is computed **incrementally** (`ingest` per record) and keeps only
  a bounded top-N of slowest spans, so summarizing a large run is O(records) time
  and O(N) retained span memory.
- The MCP `events` resource re-serializes validated records up to a byte cap on
  whole-line boundaries; source slices are line-capped.

## Performance fields

Surface suspected hotspots as semantic fields rather than prose so they are
queryable:

```text
perf.suspect      true
perf.duration_ms  312
perf.alloc_bytes  4096   (when available)
```

`RunSummary` counts `perf.suspect` events and ranks the slowest closed spans by
`duration_ms`, giving an agent an immediate "where is the time going" view.

## Scope

SpanSpector can identify **slow spans** and suspicious latency from span
durations. It is **not** a CPU profiler: detailed attribution (which function,
which allocation) still requires `cargo flamegraph`, `perf`, or `criterion`
benchmarks. Treat SpanSpector timings as a triage signal that tells you *where to
profile next*.

## Measuring overhead

When changing tracing or parsing hot paths, measure rather than guess:

```bash
cargo build --workspace --timings   # build-time impact of a change
cargo bench --bench <name>          # runtime impact, when a bench exists
```

Avoid speculative micro-optimizations; add a benchmark when a path is genuinely
hot and preserve readability unless profiling justifies the complexity.
