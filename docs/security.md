# Security and redaction

SpanSpector treats redaction and input hostility as first-class concerns. This
document states the threat model, the guarantees, and the residual risks.

## Threat model

Assume both **trace inputs** and **MCP requests** may be malicious:

- A trace file may contain malformed lines, oversized payloads, unredacted
  secrets, or path-like strings crafted to escape the workspace.
- An MCP request may ask to run arbitrary commands, read arbitrary files, or
  exhaust memory.

## Redaction

Redaction is enforced as a **validation invariant**, not an optional layer. A
field whose key is classified sensitive must serialize as a redacted object
(`{class, present, redacted, size_bytes, digest}`); a raw value under such a key
is a hard validation error (`UnredactedSensitiveField`). Both
`spanspector_schema::to_jsonl_line` (write) and `from_jsonl_line` (read) enforce
it, and the tracing layer redacts at the capture boundary before a value is ever
buffered.

Classification is **key-based** and case/separator-insensitive: `auth.token`,
`Authorization`, and `refresh-token` all match. Covered classes include
passwords, tokens/JWTs/API keys, cookies/sessions, private keys, and
connection strings. When unsure, the rule is **redact**.

Never emit raw values for: passwords, API keys, access/refresh tokens, private
keys, session cookies, payment data, health data, raw request bodies, model
prompts/outputs that may carry sensitive data, connection strings, or
infrastructure credentials. Use safe stand-ins instead: `input.class`,
`input.size_bytes`, `input.digest`, `user.id_hash`, `secret.present`.

### Residual risk

Redaction is keyed on **field names**. A secret placed in a *non-sensitively
named* field — most commonly a free-form `message` — is not detected. Guidance:
put sensitive data behind sensitively named fields (or omit it), and avoid
interpolating secrets into log messages. SpanSpector can highlight suspicious
security boundaries; it does **not** prove the absence of leaks or
vulnerabilities.

## Command execution safety

- There is **no** generic `run_shell` tool.
- Every executed command must match a fixed `cargo` allowlist
  (`validate_command`): `cargo test`, `cargo nextest run`, `cargo clippy`,
  `cargo fmt`, `cargo llvm-cov`, `cargo audit`, `cargo deny check`,
  `cargo miri test`, `cargo fuzz run`, `cargo bench`.
- Command arguments are character-checked (no whitespace or shell
  metacharacters); commands are spawned **without a shell**.
- The runner enforces a fixed working directory (workspace root), a wall-clock
  **timeout**, a per-stream **output cap** with draining to avoid pipe blocking,
  and a strict **environment allowlist** (`env_clear` + a small passthrough set),
  so parent-process secrets are not inherited.
- Command tools are **opt-in** (`--allow-commands`) and hidden otherwise.

## Path traversal

All filesystem access flows through `canonical_within`, which canonicalizes the
target (resolving symlinks and `..`) and verifies the result stays under the
workspace root. Run ids are additionally validated as single safe path segments.
A crafted run id or `source://` path therefore cannot reach `/etc/passwd` or a
sibling directory, and a symlink pointing outside the root is rejected.

## Resource exhaustion

- JSONL parsing is **streaming** and line-bounded; one bad line is isolated.
- Resource bodies are byte-capped; source slices are line-capped.
- Command output is captured into bounded buffers.

## Network posture

The MCP server has **no listener**: it speaks JSON-RPC over stdio only. There is
no port to bind and nothing to expose, so the "network listeners disabled by
default" and "localhost-only" requirements hold by construction.

## Error messages

Errors are remediation-oriented and never embed raw line contents, file bytes,
field values, or command output — so diagnostics themselves cannot leak data.
