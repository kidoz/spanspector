# MCP server: resources and tools

`spanspector-mcp` exposes SpanSpector evidence to a local MCP host over a
synchronous, line-delimited **JSON-RPC 2.0** stdio loop. There is no network
listener and no port: a host launches `spanspector serve` and drives it through
the child process's stdin/stdout.

Start it with the CLI:

```bash
spanspector serve --runs-dir /tmp/runs --workspace .
# add --allow-commands to enable the (opt-in) command-running tools
```

Runs live at `<runs_dir>/<run_id>/trace.jsonl`.

## Methods

| Method | Purpose |
| --- | --- |
| `initialize` | Report protocol version, capabilities, and server info. |
| `resources/list` | List run resources. |
| `resources/read` | Read a resource by URI. |
| `tools/list` | List available tools (command tools only when enabled). |
| `tools/call` | Invoke a tool by name with JSON arguments. |

## Resources (read-only)

```text
trace://runs                      JSON array of run ids
trace://runs/{run_id}/summary     deterministic RunSummary as JSON
trace://runs/{run_id}/events      validated records as NDJSON (size-capped)
trace://runs/{run_id}/span/{id}   all records for one span as JSON
source://{path}#L{a}-L{b}         a source slice within the workspace (line-capped)
```

Every `trace://` run id must be a single safe path segment, and every
`source://` path is resolved through workspace-root containment, so a crafted URI
cannot escape the workspace or read arbitrary files.

## Tools

### Read-only (always available)

| Tool | Arguments | Returns |
| --- | --- | --- |
| `spanspector.search_traces` | `run_id`, `field`, `value` | Matching records. |
| `spanspector.get_failure_context` | `run_id`, `span_id` | A span's events + source. |
| `spanspector.summarize_run` | `run_id` | `RunSummary`. |
| `spanspector.suggest_tests` | `run_id` | Aggregated, deterministic test hints. |
| `spanspector.find_untested_spans` | `run_id` | Closed spans with no test hints. |

### Command tools (opt-in: `--allow-commands`)

| Tool | Runs |
| --- | --- |
| `spanspector.run_focused_tests` | `cargo test [filter]` |
| `spanspector.run_clippy` | `cargo clippy --message-format=json` |
| `spanspector.run_security_audit` | `cargo audit --json` |

When command tools are disabled, they are hidden from `tools/list` and a
`tools/call` to one returns a JSON-RPC "method not found" error (`-32601`).

## Example exchange

```json
→ {"jsonrpc":"2.0","id":1,"method":"tools/call",
   "params":{"name":"spanspector.summarize_run","arguments":{"run_id":"run-1"}}}
← {"jsonrpc":"2.0","id":1,"result":{
     "content":[{"type":"text","text":"{\"run_id\":\"run-1\",\"errors\":1,…}"}],
     "isError":false}}
```

Tool results are returned as a single `text` content item holding the JSON
payload, so a host can parse the inner object directly. Errors use standard
JSON-RPC codes: `-32700` (parse), `-32600` (invalid request), `-32601` (unknown
method/tool), `-32602` (invalid params), `-32000` (server error). Error messages
include remediation hints and never echo raw command output or file contents.
