//! A minimal, synchronous, local JSON-RPC 2.0 server over stdio.
//!
//! This is intentionally not a network service: it reads line-delimited JSON-RPC
//! requests from a reader and writes responses to a writer, which a local MCP
//! host drives over a child process's stdio. There is no listener, no port, and
//! no async runtime, so the "network listeners disabled by default" rule holds by
//! construction. Command tools are exposed only when the server is explicitly
//! built with [`Server::with_commands`].

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::error::McpError;
use crate::exec::CommandRunner;
use crate::resources::ResourceRegistry;
use crate::tools;

/// Server name reported in `initialize`.
const SERVER_NAME: &str = "spanspector-mcp";
/// Server version reported in `initialize`.
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A local SpanSpector MCP server.
pub struct Server {
    resources: ResourceRegistry,
    runner: CommandRunner,
    allow_commands: bool,
}

impl Server {
    /// Create a read-only server. Command tools are disabled until
    /// [`Server::with_commands`] opts in.
    pub fn new(resources: ResourceRegistry, runner: CommandRunner) -> Self {
        Self {
            resources,
            runner,
            allow_commands: false,
        }
    }

    /// Enable or disable the allowlisted command tools.
    #[must_use]
    pub fn with_commands(mut self, allow_commands: bool) -> Self {
        self.allow_commands = allow_commands;
        self
    }

    /// Serve line-delimited JSON-RPC requests until the reader is exhausted.
    ///
    /// Each input line is one request; each output line is one response. Blank
    /// lines are ignored. A malformed line yields a JSON-RPC parse error response
    /// rather than aborting the loop.
    pub fn serve<R: BufRead, W: Write>(&self, reader: R, mut writer: W) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let response = self.handle_line(&line);
            writer.write_all(response.to_string().as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        Ok(())
    }

    /// Handle one raw request line, returning the JSON-RPC response value.
    pub fn handle_line(&self, line: &str) -> Value {
        match serde_json::from_str::<Value>(line) {
            Ok(request) => self.handle_request(&request),
            Err(_) => error_response(&Value::Null, -32700, "parse error: invalid JSON"),
        }
    }

    /// Handle one parsed JSON-RPC request value.
    pub fn handle_request(&self, request: &Value) -> Value {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            return error_response(&id, -32600, "invalid request: missing method");
        };
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let result = match method {
            "initialize" => Ok(self.initialize()),
            "resources/list" => self.list_resources(),
            "resources/read" => self.read_resource(&params),
            "tools/list" => Ok(self.list_tools()),
            "tools/call" => self.call_tool(&params),
            other => Err(McpError::UnknownMethod {
                name: other.to_owned(),
            }),
        };

        match result {
            Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
            Err(error) => {
                let (code, message) = rpc_error(&error);
                error_response(&id, code, &message)
            }
        }
    }

    fn initialize(&self) -> Value {
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "resources": {}, "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
        })
    }

    fn list_resources(&self) -> Result<Value, McpError> {
        let runs = self.resources.list_runs()?;
        let mut resources = vec![json!({
            "uri": "trace://runs",
            "name": "Trace runs",
            "mimeType": "application/json",
        })];
        for run in runs {
            resources.push(json!({
                "uri": format!("trace://runs/{run}/summary"),
                "name": format!("Run {run} summary"),
                "mimeType": "application/json",
            }));
            resources.push(json!({
                "uri": format!("trace://runs/{run}/events"),
                "name": format!("Run {run} events"),
                "mimeType": "application/x-ndjson",
            }));
        }
        Ok(json!({ "resources": resources }))
    }

    fn read_resource(&self, params: &Value) -> Result<Value, McpError> {
        let uri =
            params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams {
                    detail: "missing `uri`".to_owned(),
                })?;
        let contents = self.resources.read(uri)?;
        Ok(json!({
            "contents": [{
                "uri": contents.uri,
                "mimeType": contents.mime_type,
                "text": contents.text,
                "truncated": contents.truncated,
            }],
        }))
    }

    fn list_tools(&self) -> Value {
        let mut tools = read_only_tool_defs();
        if self.allow_commands {
            tools.extend(command_tool_defs());
        }
        json!({ "tools": tools })
    }

    fn call_tool(&self, params: &Value) -> Result<Value, McpError> {
        let name =
            params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::InvalidParams {
                    detail: "missing tool `name`".to_owned(),
                })?;
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        let payload = if tools::READ_ONLY_TOOLS.contains(&name) {
            tools::call_read_only(&self.resources, name, &args)?
        } else if tools::COMMAND_TOOLS.contains(&name) {
            if !self.allow_commands {
                return Err(McpError::UnknownMethod {
                    name: name.to_owned(),
                });
            }
            tools::call_command(&self.runner, name, &args)?
        } else {
            return Err(McpError::UnknownMethod {
                name: name.to_owned(),
            });
        };

        // MCP tool results are returned as text content holding the JSON payload.
        Ok(json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&payload)? }],
            "isError": false,
        }))
    }
}

fn read_only_tool_defs() -> Vec<Value> {
    vec![
        json!({
            "name": "spanspector.search_traces",
            "description": "Find events in a run where a field equals a value.",
            "inputSchema": object_schema(&[("run_id", true), ("field", true), ("value", true)]),
        }),
        json!({
            "name": "spanspector.get_failure_context",
            "description": "Return the events and source location for one span.",
            "inputSchema": object_schema(&[("run_id", true), ("span_id", true)]),
        }),
        json!({
            "name": "spanspector.summarize_run",
            "description": "Compute a deterministic summary of a run.",
            "inputSchema": object_schema(&[("run_id", true)]),
        }),
        json!({
            "name": "spanspector.suggest_tests",
            "description": "Aggregate test hints observed across a run.",
            "inputSchema": object_schema(&[("run_id", true)]),
        }),
        json!({
            "name": "spanspector.find_untested_spans",
            "description": "List closed spans that carry no test hints.",
            "inputSchema": object_schema(&[("run_id", true)]),
        }),
    ]
}

fn command_tool_defs() -> Vec<Value> {
    vec![
        json!({
            "name": "spanspector.run_focused_tests",
            "description": "Run `cargo test [filter]` in the workspace (allowlisted).",
            "inputSchema": object_schema(&[("test_filter", false)]),
        }),
        json!({
            "name": "spanspector.run_clippy",
            "description": "Run `cargo clippy --message-format=json` (allowlisted).",
            "inputSchema": object_schema(&[]),
        }),
        json!({
            "name": "spanspector.run_security_audit",
            "description": "Run `cargo audit --json` (allowlisted).",
            "inputSchema": object_schema(&[]),
        }),
    ]
}

/// Build a minimal JSON Schema object for a tool's inputs.
fn object_schema(fields: &[(&str, bool)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, is_required) in fields {
        properties.insert((*name).to_owned(), json!({ "type": "string" }));
        if *is_required {
            required.push(Value::String((*name).to_owned()));
        }
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
    })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// Map a domain error to a JSON-RPC error code and message.
fn rpc_error(error: &McpError) -> (i64, String) {
    let code = match error {
        McpError::InvalidParams { .. } => -32602,
        McpError::UnknownMethod { .. } => -32601,
        McpError::Json(_) => -32700,
        _ => -32000,
    };
    (code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn unique() -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn server(text: &str) -> (PathBuf, Server) {
        let base = std::env::temp_dir().join(format!(
            "spanspector-server-{}-{}",
            std::process::id(),
            unique()
        ));
        let run_dir = base.join("runs").join("run-1");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join("trace.jsonl"), text).unwrap();
        let registry = ResourceRegistry::new(base.join("runs"), &base);
        let runner = CommandRunner::new(&base);
        (base, Server::new(registry, runner))
    }

    fn sample() -> String {
        let line = r#"{"schema":"spanspector-trace/v1","run":{"id":"run-1"},"event":{"kind":"span_closed","trace_id":"t","span_id":"s1","name":"order.create","target":"app","level":"INFO","status":"error","fields":{"error.kind":"validation_error"}}}"#;
        format!("{line}\n")
    }

    fn request(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    #[test]
    fn initialize_reports_server_info() {
        let (base, server) = server(&sample());
        let response = server.handle_request(&request("initialize", Value::Null));
        assert_eq!(response["result"]["serverInfo"]["name"], "spanspector-mcp");
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn command_tools_are_hidden_until_enabled() {
        let (base, server) = server(&sample());
        let listed = server.handle_request(&request("tools/list", Value::Null));
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"spanspector.summarize_run"));
        assert!(!names.contains(&"spanspector.run_clippy"));

        // Calling a command tool while disabled is rejected as unknown.
        let call = server.handle_request(&request(
            "tools/call",
            json!({ "name": "spanspector.run_clippy", "arguments": {} }),
        ));
        assert_eq!(call["error"]["code"], -32601);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn read_resource_returns_summary() {
        let (base, server) = server(&sample());
        let response = server.handle_request(&request(
            "resources/read",
            json!({ "uri": "trace://runs/run-1/summary" }),
        ));
        let text = response["result"]["contents"][0]["text"].as_str().unwrap();
        assert!(text.contains("validation_error"));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn malformed_line_yields_parse_error() {
        let (base, server) = server(&sample());
        let response = server.handle_line("{ not json");
        assert_eq!(response["error"]["code"], -32700);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn tools_call_summarize_returns_text_content() {
        let (base, server) = server(&sample());
        let response = server.handle_request(&request(
            "tools/call",
            json!({ "name": "spanspector.summarize_run", "arguments": { "run_id": "run-1" } }),
        ));
        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"errors\":1"));
        fs::remove_dir_all(&base).ok();
    }
}
