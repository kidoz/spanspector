//! Tool implementations.
//!
//! Read-only tools answer triage questions directly from stored evidence.
//! Command tools run only allowlisted cargo invocations through the
//! [`CommandRunner`] and are exposed only when the server is explicitly built
//! with command execution enabled.

use serde_json::{Value, json};
use spanspector_schema::{EventKind, FieldValue, TraceRecord};

use crate::error::{McpError, Result};
use crate::exec::CommandRunner;
use crate::resources::ResourceRegistry;

/// Names of the read-only tools, always available.
pub const READ_ONLY_TOOLS: &[&str] = &[
    "spanspector.search_traces",
    "spanspector.get_failure_context",
    "spanspector.summarize_run",
    "spanspector.suggest_tests",
    "spanspector.find_untested_spans",
];

/// Names of the command-running tools, available only with execution enabled.
pub const COMMAND_TOOLS: &[&str] = &[
    "spanspector.run_focused_tests",
    "spanspector.run_clippy",
    "spanspector.run_security_audit",
];

/// Dispatch a read-only tool by name.
pub(crate) fn call_read_only(
    registry: &ResourceRegistry,
    name: &str,
    args: &Value,
) -> Result<Value> {
    match name {
        "spanspector.search_traces" => search_traces(registry, args),
        "spanspector.get_failure_context" => get_failure_context(registry, args),
        "spanspector.summarize_run" => {
            let run_id = string_arg(args, "run_id")?;
            Ok(serde_json::to_value(registry.summarize(&run_id)?)?)
        }
        "spanspector.suggest_tests" => suggest_tests(registry, args),
        "spanspector.find_untested_spans" => find_untested_spans(registry, args),
        _ => Err(McpError::UnknownMethod {
            name: name.to_owned(),
        }),
    }
}

/// Dispatch a command tool by name.
pub(crate) fn call_command(runner: &CommandRunner, name: &str, args: &Value) -> Result<Value> {
    let argv = match name {
        "spanspector.run_focused_tests" => {
            let mut argv = vec!["cargo".to_owned(), "test".to_owned()];
            if let Some(filter) = optional_string_arg(args, "test_filter")? {
                argv.push(filter);
            }
            argv
        }
        "spanspector.run_clippy" => vec![
            "cargo".to_owned(),
            "clippy".to_owned(),
            "--message-format=json".to_owned(),
        ],
        "spanspector.run_security_audit" => {
            vec!["cargo".to_owned(), "audit".to_owned(), "--json".to_owned()]
        }
        _ => {
            return Err(McpError::UnknownMethod {
                name: name.to_owned(),
            });
        }
    };
    Ok(serde_json::to_value(runner.run(&argv)?)?)
}

fn search_traces(registry: &ResourceRegistry, args: &Value) -> Result<Value> {
    let run_id = string_arg(args, "run_id")?;
    let field = string_arg(args, "field")?;
    let value = string_arg(args, "value")?;
    let records = registry.records(&run_id)?;
    let matched: Vec<&TraceRecord> = records
        .iter()
        .filter(|record| field_matches(record, &field, &value))
        .collect();
    Ok(serde_json::to_value(matched)?)
}

fn get_failure_context(registry: &ResourceRegistry, args: &Value) -> Result<Value> {
    let run_id = string_arg(args, "run_id")?;
    let span_id = string_arg(args, "span_id")?;
    let records = registry.records(&run_id)?;
    let related: Vec<&TraceRecord> = records
        .iter()
        .filter(|record| record.event.span_id == span_id)
        .collect();
    if related.is_empty() {
        return Err(McpError::NotFound {
            what: format!("span {span_id} in run {run_id}"),
        });
    }
    let source = related
        .iter()
        .find_map(|record| record.event.source.as_ref());
    Ok(json!({
        "run_id": run_id,
        "span_id": span_id,
        "events": related,
        "source": source,
    }))
}

fn suggest_tests(registry: &ResourceRegistry, args: &Value) -> Result<Value> {
    let run_id = string_arg(args, "run_id")?;
    let records = registry.records(&run_id)?;
    let mut hints: Vec<Value> = Vec::new();
    for record in &records {
        for hint in &record.event.test_hints {
            hints.push(json!({
                "span_id": record.event.span_id,
                "name": record.event.name,
                "hint": hint,
                "repro": record.event.repro,
            }));
        }
    }
    // Deterministic order: by suggested test name, then span id.
    hints.sort_by(|a, b| {
        let a_key = (
            a["hint"]["suggested_name"].as_str().unwrap_or_default(),
            a["span_id"].as_str().unwrap_or_default(),
        );
        let b_key = (
            b["hint"]["suggested_name"].as_str().unwrap_or_default(),
            b["span_id"].as_str().unwrap_or_default(),
        );
        a_key.cmp(&b_key)
    });
    Ok(Value::Array(hints))
}

fn find_untested_spans(registry: &ResourceRegistry, args: &Value) -> Result<Value> {
    let run_id = string_arg(args, "run_id")?;
    let records = registry.records(&run_id)?;
    let mut spans: Vec<Value> = records
        .iter()
        .filter(|record| {
            record.event.kind == EventKind::SpanClosed && record.event.test_hints.is_empty()
        })
        .map(|record| {
            json!({
                "span_id": record.event.span_id,
                "name": record.event.name,
                "status": record.event.status,
                "source": record.event.source,
            })
        })
        .collect();
    spans.sort_by(|a, b| {
        a["span_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["span_id"].as_str().unwrap_or_default())
    });
    Ok(Value::Array(spans))
}

/// Match a record against a `field == value` query over its textual fields,
/// plus a small set of structural shortcuts (`name`, `status`, `span_id`).
fn field_matches(record: &TraceRecord, field: &str, value: &str) -> bool {
    match field {
        "name" => record.event.name == value,
        "span_id" => record.event.span_id == value,
        "trace_id" => record.event.trace_id == value,
        _ => match record.event.fields.get(field) {
            Some(FieldValue::Text(text)) => text == value,
            Some(FieldValue::Bool(flag)) => flag.to_string() == value,
            Some(FieldValue::Integer(number)) => number.to_string() == value,
            _ => false,
        },
    }
}

fn string_arg(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| McpError::InvalidParams {
            detail: format!("missing string argument `{key}`"),
        })
}

fn optional_string_arg(args: &Value, key: &str) -> Result<Option<String>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(McpError::InvalidParams {
            detail: format!("argument `{key}` must be a string"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(name: &str, text: &str) -> (PathBuf, ResourceRegistry) {
        let base =
            std::env::temp_dir().join(format!("spanspector-tools-{}-{name}", std::process::id()));
        let run_dir = base.join("runs").join("run-1");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join("trace.jsonl"), text).unwrap();
        let registry = ResourceRegistry::new(base.join("runs"), &base);
        (base, registry)
    }

    fn sample() -> String {
        let tested = r#"{"schema":"spanspector-trace/v1","run":{"id":"run-1"},"event":{"kind":"span_closed","trace_id":"t","span_id":"s1","name":"order.create","target":"app","level":"INFO","status":"error","fields":{"ai.kind":"command"},"test_hints":[{"kind":"regression","suggested_name":"rejects_bad_total","assert":"rejects"}]}}"#;
        let untested = r#"{"schema":"spanspector-trace/v1","run":{"id":"run-1"},"event":{"kind":"span_closed","trace_id":"t","span_id":"s2","name":"order.read","target":"app","level":"INFO","status":"ok"}}"#;
        format!("{tested}\n{untested}\n")
    }

    #[test]
    fn search_matches_structural_and_field_queries() {
        let (base, registry) = fixture("search", &sample());
        let by_name = call_read_only(
            &registry,
            "spanspector.search_traces",
            &json!({"run_id":"run-1","field":"name","value":"order.create"}),
        )
        .unwrap();
        assert_eq!(by_name.as_array().unwrap().len(), 1);
        let by_field = call_read_only(
            &registry,
            "spanspector.search_traces",
            &json!({"run_id":"run-1","field":"ai.kind","value":"command"}),
        )
        .unwrap();
        assert_eq!(by_field.as_array().unwrap().len(), 1);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn find_untested_spans_excludes_hinted_spans() {
        let (base, registry) = fixture("untested", &sample());
        let untested = call_read_only(
            &registry,
            "spanspector.find_untested_spans",
            &json!({"run_id":"run-1"}),
        )
        .unwrap();
        let array = untested.as_array().unwrap();
        assert_eq!(array.len(), 1);
        assert_eq!(array[0]["span_id"], "s2");
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn suggest_tests_is_deterministic() {
        let (base, registry) = fixture("suggest", &sample());
        let first = call_read_only(
            &registry,
            "spanspector.suggest_tests",
            &json!({"run_id":"run-1"}),
        )
        .unwrap();
        let second = call_read_only(
            &registry,
            "spanspector.suggest_tests",
            &json!({"run_id":"run-1"}),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_array().unwrap().len(), 1);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn missing_argument_is_invalid_params() {
        let (base, registry) = fixture("missing", &sample());
        let error = call_read_only(&registry, "spanspector.summarize_run", &json!({})).unwrap_err();
        assert!(matches!(error, McpError::InvalidParams { .. }));
        fs::remove_dir_all(&base).ok();
    }
}
