//! Integration test against the committed example fixture at
//! `tests/fixtures/example-run/trace.jsonl`, exercising the read-only server
//! end to end on real on-disk evidence.

use std::path::PathBuf;

use serde_json::{Value, json};
use spanspector_mcp::{CommandRunner, ResourceRegistry, Server};

/// Repo root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn server() -> Server {
    let root = repo_root();
    let runs_dir = root.join("tests").join("fixtures");
    let registry = ResourceRegistry::new(runs_dir, &root);
    Server::new(registry, CommandRunner::new(&root))
}

fn request(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

#[test]
fn fixture_summary_reports_the_failed_validation() {
    let response = server().handle_request(&request(
        "resources/read",
        json!({ "uri": "trace://runs/example-run/summary" }),
    ));
    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .expect("summary text");
    let summary: Value = serde_json::from_str(text).expect("summary json");

    assert_eq!(summary["run_id"], "2026-06-27T10-15-32Z-local");
    assert_eq!(summary["total_events"], 2);
    assert_eq!(summary["errors"], 2);
    assert_eq!(summary["error_kinds"]["validation_error"], 1);
    assert_eq!(summary["security_decisions"]["validation:reject"], 1);
}

#[test]
fn fixture_span_is_served_with_redacted_token() {
    let response = server().handle_request(&request(
        "resources/read",
        json!({ "uri": "trace://runs/example-run/span/1" }),
    ));
    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .expect("span text");

    // The sensitive value never appears; the redacted marker and digest do.
    assert!(!text.contains("do-not-log-me"));
    assert!(text.contains("\"redacted\""));
    assert!(text.contains("sha256:"));
}

#[test]
fn fixture_events_resource_is_valid_ndjson() {
    let response = server().handle_request(&request(
        "resources/read",
        json!({ "uri": "trace://runs/example-run/events" }),
    ));
    let text = response["result"]["contents"][0]["text"]
        .as_str()
        .expect("events text");
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        let _: Value = serde_json::from_str(line).expect("each line is valid JSON");
    }
}
