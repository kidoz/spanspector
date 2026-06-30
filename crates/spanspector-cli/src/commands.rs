//! Implementations of the CLI subcommands.

use std::fs::File;
use std::io::{BufReader, Write};
use std::process::exit;

use anyhow::{Context, Result};
use spanspector_mcp::{CommandRunner, ResourceRegistry, Server};
use spanspector_schema::{
    DEFAULT_SLOWEST_SPANS, FieldValue, JsonlLine, RunSummary, TraceRecord, read_jsonl,
    to_jsonl_line,
};

/// Validate JSONL files, printing per-file counts. Exits non-zero on any fault.
pub(crate) fn validate(files: &[String]) -> Result<()> {
    let mut total_records = 0usize;
    let mut total_faults = 0usize;

    for path in files {
        let (records, faults) = scan_file(path)?;
        for (line_number, message) in &faults {
            // Error text is schema-sourced and never includes the raw line.
            eprintln!("{path}:{line_number}: {message}");
        }
        println!("{path}: {} valid, {} malformed", records, faults.len());
        total_records += records;
        total_faults += faults.len();
    }

    println!("total: {total_records} valid, {total_faults} malformed");
    if total_faults > 0 {
        // Surface failure to CI with a non-zero status without panicking.
        exit(1);
    }
    Ok(())
}

/// Summarize all files into one [`RunSummary`] printed as pretty JSON.
pub(crate) fn summarize(files: &[String]) -> Result<()> {
    let mut summary = RunSummary::with_capacity(DEFAULT_SLOWEST_SPANS);
    for path in files {
        let file = open(path)?;
        for line in read_jsonl(BufReader::new(file)) {
            match line {
                JsonlLine::Record(record) => summary.ingest(&record),
                JsonlLine::Fault { .. } => summary.note_malformed(),
            }
        }
    }
    let json = serde_json::to_string_pretty(&summary)?;
    println!("{json}");
    Ok(())
}

/// Print records matching `field == value` as JSONL on stdout.
pub(crate) fn search(field: &str, value: &str, files: &[String]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for path in files {
        let file = open(path)?;
        for line in read_jsonl(BufReader::new(file)) {
            if let JsonlLine::Record(record) = line
                && field_matches(&record, field, value)
            {
                // `to_jsonl_line` re-validates, so output is always well-formed.
                let serialized = to_jsonl_line(&record)?;
                out.write_all(serialized.as_bytes())?;
            }
        }
    }
    out.flush()?;
    Ok(())
}

/// Start the local MCP stdio server.
pub(crate) fn serve(runs_dir: &str, workspace: Option<&str>, allow_commands: bool) -> Result<()> {
    let workspace = workspace
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
        .context("resolving workspace root")?;

    let registry = ResourceRegistry::new(runs_dir, &workspace);
    let runner = CommandRunner::new(&workspace);
    let server = Server::new(registry, runner).with_commands(allow_commands);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    server
        .serve(stdin.lock(), stdout.lock())
        .context("serving MCP requests over stdio")?;
    Ok(())
}

/// Parse a file, returning `(valid_count, faults)` where each fault is its line
/// number and message. Never returns the offending line content.
fn scan_file(path: &str) -> Result<(usize, Vec<(usize, String)>)> {
    let file = open(path)?;
    let mut records = 0usize;
    let mut faults = Vec::new();
    for line in read_jsonl(BufReader::new(file)) {
        match line {
            JsonlLine::Record(_) => records += 1,
            JsonlLine::Fault { line_number, error } => {
                faults.push((line_number, error.to_string()))
            }
        }
    }
    Ok((records, faults))
}

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

fn open(path: &str) -> Result<File> {
    File::open(path).with_context(|| format!("opening {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_temp(name: &str, body: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "spanspector-cli-{}-{}.jsonl",
            std::process::id(),
            name
        ));
        fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn sample() -> String {
        let line = r#"{"schema":"spanspector-trace/v1","run":{"id":"run-1"},"event":{"kind":"span_closed","trace_id":"t","span_id":"s1","name":"order.create","target":"app","level":"INFO","duration_ms":7,"status":"ok","fields":{"ai.kind":"command"}}}"#;
        format!("{line}\n{{ bad }}\n")
    }

    #[test]
    fn scan_file_separates_valid_and_malformed() {
        let path = write_temp("scan", &sample());
        let (records, faults) = scan_file(&path).unwrap();
        assert_eq!(records, 1);
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].0, 2);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn field_matches_structural_and_fields() {
        let path = write_temp("match", &sample());
        let file = open(&path).unwrap();
        let record = read_jsonl(BufReader::new(file))
            .into_iter()
            .find_map(|line| match line {
                JsonlLine::Record(record) => Some(*record),
                JsonlLine::Fault { .. } => None,
            })
            .unwrap();
        assert!(field_matches(&record, "name", "order.create"));
        assert!(field_matches(&record, "ai.kind", "command"));
        assert!(!field_matches(&record, "ai.kind", "query"));
        fs::remove_file(&path).ok();
    }
}
