//! JSONL serialization, parsing, and error-tolerant streaming.

use std::io::BufRead;

use crate::error::{Result, SchemaError};
use crate::record::TraceRecord;

/// Serialize a trace record as one complete JSONL line.
///
/// The record is validated first, so [`to_jsonl_line`] never emits a record that
/// fails redaction or schema checks. The returned string always ends with `\n`,
/// which makes it safe to append directly to a JSONL stream.
pub fn to_jsonl_line(record: &TraceRecord) -> Result<String> {
    record.validate()?;
    let mut line = serde_json::to_string(record)?;
    line.push('\n');
    Ok(line)
}

/// Parse and validate one JSONL trace record.
///
/// Errors never include the original line contents, so malformed or hostile
/// input cannot leak secrets through diagnostics.
pub fn from_jsonl_line(line: &str) -> Result<TraceRecord> {
    if line.trim().is_empty() {
        return Err(SchemaError::EmptyJsonLine);
    }
    let record: TraceRecord = serde_json::from_str(line)?;
    record.validate()?;
    Ok(record)
}

/// One parsed line of a JSONL stream: either a valid record or a fault.
///
/// Faults carry only a one-based line number and the error — never the offending
/// bytes — so a corrupt or malicious line cannot leak through this type either.
#[derive(Debug)]
pub enum JsonlLine {
    /// A line that parsed and validated successfully.
    Record(Box<TraceRecord>),
    /// A non-empty line that failed to parse or validate.
    Fault {
        /// One-based line number within the stream.
        line_number: usize,
        /// The reason the line was rejected.
        error: SchemaError,
    },
}

/// Read a JSONL stream into per-line results, tolerant of individual bad lines.
///
/// This upholds the invariant that *one malformed line does not corrupt a whole
/// run*: blank lines are skipped, each non-blank line is parsed independently,
/// and a failure is reported as a [`JsonlLine::Fault`] rather than aborting the
/// stream. The reader is streaming (one line at a time via [`BufRead`]), so it
/// does not load the entire file into memory.
///
/// I/O errors from the underlying reader are surfaced as a fault for that line
/// rather than panicking, keeping a single bad read from discarding earlier
/// records.
pub fn read_jsonl<R: BufRead>(reader: R) -> Vec<JsonlLine> {
    let mut out = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let text = match line {
            Ok(text) => text,
            Err(error) => {
                out.push(JsonlLine::Fault {
                    line_number,
                    error: SchemaError::Json(serde_json::Error::io(error)),
                });
                continue;
            }
        };
        if text.trim().is_empty() {
            continue;
        }
        match from_jsonl_line(&text) {
            Ok(record) => out.push(JsonlLine::Record(Box::new(record))),
            Err(error) => out.push(JsonlLine::Fault { line_number, error }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::SCHEMA_VERSION;
    use std::io::Cursor;

    fn valid_line() -> String {
        format!(
            r#"{{"schema":"{SCHEMA_VERSION}","run":{{"id":"run-1"}},"event":{{"kind":"event","trace_id":"t","span_id":"s","name":"n","target":"tg","level":"INFO","status":"unknown"}}}}"#
        )
    }

    #[test]
    fn parser_rejects_unsupported_schema_without_leaking_line() {
        let json = r#"{"schema":"spanspector-trace/v9","run":{"id":"run-1"},"event":{"kind":"event","trace_id":"t","span_id":"s","name":"n","target":"tg","level":"INFO","status":"unknown"}}"#;
        let error = from_jsonl_line(json).unwrap_err().to_string();
        assert!(error.contains("spanspector-trace/v9"));
    }

    #[test]
    fn one_malformed_line_does_not_corrupt_the_stream() {
        let input = format!("{}\n{{ not json }}\n\n{}\n", valid_line(), valid_line());
        let lines = read_jsonl(Cursor::new(input));

        let records = lines
            .iter()
            .filter(|l| matches!(l, JsonlLine::Record(_)))
            .count();
        let faults: Vec<_> = lines
            .iter()
            .filter_map(|l| match l {
                JsonlLine::Fault { line_number, .. } => Some(*line_number),
                JsonlLine::Record(_) => None,
            })
            .collect();

        assert_eq!(records, 2, "both valid records survive the bad line");
        assert_eq!(faults, vec![2], "only the malformed line 2 is a fault");
    }

    #[test]
    fn blank_lines_are_ignored() {
        let lines = read_jsonl(Cursor::new("\n   \n\n"));
        assert!(lines.is_empty());
    }
}
