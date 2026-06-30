//! Schema validation and JSONL conversion errors.

use thiserror::Error;

/// Result type used by schema APIs.
pub type Result<T> = std::result::Result<T, SchemaError>;

/// Errors returned by schema validation and JSONL conversion.
///
/// Error values never embed the original line contents or field values, so a
/// malformed or hostile input cannot leak secrets through an error message.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// A trace record used an unsupported schema identifier.
    #[error("unsupported trace schema `{actual}`; expected `{expected}`")]
    UnsupportedSchema {
        /// Schema expected by this crate.
        expected: &'static str,
        /// Schema found in input.
        actual: String,
    },

    /// A required field was empty or whitespace-only.
    #[error("required field `{field}` must not be empty")]
    EmptyRequiredField {
        /// Stable path to the invalid field.
        field: &'static str,
    },

    /// A field whose key is classified as sensitive was not redacted.
    #[error("sensitive field `{field}` must be represented as a redacted value")]
    UnredactedSensitiveField {
        /// Field key that matched redaction rules.
        field: String,
    },

    /// A JSONL line was empty or contained only whitespace.
    #[error("jsonl line is empty")]
    EmptyJsonLine,

    /// JSON serialization or parsing failed.
    #[error("json conversion failed: {0}")]
    Json(#[from] serde_json::Error),
}
