//! Errors for the MCP server. Messages are remediation-oriented and never embed
//! raw command output or file contents.

use thiserror::Error;

/// Result type used across the MCP crate.
pub type Result<T> = std::result::Result<T, McpError>;

/// Errors produced by command-safety, path-safety, resources, and the server.
#[derive(Debug, Error)]
pub enum McpError {
    /// The requested command was empty.
    #[error("empty command: provide a cargo subcommand from the allowlist")]
    EmptyCommand,

    /// The requested command is not on the allowlist.
    #[error("command `{command}` is not allowlisted; see the documented safe command set")]
    DisallowedCommand {
        /// The rejected command, rendered as a single safe label.
        command: String,
    },

    /// A command argument contained unsafe characters.
    #[error("argument `{argument}` contains characters that are not permitted")]
    UnsafeArgument {
        /// The rejected argument.
        argument: String,
    },

    /// A path resolved outside the workspace root.
    #[error("path `{path}` escapes the workspace root and was refused")]
    WorkspaceEscape {
        /// The offending request path (not the resolved absolute path).
        path: String,
    },

    /// A run identifier was not a single safe path segment.
    #[error("run id `{run_id}` is not a valid single path segment")]
    InvalidRunId {
        /// The rejected run id.
        run_id: String,
    },

    /// A requested path or run did not exist.
    #[error("resource `{what}` was not found")]
    NotFound {
        /// What was missing (a uri, run id, or path).
        what: String,
    },

    /// A resource URI could not be parsed or is unsupported.
    #[error("unsupported or malformed resource uri `{uri}`")]
    InvalidResourceUri {
        /// The offending URI.
        uri: String,
    },

    /// A tool or method received missing or malformed parameters.
    #[error("invalid parameters: {detail}")]
    InvalidParams {
        /// What was wrong with the parameters.
        detail: String,
    },

    /// A tool or method name was not recognized, or is disabled.
    #[error("unknown or disabled method/tool `{name}`")]
    UnknownMethod {
        /// The unrecognized name.
        name: String,
    },

    /// The command timed out before completing.
    #[error("command timed out after {seconds} seconds and was terminated")]
    Timeout {
        /// Configured timeout in seconds.
        seconds: u64,
    },

    /// An I/O failure. The message is the OS error kind, never file contents.
    #[error("io error: {0}")]
    Io(String),

    /// Schema parsing or validation failed.
    #[error("schema error: {0}")]
    Schema(#[from] spanspector_schema::SchemaError),

    /// JSON-RPC request/response (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<std::io::Error> for McpError {
    fn from(value: std::io::Error) -> Self {
        // Carry only the error kind, not any path or payload the OS may include.
        McpError::Io(value.kind().to_string())
    }
}
