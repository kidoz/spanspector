//! `spanspector` — the SpanSpector command-line interface.
//!
//! Subcommands operate on `spanspector-trace/v1` JSONL evidence:
//!
//! - `validate` — parse and validate JSONL, reporting malformed lines.
//! - `summarize` — compute a deterministic [`RunSummary`] across files.
//! - `search` — print records whose field matches a value.
//! - `serve` — run the local MCP stdio server.
//!
//! [`RunSummary`]: spanspector_schema::RunSummary

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// AI-ready tracing diagnostics for Rust.
#[derive(Debug, Parser)]
#[command(name = "spanspector", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate JSONL trace files, reporting malformed lines.
    Validate {
        /// One or more `.jsonl` files to validate.
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Summarize one or more JSONL trace files as JSON.
    Summarize {
        /// One or more `.jsonl` files to summarize.
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Print records whose field equals a value.
    Search {
        /// Field name (`name`, `span_id`, `trace_id`, or an `event.fields` key).
        #[arg(long)]
        field: String,
        /// Value to match.
        #[arg(long)]
        value: String,
        /// One or more `.jsonl` files to search.
        #[arg(required = true)]
        files: Vec<String>,
    },
    /// Serve evidence over the local MCP stdio protocol.
    Serve {
        /// Directory holding `<run_id>/trace.jsonl` runs.
        #[arg(long)]
        runs_dir: String,
        /// Workspace root for `source://` resolution (defaults to current dir).
        #[arg(long)]
        workspace: Option<String>,
        /// Enable the allowlisted command-running tools (opt-in).
        #[arg(long, default_value_t = false)]
        allow_commands: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate { files } => commands::validate(&files),
        Command::Summarize { files } => commands::summarize(&files),
        Command::Search {
            field,
            value,
            files,
        } => commands::search(&field, &value, &files),
        Command::Serve {
            runs_dir,
            workspace,
            allow_commands,
        } => commands::serve(&runs_dir, workspace.as_deref(), allow_commands),
    }
}
