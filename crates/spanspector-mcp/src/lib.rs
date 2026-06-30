//! A safe, local MCP-style diagnostics server for SpanSpector evidence.
//!
//! The server exposes runtime evidence to AI agents without granting unsafe
//! access. Its safety properties are structural, not advisory:
//!
//! - **No network.** [`Server`] reads JSON-RPC from a reader and writes to a
//!   writer; there is no listener or port. A local host drives it over stdio.
//! - **Read-only by default.** Command tools are hidden and rejected unless the
//!   server is built with [`Server::with_commands`].
//! - **Allowlisted commands only.** Every execution passes [`validate_command`];
//!   there is no `run_shell`. See [`CommandRunner`] for timeout, output-cap, and
//!   environment-filtering controls.
//! - **No path traversal.** Resource and source paths resolve through
//!   [`canonical_within`], which keeps every access under the workspace root.

mod error;
mod exec;
mod path;
mod resources;
mod safety;
mod server;
mod tools;

pub use error::{McpError, Result};
pub use exec::{CommandOutput, CommandRunner};
pub use path::{canonical_within, validate_segment};
pub use resources::{ResourceContents, ResourceRegistry};
pub use safety::{is_allowed, validate_command};
pub use server::Server;
pub use tools::{COMMAND_TOOLS, READ_ONLY_TOOLS};
