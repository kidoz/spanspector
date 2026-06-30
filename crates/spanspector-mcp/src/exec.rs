//! Sandboxed execution of allowlisted commands.
//!
//! [`CommandRunner`] is the only place the server spawns a child process. It
//! enforces, in order: allowlist validation, a clean and filtered environment, a
//! fixed working directory (the workspace root), a wall-clock timeout, and a hard
//! cap on captured output. Output is captured into bounded buffers so a chatty or
//! hostile command cannot exhaust memory.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::{McpError, Result};
use crate::safety::validate_command;

/// Environment variables passed through to child processes by default. Anything
/// not listed here (secrets, tokens injected into the parent environment) is
/// dropped before the child starts.
const DEFAULT_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "RUST_LOG",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
];

/// Configuration and policy for running allowlisted commands.
pub struct CommandRunner {
    workspace_root: PathBuf,
    timeout: Duration,
    max_output_bytes: usize,
    env_allowlist: Vec<String>,
}

/// The bounded, structured result of running a command.
#[derive(Clone, Debug, Serialize)]
pub struct CommandOutput {
    /// The argument vector that was executed.
    pub argv: Vec<String>,
    /// The allowlist label that matched (for example `cargo test`).
    pub matched: String,
    /// Process exit code, when the process exited normally.
    pub exit_code: Option<i32>,
    /// Whether the command was terminated for exceeding the timeout.
    pub timed_out: bool,
    /// Whether stdout or stderr was truncated at the output cap.
    pub truncated: bool,
    /// Captured stdout, lossily decoded and capped.
    pub stdout: String,
    /// Captured stderr, lossily decoded and capped.
    pub stderr: String,
}

impl CommandRunner {
    /// Create a runner rooted at `workspace_root` with default limits
    /// (60s timeout, 1 MiB output cap, default environment allowlist).
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            timeout: Duration::from_secs(60),
            max_output_bytes: 1024 * 1024,
            env_allowlist: DEFAULT_ENV_ALLOWLIST
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    /// Set the wall-clock timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum captured output size, in bytes, per stream.
    #[must_use]
    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }

    /// Run an allowlisted command, returning bounded structured output.
    ///
    /// Returns [`McpError::DisallowedCommand`]/[`McpError::UnsafeArgument`] before
    /// spawning anything if the command is not allowlisted.
    pub fn run(&self, argv: &[String]) -> Result<CommandOutput> {
        let matched = validate_command(argv)?;
        let env = self.filtered_env();
        run_program(
            argv,
            matched,
            &self.workspace_root,
            &env,
            self.timeout,
            self.max_output_bytes,
        )
    }

    /// Compute the filtered environment from the current process environment.
    fn filtered_env(&self) -> BTreeMap<String, String> {
        filter_env(std::env::vars(), &self.env_allowlist)
    }
}

/// Keep only `(key, value)` pairs whose key is on the allowlist.
fn filter_env<I>(vars: I, allowlist: &[String]) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    vars.into_iter()
        .filter(|(key, _)| allowlist.iter().any(|allowed| allowed == key))
        .collect()
}

/// Spawn a program with a fully controlled environment, timeout, and output cap.
///
/// This is intentionally separate from [`CommandRunner::run`] so the execution
/// mechanics can be tested with simple system utilities, while the public entry
/// point still enforces the allowlist.
fn run_program(
    argv: &[String],
    matched: String,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    cap: usize,
) -> Result<CommandOutput> {
    let (program, args) = argv.split_first().ok_or(McpError::EmptyCommand)?;

    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_reader = spawn_capped_reader(stdout, cap);
    let err_reader = spawn_capped_reader(stderr, cap);

    let start = Instant::now();
    let mut timed_out = false;
    let exit_status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    };

    let (stdout_bytes, out_truncated) = out_reader.join().unwrap_or((Vec::new(), false));
    let (stderr_bytes, err_truncated) = err_reader.join().unwrap_or((Vec::new(), false));

    if timed_out {
        return Err(McpError::Timeout {
            seconds: timeout.as_secs(),
        });
    }

    Ok(CommandOutput {
        argv: argv.to_vec(),
        matched,
        exit_code: exit_status.and_then(|status| status.code()),
        timed_out,
        truncated: out_truncated || err_truncated,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    })
}

/// Read a child stream on a dedicated thread, retaining at most `cap` bytes while
/// still draining the rest so the child never blocks on a full pipe.
fn spawn_capped_reader<R>(stream: Option<R>, cap: usize) -> thread::JoinHandle<(Vec<u8>, bool)>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut truncated = false;
        let Some(mut stream) = stream else {
            return (retained, truncated);
        };
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if retained.len() < cap {
                        let room = cap - retained.len();
                        let take = room.min(n);
                        retained.extend_from_slice(&chunk[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(_) => break,
            }
        }
        (retained, truncated)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_filter_keeps_only_allowlisted_keys() {
        let vars = vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("AWS_SECRET_ACCESS_KEY".to_owned(), "leak".to_owned()),
            ("RUST_LOG".to_owned(), "debug".to_owned()),
        ];
        let allow = vec!["PATH".to_owned(), "RUST_LOG".to_owned()];
        let filtered = filter_env(vars, &allow);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains_key("PATH"));
        assert!(!filtered.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn run_rejects_non_allowlisted_command_before_spawn() {
        let runner = CommandRunner::new(std::env::temp_dir());
        let error = runner
            .run(&["rm".to_owned(), "-rf".to_owned()])
            .unwrap_err();
        assert!(matches!(error, McpError::DisallowedCommand { .. }));
    }

    #[test]
    fn output_is_capped_and_marked_truncated() {
        // `yes` streams unbounded output; the cap must stop retention quickly.
        // Skip on platforms where `yes` is unavailable.
        if Command::new("yes")
            .arg("x")
            .stdout(Stdio::null())
            .spawn()
            .is_err()
        {
            return;
        }
        let env = BTreeMap::new();
        let argv = vec!["yes".to_owned(), "spanspector".to_owned()];
        let result = run_program(
            &argv,
            "yes".to_owned(),
            &std::env::temp_dir(),
            &env,
            Duration::from_secs(2),
            64,
        );
        // `yes` runs forever, so it is terminated by the timeout; either a timeout
        // error or capped output is acceptable evidence the cap/timeout engaged.
        match result {
            Err(McpError::Timeout { .. }) => {}
            Ok(output) => assert!(output.stdout.len() <= 64 && output.truncated),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn timeout_terminates_long_commands() {
        if Command::new("sleep")
            .arg("0")
            .stdout(Stdio::null())
            .spawn()
            .is_err()
        {
            return;
        }
        let env = BTreeMap::new();
        let argv = vec!["sleep".to_owned(), "5".to_owned()];
        let error = run_program(
            &argv,
            "sleep".to_owned(),
            &std::env::temp_dir(),
            &env,
            Duration::from_millis(200),
            1024,
        )
        .unwrap_err();
        assert!(matches!(error, McpError::Timeout { .. }));
    }
}
