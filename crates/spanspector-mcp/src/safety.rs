//! Command allowlist.
//!
//! SpanSpector never offers a generic `run_shell` tool. Every command that can be
//! executed must match one of a small set of fixed `cargo` prefixes, and every
//! trailing argument must pass a conservative character check. Validation is the
//! single gate all execution goes through, so an attacker-supplied tool argument
//! cannot smuggle in a different program or shell metacharacters.

use crate::error::{McpError, Result};

/// Allowlisted command prefixes. A request is permitted only if its argument
/// vector begins with one of these exact token sequences.
const ALLOWED_PREFIXES: &[&[&str]] = &[
    &["cargo", "test"],
    &["cargo", "nextest", "run"],
    &["cargo", "clippy"],
    &["cargo", "fmt"],
    &["cargo", "llvm-cov"],
    &["cargo", "audit"],
    &["cargo", "deny", "check"],
    &["cargo", "miri", "test"],
    &["cargo", "fuzz", "run"],
    &["cargo", "bench"],
];

/// Validate an argument vector against the allowlist.
///
/// Returns the canonical matched prefix (as a space-joined label) on success.
/// Even though commands are executed without a shell — so metacharacters are not
/// interpreted — arguments are still character-checked to keep tool inputs
/// predictable and auditable.
pub fn validate_command(argv: &[String]) -> Result<String> {
    if argv.is_empty() {
        return Err(McpError::EmptyCommand);
    }

    for argument in argv {
        if !is_safe_arg(argument) {
            return Err(McpError::UnsafeArgument {
                argument: argument.clone(),
            });
        }
    }

    let matched = ALLOWED_PREFIXES
        .iter()
        .find(|prefix| starts_with(argv, prefix));

    match matched {
        Some(prefix) => Ok(prefix.join(" ")),
        None => Err(McpError::DisallowedCommand {
            command: argv.join(" "),
        }),
    }
}

/// Convenience predicate over [`validate_command`].
pub fn is_allowed(argv: &[String]) -> bool {
    validate_command(argv).is_ok()
}

fn starts_with(argv: &[String], prefix: &[&str]) -> bool {
    argv.len() >= prefix.len()
        && argv
            .iter()
            .zip(prefix)
            .all(|(arg, expected)| arg == expected)
}

/// A trailing argument is safe when it contains only characters that appear in
/// ordinary cargo invocations (flags, paths, test names, feature lists). This
/// rejects shell metacharacters, whitespace, and control characters outright.
fn is_safe_arg(arg: &str) -> bool {
    !arg.is_empty()
        && arg.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_' | '.' | '/' | '=' | ':' | ',' | '+')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn allows_documented_safe_commands() {
        for command in [
            &["cargo", "test"][..],
            &["cargo", "test", "my_test", "--no-run"][..],
            &["cargo", "nextest", "run"][..],
            &["cargo", "clippy", "--message-format=json"][..],
            &["cargo", "audit", "--json"][..],
            &["cargo", "deny", "check"][..],
            &["cargo", "fuzz", "run", "parse_target"][..],
            &["cargo", "bench", "--bench", "throughput"][..],
        ] {
            assert!(is_allowed(&argv(command)), "{command:?} should be allowed");
        }
    }

    #[test]
    fn rejects_non_allowlisted_programs() {
        for command in [
            &["rm", "-rf", "/"][..],
            &["bash", "-c", "echo"][..],
            &["cargo", "install", "ripgrep"][..],
            &["cargo", "run"][..],
            &["cargo"][..],
        ] {
            assert!(
                !is_allowed(&argv(command)),
                "{command:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_shell_metacharacters_in_arguments() {
        for bad in ["test;rm", "test|cat", "$(whoami)", "a b", "back`tick`"] {
            let command = argv(&["cargo", "test", bad]);
            let error = validate_command(&command).unwrap_err();
            assert!(matches!(error, McpError::UnsafeArgument { .. }));
        }
    }

    #[test]
    fn empty_command_is_rejected() {
        assert!(matches!(
            validate_command(&[]).unwrap_err(),
            McpError::EmptyCommand
        ));
    }
}
