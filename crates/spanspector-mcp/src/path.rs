//! Path-traversal-safe resolution within a workspace root.
//!
//! Every filesystem access the server performs is funneled through
//! [`canonical_within`], which resolves symlinks and `..` segments and then
//! confirms the result is still under the workspace root. A malicious resource
//! URI or run id therefore cannot reach `/etc/passwd` or any sibling directory.

use std::path::{Component, Path, PathBuf};

use crate::error::{McpError, Result};

/// Resolve `candidate` (absolute or relative to `root`) and ensure the canonical
/// result lies within the canonical `root`.
///
/// Resolution uses [`Path::canonicalize`], which fails if the target does not
/// exist; a missing target is reported as [`McpError::NotFound`] rather than
/// silently succeeding. Because canonicalization resolves symlinks, a symlink
/// pointing outside the root is caught by the containment check.
pub fn canonical_within(root: &Path, candidate: &Path) -> Result<PathBuf> {
    let root = root.canonicalize().map_err(|_| McpError::NotFound {
        what: root.display().to_string(),
    })?;

    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };

    let resolved = joined.canonicalize().map_err(|_| McpError::NotFound {
        what: candidate.display().to_string(),
    })?;

    if resolved.starts_with(&root) {
        Ok(resolved)
    } else {
        Err(McpError::WorkspaceEscape {
            path: candidate.display().to_string(),
        })
    }
}

/// Validate that `segment` is a single safe path component.
///
/// Run ids and similar identifiers must not contain separators, `..`, or a
/// leading `.`; this stops a crafted run id from walking the filesystem before it
/// ever reaches [`canonical_within`].
pub fn validate_segment(segment: &str) -> Result<()> {
    let is_safe = !segment.is_empty()
        && !segment.starts_with('.')
        && Path::new(segment).components().count() == 1
        && matches!(
            Path::new(segment).components().next(),
            Some(Component::Normal(_))
        )
        && segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'));

    if is_safe {
        Ok(())
    } else {
        Err(McpError::InvalidRunId {
            run_id: segment.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resolves_paths_inside_root() {
        let dir = std::env::temp_dir().join(format!("spanspector-path-{}", std::process::id()));
        fs::create_dir_all(dir.join("runs")).unwrap();
        let file = dir.join("runs").join("trace.jsonl");
        fs::write(&file, b"{}").unwrap();

        let resolved = canonical_within(&dir, Path::new("runs/trace.jsonl")).unwrap();
        assert!(resolved.ends_with("trace.jsonl"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_traversal_outside_root() {
        let dir = std::env::temp_dir().join(format!("spanspector-esc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let error = canonical_within(&dir, Path::new("../../etc/passwd")).unwrap_err();
        assert!(matches!(
            error,
            McpError::NotFound { .. } | McpError::WorkspaceEscape { .. }
        ));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn segment_validation_blocks_traversal() {
        for bad in ["..", ".", "a/b", "../x", "", ".hidden", "a b"] {
            assert!(validate_segment(bad).is_err(), "{bad:?} should be invalid");
        }
        for good in ["run-1", "2026-06-27T10-15-32Z-local", "abc_123"] {
            assert!(validate_segment(good).is_ok(), "{good:?} should be valid");
        }
    }
}
