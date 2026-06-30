//! Run metadata shared by every event emitted during one diagnostic run.

use serde::{Deserialize, Serialize};

/// Metadata describing the run that produced a set of trace events.
///
/// One run corresponds to one execution of an instrumented program (a test
/// binary, a CLI invocation, a request handler under load). The `id` is required
/// and stable; the rest are optional context that helps an agent attribute a
/// failure to a revision, profile, or crate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunMetadata {
    /// Stable run identifier, for example `2026-06-27T10-15-32Z-local`.
    pub id: String,
    /// Git revision when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// Execution profile, such as `test`, `dev`, or `ci`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Crate or application that emitted the records.
    #[serde(rename = "crate", skip_serializing_if = "Option::is_none")]
    pub crate_name: Option<String>,
}

impl RunMetadata {
    /// Create run metadata with a required stable run id.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::default()
        }
    }

    /// Set the git revision, returning `self` for builder-style use.
    #[must_use]
    pub fn with_git_sha(mut self, git_sha: impl Into<String>) -> Self {
        self.git_sha = Some(git_sha.into());
        self
    }

    /// Set the execution profile, returning `self` for builder-style use.
    #[must_use]
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the emitting crate name, returning `self` for builder-style use.
    #[must_use]
    pub fn with_crate(mut self, crate_name: impl Into<String>) -> Self {
        self.crate_name = Some(crate_name.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_optional_fields() {
        let run = RunMetadata::new("run-1")
            .with_git_sha("abc1234")
            .with_profile("test")
            .with_crate("example-app");
        assert_eq!(run.id, "run-1");
        assert_eq!(run.git_sha.as_deref(), Some("abc1234"));
        assert_eq!(run.crate_name.as_deref(), Some("example-app"));
    }

    #[test]
    fn crate_name_serializes_under_crate_key() {
        let run = RunMetadata::new("run-1").with_crate("example-app");
        let json = serde_json::to_string(&run).unwrap();
        assert!(json.contains("\"crate\":\"example-app\""));
        // Optional fields that are unset must not appear.
        assert!(!json.contains("git_sha"));
    }
}
