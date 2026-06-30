# SpanSpector task runner. Run `just` to list recipes.

# Default revision for the git-consumer smoke: the current HEAD commit.
rev := `git rev-parse HEAD`
# Default git URL: this repo's local .git, so the smoke works without a remote.
git_url := "file://" + justfile_directory() + "/.git"

# List available recipes.
default:
    @just --list

# Format the whole workspace.
fmt:
    cargo fmt --all

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy, denying warnings (the release gate).
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run the whole test suite.
test:
    cargo test --workspace --all-features

# Build the docs, denying rustdoc warnings.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Full local gate: fmt-check, clippy, test, doc.
ci: fmt-check clippy test doc

# Smoke-test consuming SpanSpector as a *git dependency* — the supported
# downstream mode while the crates are `publish = false`. Generates a throwaway
# crate that pulls `spanspector-tracing` at GIT_URL@REV and exercises the
# downstream API (EvidenceBuilder, non-blocking writer, redaction extension),
# then builds and runs it.
#
# A git dependency resolves the *committed* tree at REV, not your working tree —
# commit your changes before expecting them to appear here.
#
#   just git-consumer-smoke
#   just git-consumer-smoke "file://$PWD/.git" <sha>
git-consumer-smoke git_url=git_url rev=rev:
    #!/usr/bin/env bash
    set -euo pipefail
    workdir="$(mktemp -d)"
    trap 'rm -rf "${workdir}"' EXIT
    crate_dir="${workdir}/consumer"
    mkdir -p "${crate_dir}/src"

    cat >"${crate_dir}/Cargo.toml" <<EOF
    [package]
    name = "spanspector-git-consumer-smoke"
    version = "0.0.0"
    edition = "2024"
    publish = false

    [dependencies]
    spanspector-tracing = { git = "{{ git_url }}", rev = "{{ rev }}", package = "spanspector-tracing" }
    tracing = "0.1"
    tracing-subscriber = "0.3"
    EOF

    cat >"${crate_dir}/src/main.rs" <<'EOF'
    //! Exercises the public downstream API exactly as a server would.
    use spanspector_tracing::{EvidenceBuilder, RedactionPolicy, SensitiveClass};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join("spanspector-git-consumer-smoke");
        let evidence = EvidenceBuilder::new()
            .runs_dir(&dir)
            .run_id("smoke")
            .crate_name("git_consumer_smoke")
            .redaction(RedactionPolicy::new().with_key("sql.literal", SensitiveClass::Secret))
            .build()?;
        let path = evidence.path.clone();

        tracing_subscriber::registry().with(evidence.layer).init();
        {
            let span = tracing::info_span!("work", auth.token = "secret", sql.literal = "x");
            let _entered = span.enter();
            tracing::error!(error.kind = "boom", "failed");
        }
        evidence.guard.shutdown()?;

        let written = std::fs::read_to_string(&path)?;
        assert!(!written.is_empty(), "evidence was written");
        assert!(!written.contains("secret"), "secret must be redacted");
        println!("git-consumer smoke OK: {}", path.display());
        Ok(())
    }
    EOF

    echo "Building git-consumer smoke against {{ git_url }} @ {{ rev }}"
    cargo run --quiet --manifest-path "${crate_dir}/Cargo.toml"
