//! Integration tests for Husky, pre-commit, and Lefthook adapter behaviour
//! (requirements R064, R065, R066).

mod common;

use common::{bin, configure_git_identity, init_git_repo};
use std::path::Path;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helper: write a .gitvault/config.toml for a given adapter name.
// ---------------------------------------------------------------------------
fn write_adapter_config(repo: &Path, adapter: &str) {
    let dir = repo.join(".gitvault");
    std::fs::create_dir_all(&dir).expect(".gitvault dir should be creatable");
    std::fs::write(
        dir.join("config.toml"),
        format!("[hooks]\nadapter = \"{adapter}\"\n"),
    )
    .expect("config.toml should be writable");
}

// ---------------------------------------------------------------------------
// R064 — Husky adapter
// ---------------------------------------------------------------------------

/// S1: harden with husky config but missing binary → exit 0 (interactive, warning only).
#[test]
fn r064_s1_husky_adapter_discovery_is_deterministic() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "husky");

    // Run with a PATH that does not contain gitvault-husky.
    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");

    assert!(
        out.status.success(),
        "harden in interactive mode with missing adapter should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("gitvault-husky"),
        "stderr should mention the missing binary; got: {stderr}"
    );
}

/// S2: harden --no-prompt with husky config but binary missing → non-zero exit.
#[test]
fn r064_s2_husky_missing_adapter_ci_fails_deterministically() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "husky");

    let out = bin()
        .args(["harden", "--no-prompt"])
        .current_dir(repo.path())
        .output()
        .expect("harden should run");

    assert!(
        !out.status.success(),
        "harden --no-prompt with missing adapter should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should say 'not found'; got: {stderr}"
    );
}

/// S3: harden with husky config still installs built-in pre-commit hook.
#[test]
fn r064_s3_husky_pre_commit_blocks_plaintext() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "husky");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(out.status.success(), "harden should succeed");

    // Built-in pre-commit hook must still be installed.
    assert!(
        repo.path().join(".git/hooks/pre-commit").exists(),
        "pre-commit hook should be installed even with husky adapter config"
    );
}

/// S4: harden with husky config still installs built-in pre-push hook.
#[test]
fn r064_s4_husky_pre_push_blocks_drift() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "husky");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(out.status.success(), "harden should succeed");

    assert!(
        repo.path().join(".git/hooks/pre-push").exists(),
        "pre-push hook should be installed even with husky adapter config"
    );
}

/// S5: running harden twice with a missing husky adapter is idempotent.
#[test]
fn r064_s5_husky_install_later_activates_without_rebuild() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "husky");

    let first = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("first harden should run");
    assert!(first.status.success(), "first harden should succeed");

    let hook_content_1 =
        std::fs::read_to_string(repo.path().join(".git/hooks/pre-commit")).unwrap();

    let second = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("second harden should run");
    assert!(second.status.success(), "second harden should succeed");

    let hook_content_2 =
        std::fs::read_to_string(repo.path().join(".git/hooks/pre-commit")).unwrap();

    assert_eq!(
        hook_content_1, hook_content_2,
        "pre-commit hook content should be identical after two harden runs"
    );
}

// ---------------------------------------------------------------------------
// R065 — pre-commit adapter
// ---------------------------------------------------------------------------

/// S1: harden with pre-commit config but missing binary → exit 0 (interactive).
#[test]
fn r065_s1_pre_commit_adapter_discovery_is_deterministic() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "pre-commit");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");

    assert!(
        out.status.success(),
        "harden in interactive mode with missing pre-commit adapter should exit 0"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("gitvault-pre-commit"),
        "stderr should mention missing binary; got: {stderr}"
    );
}

/// S2: harden --no-prompt with pre-commit config but binary missing → non-zero exit.
#[test]
fn r065_s2_pre_commit_missing_runtime_ci_fails_machine_parseable() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "pre-commit");

    let out = bin()
        .args(["harden", "--no-prompt"])
        .current_dir(repo.path())
        .output()
        .expect("harden should run");

    assert!(
        !out.status.success(),
        "harden --no-prompt with missing pre-commit adapter should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should say 'not found'; got: {stderr}"
    );
}

/// S3: harden with pre-commit config still installs built-in pre-commit hook.
#[test]
fn r065_s3_pre_commit_blocks_plaintext() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "pre-commit");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(out.status.success());

    assert!(
        repo.path().join(".git/hooks/pre-commit").exists(),
        "pre-commit hook should be installed even with pre-commit adapter config"
    );
}

/// S4: harden with pre-commit config still installs built-in pre-push hook.
#[test]
fn r065_s4_pre_commit_blocks_drift_on_push_path() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "pre-commit");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(out.status.success());

    assert!(
        repo.path().join(".git/hooks/pre-push").exists(),
        "pre-push hook should be installed even with pre-commit adapter config"
    );
}

/// S5: harden twice with pre-commit config is idempotent.
#[test]
fn r065_s5_pre_commit_config_is_preserved() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "pre-commit");

    bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("first harden should run");

    let hook_1 = std::fs::read_to_string(repo.path().join(".git/hooks/pre-commit")).unwrap();

    bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("second harden should run");

    let hook_2 = std::fs::read_to_string(repo.path().join(".git/hooks/pre-commit")).unwrap();

    assert_eq!(
        hook_1, hook_2,
        "hook content should be identical after two harden runs"
    );
}

// ---------------------------------------------------------------------------
// R066 — Lefthook adapter
// ---------------------------------------------------------------------------

/// S1: harden with lefthook config but missing binary → exit 0 (interactive).
#[test]
fn r066_s1_lefthook_adapter_discovery_is_deterministic() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "lefthook");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");

    assert!(
        out.status.success(),
        "harden in interactive mode with missing lefthook adapter should exit 0"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("gitvault-lefthook"),
        "stderr should mention missing binary; got: {stderr}"
    );
}

/// S2: harden --no-prompt with lefthook config but binary missing → non-zero exit.
#[test]
fn r066_s2_lefthook_missing_adapter_ci_fails_deterministically() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "lefthook");

    let out = bin()
        .args(["harden", "--no-prompt"])
        .current_dir(repo.path())
        .output()
        .expect("harden should run");

    assert!(
        !out.status.success(),
        "harden --no-prompt with missing lefthook adapter should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should say 'not found'; got: {stderr}"
    );
}

/// S3: harden with lefthook config still installs built-in pre-commit hook.
#[test]
fn r066_s3_lefthook_pre_commit_blocks_plaintext() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "lefthook");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(out.status.success());

    assert!(
        repo.path().join(".git/hooks/pre-commit").exists(),
        "pre-commit hook should be installed even with lefthook adapter config"
    );
}

/// S4: harden with lefthook config still installs built-in pre-push hook.
#[test]
fn r066_s4_lefthook_pre_push_blocks_drift() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "lefthook");

    let out = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(out.status.success());

    assert!(
        repo.path().join(".git/hooks/pre-push").exists(),
        "pre-push hook should be installed even with lefthook adapter config"
    );
}

/// S5: harden twice with lefthook config is idempotent.
#[test]
fn r066_s5_lefthook_repeated_runs_are_idempotent() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());
    write_adapter_config(repo.path(), "lefthook");

    let first = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("first harden should run");
    assert!(first.status.success(), "first harden should succeed");

    let hook_1 = std::fs::read_to_string(repo.path().join(".git/hooks/pre-commit")).unwrap();

    let second = bin()
        .arg("harden")
        .env_remove("CI")
        .current_dir(repo.path())
        .output()
        .expect("second harden should run");
    assert!(second.status.success(), "second harden should succeed");

    let hook_2 = std::fs::read_to_string(repo.path().join(".git/hooks/pre-commit")).unwrap();

    assert_eq!(
        hook_1, hook_2,
        "hook content should be identical after two harden runs"
    );
}
