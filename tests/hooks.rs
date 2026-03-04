//! Integration tests for hook installation, gitignore, and `gitvault harden`.

mod common;

use common::{bin, configure_git_identity, gitvault_path_env, init_git_repo};
use std::process::Command;
use tempfile::TempDir;

#[test]
fn harden_and_status_work_in_repo() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    let harden = bin()
        .arg("harden")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(harden.status.success());

    let status = bin()
        .arg("status")
        .current_dir(repo.path())
        .output()
        .expect("status should run");
    assert!(status.status.success());
}

#[test]
fn harden_installs_hook_that_blocks_plaintext_commit() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());

    let harden = bin()
        .arg("harden")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(harden.status.success());

    std::fs::write(repo.path().join(".env"), "SECRET=oops\n").unwrap();
    let add = Command::new("git")
        .args(["add", "-f", ".env"])
        .current_dir(repo.path())
        .status()
        .expect("git add -f .env should run");
    assert!(add.success());

    let commit = Command::new("git")
        .args(["commit", "-m", "should be blocked"])
        .current_dir(repo.path())
        .output()
        .expect("git commit should run");

    assert_eq!(
        commit.status.code(),
        Some(1),
        "expected pre-commit hook rejection, stderr: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    let stderr = String::from_utf8_lossy(&commit.stderr);
    assert!(
        stderr.contains("gitvault: refusing commit") || stderr.contains("hook declined"),
        "expected hook rejection message in stderr, got: {stderr}"
    );
}

#[test]
fn harden_installs_hook_that_blocks_push_on_drift() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());

    let harden = bin()
        .arg("harden")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(harden.status.success());

    std::fs::create_dir_all(repo.path().join(".gitvault/store/dev")).unwrap();
    std::fs::write(
        repo.path().join(".gitvault/store/dev/app.env.age"),
        "ciphertext-v1\n",
    )
    .unwrap();
    let add_initial = Command::new("git")
        .args(["add", "."])
        .current_dir(repo.path())
        .status()
        .expect("git add should run");
    assert!(add_initial.success());
    let commit_initial = Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(repo.path())
        .status()
        .expect("git commit should run");
    assert!(commit_initial.success());

    let remote = TempDir::new().unwrap();
    let init_bare = Command::new("git")
        .args(["init", "--bare", "-q"])
        .current_dir(remote.path())
        .status()
        .expect("git init --bare should run");
    assert!(init_bare.success());

    let add_remote = Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            remote.path().to_string_lossy().as_ref(),
        ])
        .current_dir(repo.path())
        .status()
        .expect("git remote add should run");
    assert!(add_remote.success());

    let path_env = gitvault_path_env();
    let first_push = Command::new("git")
        .args(["push", "-u", "origin", "HEAD"])
        .env("PATH", &path_env)
        .current_dir(repo.path())
        .status()
        .expect("initial git push should run");
    assert!(first_push.success());

    std::fs::write(
        repo.path().join(".gitvault/store/dev/app.env.age"),
        "ciphertext-v2\n",
    )
    .unwrap();
    std::fs::write(repo.path().join("note.txt"), "push trigger\n").unwrap();
    let add_note = Command::new("git")
        .args(["add", "note.txt"])
        .current_dir(repo.path())
        .status()
        .expect("git add note.txt should run");
    assert!(add_note.success());
    let commit_note = Command::new("git")
        .args(["commit", "-m", "note"])
        .current_dir(repo.path())
        .status()
        .expect("git commit note should run");
    assert!(commit_note.success());

    let push = Command::new("git")
        .arg("push")
        .env("PATH", &path_env)
        .current_dir(repo.path())
        .output()
        .expect("git push should run");

    assert!(
        !push.status.success(),
        "push should fail due to pre-push drift check"
    );
}
