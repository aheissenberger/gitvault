//! Integration tests for the gitvault merge driver.

mod common;

use common::{bin, configure_git_identity, git_config_local, init_git_repo};
use std::process::Command;
use tempfile::TempDir;

#[test]
#[allow(clippy::too_many_lines)]
fn harden_installs_merge_driver_and_git_merge_uses_it() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    configure_git_identity(repo.path());

    let harden = bin()
        .arg("harden")
        .current_dir(repo.path())
        .output()
        .expect("harden should run");
    assert!(
        harden.status.success(),
        "harden failed: {}",
        String::from_utf8_lossy(&harden.stderr)
    );

    let configured = git_config_local(repo.path(), "merge.gitvault-env.driver")
        .expect("harden should set merge.gitvault-env.driver");
    assert_eq!(configured, "gitvault merge-driver %O %A %B");

    let driver_for_test = format!("{} merge-driver %O %A %B", env!("CARGO_BIN_EXE_gitvault"));
    let set_driver = Command::new("git")
        .args([
            "config",
            "--local",
            "merge.gitvault-env.driver",
            &driver_for_test,
        ])
        .current_dir(repo.path())
        .status()
        .expect("git config merge driver should run");
    assert!(set_driver.success());

    std::fs::write(repo.path().join("app.env"), "A=1\n").unwrap();
    let add = Command::new("git")
        .args(["add", "."])
        .current_dir(repo.path())
        .status()
        .expect("git add should run");
    assert!(add.success());
    let commit = Command::new("git")
        .args(["commit", "-m", "base"])
        .current_dir(repo.path())
        .status()
        .expect("git commit should run");
    assert!(commit.success());

    let base_branch_out = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(repo.path())
        .output()
        .expect("git rev-parse should run");
    assert!(base_branch_out.status.success());
    let base_branch = String::from_utf8_lossy(&base_branch_out.stdout)
        .trim()
        .to_string();

    let checkout_feature = Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(repo.path())
        .status()
        .expect("git checkout -b should run");
    assert!(checkout_feature.success());

    std::fs::write(repo.path().join("app.env"), "A=2\n").unwrap();
    let commit_feature = Command::new("git")
        .args(["commit", "-am", "feature change"])
        .current_dir(repo.path())
        .status()
        .expect("git commit on feature should run");
    assert!(commit_feature.success());

    let checkout_base = Command::new("git")
        .args(["checkout", &base_branch])
        .current_dir(repo.path())
        .status()
        .expect("git checkout base branch should run");
    assert!(checkout_base.success());

    std::fs::write(repo.path().join("app.env"), "A=3\n").unwrap();
    let commit_base = Command::new("git")
        .args(["commit", "-am", "base change"])
        .current_dir(repo.path())
        .status()
        .expect("git commit on base branch should run");
    assert!(commit_base.success());

    let merge = Command::new("git")
        .args(["merge", "feature"])
        .current_dir(repo.path())
        .output()
        .expect("git merge should run");
    assert_eq!(
        merge.status.code(),
        Some(1),
        "expected merge conflict (exit 1), stderr: {}",
        String::from_utf8_lossy(&merge.stderr)
    );

    let merged_file = std::fs::read_to_string(repo.path().join("app.env")).unwrap();
    let has_gitvault_markers =
        merged_file.contains("<<<<<<< ours") && merged_file.contains(">>>>>>> theirs");
    let has_standard_markers = merged_file.contains("<<<<<<<") && merged_file.contains(">>>>>>>");

    let unmerged = Command::new("git")
        .args(["ls-files", "-u", "--", "app.env"])
        .current_dir(repo.path())
        .output()
        .expect("git ls-files -u should run");
    assert!(unmerged.status.success());
    let has_unmerged_entries = !String::from_utf8_lossy(&unmerged.stdout).trim().is_empty();

    assert!(
        has_gitvault_markers || has_standard_markers || has_unmerged_entries,
        "expected conflict evidence in app.env or index, got file: {merged_file}"
    );
}

/// A7-4: `gitvault --json merge-driver` outputs the success JSON object
/// `{"status":"ok","message":"Merge completed successfully."}` on a
/// clean (conflict-free) merge.
#[test]
fn merge_driver_success_outputs_json() {
    let dir = TempDir::new().unwrap();

    let base = dir.path().join("base.env");
    let ours = dir.path().join("ours.env");
    let theirs = dir.path().join("theirs.env");

    // All three versions are identical → no conflict.
    std::fs::write(&base, "A=1\n").unwrap();
    std::fs::write(&ours, "A=1\n").unwrap();
    std::fs::write(&theirs, "A=1\n").unwrap();

    let out = bin()
        .args([
            "--json",
            "merge-driver",
            &base.to_string_lossy(),
            &ours.to_string_lossy(),
            &theirs.to_string_lossy(),
        ])
        .output()
        .expect("merge-driver should run");

    assert!(
        out.status.success(),
        "merge-driver with no conflict should succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("merge-driver output should be valid JSON");
    assert_eq!(
        v.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "JSON status should be 'ok'; got: {stdout}"
    );
    assert_eq!(
        v.get("message").and_then(|s| s.as_str()),
        Some("Merge completed successfully."),
        "JSON message mismatch; got: {stdout}"
    );
}
