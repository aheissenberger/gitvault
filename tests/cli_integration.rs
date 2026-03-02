use age::secrecy::ExposeSecret;
use age::x25519;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gitvault"))
}
fn init_git_repo(path: &Path) {
    let status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .status()
        .expect("git init should run");
    assert!(status.success());
}

fn write_identity_file() -> (TempDir, String, String) {
    let tmp = TempDir::new().expect("temp dir should be created");
    let identity = x25519::Identity::generate();
    let secret = identity.to_string();
    let public = identity.to_public().to_string();
    let path = tmp.path().join("identity.agekey");
    std::fs::write(&path, secret.expose_secret()).expect("identity should be written");
    (tmp, path.to_string_lossy().to_string(), public)
}

#[test]
fn help_exits_zero() {
    let out = bin().arg("--help").output().expect("help should run");
    assert!(out.status.success());
}

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
fn check_without_identity_fails_usage() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    let out = bin()
        .arg("check")
        .current_dir(repo.path())
        .output()
        .expect("check should run");

    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn encrypt_decrypt_and_materialize_roundtrip() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_identity_tmp, identity_path, pubkey) = write_identity_file();

    let plain = repo.path().join("app.env");
    std::fs::write(&plain, "API_KEY=abc123\n").unwrap();

    let encrypt = bin()
        .args(["encrypt", "app.env", "--recipient", &pubkey])
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("SECRETS_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(encrypt.status.success());

    let enc_path = repo.path().join("secrets/dev/app.env.age");
    assert!(enc_path.exists());

    let decrypt = bin()
        .args([
            "decrypt",
            "secrets/dev/app.env.age",
            "--identity",
            &identity_path,
            "--reveal",
        ])
        .current_dir(repo.path())
        .output()
        .expect("decrypt should run");
    assert!(
        decrypt.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&decrypt.stderr)
    );
    assert!(
        String::from_utf8_lossy(&decrypt.stdout).contains("API_KEY=abc123"),
        "decrypt output did not contain expected plaintext"
    );

    let materialize = bin()
        .arg("materialize")
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("SECRETS_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("materialize should run");
    assert!(materialize.status.success());
    assert!(repo.path().join(".env").exists());
}

#[test]
fn recipient_add_list_remove_flow() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let pubkey = x25519::Identity::generate().to_public().to_string();

    let add = bin()
        .args(["--json", "recipient", "add", &pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient add should run");
    assert!(add.status.success());

    let list = bin()
        .args(["recipient", "list"])
        .current_dir(repo.path())
        .output()
        .expect("recipient list should run");
    assert!(list.status.success());

    let remove = bin()
        .args(["recipient", "remove", &pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient remove should run");
    assert!(remove.status.success());
}

#[test]
fn run_command_propagates_exit_code() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_identity_tmp, identity_path, pubkey) = write_identity_file();

    let plain = repo.path().join("run.env");
    std::fs::write(&plain, "X=1\n").unwrap();
    let encrypt = bin()
        .args(["encrypt", "run.env", "--recipient", &pubkey])
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("SECRETS_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(encrypt.status.success());

    let run = bin()
        .args([
            "run",
            "--identity",
            &identity_path,
            "--",
            "sh",
            "-c",
            "exit 7",
        ])
        .current_dir(repo.path())
        .output()
        .expect("run should execute child");
    assert_eq!(run.status.code(), Some(7));
}

// ── A7 expanded tests ──────────────────────────────────────────────────────────

/// A7-1: `gitvault check` exits with code 3 (EXIT_PLAINTEXT_LEAK) when a
/// plaintext secret file is staged in the git index.
#[test]
fn check_exits_3_on_plaintext_leak() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    // Stage .env so that `git ls-files .env` reports it as tracked.
    std::fs::write(repo.path().join(".env"), "SECRET=oops\n").unwrap();
    let add_status = Command::new("git")
        .args(["add", ".env"])
        .current_dir(repo.path())
        .status()
        .expect("git add should run");
    assert!(add_status.success(), "git add .env should succeed");

    let out = bin()
        .arg("check")
        .current_dir(repo.path())
        .output()
        .expect("check should run");

    assert_eq!(
        out.status.code(),
        Some(3),
        "check should exit 3 (PlaintextLeak); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A7-2: `gitvault run --env prod` exits with code 5 (EXIT_BARRIER) when
/// the `--prod` flag is absent (production barrier not satisfied).
#[test]
fn run_exits_barrier_without_prod_flag() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_identity_tmp, identity_path, _pubkey) = write_identity_file();

    // Run with env=prod but without --prod; barrier should reject immediately.
    let out = bin()
        .args([
            "run",
            "--env",
            "prod",
            "--no-prompt",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .env("GITVAULT_IDENTITY", &identity_path)
        .current_dir(repo.path())
        .output()
        .expect("run should execute");

    assert_eq!(
        out.status.code(),
        Some(5),
        "run without --prod flag should exit 5 (EXIT_BARRIER); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A7-3: `gitvault status --json` outputs valid JSON that contains a
/// top-level `"status"` field.
#[test]
fn status_json_flag_outputs_valid_json_with_status_field() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    let out = bin()
        .args(["--json", "status"])
        .current_dir(repo.path())
        .output()
        .expect("status should run");

    assert!(
        out.status.success(),
        "status --json should succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("status output should be valid JSON");
    assert!(
        v.get("status").is_some(),
        "JSON output should contain a 'status' field; got: {stdout}"
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

/// A7-5: `gitvault --json recipient list` outputs valid JSON containing a
/// `"recipients"` array field.
#[test]
fn recipient_list_json_outputs_valid_json() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let pubkey = x25519::Identity::generate().to_public().to_string();

    // Add a recipient so the list is non-empty.
    let add = bin()
        .args(["recipient", "add", &pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient add should run");
    assert!(add.status.success(), "recipient add should succeed");

    let list = bin()
        .args(["--json", "recipient", "list"])
        .current_dir(repo.path())
        .output()
        .expect("recipient list should run");

    assert!(
        list.status.success(),
        "recipient list --json should succeed; stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );

    let stdout = String::from_utf8_lossy(&list.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("recipient list output should be valid JSON");
    assert!(
        v.get("recipients").and_then(|r| r.as_array()).is_some(),
        "JSON output should contain a 'recipients' array; got: {stdout}"
    );
}

/// A7-6: `gitvault check` exits with code 0 when the repo is properly
/// configured with a valid identity and at least one valid recipient.
#[test]
fn check_succeeds_with_valid_setup() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_identity_tmp, identity_path, pubkey) = write_identity_file();

    // Register the public key as a recipient.
    let add = bin()
        .args(["recipient", "add", &pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient add should run");
    assert!(add.status.success(), "recipient add should succeed");

    let out = bin()
        .arg("check")
        .env("GITVAULT_IDENTITY", &identity_path)
        .current_dir(repo.path())
        .output()
        .expect("check should run");

    assert_eq!(
        out.status.code(),
        Some(0),
        "check should succeed (exit 0) with valid identity and recipient; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
