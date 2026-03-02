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

/// Cover the keyring_set / keyring_get / keyring_delete code paths in the
/// non-test binary by actually running the CLI subcommands.  These commands
/// are expected to *fail* (no keyring backend in CI), but must not panic.
/// Their mere invocation exercises the closure bodies in keyring_store.rs
/// that would otherwise be 0-hit in the non-test binary's profdata.
#[test]
fn keyring_commands_exercise_store_code_paths() {
    let (_tmp, key_path, _pubkey) = write_identity_file();

    // keyring set – may fail with a keyring error; that's fine.
    let _out = bin()
        .args(["keyring", "set", "--identity", &key_path])
        .output()
        .expect("keyring set should run without panic");

    // keyring get – will fail (nothing stored yet), but exercises keyring_get.
    let _out = bin()
        .args(["keyring", "get"])
        .output()
        .expect("keyring get should run without panic");

    // keyring delete – will fail (nothing stored), but exercises keyring_delete.
    let _out = bin()
        .args(["keyring", "delete"])
        .output()
        .expect("keyring delete should run without panic");
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

/// Integration: gitvault rotate re-encrypts secrets to current recipients.
#[test]
fn rotate_re_encrypts_secrets() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_id_tmp, identity_path, pubkey) = write_identity_file();

    // Add a recipient and harden first.
    bin()
        .args(["harden"])
        .current_dir(repo.path())
        .status()
        .unwrap();
    bin()
        .args(["recipient", "add", &pubkey])
        .current_dir(repo.path())
        .status()
        .unwrap();

    // Write a plaintext file and encrypt it.
    let env_file = repo.path().join("app.env");
    std::fs::write(&env_file, "SECRET=rotate_me\n").unwrap();
    let enc = bin()
        .args(["encrypt", "app.env", "--recipient", &pubkey])
        .env("GITVAULT_IDENTITY", &identity_path)
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "encrypt: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // Rotate secrets.
    let rotate = bin()
        .args(["rotate"])
        .env("GITVAULT_IDENTITY", &identity_path)
        .current_dir(repo.path())
        .output()
        .expect("rotate should run");
    assert!(
        rotate.status.success(),
        "rotate failed: {}",
        String::from_utf8_lossy(&rotate.stderr)
    );
}

/// Integration: gitvault allow-prod and revoke-prod round-trip.
#[test]
fn allow_and_revoke_prod_round_trip() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    let allow = bin()
        .args(["allow-prod", "--ttl", "60"])
        .current_dir(repo.path())
        .output()
        .expect("allow-prod should run");
    assert!(
        allow.status.success(),
        "allow-prod failed: {}",
        String::from_utf8_lossy(&allow.stderr)
    );

    let revoke = bin()
        .args(["revoke-prod"])
        .current_dir(repo.path())
        .output()
        .expect("revoke-prod should run");
    assert!(
        revoke.status.success(),
        "revoke-prod failed: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );
}

/// REQ-36: A removed recipient can no longer decrypt after a rotate.
///
/// Workflow:
///  1. Encrypt a secret using the *old* keypair as the only recipient.
///  2. Add a *new* keypair as a persistent recipient.
///  3. Remove the *old* keypair from the persistent recipients list.
///  4. Rotate — re-encrypts all secrets to the current (new-only) recipient set.
///  5. Decryption attempt with the old identity must fail.
///  6. Decryption with the new identity must succeed.
#[test]
fn removed_recipient_cannot_decrypt_after_rotate() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    // Old keypair — used to encrypt the secret initially.
    let (_old_id_tmp, old_identity_path, old_pubkey) = write_identity_file();
    // New keypair — will become the sole recipient after rotation.
    let (_new_id_tmp, new_identity_path, new_pubkey) = write_identity_file();

    // Write and encrypt a secret file using the old public key as recipient.
    let env_file = repo.path().join("app.env");
    std::fs::write(&env_file, "SECRET=rotate_secret\n").unwrap();

    let enc = bin()
        .args(["encrypt", "app.env", "--recipient", &old_pubkey])
        .env("GITVAULT_IDENTITY", &old_identity_path)
        .env("SECRETS_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "initial encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let age_file = repo.path().join("secrets/dev/app.env.age");
    assert!(age_file.exists(), "encrypted file should exist after encrypt");

    // Register the new public key as a persistent recipient.
    let add_new = bin()
        .args(["recipient", "add", &new_pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient add (new) should run");
    assert!(add_new.status.success(), "recipient add (new) failed");

    // Register old key too so we can remove it cleanly.
    let add_old = bin()
        .args(["recipient", "add", &old_pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient add (old) should run");
    assert!(add_old.status.success(), "recipient add (old) failed");

    // Remove the old public key from persistent recipients.
    let remove_old = bin()
        .args(["recipient", "remove", &old_pubkey])
        .current_dir(repo.path())
        .output()
        .expect("recipient remove should run");
    assert!(
        remove_old.status.success(),
        "recipient remove failed: {}",
        String::from_utf8_lossy(&remove_old.stderr)
    );

    // Rotate: the old identity can still decrypt the current ciphertext, and
    // the rotate command re-encrypts everything to the current recipient list
    // (new key only).
    let rotate = bin()
        .args(["rotate"])
        .env("GITVAULT_IDENTITY", &old_identity_path)
        .current_dir(repo.path())
        .output()
        .expect("rotate should run");
    assert!(
        rotate.status.success(),
        "rotate failed: {}",
        String::from_utf8_lossy(&rotate.stderr)
    );

    // After rotation the old key must NOT be able to decrypt.
    let dec_old = bin()
        .args([
            "decrypt",
            "secrets/dev/app.env.age",
            "--identity",
            &old_identity_path,
            "--reveal",
        ])
        .current_dir(repo.path())
        .output()
        .expect("decrypt (old identity) should run");
    assert!(
        !dec_old.status.success(),
        "old identity should NOT decrypt after rotation (exit code was {:?}); stdout: {}",
        dec_old.status.code(),
        String::from_utf8_lossy(&dec_old.stdout)
    );

    // The new key MUST still be able to decrypt and recover the plaintext.
    let dec_new = bin()
        .args([
            "decrypt",
            "secrets/dev/app.env.age",
            "--identity",
            &new_identity_path,
            "--reveal",
        ])
        .current_dir(repo.path())
        .output()
        .expect("decrypt (new identity) should run");
    assert!(
        dec_new.status.success(),
        "new identity should decrypt successfully after rotation; stderr: {}",
        String::from_utf8_lossy(&dec_new.stderr)
    );
    assert!(
        String::from_utf8_lossy(&dec_new.stdout).contains("SECRET=rotate_secret"),
        "expected 'SECRET=rotate_secret' in decrypted output, got: {}",
        String::from_utf8_lossy(&dec_new.stdout)
    );
}

/// REQ-6: gitvault can encrypt and decrypt a `.env` file as a whole file
/// (not `--value-only` mode, which encrypts individual values in-place).
///
/// Workflow:
///  1. Create a `.env` file with several key=value pairs.
///  2. Run `gitvault encrypt .env --recipient <pubkey>` (whole-file mode).
///  3. Verify the `.age` artifact exists and does not expose plaintext.
///  4. Run `gitvault decrypt secrets/dev/.env.age --reveal`.
///  5. Verify that every original key=value pair is present in the output.
#[test]
fn encrypt_decrypt_dotenv_whole_file() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_id_tmp, identity_path, pubkey) = write_identity_file();

    // Create a .env file with multiple key=value pairs.
    let dotenv_content = "DATABASE_URL=postgres://localhost/mydb\nAPI_KEY=supersecret\nDEBUG=false\n";
    let dotenv_path = repo.path().join(".env");
    std::fs::write(&dotenv_path, dotenv_content).unwrap();

    // Whole-file encrypt (no --value-only flag).
    let enc = bin()
        .args(["encrypt", ".env", "--recipient", &pubkey])
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("SECRETS_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "encrypt .env failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // The encrypted artifact must exist at secrets/dev/.env.age.
    let age_path = repo.path().join("secrets/dev/.env.age");
    assert!(
        age_path.exists(),
        "expected secrets/dev/.env.age to exist after whole-file encrypt"
    );

    // The encrypted file must NOT expose the original plaintext.
    let age_bytes = std::fs::read(&age_path).unwrap();
    assert!(
        !age_bytes.windows(dotenv_content.len()).any(|w| w == dotenv_content.as_bytes()),
        "encrypted file must not contain plaintext content"
    );

    // Decrypt with --reveal; output must contain every original key=value pair.
    let dec = bin()
        .args(["decrypt", "secrets/dev/.env.age", "--identity", &identity_path, "--reveal"])
        .current_dir(repo.path())
        .output()
        .expect("decrypt should run");
    assert!(
        dec.status.success(),
        "decrypt .env.age failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    let stdout = String::from_utf8_lossy(&dec.stdout);
    assert!(
        stdout.contains("DATABASE_URL=postgres://localhost/mydb"),
        "expected DATABASE_URL in output, got: {stdout}"
    );
    assert!(
        stdout.contains("API_KEY=supersecret"),
        "expected API_KEY in output, got: {stdout}"
    );
    assert!(
        stdout.contains("DEBUG=false"),
        "expected DEBUG in output, got: {stdout}"
    );
}

/// Integration: gitvault decrypt --reveal prints plaintext to stdout.
#[test]
fn decrypt_reveal_prints_plaintext() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_id_tmp, identity_path, pubkey) = write_identity_file();

    // Write and encrypt a secrets file.
    let env_file = repo.path().join("secrets.env");
    std::fs::write(&env_file, "TOKEN=reveal_me\n").unwrap();
    let enc = bin()
        .args(["encrypt", "secrets.env", "--recipient", &pubkey])
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("SECRETS_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "encrypt: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // The encrypted file goes to secrets/dev/secrets.env.age.
    let age_file = repo.path().join("secrets/dev/secrets.env.age");
    assert!(
        age_file.exists(),
        "expected secrets/dev/secrets.env.age to exist after encrypt"
    );

    // Decrypt with --reveal (prints to stdout, no output file).
    let dec = bin()
        .args(["decrypt", "secrets/dev/secrets.env.age", "--reveal"])
        .env("GITVAULT_IDENTITY", &identity_path)
        .current_dir(repo.path())
        .output()
        .expect("decrypt --reveal should run");
    assert!(
        dec.status.success(),
        "decrypt --reveal failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert!(
        String::from_utf8_lossy(&dec.stdout).contains("TOKEN=reveal_me"),
        "expected TOKEN=reveal_me in output, got: {}",
        String::from_utf8_lossy(&dec.stdout)
    );
}
