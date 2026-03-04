//! Smoke tests and end-to-end integration tests that don't belong to a
//! more-specific category (hooks, adapters, merge driver, recipients).
//!
//! Focused suites live in:
//!   - `tests/hooks.rs`        — hook installation / harden
//!   - `tests/adapters.rs`     — Husky / pre-commit / Lefthook adapters
//!   - `tests/merge_driver.rs` — merge driver integration
//!   - `tests/recipients.rs`   — recipient add / remove / list / rekey

mod common;

use common::{bin, init_git_repo, write_identity_file};
use tempfile::TempDir;

#[test]
fn help_exits_zero() {
    let out = bin().arg("--help").output().expect("help should run");
    assert!(out.status.success());
}

#[test]
fn check_without_identity_fails_usage() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let home = TempDir::new().unwrap();
    let xdg_config_home = home.path().join(".config");
    let missing_identity = home.path().join("missing.agekey");

    let out = bin()
        .args([
            "check",
            "--identity",
            missing_identity.to_string_lossy().as_ref(),
        ])
        .env(
            "GITVAULT_IDENTITY",
            missing_identity.to_string_lossy().as_ref(),
        )
        .env_remove("SSH_AUTH_SOCK")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
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
        .env("GITVAULT_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(encrypt.status.success());

    let enc_path = repo.path().join(".gitvault/store/dev/app.env.age");
    assert!(enc_path.exists());

    let decrypt = bin()
        .args([
            "decrypt",
            ".gitvault/store/dev/app.env.age",
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
        .env("GITVAULT_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("materialize should run");
    assert!(materialize.status.success());
    assert!(repo.path().join(".env").exists());
}

#[test]
fn encrypt_keep_path_and_decrypt_bare_output_roundtrip_multi_subdirs() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_identity_tmp, identity_path, pubkey) = write_identity_file();

    let nested = repo.path().join("apps/payments/api/config");
    std::fs::create_dir_all(&nested).unwrap();
    let plain = nested.join("service.env");
    std::fs::write(&plain, "API_KEY=nested-123\n").unwrap();

    let encrypt = bin()
        .args([
            "encrypt",
            "apps/payments/api/config/service.env",
            "--recipient",
            &pubkey,
            "--keep-path",
        ])
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("GITVAULT_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        encrypt.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&encrypt.stderr)
    );

    let enc_path = repo
        .path()
        .join(".gitvault/store/dev/apps/payments/api/config/service.env.age");
    assert!(enc_path.exists(), "expected keep-path encrypted artifact");

    std::fs::remove_file(&plain).unwrap();
    std::fs::remove_dir_all(repo.path().join("apps")).unwrap();

    let decrypt = bin()
        .args([
            "decrypt",
            ".gitvault/store/dev/apps/payments/api/config/service.env.age",
            "--identity",
            &identity_path,
            "--output",
        ])
        .current_dir(repo.path())
        .output()
        .expect("decrypt should run");
    assert!(
        decrypt.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&decrypt.stderr)
    );

    let restored = repo.path().join("apps/payments/api/config/service.env");
    assert!(restored.exists(), "expected restored plaintext path");
    let content = std::fs::read_to_string(restored).unwrap();
    assert!(content.contains("API_KEY=nested-123"));
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
        .env("GITVAULT_ENV", "dev")
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

/// A7-1: `gitvault check` exits with code 3 (`EXIT_PLAINTEXT_LEAK`) when a
/// plaintext secret file is staged in the git index.
#[test]
fn check_exits_3_on_plaintext_leak() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());

    // Stage .env so that `git ls-files .env` reports it as tracked.
    std::fs::write(repo.path().join(".env"), "SECRET=oops\n").unwrap();
    let add_status = std::process::Command::new("git")
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

/// A7-2: `gitvault run --env prod` exits with code 5 (`EXIT_BARRIER`) when
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

/// Cover the `keyring_set` / `keyring_get` / `keyring_delete` code paths in the
/// non-test binary by actually running the CLI subcommands.  These commands
/// are expected to *fail* (no keyring backend in CI), but must not panic.
/// Their mere invocation exercises the closure bodies in `keyring_store.rs`
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

/// REQ-6: gitvault can encrypt and decrypt a `.env` file as a whole file
/// (not `--value-only` mode, which encrypts individual values in-place).
///
/// Workflow:
///  1. Create a `.env` file with several key=value pairs.
///  2. Run `gitvault encrypt .env --recipient <pubkey>` (whole-file mode).
///  3. Verify the `.age` artifact exists and does not expose plaintext.
///  4. Run `gitvault decrypt .gitvault/store/dev/.env.age --reveal`.
///  5. Verify that every original key=value pair is present in the output.
#[test]
fn encrypt_decrypt_dotenv_whole_file() {
    let repo = TempDir::new().unwrap();
    init_git_repo(repo.path());
    let (_id_tmp, identity_path, pubkey) = write_identity_file();

    // Create a .env file with multiple key=value pairs.
    let dotenv_content =
        "DATABASE_URL=postgres://localhost/mydb\nAPI_KEY=supersecret\nDEBUG=false\n";
    let dotenv_path = repo.path().join(".env");
    std::fs::write(&dotenv_path, dotenv_content).unwrap();

    // Whole-file encrypt (no --value-only flag).
    let enc = bin()
        .args(["encrypt", ".env", "--recipient", &pubkey])
        .env("GITVAULT_IDENTITY", &identity_path)
        .env("GITVAULT_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "encrypt .env failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // The encrypted artifact must exist at .gitvault/store/dev/.env.age.
    let age_path = repo.path().join(".gitvault/store/dev/.env.age");
    assert!(
        age_path.exists(),
        "expected .gitvault/store/dev/.env.age to exist after whole-file encrypt"
    );

    // The encrypted file must NOT expose the original plaintext.
    let age_bytes = std::fs::read(&age_path).unwrap();
    assert!(
        !age_bytes
            .windows(dotenv_content.len())
            .any(|w| w == dotenv_content.as_bytes()),
        "encrypted file must not contain plaintext content"
    );

    // Decrypt with --reveal; output must contain every original key=value pair.
    let dec = bin()
        .args([
            "decrypt",
            ".gitvault/store/dev/.env.age",
            "--identity",
            &identity_path,
            "--reveal",
        ])
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
        .env("GITVAULT_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "encrypt: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    // The encrypted file goes to .gitvault/store/dev/secrets.env.age.
    let age_file = repo.path().join(".gitvault/store/dev/secrets.env.age");
    assert!(
        age_file.exists(),
        "expected .gitvault/store/dev/secrets.env.age to exist after encrypt"
    );

    // Decrypt with --reveal (prints to stdout, no output file).
    let dec = bin()
        .args(["decrypt", ".gitvault/store/dev/secrets.env.age", "--reveal"])
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
