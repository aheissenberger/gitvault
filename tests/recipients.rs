//! Integration tests for recipient management: add, remove, list, add-self, rekey.

mod common;

use age::x25519;
use common::{bin, init_git_repo, write_identity_file};
use tempfile::TempDir;

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

/// Integration: gitvault rekey re-encrypts secrets to current recipients.
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

    // Rekey secrets.
    let rekey = bin()
        .args(["rekey"])
        .env("GITVAULT_IDENTITY", &identity_path)
        .current_dir(repo.path())
        .output()
        .expect("rekey should run");
    assert!(
        rekey.status.success(),
        "rekey failed: {}",
        String::from_utf8_lossy(&rekey.stderr)
    );
}

/// REQ-36: A removed recipient can no longer decrypt after a rekey.
///
/// Workflow:
///  1. Encrypt a secret using the *old* keypair as the only recipient.
///  2. Add a *new* keypair as a persistent recipient.
///  3. Remove the *old* keypair from the persistent recipients list.
///  4. Rekey — re-encrypts all secrets to the current (new-only) recipient set.
///  5. Decryption attempt with the old identity must fail.
///  6. Decryption with the new identity must succeed.
#[test]
fn removed_recipient_cannot_decrypt_after_rekey() {
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
        .env("GITVAULT_ENV", "dev")
        .current_dir(repo.path())
        .output()
        .expect("encrypt should run");
    assert!(
        enc.status.success(),
        "initial encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let age_file = repo.path().join(".gitvault/store/dev/app.env.age");
    assert!(
        age_file.exists(),
        "encrypted file should exist after encrypt"
    );

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

    // Rekey: the old identity can still decrypt the current ciphertext, and
    // the rekey command re-encrypts everything to the current recipient list
    // (new key only).
    let rekey = bin()
        .args(["rekey"])
        .env("GITVAULT_IDENTITY", &old_identity_path)
        .current_dir(repo.path())
        .output()
        .expect("rekey should run");
    assert!(
        rekey.status.success(),
        "rekey failed: {}",
        String::from_utf8_lossy(&rekey.stderr)
    );

    // After rotation the old key must NOT be able to decrypt.
    let dec_old = bin()
        .args([
            "decrypt",
            ".gitvault/store/dev/app.env.age",
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
            ".gitvault/store/dev/app.env.age",
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
