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
