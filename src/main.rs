mod cli;
mod crypto;
mod env;
mod error;
mod materialize;
mod repo;

use clap::Parser;
use cli::{Cli, Commands};
use error::GitvaultError;
use std::path::PathBuf;
use std::process;

fn main() {
    let cli = Cli::parse();

    let result = run(cli);
    match result {
        Ok(()) => process::exit(error::EXIT_SUCCESS),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(e.exit_code());
        }
    }
}

fn run(cli: Cli) -> Result<(), GitvaultError> {
    match cli.command {
        Commands::Encrypt { file, recipients } => {
            cmd_encrypt(file, recipients, cli.json, cli.no_prompt)
        }
        Commands::Decrypt { file, identity, output } => {
            cmd_decrypt(file, identity, output, cli.json, cli.no_prompt)
        }
        Commands::Materialize { env, identity } => {
            cmd_materialize(env, identity, cli.json, cli.no_prompt)
        }
        Commands::Status => cmd_status(cli.json),
        Commands::Harden => cmd_harden(cli.json),
    }
}

/// Find the repository root by walking up from cwd looking for .git
fn find_repo_root() -> Result<PathBuf, GitvaultError> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join(".git").exists() {
            return Ok(dir);
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => return Ok(std::env::current_dir()?),
        }
    }
}

/// Output a success result, optionally as JSON
fn output_success(message: &str, json: bool) {
    if json {
        println!("{}", serde_json::json!({"status": "ok", "message": message}));
    } else {
        println!("{message}");
    }
}

/// Encrypt a file and write the .age output under secrets/
fn cmd_encrypt(file: String, recipient_keys: Vec<String>, json: bool, _no_prompt: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let input_path = PathBuf::from(&file);

    let recipient_keys = resolve_recipient_keys(recipient_keys)?;

    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r = crypto::parse_recipient(k)?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let plaintext = std::fs::read(&input_path)?;
    let ciphertext = crypto::encrypt(recipients, &plaintext)?;

    let filename = input_path
        .file_name()
        .ok_or_else(|| GitvaultError::Usage("Invalid file path".to_string()))?
        .to_string_lossy();
    let out_name = format!("{filename}.age");

    repo::ensure_dirs(&repo_root, "dev")?;
    let out_path = repo::get_encrypted_path(&repo_root, &out_name);

    std::fs::write(&out_path, &ciphertext)?;

    output_success(&format!("Encrypted to {}", out_path.display()), json);
    Ok(())
}

fn resolve_recipient_keys(recipient_keys: Vec<String>) -> Result<Vec<String>, GitvaultError> {
    if !recipient_keys.is_empty() {
        return Ok(recipient_keys);
    }

    let identity_str = load_identity(None)?;
    let identity = crypto::parse_identity(&identity_str)?;
    Ok(vec![identity.to_public().to_string()])
}

/// Decrypt a .age file and write plaintext
fn cmd_decrypt(file: String, identity_path: Option<String>, output: Option<String>, json: bool, _no_prompt: bool) -> Result<(), GitvaultError> {
    let input_path = PathBuf::from(&file);

    let ciphertext = std::fs::read(&input_path)?;
    let identity_str = load_identity(identity_path)?;
    let identity = crypto::parse_identity(&identity_str)?;

    let plaintext = crypto::decrypt(&identity, &ciphertext)?;

    let out_path = if let Some(out) = output {
        PathBuf::from(out)
    } else {
        let name = input_path.file_name().unwrap().to_string_lossy();
        let out_name = name.strip_suffix(".age").unwrap_or(&name).to_string();
        input_path.parent().unwrap_or(std::path::Path::new(".")).join(out_name)
    };

    std::fs::write(&out_path, &plaintext)?;

    output_success(&format!("Decrypted to {}", out_path.display()), json);
    Ok(())
}

/// Materialize secrets to root .env
fn cmd_materialize(env_override: Option<String>, identity_path: Option<String>, json: bool, _no_prompt: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root));

    let identity_str = load_identity(identity_path)?;
    let identity = crypto::parse_identity(&identity_str)?;

    let secrets_dir = repo_root.join(repo::SECRETS_DIR);
    let mut secrets: Vec<(String, String)> = Vec::new();

    if secrets_dir.exists() {
        for entry in std::fs::read_dir(&secrets_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("age") {
                let ciphertext = std::fs::read(&path)?;
                match crypto::decrypt(&identity, &ciphertext) {
                    Ok(plaintext) => {
                        let text = String::from_utf8_lossy(&plaintext);
                        for line in text.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            if let Some((k, v)) = line.split_once('=') {
                                secrets.push((k.trim().to_string(), v.trim().to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: could not decrypt {}: {e}", path.display());
                    }
                }
            }
        }
    }

    materialize::materialize_env_file(&repo_root, &secrets)?;

    output_success(&format!("Materialized {} secrets to .env (env: {env})", secrets.len()), json);
    Ok(())
}

/// Check repository safety status
fn cmd_status(json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;

    repo::check_no_tracked_plaintext(&repo_root)?;

    let env = env::resolve_env(&repo_root);

    if json {
        println!("{}", serde_json::json!({
            "status": "ok",
            "env": env,
            "plaintext_leaked": false
        }));
    } else {
        println!("Status: OK");
        println!("Environment: {env}");
        println!("No tracked plaintext detected.");
    }

    Ok(())
}

/// Harden the repository: update .gitignore
fn cmd_harden(json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;

    materialize::ensure_gitignored(&repo_root, materialize::REQUIRED_GITIGNORE_ENTRIES)?;

    output_success("Repository hardened: .gitignore updated.", json);
    Ok(())
}

/// Load identity key string from file path or GITVAULT_IDENTITY env var
fn load_identity(path: Option<String>) -> Result<String, GitvaultError> {
    if let Some(p) = path {
        load_identity_source(&p, "--identity")
    } else if let Ok(key) = std::env::var("GITVAULT_IDENTITY") {
        load_identity_source(&key, "GITVAULT_IDENTITY")
    } else {
        Err(GitvaultError::Usage(
            "No identity provided. Use --identity <file> or set GITVAULT_IDENTITY".to_string(),
        ))
    }
}

fn load_identity_source(source: &str, source_name: &str) -> Result<String, GitvaultError> {
    let value = source.trim();

    if value.starts_with("AGE-SECRET-KEY-") {
        return Ok(value.to_string());
    }

    std::fs::read_to_string(value).map_err(|e| {
        GitvaultError::Usage(format!(
            "{source_name} must be an identity file path or AGE-SECRET-KEY value: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use age::x25519;
    use tempfile::NamedTempFile;

    #[test]
    fn test_resolve_recipient_keys_defaults_to_local_identity_public_key() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let expected_recipient = identity.to_public().to_string();

        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe { std::env::set_var("GITVAULT_IDENTITY", identity_secret.expose_secret()); }

        let resolved = resolve_recipient_keys(vec![]).expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe { std::env::set_var("GITVAULT_IDENTITY", value); },
            None => unsafe { std::env::remove_var("GITVAULT_IDENTITY"); },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_defaults_from_identity_file_path() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let expected_recipient = identity.to_public().to_string();

        let identity_file = NamedTempFile::new().expect("temp file should be created");
        std::fs::write(identity_file.path(), identity_secret.expose_secret())
            .expect("identity should be written to temp file");

        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var(
                "GITVAULT_IDENTITY",
                identity_file.path().to_string_lossy().to_string(),
            );
        }

        let resolved = resolve_recipient_keys(vec![]).expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe { std::env::set_var("GITVAULT_IDENTITY", value); },
            None => unsafe { std::env::remove_var("GITVAULT_IDENTITY"); },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_fails_without_identity_source() {
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe { std::env::remove_var("GITVAULT_IDENTITY"); }

        let result = resolve_recipient_keys(vec![]);

        match previous {
            Some(value) => unsafe { std::env::set_var("GITVAULT_IDENTITY", value); },
            None => unsafe { std::env::remove_var("GITVAULT_IDENTITY"); },
        }

        match result {
            Err(GitvaultError::Usage(message)) => {
                assert!(message.contains("No identity provided"));
            }
            other => panic!("expected usage error for missing identity, got: {other:?}"),
        }
    }

    #[test]
    fn test_resolve_recipient_keys_fails_with_malformed_identity_key() {
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe { std::env::set_var("GITVAULT_IDENTITY", "AGE-SECRET-KEY-INVALID"); }

        let result = resolve_recipient_keys(vec![]);

        match previous {
            Some(value) => unsafe { std::env::set_var("GITVAULT_IDENTITY", value); },
            None => unsafe { std::env::remove_var("GITVAULT_IDENTITY"); },
        }

        match result {
            Err(GitvaultError::Decryption(message)) => {
                assert!(message.contains("Invalid identity key"));
            }
            other => panic!("expected decryption error for malformed identity, got: {other:?}"),
        }
    }
}
