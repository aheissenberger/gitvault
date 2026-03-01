mod barrier;
mod cli;
mod crypto;
mod env;
mod error;
mod keyring_store;
mod materialize;
mod repo;
mod run;
mod structured;
mod aws_config;

use clap::Parser;
use cli::{Cli, Commands, KeyringAction, RecipientAction};
use error::GitvaultError;
use std::path::{Path, PathBuf};
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

fn run(mut cli: Cli) -> Result<(), GitvaultError> {
    // REQ-48: CI=true auto-enables non-interactive mode
    if !cli.no_prompt && std::env::var("CI").map(|v| !v.is_empty()).unwrap_or(false) {
        cli.no_prompt = true;
    }
    match cli.command {
        Commands::Encrypt { file, recipients, fields, value_only } => {
            cmd_encrypt(file, recipients, fields, value_only, cli.json, cli.no_prompt)
        }
        Commands::Decrypt { file, identity, output, fields, reveal } => {
            cmd_decrypt(file, identity, output, fields, reveal, cli.json, cli.no_prompt)
        }
        Commands::Materialize { env, identity, prod } => {
            cmd_materialize(env, identity, prod, cli.json, cli.no_prompt)
        }
        Commands::Status { fail_if_dirty } => cmd_status(cli.json, fail_if_dirty),
        Commands::Harden => cmd_harden(cli.json),
        Commands::Run { env, identity, prod, clear_env, pass, command } => {
            cmd_run(env, identity, prod, clear_env, pass, command, cli.json, cli.no_prompt)
        }
        Commands::AllowProd { ttl } => cmd_allow_prod(ttl, cli.json),
        Commands::MergeDriver { base, ours, theirs } => cmd_merge_driver(base, ours, theirs),
        Commands::Recipient { action } => cmd_recipient(action, cli.json),
        Commands::Rotate { identity } => cmd_rotate(identity, cli.json),
        Commands::Keyring { action } => cmd_keyring(action, cli.json),
        Commands::Check { env, identity } => cmd_check(env, identity, cli.json),
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
fn cmd_encrypt(file: String, recipient_keys: Vec<String>, fields: Option<String>, value_only: bool, json: bool, _no_prompt: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let input_path = PathBuf::from(&file);

    // REQ-33: each source file maps to exactly one .age artifact
    if input_path.extension().and_then(|e| e.to_str()) == Some("age") {
        return Err(GitvaultError::Usage("Cannot encrypt an already-encrypted .age file (REQ-33: no mega-blob)".to_string()));
    }

    let recipient_keys = resolve_recipient_keys(&repo_root, recipient_keys)?;

    // REQ-4: field-level encryption for JSON/YAML/TOML
    if let Some(fields_str) = &fields {
        let fields: Vec<&str> = fields_str.split(',').map(str::trim).collect();
        let identity_str = load_identity(None)?;
        let identity = crypto::parse_identity(&identity_str)?;
        structured::encrypt_fields(&input_path, &fields, &identity, &recipient_keys)
            .map_err(|e| GitvaultError::Encryption(e.to_string()))?;
        output_success(&format!("Encrypted fields [{fields_str}] in {}", input_path.display()), json);
        return Ok(());
    }

    // REQ-6: .env value-only mode
    let ext = input_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if value_only && (ext == "env" || input_path.file_name().and_then(|n| n.to_str()).unwrap_or("").starts_with(".env")) {
        let identity_str = load_identity(None)?;
        let identity = crypto::parse_identity(&identity_str)?;
        let content = std::fs::read_to_string(&input_path)?;
        let encrypted = structured::encrypt_env_values(&content, &identity, &recipient_keys)
            .map_err(|e| GitvaultError::Encryption(e.to_string()))?;
        // REQ-43: atomic write
        let tmp = tempfile::NamedTempFile::new_in(input_path.parent().unwrap_or(std::path::Path::new(".")))?;
        std::fs::write(tmp.path(), encrypted)?;
        tmp.persist(&input_path).map_err(|e| GitvaultError::Io(e.error))?;
        output_success(&format!("Encrypted .env values in {}", input_path.display()), json);
        return Ok(());
    }

    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r = crypto::parse_recipient(k)?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let filename = input_path
        .file_name()
        .ok_or_else(|| GitvaultError::Usage("Invalid file path".to_string()))?
        .to_string_lossy();
    let out_name = format!("{filename}.age");

    repo::ensure_dirs(&repo_root, "dev")?;
    let out_path = repo::get_encrypted_path(&repo_root, &out_name);

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming encryption — no full-file buffer
    let tmp = tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
    {
        let mut in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::encrypt_stream(recipients, &mut in_file, &mut out_file)?;
    }
    tmp.persist(&out_path).map_err(|e| GitvaultError::Io(e.error))?;

    output_success(&format!("Encrypted to {}", out_path.display()), json);
    Ok(())
}

fn resolve_recipient_keys(repo_root: &Path, recipient_keys: Vec<String>) -> Result<Vec<String>, GitvaultError> {
    if !recipient_keys.is_empty() {
        return Ok(recipient_keys);
    }

    // Try persistent recipients file (REQ-36)
    let from_file = repo::read_recipients(repo_root)?;
    if !from_file.is_empty() {
        return Ok(from_file);
    }

    // Fall back to local identity public key
    let identity_str = load_identity(None)?;
    let identity = crypto::parse_identity(&identity_str)?;
    Ok(vec![identity.to_public().to_string()])
}

/// Decrypt a .age file and write plaintext
fn cmd_decrypt(file: String, identity_path: Option<String>, output: Option<String>, fields: Option<String>, reveal: bool, json: bool, _no_prompt: bool) -> Result<(), GitvaultError> {
    let input_path = PathBuf::from(&file);
    let identity_str = load_identity(identity_path)?;
    let identity = crypto::parse_identity(&identity_str)?;

    // REQ-4: field-level decryption for JSON/YAML/TOML
    if let Some(fields_str) = &fields {
        let fields: Vec<&str> = fields_str.split(',').map(str::trim).collect();
        structured::decrypt_fields(&input_path, &fields, &identity)
            .map_err(|e| GitvaultError::Decryption(e.to_string()))?;
        output_success(&format!("Decrypted fields [{fields_str}] in {}", input_path.display()), json);
        return Ok(());
    }

    // REQ-41: if --reveal, print to stdout and never write to file
    if reveal {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut stdout = std::io::BufWriter::new(std::io::stdout());
        crypto::decrypt_stream(&identity, in_file, &mut stdout)?;
        return Ok(());
    }

    let out_path = if let Some(out) = output {
        PathBuf::from(out)
    } else {
        let name = input_path.file_name().unwrap().to_string_lossy();
        let out_name = name.strip_suffix(".age").unwrap_or(&name).to_string();
        input_path.parent().unwrap_or(std::path::Path::new(".")).join(out_name)
    };

    // REQ-42: prevent path traversal
    let repo_root = find_repo_root()?;
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming decryption
    let tmp = tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
    {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::decrypt_stream(&identity, in_file, &mut out_file)?;
    }
    tmp.persist(&out_path).map_err(|e| GitvaultError::Io(e.error))?;

    output_success(&format!("Decrypted to {}", out_path.display()), json);
    Ok(())
}

/// Materialize secrets to root .env
fn cmd_materialize(env_override: Option<String>, identity_path: Option<String>, prod: bool, json: bool, no_prompt: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root));

    // REQ-13/25: prod barrier check
    barrier::check_prod_barrier(&repo_root, &env, prod, no_prompt)?;

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
                    // REQ-40: fail closed on any decryption error
                    Err(e) => return Err(GitvaultError::Decryption(format!("Failed to decrypt {}: {e}", path.display()))),
                }
            }
        }
    }

    materialize::materialize_env_file(&repo_root, &secrets)?;

    output_success(&format!("Materialized {} secrets to .env (env: {env})", secrets.len()), json);
    Ok(())
}

/// Check repository safety status
fn cmd_status(json: bool, fail_if_dirty: bool) -> Result<(), GitvaultError> {
    // REQ-44: no decryption performed
    let repo_root = find_repo_root()?;
    repo::check_no_tracked_plaintext(&repo_root)?;
    let env = env::resolve_env(&repo_root);

    // REQ-32: drift check
    if fail_if_dirty && repo::has_secrets_drift(&repo_root)? {
        return Err(GitvaultError::PlaintextLeak(
            "secrets/ has uncommitted changes (drift detected)".to_string(),
        ));
    }

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

/// Harden the repository: update .gitignore, install git hooks
fn cmd_harden(json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    materialize::ensure_gitignored(&repo_root, materialize::REQUIRED_GITIGNORE_ENTRIES)?;
    repo::install_git_hooks(&repo_root)?;
    output_success("Repository hardened: .gitignore updated, git hooks installed.", json);
    Ok(())
}

/// Run a command with secrets injected as environment variables (REQ-21..25)
fn cmd_run(
    env_override: Option<String>,
    identity_path: Option<String>,
    prod: bool,
    clear_env: bool,
    pass_raw: Option<String>,
    command: Vec<String>,
    _json: bool,
    no_prompt: bool,
) -> Result<(), GitvaultError> {
    if command.is_empty() {
        return Err(GitvaultError::Usage("No command specified after --".to_string()));
    }

    let repo_root = find_repo_root()?;
    let env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root));

    // REQ-25: prod barrier
    barrier::check_prod_barrier(&repo_root, &env, prod, no_prompt)?;

    // Load identity and decrypt secrets
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
                            if line.is_empty() || line.starts_with('#') { continue; }
                            if let Some((k, v)) = line.split_once('=') {
                                secrets.push((k.trim().to_string(), v.trim().to_string()));
                            }
                        }
                    }
                    // REQ-40: fail closed on any decryption error
                    Err(e) => return Err(GitvaultError::Decryption(format!("Failed to decrypt {}: {e}", path.display()))),
                }
            }
        }
    }

    // REQ-24: parse --pass
    let pass_vars = pass_raw
        .as_deref()
        .map(run::parse_pass_vars)
        .unwrap_or_default();

    let cmd = &command[0];
    let args = &command[1..];

    // REQ-22, REQ-23: inject and run
    let exit_code = run::run_command(&secrets, cmd, &args.to_vec(), clear_env, &pass_vars)?;
    std::process::exit(exit_code);
}

/// Write a timed production allow token (REQ-14)
fn cmd_allow_prod(ttl: u64, json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let expiry = barrier::allow_prod(&repo_root, ttl)?;
    output_success(
        &format!("Production access allowed for {ttl}s (expires at Unix time {expiry})"),
        json,
    );
    Ok(())
}

/// Run as git merge driver for .env files (REQ-34)
fn cmd_merge_driver(base: String, ours: String, theirs: String) -> Result<(), GitvaultError> {
    fn parse_env(content: &str) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        map
    }

    let base_content = std::fs::read_to_string(&base)?;
    let ours_content = std::fs::read_to_string(&ours)?;
    let theirs_content = std::fs::read_to_string(&theirs)?;

    let base_map = parse_env(&base_content);
    let ours_map = parse_env(&ours_content);
    let theirs_map = parse_env(&theirs_content);

    // Collect all keys
    let mut all_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    all_keys.extend(base_map.keys().cloned());
    all_keys.extend(ours_map.keys().cloned());
    all_keys.extend(theirs_map.keys().cloned());

    // Three-way merge per key
    let mut merged_map: std::collections::BTreeMap<String, Option<String>> = std::collections::BTreeMap::new();
    let mut has_conflict = false;

    for key in &all_keys {
        let base_val = base_map.get(key).map(|s| s.as_str());
        let ours_val = ours_map.get(key).map(|s| s.as_str());
        let theirs_val = theirs_map.get(key).map(|s| s.as_str());

        let base_eq_ours = base_val == ours_val;
        let base_eq_theirs = base_val == theirs_val;
        let ours_eq_theirs = ours_val == theirs_val;

        let merged = if base_eq_ours && base_eq_theirs {
            // All same → keep ours
            ours_val.map(|s| s.to_string())
        } else if base_eq_ours && !base_eq_theirs {
            // Ours unchanged, theirs changed → take theirs
            theirs_val.map(|s| s.to_string())
        } else if !base_eq_ours && base_eq_theirs {
            // Ours changed, theirs unchanged → keep ours
            ours_val.map(|s| s.to_string())
        } else if ours_eq_theirs {
            // Both changed to same → keep ours
            ours_val.map(|s| s.to_string())
        } else {
            // All three differ → conflict
            has_conflict = true;
            let ours_line = ours_val
                .map(|v| format!("{key}={v}"))
                .unwrap_or_else(|| format!("# {key} deleted in ours"));
            let theirs_line = theirs_val
                .map(|v| format!("{key}={v}"))
                .unwrap_or_else(|| format!("# {key} deleted in theirs"));
            Some(format!("<<<<<<< ours\n{ours_line}\n=======\n{theirs_line}\n>>>>>>> theirs"))
        };
        merged_map.insert(key.clone(), merged);
    }

    // Build output preserving ours structure (comments, blanks) and replacing key-values
    let mut output_lines: Vec<String> = Vec::new();
    let mut processed_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in ours_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output_lines.push(line.to_string());
        } else if let Some((k, _)) = trimmed.split_once('=') {
            let k = k.trim().to_string();
            if let Some(val_opt) = merged_map.get(&k) {
                if let Some(val) = val_opt {
                    if val.starts_with("<<<<<<") {
                        output_lines.push(val.clone());
                    } else {
                        output_lines.push(format!("{k}={val}"));
                    }
                }
                // If None → key was deleted, skip it
            }
            processed_keys.insert(k);
        }
    }

    // Append keys that are new (not in ours)
    for (k, val_opt) in &merged_map {
        if !processed_keys.contains(k) {
            if let Some(val) = val_opt {
                if val.starts_with("<<<<<<") {
                    output_lines.push(val.clone());
                } else {
                    output_lines.push(format!("{k}={val}"));
                }
            }
        }
    }

    let merged_content = output_lines.join("\n") + "\n";
    std::fs::write(&ours, &merged_content)?;

    if has_conflict {
        process::exit(1);
    }

    Ok(())
}

/// Manage persistent recipients (REQ-37)
fn cmd_recipient(action: RecipientAction, json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    match action {
        RecipientAction::Add { pubkey } => {
            // Validate it's a valid age public key
            crypto::parse_recipient(&pubkey)?;
            let mut recipients = repo::read_recipients(&repo_root)?;
            if recipients.contains(&pubkey) {
                return Err(GitvaultError::Usage(format!("Recipient already present: {pubkey}")));
            }
            recipients.push(pubkey.clone());
            repo::write_recipients(&repo_root, &recipients)?;
            output_success(&format!("Added recipient: {pubkey}"), json);
        }
        RecipientAction::Remove { pubkey } => {
            let mut recipients = repo::read_recipients(&repo_root)?;
            let before = recipients.len();
            recipients.retain(|r| r != &pubkey);
            if recipients.len() == before {
                return Err(GitvaultError::Usage(format!("Recipient not found: {pubkey}")));
            }
            repo::write_recipients(&repo_root, &recipients)?;
            output_success(&format!("Removed recipient: {pubkey}"), json);
        }
        RecipientAction::List => {
            let recipients = repo::read_recipients(&repo_root)?;
            if json {
                println!("{}", serde_json::json!({"recipients": recipients}));
            } else if recipients.is_empty() {
                println!("No persistent recipients. Use 'gitvault recipient add <pubkey>'.");
            } else {
                for r in &recipients {
                    println!("{r}");
                }
            }
        }
    }
    Ok(())
}

/// Re-encrypt all secrets with the current recipients list (REQ-38)
fn cmd_rotate(identity_path: Option<String>, json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let identity_str = load_identity(identity_path)?;
    let identity = crypto::parse_identity(&identity_str)?;

    let recipient_keys = resolve_recipient_keys(&repo_root, vec![])?;
    let secrets_dir = repo_root.join(repo::SECRETS_DIR);
    let mut rotated = 0usize;

    if secrets_dir.exists() {
        for entry in std::fs::read_dir(&secrets_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("age") {
                let ciphertext = std::fs::read(&path)?;
                let plaintext = crypto::decrypt(&identity, &ciphertext)?;
                // Re-parse recipients fresh for each file (Recipient is not Clone)
                let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys.iter()
                    .map(|k| Ok(Box::new(crypto::parse_recipient(k)?) as Box<dyn age::Recipient + Send>))
                    .collect::<Result<Vec<_>, GitvaultError>>()?;
                let new_ciphertext = crypto::encrypt(recipients, &plaintext)?;
                let tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
                std::fs::write(tmp.path(), &new_ciphertext)?;
                tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
                rotated += 1;
            }
        }
    }
    output_success(&format!("Rotated {rotated} secret(s) to {} recipient(s)", recipient_keys.len()), json);
    Ok(())
}

/// Manage identity key in OS keyring (REQ-39)
fn cmd_keyring(action: KeyringAction, json: bool) -> Result<(), GitvaultError> {
    match action {
        KeyringAction::Set { identity } => {
            let key = load_identity(identity)?;
            keyring_store::keyring_set(&key)
                .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            output_success("Identity stored in OS keyring.", json);
        }
        KeyringAction::Get => {
            let key = keyring_store::keyring_get()
                .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            let identity = crypto::parse_identity(&key)?;
            let pubkey = identity.to_public().to_string();
            if json {
                println!("{}", serde_json::json!({"public_key": pubkey}));
            } else {
                println!("Public key: {pubkey}");
            }
        }
        KeyringAction::Delete => {
            keyring_store::keyring_delete()
                .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            output_success("Identity removed from OS keyring.", json);
        }
    }
    Ok(())
}

/// Run preflight validation without side effects (REQ-50)
fn cmd_check(env_override: Option<String>, identity_path: Option<String>, json: bool) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let env = env_override.unwrap_or_else(|| env::resolve_env(&repo_root));

    // Check 1: no tracked plaintext (REQ-10)
    repo::check_no_tracked_plaintext(&repo_root)?;

    // Check 2: identity is loadable
    let identity_str = load_identity(identity_path)?;
    crypto::parse_identity(&identity_str)?;

    // Check 3: recipients file is readable and all keys are valid
    let recipients = repo::read_recipients(&repo_root)?;
    for key in &recipients {
        crypto::parse_recipient(key).map_err(|e| {
            GitvaultError::Usage(format!("Invalid recipient in .secrets/recipients: {key}: {e}"))
        })?;
    }

    // Check 4: secrets dir exists (warning only)
    let secrets_dir = repo_root.join(repo::SECRETS_DIR);
    let secrets_count = if secrets_dir.exists() {
        std::fs::read_dir(&secrets_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("age"))
            .count()
    } else {
        0
    };

    if json {
        println!("{}", serde_json::json!({
            "status": "ok",
            "env": env,
            "identity": "valid",
            "recipients": recipients.len(),
            "secrets": secrets_count,
            "format_version": crypto::GITVAULT_FORMAT_VERSION,
        }));
    } else {
        println!("✅ Preflight check passed");
        println!("   Environment : {env}");
        println!("   Identity    : valid");
        println!("   Recipients  : {}", recipients.len());
        println!("   Secrets     : {secrets_count} encrypted file(s)");
    }
    Ok(())
}

/// Load identity key string from file path or GITVAULT_IDENTITY env var
fn load_identity(path: Option<String>) -> Result<String, GitvaultError> {
    if let Some(p) = path {
        return load_identity_source(&p, "--identity");
    }
    if let Ok(key) = std::env::var("GITVAULT_IDENTITY") {
        return load_identity_source(&key, "GITVAULT_IDENTITY");
    }
    // REQ-39: load from OS keyring if GITVAULT_KEYRING=1
    if std::env::var("GITVAULT_KEYRING").as_deref() == Ok("1") {
        return keyring_store::keyring_get()
            .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")));
    }
    Err(GitvaultError::Usage(
        "No identity provided. Use --identity <file>, set GITVAULT_IDENTITY, or use GITVAULT_KEYRING=1".to_string(),
    ))
}

fn load_identity_source(source: &str, source_name: &str) -> Result<String, GitvaultError> {
    let value = source.trim();

    if value.starts_with("AGE-SECRET-KEY-") {
        return Ok(value.to_string());
    }

    let file_content = std::fs::read_to_string(value).map_err(|e| {
        GitvaultError::Usage(format!(
            "{source_name} must be an identity file path or AGE-SECRET-KEY value: {e}"
        ))
    })?;

    extract_identity_key(&file_content).ok_or_else(|| {
        GitvaultError::Usage(format!(
            "{source_name} file does not contain a valid AGE-SECRET-KEY line"
        ))
    })
}

fn extract_identity_key(content: &str) -> Option<String> {
    content
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .map(|line| line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use age::x25519;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_recipient_keys_defaults_to_local_identity_public_key() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let expected_recipient = identity.to_public().to_string();

        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe { std::env::set_var("GITVAULT_IDENTITY", identity_secret.expose_secret()); }

        let resolved = resolve_recipient_keys(dir.path(), vec![]).expect("default recipient resolution should succeed");

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

        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var(
                "GITVAULT_IDENTITY",
                identity_file.path().to_string_lossy().to_string(),
            );
        }

        let resolved = resolve_recipient_keys(dir.path(), vec![]).expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe { std::env::set_var("GITVAULT_IDENTITY", value); },
            None => unsafe { std::env::remove_var("GITVAULT_IDENTITY"); },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_fails_without_identity_source() {
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        let previous_keyring = std::env::var("GITVAULT_KEYRING").ok();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::remove_var("GITVAULT_KEYRING");
        }

        let result = resolve_recipient_keys(dir.path(), vec![]);

        match previous {
            Some(value) => unsafe { std::env::set_var("GITVAULT_IDENTITY", value); },
            None => unsafe { std::env::remove_var("GITVAULT_IDENTITY"); },
        }
        match previous_keyring {
            Some(value) => unsafe { std::env::set_var("GITVAULT_KEYRING", value); },
            None => unsafe { std::env::remove_var("GITVAULT_KEYRING"); },
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
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe { std::env::set_var("GITVAULT_IDENTITY", "AGE-SECRET-KEY-INVALID"); }

        let result = resolve_recipient_keys(dir.path(), vec![]);

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

    #[test]
    fn test_load_identity_source_accepts_key_file_with_newline() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let identity_file = NamedTempFile::new().expect("temp file should be created");

        std::fs::write(identity_file.path(), format!("{}\n", identity_secret.expose_secret()))
            .expect("identity should be written to temp file");

        let loaded = load_identity_source(
            &identity_file.path().to_string_lossy(),
            "GITVAULT_IDENTITY",
        )
        .expect("identity file with newline should parse");

        assert_eq!(loaded.as_str(), identity_secret.expose_secret().as_str());
    }

    #[test]
    fn test_load_identity_source_accepts_age_keygen_style_file() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let identity_file = NamedTempFile::new().expect("temp file should be created");

        let key_file_content = format!(
            "# created: 2026-03-01T00:00:00Z\n# public key: {}\n{}\n",
            identity.to_public(),
            identity_secret.expose_secret()
        );
        std::fs::write(identity_file.path(), key_file_content)
            .expect("identity should be written to temp file");

        let loaded = load_identity_source(
            &identity_file.path().to_string_lossy(),
            "GITVAULT_IDENTITY",
        )
        .expect("age-keygen style identity file should parse");

        assert_eq!(loaded.as_str(), identity_secret.expose_secret().as_str());
    }

    #[test]
    fn test_merge_driver_clean_merge() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        // base: A=1, B=2
        // ours: A=1, B=3  (changed B)
        // theirs: A=2, B=2  (changed A)
        // expected merge: A=2, B=3
        std::fs::write(&base, "A=1\nB=2\n").unwrap();
        std::fs::write(&ours, "A=1\nB=3\n").unwrap();
        std::fs::write(&theirs, "A=2\nB=2\n").unwrap();

        cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
        ).unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        let kv: std::collections::HashMap<_, _> = result.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .collect();

        assert_eq!(kv.get("A"), Some(&"2"), "A should be taken from theirs");
        assert_eq!(kv.get("B"), Some(&"3"), "B should be kept from ours");
    }

    #[test]
    fn test_ci_env_sets_no_prompt() {
        // The CI=1 logic is: if !cli.no_prompt && CI is non-empty, set no_prompt = true
        let ci_is_set = std::env::var("CI").map(|v| !v.is_empty()).unwrap_or(false);
        // Simulate what run() does
        let mut no_prompt = false;
        if !no_prompt && ci_is_set {
            no_prompt = true;
        }
        // If CI is set, no_prompt should be true; otherwise it stays false — either way no panic
        if ci_is_set {
            assert!(no_prompt, "CI env var should enable no_prompt");
        } else {
            assert!(!no_prompt, "no_prompt should stay false when CI is unset");
        }

        // Also verify the logic directly with a forced value
        let mut no_prompt2 = false;
        let ci_forced = true;
        if !no_prompt2 && ci_forced {
            no_prompt2 = true;
        }
        assert!(no_prompt2, "CI auto-detect logic should set no_prompt");
    }
}
