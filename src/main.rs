mod aws_config;
mod barrier;
mod cli;
mod crypto;
mod env;
mod error;
mod fhsm;
mod identity;
mod keyring_store;
mod materialize;
mod merge;
mod permissions;
mod repo;
mod run;
mod structured;

use clap::Parser;
use cli::{Cli, Commands, KeyringAction, RecipientAction};
use error::GitvaultError;
use identity::*;
use merge::*;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandOutcome {
    Success,
    Exit(i32),
}

fn main() {
    let cli = Cli::parse();

    let result = run(cli);
    match result {
        Ok(CommandOutcome::Success) => process::exit(error::EXIT_SUCCESS),
        Ok(CommandOutcome::Exit(code)) => process::exit(code),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(e.exit_code());
        }
    }
}

fn run(mut cli: Cli) -> Result<CommandOutcome, GitvaultError> {
    cli.no_prompt = resolve_no_prompt(cli.no_prompt);
    match cli.command {
        Commands::Encrypt {
            file,
            recipients,
            fields,
            value_only,
        } => {
            cmd_encrypt(
                file,
                recipients,
                fields,
                value_only,
                cli.json,
                cli.no_prompt,
            )?;
            Ok(CommandOutcome::Success)
        }
        Commands::Decrypt {
            file,
            identity,
            output,
            fields,
            reveal,
        } => {
            cmd_decrypt(
                file,
                identity,
                output,
                fields,
                reveal,
                cli.json,
                cli.no_prompt,
            )?;
            Ok(CommandOutcome::Success)
        }
        Commands::Materialize {
            env,
            identity,
            prod,
        } => {
            cmd_materialize(env, identity, prod, cli.json, cli.no_prompt)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Status { fail_if_dirty } => {
            cmd_status(cli.json, fail_if_dirty)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Harden => {
            cmd_harden(cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Run {
            env,
            identity,
            prod,
            clear_env,
            pass,
            command,
        } => cmd_run(
            env,
            identity,
            prod,
            clear_env,
            pass,
            command,
            cli.json,
            cli.no_prompt,
        ),
        Commands::AllowProd { ttl } => {
            cmd_allow_prod(ttl, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::MergeDriver { base, ours, theirs } => cmd_merge_driver(base, ours, theirs),
        Commands::Recipient { action } => {
            cmd_recipient(action, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Rotate { identity } => {
            cmd_rotate(identity, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Keyring { action } => {
            cmd_keyring(action, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Check { env, identity } => {
            cmd_check(env, identity, cli.json)?;
            Ok(CommandOutcome::Success)
        }
    }
}

fn resolve_no_prompt(no_prompt: bool) -> bool {
    no_prompt || ci_is_non_interactive()
}

fn ci_is_non_interactive() -> bool {
    std::env::var("CI").map(|v| !v.is_empty()).unwrap_or(false)
}

/// Walk up from `start` until a `.git` directory is found, returning that directory.
/// Falls back to `start` itself when no `.git` is found (e.g. outside any repository).
fn find_repo_root_from(start: &Path) -> Result<PathBuf, GitvaultError> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join(".git").exists() {
            return Ok(dir);
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => return Ok(start.to_path_buf()),
        }
    }
}

/// Find the repository root by walking up from cwd looking for .git
fn find_repo_root() -> Result<PathBuf, GitvaultError> {
    find_repo_root_from(&std::env::current_dir()?)
}

/// Output a success result, optionally as JSON
fn output_success(message: &str, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"status": "ok", "message": message})
        );
    } else {
        println!("{message}");
    }
}

/// Encrypt a file and write the .age output under secrets/
fn cmd_encrypt(
    file: String,
    recipient_keys: Vec<String>,
    fields: Option<String>,
    value_only: bool,
    json: bool,
    _no_prompt: bool,
) -> Result<(), GitvaultError> {
    let repo_root = find_repo_root()?;
    let input_path = PathBuf::from(&file);

    // REQ-33: each source file maps to exactly one .age artifact
    if input_path.extension().and_then(|e| e.to_str()) == Some("age") {
        return Err(GitvaultError::Usage(
            "Cannot encrypt an already-encrypted .age file (REQ-33: no mega-blob)".to_string(),
        ));
    }

    let recipient_keys = resolve_recipient_keys(&repo_root, recipient_keys)?;

    // REQ-4: field-level encryption for JSON/YAML/TOML
    if let Some(fields_str) = &fields {
        let fields: Vec<&str> = fields_str.split(',').map(str::trim).collect();
        let identity_str = load_identity(None)?;
        let identity = crypto::parse_identity(&identity_str)?;
        structured::encrypt_fields(&input_path, &fields, &identity, &recipient_keys)
            .map_err(|e| GitvaultError::Encryption(e.to_string()))?;
        output_success(
            &format!(
                "Encrypted fields [{fields_str}] in {}",
                input_path.display()
            ),
            json,
        );
        return Ok(());
    }

    // REQ-6: .env value-only mode
    let ext = input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if value_only
        && (ext == "env"
            || input_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .starts_with(".env"))
    {
        let identity_str = load_identity(None)?;
        let identity = crypto::parse_identity(&identity_str)?;
        let content = std::fs::read_to_string(&input_path)?;
        let encrypted = structured::encrypt_env_values(&content, &identity, &recipient_keys)
            .map_err(|e| GitvaultError::Encryption(e.to_string()))?;
        // REQ-43: atomic write
        let tmp = tempfile::NamedTempFile::new_in(
            input_path.parent().unwrap_or(std::path::Path::new(".")),
        )?;
        std::fs::write(tmp.path(), encrypted)?;
        tmp.persist(&input_path)
            .map_err(|e| GitvaultError::Io(e.error))?;
        output_success(
            &format!("Encrypted .env values in {}", input_path.display()),
            json,
        );
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
    let active_env = env::resolve_env(&repo_root);

    repo::ensure_dirs(&repo_root, &active_env)?;
    let out_path = repo::get_env_encrypted_path(&repo_root, &active_env, &out_name);

    // REQ-42: prevent path traversal
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming encryption — no full-file buffer
    let tmp =
        tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
    {
        let mut in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::encrypt_stream(recipients, &mut in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    output_success(&format!("Encrypted to {}", out_path.display()), json);
    Ok(())
}

/// Decrypt a .age file and write plaintext
fn cmd_decrypt(
    file: String,
    identity_path: Option<String>,
    output: Option<String>,
    fields: Option<String>,
    reveal: bool,
    json: bool,
    no_prompt: bool,
) -> Result<(), GitvaultError> {
    // Use FHSM to resolve the identity source; file I/O remains here.
    let event = fhsm::Event::Decrypt {
        file: file.clone(),
        identity: identity_path,
        no_prompt,
        output: output.clone(),
    };
    let effects = fhsm::transition(&event).map_err(|e| GitvaultError::Usage(e.to_string()))?;
    let identity_str = effects
        .iter()
        .find_map(|e| {
            if let fhsm::Effect::ResolveIdentity { source } = e {
                Some(load_identity_from_source(source))
            } else {
                None
            }
        })
        .unwrap_or_else(|| load_identity(None))?;

    let input_path = PathBuf::from(&file);
    let identity = crypto::parse_identity(&identity_str)?;

    // REQ-4: field-level decryption for JSON/YAML/TOML
    if let Some(fields_str) = &fields {
        let fields: Vec<&str> = fields_str.split(',').map(str::trim).collect();
        structured::decrypt_fields(&input_path, &fields, &identity)
            .map_err(|e| GitvaultError::Decryption(e.to_string()))?;
        output_success(
            &format!(
                "Decrypted fields [{fields_str}] in {}",
                input_path.display()
            ),
            json,
        );
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
        input_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(out_name)
    };

    // REQ-42: prevent path traversal
    let repo_root = find_repo_root()?;
    repo::validate_write_path(&repo_root, &out_path)?;

    // REQ-51: streaming decryption
    let tmp =
        tempfile::NamedTempFile::new_in(out_path.parent().unwrap_or(std::path::Path::new(".")))?;
    {
        let in_file = std::io::BufReader::new(std::fs::File::open(&input_path)?);
        let mut out_file = std::io::BufWriter::new(tmp.as_file());
        crypto::decrypt_stream(&identity, in_file, &mut out_file)?;
    }
    tmp.persist(&out_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    output_success(&format!("Decrypted to {}", out_path.display()), json);
    Ok(())
}

fn decrypt_env_secrets(
    repo_root: &Path,
    env: &str,
    identity: &dyn age::Identity,
) -> Result<Vec<(String, String)>, GitvaultError> {
    let mut secrets: Vec<(String, String)> = Vec::new();
    let encrypted_files = repo::list_encrypted_files_for_env(repo_root, env)?;

    for path in encrypted_files {
        let ciphertext = std::fs::read(&path)?;
        match crypto::decrypt(identity, &ciphertext) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                secrets.extend(parse_env_pairs(&text)?);
            }
            Err(e) => {
                return Err(GitvaultError::Decryption(format!(
                    "Failed to decrypt {}: {e}",
                    path.display()
                )));
            }
        }
    }

    Ok(secrets)
}

/// Injectable side-effect executor for [`execute_effects_with`].
///
/// Each method corresponds to one [`fhsm::Effect`] variant that requires I/O.
/// Implementations receive the repo root and accumulated state as parameters.
trait EffectRunner {
    fn check_prod_barrier(
        &self,
        repo_root: &Path,
        env: &str,
        prod: bool,
        no_prompt: bool,
    ) -> Result<(), GitvaultError>;

    fn load_identity_str(&self, source: &fhsm::IdentitySource) -> Result<String, GitvaultError>;

    fn decrypt_secrets(
        &self,
        repo_root: &Path,
        env: &str,
        identity: &dyn age::Identity,
    ) -> Result<Vec<(String, String)>, GitvaultError>;

    fn run_command(
        &self,
        secrets: &[(String, String)],
        command: &[String],
        clear_env: bool,
        pass_vars: &[(String, String)],
    ) -> Result<i32, GitvaultError>;

    fn materialize_secrets(
        &self,
        repo_root: &Path,
        secrets: &[(String, String)],
    ) -> Result<(), GitvaultError>;
}

/// Production implementation — delegates to the real I/O functions.
struct RealEffectRunner;

impl EffectRunner for RealEffectRunner {
    fn check_prod_barrier(
        &self,
        repo_root: &Path,
        env: &str,
        prod: bool,
        no_prompt: bool,
    ) -> Result<(), GitvaultError> {
        barrier::check_prod_barrier(repo_root, env, prod, no_prompt)
    }

    fn load_identity_str(&self, source: &fhsm::IdentitySource) -> Result<String, GitvaultError> {
        load_identity_from_source(source)
    }

    fn decrypt_secrets(
        &self,
        repo_root: &Path,
        env: &str,
        identity: &dyn age::Identity,
    ) -> Result<Vec<(String, String)>, GitvaultError> {
        decrypt_env_secrets(repo_root, env, identity)
    }

    fn run_command(
        &self,
        secrets: &[(String, String)],
        command: &[String],
        clear_env: bool,
        pass_vars: &[(String, String)],
    ) -> Result<i32, GitvaultError> {
        let cmd = &command[0];
        let args = &command[1..];
        // Extract var names from key-value pairs for run_command's pass-through lookup.
        let pass_var_names: Vec<String> = pass_vars.iter().map(|(k, _)| k.clone()).collect();
        run::run_command(secrets, cmd, args, clear_env, &pass_var_names)
    }

    fn materialize_secrets(
        &self,
        repo_root: &Path,
        secrets: &[(String, String)],
    ) -> Result<(), GitvaultError> {
        materialize::materialize_env_file(repo_root, secrets)
    }
}

/// Execute an ordered list of FHSM [`fhsm::Effect`]s, delegating I/O to `runner`.
///
/// State (resolved identity, decrypted secrets) is accumulated across effects so
/// that later effects can depend on earlier ones.  Returns early with the
/// subprocess exit code for [`fhsm::Effect::RunCommand`].
fn execute_effects_with(
    effects: Vec<fhsm::Effect>,
    repo_root: &Path,
    runner: &dyn EffectRunner,
) -> Result<CommandOutcome, GitvaultError> {
    let mut identity_opt: Option<Box<dyn age::Identity>> = None;
    let mut secrets_opt: Option<Vec<(String, String)>> = None;

    for effect in effects {
        match effect {
            fhsm::Effect::CheckProdBarrier {
                env,
                prod,
                no_prompt,
            } => {
                runner.check_prod_barrier(repo_root, &env, prod, no_prompt)?;
            }
            fhsm::Effect::ResolveIdentity { source } => {
                let identity_str = runner.load_identity_str(&source)?;
                identity_opt = Some(Box::new(crypto::parse_identity(&identity_str)?));
            }
            fhsm::Effect::DecryptSecrets { env } => {
                let identity = identity_opt
                    .as_deref()
                    .ok_or_else(|| GitvaultError::Usage("identity not resolved".to_string()))?;
                secrets_opt = Some(runner.decrypt_secrets(repo_root, &env, identity)?);
            }
            fhsm::Effect::RunCommand {
                command,
                clear_env,
                pass_vars,
            } => {
                let secrets = secrets_opt.as_deref().unwrap_or(&[]);
                let exit_code = runner.run_command(secrets, &command, clear_env, &pass_vars)?;
                return Ok(CommandOutcome::Exit(exit_code));
            }
            fhsm::Effect::MaterializeSecrets { env: _ } => {
                let secrets = secrets_opt
                    .as_ref()
                    .ok_or_else(|| GitvaultError::Usage("secrets not decrypted".to_string()))?;
                runner.materialize_secrets(repo_root, secrets)?;
            }
            // DecryptFile effects are handled directly in cmd_decrypt.
            fhsm::Effect::DecryptFile { .. } => {}
        }
    }
    Ok(CommandOutcome::Success)
}

/// Execute an ordered list of FHSM [`fhsm::Effect`]s using the real I/O functions.
fn execute_effects(effects: Vec<fhsm::Effect>) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = find_repo_root()?;
    execute_effects_with(effects, &repo_root, &RealEffectRunner)
}

/// Materialize secrets to root .env
fn cmd_materialize(
    env_override: Option<String>,
    identity_path: Option<String>,
    prod: bool,
    json: bool,
    no_prompt: bool,
) -> Result<(), GitvaultError> {
    let event = fhsm::Event::Materialize {
        env: env_override,
        identity: identity_path,
        prod,
        no_prompt,
    };
    let effects = fhsm::transition(&event).map_err(|e| GitvaultError::Usage(e.to_string()))?;
    execute_effects(effects)?;
    output_success("Materialized secrets to .env", json);
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
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "env": env,
                "plaintext_leaked": false
            })
        );
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
    output_success(
        "Repository hardened: .gitignore updated, git hooks installed.",
        json,
    );
    Ok(())
}

/// Run a command with secrets injected as environment variables (REQ-21..25)
#[allow(clippy::too_many_arguments)]
fn cmd_run(
    env_override: Option<String>,
    identity_path: Option<String>,
    prod: bool,
    clear_env: bool,
    pass_raw: Option<String>,
    command: Vec<String>,
    _json: bool,
    no_prompt: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let event = fhsm::Event::Run {
        env: env_override,
        identity: identity_path,
        prod,
        no_prompt,
        clear_env,
        pass_raw,
        command,
    };
    let effects = fhsm::transition(&event).map_err(|e| GitvaultError::Usage(e.to_string()))?;
    execute_effects(effects)
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
fn cmd_merge_driver(
    base: String,
    ours: String,
    theirs: String,
) -> Result<CommandOutcome, GitvaultError> {
    let base_content = std::fs::read_to_string(&base)?;
    let ours_content = std::fs::read_to_string(&ours)?;
    let theirs_content = std::fs::read_to_string(&theirs)?;

    let (merged_content, has_conflict) =
        merge_env_content(&base_content, &ours_content, &theirs_content);

    let ours_path = std::path::PathBuf::from(&ours);
    let tmp =
        tempfile::NamedTempFile::new_in(ours_path.parent().unwrap_or(std::path::Path::new(".")))?;
    std::fs::write(tmp.path(), &merged_content)?;
    tmp.persist(&ours_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    if has_conflict {
        return Ok(CommandOutcome::Exit(1));
    }

    Ok(CommandOutcome::Success)
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
                return Err(GitvaultError::Usage(format!(
                    "Recipient already present: {pubkey}"
                )));
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
                return Err(GitvaultError::Usage(format!(
                    "Recipient not found: {pubkey}"
                )));
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
    let mut rotated = 0usize;

    let encrypted_files = repo::list_all_encrypted_files(&repo_root)?;
    for path in encrypted_files {
        let ciphertext = std::fs::read(&path)?;
        let plaintext = crypto::decrypt(&identity, &ciphertext)?;
        let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
            .iter()
            .map(|k| Ok(Box::new(crypto::parse_recipient(k)?) as Box<dyn age::Recipient + Send>))
            .collect::<Result<Vec<_>, GitvaultError>>()?;
        let new_ciphertext = crypto::encrypt(recipients, &plaintext)?;
        let tmp =
            tempfile::NamedTempFile::new_in(path.parent().unwrap_or(std::path::Path::new(".")))?;
        std::fs::write(tmp.path(), &new_ciphertext)?;
        tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
        rotated += 1;
    }
    output_success(
        &format!(
            "Rotated {rotated} secret(s) to {} recipient(s)",
            recipient_keys.len()
        ),
        json,
    );
    Ok(())
}

/// Manage identity key in OS keyring (REQ-39)
fn cmd_keyring(action: KeyringAction, json: bool) -> Result<(), GitvaultError> {
    cmd_keyring_with_ops(
        action,
        json,
        keyring_store::keyring_set,
        keyring_store::keyring_get,
        keyring_store::keyring_delete,
    )
}

fn cmd_keyring_with_ops<SetFn, GetFn, DeleteFn>(
    action: KeyringAction,
    json: bool,
    keyring_set_fn: SetFn,
    keyring_get_fn: GetFn,
    keyring_delete_fn: DeleteFn,
) -> Result<(), GitvaultError>
where
    SetFn: Fn(&str) -> Result<(), String>,
    GetFn: Fn() -> Result<String, String>,
    DeleteFn: Fn() -> Result<(), String>,
{
    match action {
        KeyringAction::Set { identity } => {
            let key = load_identity(identity)?;
            keyring_set_fn(&key)
                .map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            output_success("Identity stored in OS keyring.", json);
        }
        KeyringAction::Get => {
            let key = keyring_get_fn()
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
            keyring_delete_fn().map_err(|e| GitvaultError::Other(format!("Keyring error: {e}")))?;
            output_success("Identity removed from OS keyring.", json);
        }
    }
    Ok(())
}

/// Run preflight validation without side effects (REQ-50)
fn cmd_check(
    env_override: Option<String>,
    identity_path: Option<String>,
    json: bool,
) -> Result<(), GitvaultError> {
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
            GitvaultError::Usage(format!(
                "Invalid recipient in .secrets/recipients: {key}: {e}"
            ))
        })?;
    }

    // Check 4: secrets count for active env (with legacy fallback)
    let secrets_count = repo::list_encrypted_files_for_env(&repo_root, &env)?.len();

    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "env": env,
                "identity": "valid",
                "recipients": recipients.len(),
                "secrets": secrets_count,
                "format_version": crypto::GITVAULT_FORMAT_VERSION,
            })
        );
    } else {
        println!("✅ Preflight check passed");
        println!("   Environment : {env}");
        println!("   Identity    : valid");
        println!("   Recipients  : {}", recipients.len());
        println!("   Secrets     : {secrets_count} encrypted file(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use age::x25519;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    fn global_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct CwdGuard {
        previous: std::path::PathBuf,
    }

    impl CwdGuard {
        fn enter(path: &Path) -> Self {
            let previous = std::env::current_dir().expect("current dir should be readable");
            std::env::set_current_dir(path).expect("should switch cwd");
            Self { previous }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.previous);
        }
    }

    fn init_git_repo(path: &Path) {
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .expect("git init should run");
        assert!(status.success());
    }

    fn setup_identity_file() -> (NamedTempFile, x25519::Identity) {
        let identity = x25519::Identity::generate();
        let identity_file = NamedTempFile::new().expect("temp file should be created");
        std::fs::write(identity_file.path(), identity.to_string().expose_secret())
            .expect("identity should be written");
        (identity_file, identity)
    }

    fn with_identity_env<T>(identity_path: &Path, f: impl FnOnce() -> T) -> T {
        with_env_var(
            "GITVAULT_IDENTITY",
            Some(identity_path.to_string_lossy().as_ref()),
            f,
        )
    }

    fn with_env_var<T>(name: &str, value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let previous = std::env::var(name).ok();
        match value {
            Some(v) => unsafe {
                std::env::set_var(name, v);
            },
            None => unsafe {
                std::env::remove_var(name);
            },
        }

        let out = f();

        match previous {
            Some(v) => unsafe {
                std::env::set_var(name, v);
            },
            None => unsafe {
                std::env::remove_var(name);
            },
        }

        out
    }

    fn write_encrypted_env_file(
        repo_root: &Path,
        env_name: &str,
        file_name: &str,
        identity: &x25519::Identity,
        plaintext: &str,
    ) {
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext =
            crypto::encrypt(recipients, plaintext.as_bytes()).expect("encryption should succeed");
        let out_path = repo::get_env_encrypted_path(repo_root, env_name, file_name);
        std::fs::create_dir_all(
            out_path
                .parent()
                .expect("encrypted output should have parent directory"),
        )
        .expect("env secrets directory should be created");
        std::fs::write(out_path, ciphertext).expect("ciphertext should be written");
    }

    #[test]
    fn test_resolve_recipient_keys_defaults_to_local_identity_public_key() {
        let _lock = global_test_lock().lock().unwrap();
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let expected_recipient = identity.to_public().to_string();

        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var("GITVAULT_IDENTITY", identity_secret.expose_secret());
        }

        let resolved = resolve_recipient_keys(dir.path(), vec![])
            .expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_defaults_from_identity_file_path() {
        let _lock = global_test_lock().lock().unwrap();
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

        let resolved = resolve_recipient_keys(dir.path(), vec![])
            .expect("default recipient resolution should succeed");

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }

        assert_eq!(resolved, vec![expected_recipient]);
    }

    #[test]
    fn test_resolve_recipient_keys_fails_without_identity_source() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        let previous_keyring = std::env::var("GITVAULT_KEYRING").ok();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::remove_var("GITVAULT_KEYRING");
        }

        let result = resolve_recipient_keys(dir.path(), vec![]);

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
        }
        match previous_keyring {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_KEYRING", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_KEYRING");
            },
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
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let previous = std::env::var("GITVAULT_IDENTITY").ok();
        unsafe {
            std::env::set_var("GITVAULT_IDENTITY", "AGE-SECRET-KEY-INVALID");
        }

        let result = resolve_recipient_keys(dir.path(), vec![]);

        match previous {
            Some(value) => unsafe {
                std::env::set_var("GITVAULT_IDENTITY", value);
            },
            None => unsafe {
                std::env::remove_var("GITVAULT_IDENTITY");
            },
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

        std::fs::write(
            identity_file.path(),
            format!("{}\n", identity_secret.expose_secret()),
        )
        .expect("identity should be written to temp file");

        let loaded =
            load_identity_source(&identity_file.path().to_string_lossy(), "GITVAULT_IDENTITY")
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

        let loaded =
            load_identity_source(&identity_file.path().to_string_lossy(), "GITVAULT_IDENTITY")
                .expect("age-keygen style identity file should parse");

        assert_eq!(loaded.as_str(), identity_secret.expose_secret().as_str());
    }

    #[test]
    fn test_load_identity_source_accepts_inline_comment_after_key() {
        let identity = x25519::Identity::generate();
        let identity_secret = identity.to_string();
        let identity_file = NamedTempFile::new().expect("temp file should be created");

        std::fs::write(
            identity_file.path(),
            format!("{} # local-dev\n", identity_secret.expose_secret()),
        )
        .expect("identity should be written to temp file");

        let loaded =
            load_identity_source(&identity_file.path().to_string_lossy(), "GITVAULT_IDENTITY")
                .expect("identity file with inline comment should parse");

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
        )
        .unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        let kv: std::collections::HashMap<_, _> = result
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .collect();

        assert_eq!(kv.get("A"), Some(&"2"), "A should be taken from theirs");
        assert_eq!(kv.get("B"), Some(&"3"), "B should be kept from ours");
    }

    #[test]
    fn test_merge_driver_preserves_unchanged_line_formatting() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        let line = "A = 1 # keep-comment";
        std::fs::write(&base, format!("{line}\n")).unwrap();
        std::fs::write(&ours, format!("{line}\n")).unwrap();
        std::fs::write(&theirs, format!("{line}\n")).unwrap();

        cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
        )
        .unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        assert!(
            result.contains(line),
            "unchanged assignment line should be preserved byte-for-byte"
        );
    }

    #[test]
    fn test_merge_driver_preserves_prefix_and_inline_comment_on_change() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        std::fs::write(&base, "A = 1 # keep-comment\n").unwrap();
        std::fs::write(&ours, "A = 1 # keep-comment\n").unwrap();
        std::fs::write(&theirs, "A = 2\n").unwrap();

        cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
        )
        .unwrap();

        let result = std::fs::read_to_string(&ours).unwrap();
        assert!(
            result.contains("A = 2 # keep-comment"),
            "changed assignment should keep original lhs spacing and inline comment"
        );
    }

    #[test]
    fn test_ci_env_sets_no_prompt() {
        with_env_var("CI", Some("1"), || {
            assert!(resolve_no_prompt(false));
            assert!(resolve_no_prompt(true));
            assert!(ci_is_non_interactive());
        });

        with_env_var("CI", None, || {
            assert!(!resolve_no_prompt(false));
            assert!(resolve_no_prompt(true));
            assert!(!ci_is_non_interactive());
        });
    }

    #[test]
    fn test_cmd_harden_and_status_in_git_repo() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false).expect("harden should succeed");
        cmd_status(false, false).expect("status should succeed in clean repo");

        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore"))
            .expect("gitignore should exist after harden");
        assert!(gitignore.contains(".env"));
        assert!(gitignore.contains(".secrets/plain/"));

        let pre_push = std::fs::read_to_string(dir.path().join(".git/hooks/pre-push"))
            .expect("pre-push hook should be created");
        assert!(pre_push.contains("--fail-if-dirty"));
    }

    #[test]
    fn test_cmd_allow_prod_and_check() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            cmd_allow_prod(30, false).expect("allow-prod should succeed");
            cmd_check(None, None, true).expect("check should succeed with identity and clean repo");
        });
    }

    #[test]
    fn test_cmd_materialize_and_rotate_env_scoped() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(
            dir.path(),
            "dev",
            "app.env.age",
            &identity,
            "API_KEY=abc123\n",
        );

        with_identity_env(identity_file.path(), || {
            cmd_materialize(None, None, false, false, true)
                .expect("materialize should decrypt env-scoped secrets");
            cmd_rotate(None, true).expect("rotate should process env-scoped files");
        });

        let materialized =
            std::fs::read_to_string(dir.path().join(".env")).expect(".env should be created");
        assert!(materialized.contains("API_KEY=\"abc123\""));
    }

    #[test]
    fn test_cmd_recipient_add_list_remove() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let pubkey = x25519::Identity::generate().to_public().to_string();
        cmd_recipient(
            RecipientAction::Add {
                pubkey: pubkey.clone(),
            },
            true,
        )
        .expect("add recipient should succeed");

        cmd_recipient(RecipientAction::List, false).expect("list recipient should succeed");

        cmd_recipient(
            RecipientAction::Remove {
                pubkey: pubkey.clone(),
            },
            false,
        )
        .expect("remove recipient should succeed");

        let recipients = repo::read_recipients(dir.path()).expect("recipients should be readable");
        assert!(recipients.is_empty());
    }

    #[test]
    fn test_run_dispatch_check_and_status() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            let check_cli = Cli {
                json: true,
                no_prompt: true,
                aws_profile: None,
                aws_role_arn: None,
                command: Commands::Check {
                    env: None,
                    identity: None,
                },
            };
            let outcome = run(check_cli).expect("dispatch check should succeed");
            assert_eq!(outcome, CommandOutcome::Success);

            let status_cli = Cli {
                json: false,
                no_prompt: true,
                aws_profile: None,
                aws_role_arn: None,
                command: Commands::Status {
                    fail_if_dirty: false,
                },
            };
            let outcome = run(status_cli).expect("dispatch status should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });
    }

    #[test]
    fn test_run_dispatch_run_returns_exit_outcome() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(dir.path(), "dev", "run.env.age", &identity, "X=1\n");

        with_identity_env(identity_file.path(), || {
            let cli = Cli {
                json: false,
                no_prompt: true,
                aws_profile: None,
                aws_role_arn: None,
                command: Commands::Run {
                    env: Some("dev".to_string()),
                    identity: Some(identity_file.path().to_string_lossy().to_string()),
                    prod: false,
                    clear_env: false,
                    pass: None,
                    command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
                },
            };

            let outcome = run(cli).expect("run dispatch should succeed");
            assert_eq!(outcome, CommandOutcome::Exit(7));
        });
    }

    #[test]
    fn test_merge_driver_conflict_returns_exit_outcome() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        std::fs::write(&base, "A=1\n").unwrap();
        std::fs::write(&ours, "A=2\n").unwrap();
        std::fs::write(&theirs, "A=3\n").unwrap();

        let outcome = cmd_merge_driver(
            base.to_string_lossy().to_string(),
            ours.to_string_lossy().to_string(),
            theirs.to_string_lossy().to_string(),
        )
        .expect("merge driver should return outcome");

        assert_eq!(outcome, CommandOutcome::Exit(1));
    }

    #[test]
    fn test_cmd_encrypt_rejects_age_input_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let in_path = dir.path().join("already.age");
        std::fs::write(&in_path, b"x").unwrap();

        let err = cmd_encrypt(
            in_path.to_string_lossy().to_string(),
            vec![],
            None,
            false,
            true,
            true,
        )
        .expect_err("encrypting .age input should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_encrypt_value_only_writes_in_place() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        let env_file = dir.path().join(".env.local");
        std::fs::write(&env_file, "API_KEY=secret\n").unwrap();

        with_identity_env(identity_file.path(), || {
            cmd_encrypt(
                env_file.to_string_lossy().to_string(),
                vec![recipient],
                None,
                true,
                true,
                true,
            )
            .expect("value-only encryption should succeed");
        });

        let updated = std::fs::read_to_string(&env_file).unwrap();
        assert!(updated.contains("API_KEY=age:"));
    }

    #[test]
    fn test_cmd_encrypt_then_decrypt_fields_roundtrip() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let recipient = identity.to_public().to_string();

        let json_file = dir.path().join("config.json");
        std::fs::write(&json_file, r#"{"secret":"abc","name":"demo"}"#).unwrap();

        with_identity_env(identity_file.path(), || {
            cmd_encrypt(
                json_file.to_string_lossy().to_string(),
                vec![recipient.clone()],
                Some("secret".to_string()),
                false,
                true,
                true,
            )
            .expect("field encryption should succeed");

            cmd_decrypt(
                json_file.to_string_lossy().to_string(),
                None,
                None,
                Some("secret".to_string()),
                false,
                true,
                true,
            )
            .expect("field decryption should succeed");
        });

        let content = std::fs::read_to_string(&json_file).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["secret"], "abc");
        assert_eq!(value["name"], "demo");
    }

    #[test]
    fn test_cmd_run_empty_command_is_usage_error() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let err = cmd_run(None, None, false, false, None, vec![], false, true)
            .expect_err("empty command should fail");

        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_decrypt_reveal_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crypto::encrypt(recipients, b"TOP_SECRET=1\n").unwrap();
        let encrypted_file = dir.path().join("secret.env.age");
        std::fs::write(&encrypted_file, ciphertext).unwrap();

        cmd_decrypt(
            encrypted_file.to_string_lossy().to_string(),
            Some(identity_file.path().to_string_lossy().to_string()),
            None,
            None,
            true,
            true,
            true,
        )
        .expect("reveal mode should decrypt to stdout without error");
    }

    #[test]
    fn test_cmd_decrypt_default_output_path_writes_plaintext() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(identity.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crypto::encrypt(recipients, b"X=42\n").unwrap();
        let encrypted_file = dir.path().join("app.env.age");
        std::fs::write(&encrypted_file, ciphertext).unwrap();

        cmd_decrypt(
            encrypted_file.to_string_lossy().to_string(),
            Some(identity_file.path().to_string_lossy().to_string()),
            None,
            None,
            false,
            true,
            true,
        )
        .expect("default output decrypt should succeed");

        let plain = std::fs::read_to_string(dir.path().join("app.env")).unwrap();
        assert!(plain.contains("X=42"));
    }

    #[test]
    fn test_cmd_materialize_fail_closed_on_invalid_ciphertext() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let env_dir = dir.path().join("secrets/dev");
        std::fs::create_dir_all(&env_dir).unwrap();
        let bad_file = env_dir.join("broken.env.age");
        std::fs::write(&bad_file, b"not-age-data").unwrap();

        let err = cmd_materialize(
            Some("dev".to_string()),
            Some(identity_file.path().to_string_lossy().to_string()),
            false,
            true,
            true,
        )
        .expect_err("invalid ciphertext must fail closed");

        match err {
            GitvaultError::Decryption(message) => {
                assert!(message.contains("Failed to decrypt"));
            }
            other => panic!("expected decryption error, got: {other:?}"),
        }
    }

    #[test]
    fn test_cmd_run_fail_closed_on_invalid_ciphertext() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let env_dir = dir.path().join("secrets/dev");
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(env_dir.join("broken.env.age"), b"not-age-data").unwrap();

        let err = cmd_run(
            Some("dev".to_string()),
            Some(identity_file.path().to_string_lossy().to_string()),
            false,
            false,
            None,
            vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            true,
            true,
        )
        .expect_err("run should fail closed on decrypt error");

        assert!(matches!(err, GitvaultError::Decryption(_)));
    }

    #[test]
    fn test_run_dispatch_encrypt_then_decrypt_arms() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        let plain_file = dir.path().join("dispatch.txt");
        std::fs::write(&plain_file, "DISPATCH=1\n").unwrap();

        let encrypt_cli = Cli {
            json: true,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            command: Commands::Encrypt {
                file: plain_file.to_string_lossy().to_string(),
                recipients: vec![identity.to_public().to_string()],
                fields: None,
                value_only: false,
            },
        };
        let encrypt_outcome = run(encrypt_cli).expect("encrypt dispatch should succeed");
        assert_eq!(encrypt_outcome, CommandOutcome::Success);

        let encrypted_path = dir.path().join("secrets/dev/dispatch.txt.age");
        assert!(encrypted_path.exists());

        let decrypt_cli = Cli {
            json: true,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            command: Commands::Decrypt {
                file: encrypted_path.to_string_lossy().to_string(),
                identity: Some(identity_file.path().to_string_lossy().to_string()),
                output: Some(
                    dir.path()
                        .join("dispatch.out")
                        .to_string_lossy()
                        .to_string(),
                ),
                fields: None,
                reveal: false,
            },
        };
        let decrypt_outcome = run(decrypt_cli).expect("decrypt dispatch should succeed");
        assert_eq!(decrypt_outcome, CommandOutcome::Success);

        let decrypted = std::fs::read_to_string(dir.path().join("dispatch.out")).unwrap();
        assert!(decrypted.contains("DISPATCH=1"));
    }

    #[test]
    fn test_cmd_recipient_duplicate_add_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let pubkey = x25519::Identity::generate().to_public().to_string();

        cmd_recipient(
            RecipientAction::Add {
                pubkey: pubkey.clone(),
            },
            true,
        )
        .unwrap();

        let err = cmd_recipient(RecipientAction::Add { pubkey }, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_recipient_remove_missing_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let missing = x25519::Identity::generate().to_public().to_string();
        let err = cmd_recipient(RecipientAction::Remove { pubkey: missing }, true).unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_cmd_status_fail_if_dirty_returns_plaintext_leak() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        std::fs::create_dir_all(dir.path().join("secrets/dev")).unwrap();
        std::fs::write(dir.path().join("secrets/dev/app.env.age"), b"x").unwrap();

        let err = cmd_status(true, true).unwrap_err();
        assert!(matches!(err, GitvaultError::PlaintextLeak(_)));
    }

    #[test]
    fn test_cmd_keyring_with_ops_success_paths() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();
        let key = identity.to_string().expose_secret().to_string();

        cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            true,
            |_value| Ok(()),
            || Ok(key.clone()),
            || Ok(()),
        )
        .unwrap();

        cmd_keyring_with_ops(
            KeyringAction::Get,
            true,
            |_value| Ok(()),
            || Ok(key.clone()),
            || Ok(()),
        )
        .unwrap();

        cmd_keyring_with_ops(
            KeyringAction::Delete,
            true,
            |_value| Ok(()),
            || Ok(key.clone()),
            || Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn test_cmd_keyring_with_ops_error_paths() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let set_err = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(identity_file.path().to_string_lossy().to_string()),
            },
            true,
            |_value| Err("set-failed".to_string()),
            || Ok("unused".to_string()),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(set_err, GitvaultError::Other(_)));

        let get_err = cmd_keyring_with_ops(
            KeyringAction::Get,
            true,
            |_value| Ok(()),
            || Err("get-failed".to_string()),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(get_err, GitvaultError::Other(_)));

        let delete_err = cmd_keyring_with_ops(
            KeyringAction::Delete,
            true,
            |_value| Ok(()),
            || Ok("unused".to_string()),
            || Err("delete-failed".to_string()),
        )
        .unwrap_err();
        assert!(matches!(delete_err, GitvaultError::Other(_)));
    }

    #[test]
    fn test_with_env_var_restores_existing_value() {
        let _lock = global_test_lock().lock().unwrap();
        unsafe {
            std::env::set_var("GITVAULT_TEST_VAR", "before");
        }
        let _ = with_env_var("GITVAULT_TEST_VAR", Some("during"), || {
            std::env::var("GITVAULT_TEST_VAR").unwrap()
        });
        assert_eq!(
            std::env::var("GITVAULT_TEST_VAR").unwrap(),
            "before".to_string()
        );
        unsafe {
            std::env::remove_var("GITVAULT_TEST_VAR");
        }
    }

    #[test]
    fn test_load_identity_with_uses_keyring_when_enabled() {
        let _lock = global_test_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::set_var("GITVAULT_KEYRING", "1");
        }

        let value = load_identity_with(None, || Ok("AGE-SECRET-KEY-TEST".to_string())).unwrap();

        unsafe {
            std::env::remove_var("GITVAULT_KEYRING");
        }
        assert_eq!(value, "AGE-SECRET-KEY-TEST");
    }

    #[test]
    fn test_load_identity_with_maps_keyring_error() {
        let _lock = global_test_lock().lock().unwrap();
        unsafe {
            std::env::remove_var("GITVAULT_IDENTITY");
            std::env::set_var("GITVAULT_KEYRING", "1");
        }

        let err = load_identity_with(None, || Err("no key".to_string())).unwrap_err();

        unsafe {
            std::env::remove_var("GITVAULT_KEYRING");
        }
        assert!(matches!(err, GitvaultError::Other(_)));
    }

    #[test]
    fn test_cmd_check_plain_output_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            cmd_check(None, None, false).expect("plain check should succeed");
        });
    }

    #[test]
    fn test_cmd_check_invalid_recipient_fails() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let recipients_path = dir.path().join(".secrets/recipients");
        std::fs::create_dir_all(recipients_path.parent().unwrap()).unwrap();
        std::fs::write(&recipients_path, "not-a-valid-recipient\n").unwrap();

        with_identity_env(identity_file.path(), || {
            let err = cmd_check(None, None, true).unwrap_err();
            assert!(matches!(err, GitvaultError::Usage(_)));
        });
    }

    #[test]
    fn test_run_dispatch_allow_prod_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = Cli {
            json: true,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            command: Commands::AllowProd { ttl: 60 },
        };

        let outcome = run(cli).expect("allow-prod dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
        assert!(dir.path().join(".secrets/.prod-token").exists());
    }

    #[test]
    fn test_run_dispatch_rotate_succeeds() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(dir.path(), "dev", "rotate.env.age", &identity, "A=1\n");

        with_identity_env(identity_file.path(), || {
            let cli = Cli {
                json: true,
                no_prompt: true,
                aws_profile: None,
                aws_role_arn: None,
                command: Commands::Rotate { identity: None },
            };

            let outcome = run(cli).expect("rotate dispatch should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });
    }

    #[test]
    fn test_run_dispatch_merge_driver_outcomes() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();

        let base = dir.path().join("base.env");
        let ours = dir.path().join("ours.env");
        let theirs = dir.path().join("theirs.env");

        std::fs::write(&base, "A=1\n").unwrap();
        std::fs::write(&ours, "A=1\n").unwrap();
        std::fs::write(&theirs, "A=2\n").unwrap();

        let clean_cli = Cli {
            json: false,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            command: Commands::MergeDriver {
                base: base.to_string_lossy().to_string(),
                ours: ours.to_string_lossy().to_string(),
                theirs: theirs.to_string_lossy().to_string(),
            },
        };
        let clean_outcome = run(clean_cli).expect("merge-driver clean dispatch should succeed");
        assert_eq!(clean_outcome, CommandOutcome::Success);

        std::fs::write(&base, "A=1\n").unwrap();
        std::fs::write(&ours, "A=2\n").unwrap();
        std::fs::write(&theirs, "A=3\n").unwrap();

        let conflict_cli = Cli {
            json: false,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            command: Commands::MergeDriver {
                base: base.to_string_lossy().to_string(),
                ours: ours.to_string_lossy().to_string(),
                theirs: theirs.to_string_lossy().to_string(),
            },
        };
        let conflict_outcome =
            run(conflict_cli).expect("merge-driver conflict dispatch should return outcome");
        assert_eq!(conflict_outcome, CommandOutcome::Exit(1));
    }

    #[test]
    fn test_run_dispatch_keyring_set_invalid_identity_errors() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = Cli {
            json: true,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            command: Commands::Keyring {
                action: KeyringAction::Set {
                    identity: Some("/path/that/does/not/exist".to_string()),
                },
            },
        };

        let err = run(cli).expect_err("invalid identity source should fail keyring set");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    // ─── load_identity_from_source ────────────────────────────────────────────

    #[test]
    fn load_identity_from_source_file_path_valid() {
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::FilePath(tmp_file.path().to_string_lossy().to_string());
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_file_path_nonexistent_errors() {
        let source =
            fhsm::IdentitySource::FilePath("/nonexistent/path/to/identity.age".to_string());
        assert!(load_identity_from_source(&source).is_err());
    }

    #[test]
    fn load_identity_from_source_env_var_with_file_path() {
        // EnvVar(v) passes `v` as the value to load_identity_source, so a file path works.
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::EnvVar(tmp_file.path().to_string_lossy().to_string());
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_inline_nonempty_returns_ok() {
        let (_, identity) = setup_identity_file();
        let key_str = identity.to_string().expose_secret().to_string();
        let source = fhsm::IdentitySource::Inline(key_str);
        assert!(load_identity_from_source(&source).is_ok());
    }

    #[test]
    fn load_identity_from_source_inline_empty_falls_back_to_env_var() {
        let _lock = global_test_lock().lock().unwrap();
        let (tmp_file, _) = setup_identity_file();
        let source = fhsm::IdentitySource::Inline(String::new());
        // Provide GITVAULT_IDENTITY so load_identity(None) can resolve it.
        let result = with_env_var(
            "GITVAULT_IDENTITY",
            Some(tmp_file.path().to_string_lossy().as_ref()),
            || {
                with_env_var("GITVAULT_KEYRING", None, || {
                    load_identity_from_source(&source)
                })
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn load_identity_from_source_keyring_without_setup_errors() {
        let source = fhsm::IdentitySource::Keyring;
        // Without the OS keyring configured this call returns an error.
        assert!(load_identity_from_source(&source).is_err());
    }

    // ─── output_success ───────────────────────────────────────────────────────

    #[test]
    fn output_success_plain_does_not_panic() {
        output_success("hello", false);
    }

    #[test]
    fn output_success_json_does_not_panic() {
        output_success("hello", true);
    }

    // ─── cmd_keyring_with_ops ─────────────────────────────────────────────────

    #[test]
    fn test_cmd_keyring_set_stores_key() {
        let (tmp_file, _) = setup_identity_file();
        let stored = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stored_clone = stored.clone();
        let result = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(tmp_file.path().to_string_lossy().to_string()),
            },
            false,
            move |key: &str| {
                *stored_clone.lock().unwrap() = key.to_string();
                Ok(())
            },
            || Err("not used".to_string()),
            || Err("not used".to_string()),
        );
        assert!(result.is_ok());
        assert!(stored.lock().unwrap().starts_with("AGE-SECRET-KEY-"));
    }

    #[test]
    fn test_cmd_keyring_get_returns_public_key() {
        let (_, identity) = setup_identity_file();
        let key_str = identity.to_string().expose_secret().to_string();
        let result = cmd_keyring_with_ops(
            KeyringAction::Get,
            false,
            |_| Err("not used".to_string()),
            move || Ok(key_str.clone()),
            || Err("not used".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_keyring_delete_calls_delete_fn() {
        let called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let called_clone = called.clone();
        let result = cmd_keyring_with_ops(
            KeyringAction::Delete,
            false,
            |_| Err("not used".to_string()),
            || Err("not used".to_string()),
            move || {
                *called_clone.lock().unwrap() = true;
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_cmd_keyring_set_propagates_store_error() {
        let (tmp_file, _) = setup_identity_file();
        let result = cmd_keyring_with_ops(
            KeyringAction::Set {
                identity: Some(tmp_file.path().to_string_lossy().to_string()),
            },
            false,
            |_| Err("store failed".to_string()),
            || Err("not used".to_string()),
            || Err("not used".to_string()),
        );
        assert!(matches!(result, Err(GitvaultError::Other(_))));
    }

    // ─── find_repo_root_from tests ───────────────────────────────────────────

    #[test]
    fn find_repo_root_from_finds_git_dir() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let found = find_repo_root_from(tmp.path()).unwrap();
        assert_eq!(found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_walks_up() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let sub = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();
        let found = find_repo_root_from(&sub).unwrap();
        assert_eq!(found, tmp.path());
    }

    #[test]
    fn find_repo_root_from_returns_start_when_no_git() {
        let tmp = TempDir::new().unwrap();
        // No .git dir — should return start path
        let found = find_repo_root_from(tmp.path()).unwrap();
        assert_eq!(found, tmp.path());
    }

    // ─── FakeEffectRunner + execute_effects_with tests ───────────────────────

    struct FakeEffectRunner {
        /// None = Ok(()), Some(msg) = Err
        barrier_err: Option<String>,
        identity_str: Result<String, String>,
        decrypt_secrets: Result<Vec<(String, String)>, String>,
        run_exit_code: Result<i32, String>,
        materialize_err: Option<String>,
    }

    impl FakeEffectRunner {
        fn succeeds_with(identity: String, secrets: Vec<(String, String)>, exit_code: i32) -> Self {
            Self {
                barrier_err: None,
                identity_str: Ok(identity),
                decrypt_secrets: Ok(secrets),
                run_exit_code: Ok(exit_code),
                materialize_err: None,
            }
        }
    }

    impl EffectRunner for FakeEffectRunner {
        fn check_prod_barrier(
            &self,
            _repo_root: &Path,
            _env: &str,
            _prod: bool,
            _no_prompt: bool,
        ) -> Result<(), GitvaultError> {
            match &self.barrier_err {
                None => Ok(()),
                Some(msg) => Err(GitvaultError::Other(msg.clone())),
            }
        }

        fn load_identity_str(
            &self,
            _source: &fhsm::IdentitySource,
        ) -> Result<String, GitvaultError> {
            self.identity_str
                .clone()
                .map_err(|e| GitvaultError::Other(e.clone()))
        }

        fn decrypt_secrets(
            &self,
            _repo_root: &Path,
            _env: &str,
            _identity: &dyn age::Identity,
        ) -> Result<Vec<(String, String)>, GitvaultError> {
            self.decrypt_secrets
                .clone()
                .map_err(|e| GitvaultError::Other(e.clone()))
        }

        fn run_command(
            &self,
            _secrets: &[(String, String)],
            _command: &[String],
            _clear_env: bool,
            _pass_vars: &[(String, String)],
        ) -> Result<i32, GitvaultError> {
            self.run_exit_code
                .as_ref()
                .map(|c| *c)
                .map_err(|e| GitvaultError::Other(e.clone()))
        }

        fn materialize_secrets(
            &self,
            _repo_root: &Path,
            _secrets: &[(String, String)],
        ) -> Result<(), GitvaultError> {
            match &self.materialize_err {
                None => Ok(()),
                Some(msg) => Err(GitvaultError::Other(msg.clone())),
            }
        }
    }

    #[test]
    fn execute_effects_run_command_returns_exit_code() {
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().to_string();
        let runner = FakeEffectRunner::succeeds_with(key_str, vec![], 42);
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Run {
            env: Some("dev".to_string()),
            identity: Some(age_key.to_string().expose_secret().to_string()),
            prod: false,
            no_prompt: true,
            clear_env: false,
            pass_raw: None,
            command: vec!["true".to_string()],
        };
        let effects = fhsm::transition(&event).unwrap();
        let outcome = execute_effects_with(effects, tmp.path(), &runner).unwrap();
        assert!(matches!(outcome, CommandOutcome::Exit(42)));
    }

    #[test]
    fn execute_effects_barrier_denied_returns_err() {
        let runner = FakeEffectRunner {
            barrier_err: Some("denied".to_string()),
            identity_str: Ok(String::new()),
            decrypt_secrets: Ok(vec![]),
            run_exit_code: Ok(0),
            materialize_err: None,
        };
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Run {
            env: Some("prod".to_string()),
            identity: Some("key".to_string()),
            prod: true,
            no_prompt: true,
            clear_env: false,
            pass_raw: None,
            command: vec!["true".to_string()],
        };
        let effects = fhsm::transition(&event).unwrap();
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(result.is_err());
    }

    #[test]
    fn execute_effects_materialize_uses_cached_secrets() {
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().to_string();
        let secrets = vec![("FOO".to_string(), "bar".to_string())];
        let runner = FakeEffectRunner::succeeds_with(key_str, secrets, 0);
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Materialize {
            env: None,
            identity: Some(age_key.to_string().expose_secret().to_string()),
            prod: false,
            no_prompt: true,
        };
        let effects = fhsm::transition(&event).unwrap();
        let outcome = execute_effects_with(effects, tmp.path(), &runner).unwrap();
        assert_eq!(outcome, CommandOutcome::Success);
    }

    #[test]
    fn execute_effects_decrypt_without_identity_errors() {
        let runner = FakeEffectRunner {
            barrier_err: None,
            identity_str: Err("no key".to_string()),
            decrypt_secrets: Ok(vec![]),
            run_exit_code: Ok(0),
            materialize_err: None,
        };
        let tmp = TempDir::new().unwrap();
        // Manually build effects to go straight to ResolveIdentity (which will fail) then DecryptSecrets.
        let effects = vec![
            fhsm::Effect::ResolveIdentity {
                source: fhsm::IdentitySource::Inline(String::new()),
            },
            fhsm::Effect::DecryptSecrets {
                env: "dev".to_string(),
            },
        ];
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(result.is_err());
    }

    // ─── cmd_status json output ───────────────────────────────────────────────

    #[test]
    fn test_cmd_status_json_output() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        cmd_harden(false).expect("harden should succeed");
        // json=true covers the JSON output branch (lines 649-656).
        cmd_status(true, false).expect("status json should succeed");
    }

    // ─── cmd_recipient list branches ─────────────────────────────────────────

    #[test]
    fn test_cmd_recipient_list_json_with_recipients() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let pubkey = x25519::Identity::generate().to_public().to_string();
        cmd_recipient(
            RecipientAction::Add {
                pubkey: pubkey.clone(),
            },
            false,
        )
        .expect("add should succeed");

        // json=true covers the JSON recipients output branch (line 881).
        cmd_recipient(RecipientAction::List, true).expect("list json should succeed");
    }

    #[test]
    fn test_cmd_recipient_list_empty_plain() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // No recipients added → empty list message (lines 883-884).
        cmd_recipient(RecipientAction::List, false)
            .expect("list empty plain should succeed");
    }

    // ─── cmd_check with valid recipients ─────────────────────────────────────

    #[test]
    fn test_cmd_check_validates_recipient_keys_in_file() {
        let _lock = global_test_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        // Write a valid recipient so that the for loop on lines 995-1000 executes.
        let pubkey = identity.to_public().to_string();
        repo::write_recipients(dir.path(), &[pubkey]).expect("write_recipients should succeed");

        with_identity_env(identity_file.path(), || {
            cmd_check(None, None, false).expect("check with valid recipient should succeed");
        });
    }

    // ─── load_identity_source: file without AGE key ───────────────────────────

    #[test]
    fn test_load_identity_source_file_without_age_key_errors() {
        let tmp = NamedTempFile::new().expect("temp file should be created");
        std::fs::write(tmp.path(), "not-an-age-key\nsome: yaml: content\n")
            .expect("write should succeed");
        // Lines 1065-1069: extract_identity_key returns None → Usage error.
        let result = load_identity_source(tmp.path().to_str().unwrap(), "test-source");
        assert!(matches!(result, Err(GitvaultError::Usage(_))));
    }

    // ─── resolve_recipient_keys from recipients file ───────────────────────────

    #[test]
    fn test_resolve_recipient_keys_returns_recipients_from_file() {
        let dir = TempDir::new().unwrap();
        let pubkey = x25519::Identity::generate().to_public().to_string();
        // Write a non-empty recipients file so that line 330 (early return) executes.
        repo::write_recipients(dir.path(), &[pubkey.clone()])
            .expect("write_recipients should succeed");

        let result =
            resolve_recipient_keys(dir.path(), vec![]).expect("should return recipients from file");
        assert_eq!(result, vec![pubkey]);
    }

    // ─── execute_effects_with: DecryptFile arm (line 602) ────────────────────

    #[test]
    fn execute_effects_with_decrypt_file_arm_is_noop() {
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().to_string();
        let runner = FakeEffectRunner::succeeds_with(key_str, vec![], 0);
        let tmp = TempDir::new().unwrap();
        // A DecryptFile effect in execute_effects_with is a no-op (line 602).
        let effects = vec![fhsm::Effect::DecryptFile {
            file: tmp.path().join("dummy.age"),
            output: None,
        }];
        let outcome = execute_effects_with(effects, tmp.path(), &runner)
            .expect("DecryptFile arm should succeed as no-op");
        assert_eq!(outcome, CommandOutcome::Success);
    }
}
