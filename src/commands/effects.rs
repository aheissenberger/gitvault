//! FHSM effect runner infrastructure and `CommandOutcome` type.

use std::path::Path;

use crate::error::GitvaultError;
use crate::identity::load_identity_from_source_with_selector;
use crate::{barrier, crypto, fhsm, materialize, run};
use zeroize::Zeroizing;

/// Outcome returned by the top-level command dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    Success,
    Exit(i32),
}

/// Scope used when decrypting env secrets so command-specific rule sets can be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRuleScope {
    Run,
    Materialize,
}

/// Injectable side-effect executor for [`execute_effects_with`].
///
/// Each method corresponds to one [`fhsm::Effect`] variant that requires I/O.
/// Implementations receive the repo root and accumulated state as parameters.
pub trait EffectRunner {
    /// Check the production barrier. See [`barrier::check_prod_barrier`].
    ///
    /// # Errors
    ///
    /// Returns [`GitvaultError::BarrierNotSatisfied`] if the barrier is not satisfied.
    fn check_prod_barrier(
        &self,
        repo_root: &Path,
        env: &str,
        prod: bool,
        no_prompt: bool,
    ) -> Result<(), GitvaultError>;

    /// Resolve an identity key from the given source.
    ///
    /// # Errors
    ///
    /// Returns [`GitvaultError`] if the identity cannot be loaded from the source.
    fn load_identity_str(
        &self,
        source: &fhsm::IdentitySource,
    ) -> Result<Zeroizing<String>, GitvaultError>;

    /// Decrypt all `.age` files for `env` using `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`GitvaultError`] if any file cannot be read or decrypted.
    fn decrypt_secrets(
        &self,
        repo_root: &Path,
        env: &str,
        identity: &dyn age::Identity,
        scope: SecretRuleScope,
    ) -> Result<Vec<(String, String)>, GitvaultError>;

    /// Spawn `command` with `secrets` injected as environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`GitvaultError::Other`] if the child process cannot be spawned.
    fn run_command(
        &self,
        secrets: &[(String, String)],
        command: &[String],
        clear_env: bool,
        pass_vars: &[String],
    ) -> Result<i32, GitvaultError>;

    /// Write decrypted `secrets` to the root `.env` file.
    ///
    /// # Errors
    ///
    /// Returns [`GitvaultError::Io`] if writing the `.env` file fails.
    fn materialize_secrets(
        &self,
        repo_root: &Path,
        secrets: &[(String, String)],
    ) -> Result<(), GitvaultError>;
}

/// Production implementation — delegates to the real I/O functions.
#[derive(Debug, Default)]
pub struct DefaultRunner {
    /// Optional identity selector for SSH-agent key disambiguation (REQ-39/46).
    pub selector: Option<String>,
    /// Environment name that activates the production barrier (from `[env].prod_name`).
    pub prod_name: String,
    /// Output filename for `gitvault materialize` (from `[paths].materialize_output`).
    pub materialize_output: String,
    /// Rules for `gitvault materialize` secret selection.
    pub materialize_rules: Vec<crate::config::MatchRule>,
    /// Global directory-prefix behavior for `gitvault materialize`.
    pub materialize_dir_prefix: bool,
    /// Global filename-prefix behavior for `gitvault materialize`.
    pub materialize_path_prefix: bool,
    /// Rules for `gitvault run` secret selection.
    pub run_rules: Vec<crate::config::MatchRule>,
    /// Global directory-prefix behavior for `gitvault run`.
    pub run_dir_prefix: bool,
    /// Global filename-prefix behavior for `gitvault run`.
    pub run_path_prefix: bool,
}

impl DefaultRunner {
    /// Create a `DefaultRunner` with built-in defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            selector: None,
            prod_name: crate::defaults::DEFAULT_PROD_ENV.to_string(),
            materialize_output: crate::defaults::MATERIALIZE_OUTPUT.to_string(),
            materialize_rules: Vec::new(),
            materialize_dir_prefix: false,
            materialize_path_prefix: false,
            run_rules: Vec::new(),
            run_dir_prefix: false,
            run_path_prefix: false,
        }
    }

    /// Create a `DefaultRunner` with an explicit selector and configured values.
    #[must_use]
    pub fn with_selector(
        selector: Option<String>,
        prod_name: String,
        materialize_output: String,
        materialize_rules: Vec<crate::config::MatchRule>,
        materialize_dir_prefix: bool,
        materialize_path_prefix: bool,
        run_rules: Vec<crate::config::MatchRule>,
        run_dir_prefix: bool,
        run_path_prefix: bool,
    ) -> Self {
        Self {
            selector,
            prod_name,
            materialize_output,
            materialize_rules,
            materialize_dir_prefix,
            materialize_path_prefix,
            run_rules,
            run_dir_prefix,
            run_path_prefix,
        }
    }
}

impl EffectRunner for DefaultRunner {
    fn check_prod_barrier(
        &self,
        repo_root: &Path,
        env: &str,
        prod: bool,
        no_prompt: bool,
    ) -> Result<(), GitvaultError> {
        barrier::check_prod_barrier(repo_root, env, prod, no_prompt, &self.prod_name)
    }

    fn load_identity_str(
        &self,
        source: &fhsm::IdentitySource,
    ) -> Result<Zeroizing<String>, GitvaultError> {
        load_identity_from_source_with_selector(source, self.selector.as_deref())
    }

    fn decrypt_secrets(
        &self,
        repo_root: &Path,
        env: &str,
        identity: &dyn age::Identity,
        scope: SecretRuleScope,
    ) -> Result<Vec<(String, String)>, GitvaultError> {
        let (rules, dir_prefix, path_prefix) = match scope {
            SecretRuleScope::Run => (
                Some(self.run_rules.as_slice()),
                self.run_dir_prefix,
                self.run_path_prefix,
            ),
            SecretRuleScope::Materialize => (
                Some(self.materialize_rules.as_slice()),
                self.materialize_dir_prefix,
                self.materialize_path_prefix,
            ),
        };
        crate::repo::decrypt_env_secrets_with_rules(
            repo_root,
            env,
            identity,
            rules,
            dir_prefix,
            path_prefix,
        )
    }

    fn run_command(
        &self,
        secrets: &[(String, String)],
        command: &[String],
        clear_env: bool,
        pass_vars: &[String],
    ) -> Result<i32, GitvaultError> {
        let (cmd, args) = command.split_first().ok_or_else(|| {
            crate::error::GitvaultError::Usage("command must not be empty".to_string())
        })?;
        run::run_command(secrets, cmd, args, clear_env, pass_vars)
    }

    fn materialize_secrets(
        &self,
        repo_root: &Path,
        secrets: &[(String, String)],
    ) -> Result<(), GitvaultError> {
        materialize::materialize_env_file(repo_root, secrets, &self.materialize_output)
    }
}

/// Execute an ordered list of FHSM [`fhsm::Effect`]s, delegating I/O to `runner`.
///
/// State (resolved identity, decrypted secrets) is accumulated across effects so
/// that later effects can depend on earlier ones.  Returns early with the
/// subprocess exit code for [`fhsm::Effect::RunCommand`].
///
/// # Errors
///
/// Propagates any [`GitvaultError`] returned by the runner's methods.
pub fn execute_effects_with(
    effects: Vec<fhsm::Effect>,
    repo_root: &Path,
    runner: &dyn EffectRunner,
) -> Result<CommandOutcome, GitvaultError> {
    let mut identity_opt: Option<crate::crypto::AnyIdentity> = None;
    let mut secrets_opt: Option<Vec<(String, String)>> = None;

    // Determine no_prompt from CheckProdBarrier effect (decrypt flows default to false).
    let no_prompt = effects
        .iter()
        .find_map(|e| {
            if let fhsm::Effect::CheckProdBarrier { no_prompt, .. } = e {
                Some(*no_prompt)
            } else {
                None
            }
        })
        .unwrap_or(false);

    let decrypt_scope = if effects
        .iter()
        .any(|e| matches!(e, fhsm::Effect::RunCommand { .. }))
    {
        SecretRuleScope::Run
    } else {
        SecretRuleScope::Materialize
    };

    for effect in effects {
        match effect {
            fhsm::Effect::CheckProdBarrier {
                env,
                prod,
                no_prompt: np,
            } => {
                runner.check_prod_barrier(repo_root, &env, prod, np)?;
            }
            fhsm::Effect::ResolveIdentity { source } => {
                let identity_str = runner.load_identity_str(&source)?;
                let passphrase = crate::identity::try_fetch_ssh_passphrase(
                    crate::defaults::KEYRING_SERVICE,
                    crate::defaults::KEYRING_ACCOUNT,
                    no_prompt,
                );
                identity_opt = Some(crate::crypto::parse_identity_any_with_passphrase(
                    &identity_str,
                    passphrase,
                )?);
            }
            fhsm::Effect::DecryptSecrets { env } => {
                let identity = identity_opt
                    .as_ref()
                    .map(crate::crypto::AnyIdentity::as_identity)
                    .ok_or_else(|| GitvaultError::Usage("identity not resolved".to_string()))?;
                secrets_opt =
                    Some(runner.decrypt_secrets(repo_root, &env, identity, decrypt_scope)?);
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
            // Decrypt a single ciphertext file to an output path or stdout.
            fhsm::Effect::DecryptFile { file, output } => {
                let identity = identity_opt
                    .as_ref()
                    .map(crate::crypto::AnyIdentity::as_identity)
                    .ok_or_else(|| {
                        GitvaultError::Usage("identity not resolved before DecryptFile".to_string())
                    })?;
                let in_file =
                    std::io::BufReader::new(std::fs::File::open(&file).map_err(GitvaultError::Io)?);
                if let Some(out_path) = output {
                    let tmp = tempfile::NamedTempFile::new_in(
                        out_path
                            .parent()
                            .unwrap_or_else(|| std::path::Path::new(".")),
                    )?;
                    {
                        let mut out_file = std::io::BufWriter::new(tmp.as_file());
                        crypto::decrypt_stream(identity, in_file, &mut out_file)?;
                    }
                    tmp.persist(&out_path)
                        .map_err(|e| GitvaultError::Io(e.error))?;
                } else {
                    let mut stdout = std::io::BufWriter::new(std::io::stdout());
                    crypto::decrypt_stream(identity, in_file, &mut stdout)?;
                }
            }
        }
    }
    Ok(CommandOutcome::Success)
}

/// Execute an ordered list of FHSM [`fhsm::Effect`]s using the real I/O functions.
///
/// # Errors
///
/// Returns [`GitvaultError`] if the repository root cannot be found or any
/// effect execution fails.
pub fn execute_effects(
    effects: Vec<fhsm::Effect>,
    selector: Option<&str>,
) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    let cfg = crate::config::effective_config(&repo_root)?;
    execute_effects_with(
        effects,
        &repo_root,
        &DefaultRunner::with_selector(
            selector.map(str::to_owned),
            cfg.env.prod_name().to_string(),
            cfg.paths.materialize_output().to_string(),
            cfg.materialize.rules,
            cfg.materialize.dir_prefix.unwrap_or(false),
            cfg.materialize.path_prefix.unwrap_or(false),
            cfg.run.rules,
            cfg.run.dir_prefix.unwrap_or(false),
            cfg.run.path_prefix.unwrap_or(false),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use tempfile::TempDir;

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
            self.barrier_err
                .as_ref()
                .map_or(Ok(()), |msg| Err(GitvaultError::Other(msg.clone())))
        }

        fn load_identity_str(
            &self,
            _source: &fhsm::IdentitySource,
        ) -> Result<Zeroizing<String>, GitvaultError> {
            self.identity_str
                .clone()
                .map(Zeroizing::new)
                .map_err(GitvaultError::Other)
        }

        fn decrypt_secrets(
            &self,
            _repo_root: &Path,
            _env: &str,
            _identity: &dyn age::Identity,
            _scope: SecretRuleScope,
        ) -> Result<Vec<(String, String)>, GitvaultError> {
            self.decrypt_secrets.clone().map_err(GitvaultError::Other)
        }

        fn run_command(
            &self,
            _secrets: &[(String, String)],
            _command: &[String],
            _clear_env: bool,
            _pass_vars: &[String],
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
            self.materialize_err
                .as_ref()
                .map_or(Ok(()), |msg| Err(GitvaultError::Other(msg.clone())))
        }
    }

    #[test]
    fn execute_effects_run_command_returns_exit_code() {
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner::succeeds_with(key_str, vec![], 42);
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Run {
            env: Some("dev".to_string()),
            identity: Some(age_key.to_string().expose_secret().clone()),
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
        let key_str = age_key.to_string().expose_secret().clone();
        let secrets = vec![("FOO".to_string(), "bar".to_string())];
        let runner = FakeEffectRunner::succeeds_with(key_str, secrets, 0);
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Materialize {
            env: None,
            identity: Some(age_key.to_string().expose_secret().clone()),
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
                source: fhsm::IdentitySource::Unresolved,
            },
            fhsm::Effect::DecryptSecrets {
                env: "dev".to_string(),
            },
        ];
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(result.is_err());
    }

    #[test]
    fn execute_effects_with_decrypt_file_decrypts_to_output_path() {
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner::succeeds_with(key_str.clone(), vec![], 0);
        let tmp = TempDir::new().unwrap();

        // Create a real encrypted file.
        let plaintext = b"DECRYPT_FILE_TEST=1\n";
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(age_key.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crate::crypto::encrypt(recipients, plaintext).unwrap();
        let enc_path = tmp.path().join("test.env.age");
        std::fs::write(&enc_path, &ciphertext).unwrap();
        let out_path = tmp.path().join("test.env");

        // ResolveIdentity must come first so that identity_opt is populated.
        let effects = vec![
            fhsm::Effect::ResolveIdentity {
                source: fhsm::IdentitySource::Inline(key_str),
            },
            fhsm::Effect::DecryptFile {
                file: enc_path,
                output: Some(out_path.clone()),
            },
        ];
        let outcome = execute_effects_with(effects, tmp.path(), &runner)
            .expect("DecryptFile arm should decrypt successfully");
        assert_eq!(outcome, CommandOutcome::Success);

        let decrypted = std::fs::read_to_string(&out_path).expect("output file should exist");
        assert!(
            decrypted.contains("DECRYPT_FILE_TEST=1"),
            "decrypted output should contain plaintext"
        );
    }

    #[test]
    fn execute_effects_with_decrypt_file_without_identity_errors() {
        let tmp = TempDir::new().unwrap();
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner::succeeds_with(key_str, vec![], 0);

        // DecryptFile without a prior ResolveIdentity should fail.
        let effects = vec![fhsm::Effect::DecryptFile {
            file: tmp.path().join("dummy.age"),
            output: None,
        }];
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(
            result.is_err(),
            "DecryptFile without identity should return an error"
        );
    }

    #[test]
    fn default_runner_run_command_empty_command_returns_usage_error() {
        // Covers the empty-command error path in DefaultRunner::run_command (lines 89-90).
        let runner = DefaultRunner::new();
        let result = runner.run_command(&[], &[], false, &[]);
        assert!(
            result.is_err(),
            "empty command should produce a Usage error"
        );
        assert!(matches!(
            result.unwrap_err(),
            crate::error::GitvaultError::Usage(_)
        ));
    }

    #[test]
    fn execute_effects_with_decrypt_file_to_stdout() {
        // Covers DecryptFile with output=None → decrypt to stdout (lines 170-171).
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner::succeeds_with(key_str.clone(), vec![], 0);
        let tmp = TempDir::new().unwrap();

        // Create a real encrypted file.
        let plaintext = b"STDOUT_DECRYPT=1\n";
        let recipients: Vec<Box<dyn age::Recipient + Send>> =
            vec![Box::new(age_key.to_public()) as Box<dyn age::Recipient + Send>];
        let ciphertext = crate::crypto::encrypt(recipients, plaintext).unwrap();
        let enc_path = tmp.path().join("stdout.env.age");
        std::fs::write(&enc_path, &ciphertext).unwrap();

        // output=None → DecryptFile decrypts to stdout.
        let effects = vec![
            fhsm::Effect::ResolveIdentity {
                source: fhsm::IdentitySource::Inline(key_str),
            },
            fhsm::Effect::DecryptFile {
                file: enc_path,
                output: None,
            },
        ];
        let outcome = execute_effects_with(effects, tmp.path(), &runner)
            .expect("DecryptFile to stdout should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
    }

    #[test]
    fn fake_runner_materialize_error_propagates() {
        // Covers the Some(msg) error branch in FakeEffectRunner::materialize_secrets (line 267).
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner {
            barrier_err: None,
            identity_str: Ok(key_str.clone()),
            decrypt_secrets: Ok(vec![]),
            run_exit_code: Ok(0),
            materialize_err: Some("forced materialize error".to_string()),
        };
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Materialize {
            env: None,
            identity: Some(key_str),
            prod: false,
            no_prompt: true,
        };
        let effects = fhsm::transition(&event).unwrap();
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(result.is_err(), "materialize error should propagate");
    }

    #[test]
    fn execute_effects_decrypt_secrets_without_prior_identity_errors() {
        // Covers the ok_or_else "identity not resolved" closure in DecryptSecrets arm.
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner::succeeds_with(key_str, vec![], 0);
        let tmp = TempDir::new().unwrap();

        // DecryptSecrets without prior ResolveIdentity → identity_opt is None.
        let effects = vec![fhsm::Effect::DecryptSecrets {
            env: "dev".to_string(),
        }];
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(
            result.is_err(),
            "DecryptSecrets without identity should fail"
        );
        assert!(matches!(
            result.unwrap_err(),
            crate::error::GitvaultError::Usage(_)
        ));
    }

    #[test]
    fn execute_effects_materialize_without_prior_decrypt_errors() {
        // Covers the ok_or_else "secrets not decrypted" closure in MaterializeSecrets arm.
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner::succeeds_with(key_str, vec![], 0);
        let tmp = TempDir::new().unwrap();

        // MaterializeSecrets without prior DecryptSecrets → secrets_opt is None.
        let effects = vec![fhsm::Effect::MaterializeSecrets {
            env: "dev".to_string(),
        }];
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(
            result.is_err(),
            "MaterializeSecrets without secrets should fail"
        );
        assert!(matches!(
            result.unwrap_err(),
            crate::error::GitvaultError::Usage(_)
        ));
    }

    #[test]
    fn fake_runner_run_command_error_propagates() {
        // Covers the map_err error closure in FakeEffectRunner::run_command.
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner {
            barrier_err: None,
            identity_str: Ok(key_str.clone()),
            decrypt_secrets: Ok(vec![]),
            run_exit_code: Err("forced run error".to_string()),
            materialize_err: None,
        };
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Run {
            env: Some("dev".to_string()),
            identity: Some(key_str),
            prod: false,
            no_prompt: true,
            clear_env: false,
            pass_raw: None,
            command: vec!["true".to_string()],
        };
        let effects = fhsm::transition(&event).unwrap();
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(result.is_err(), "run command error should propagate");
    }

    #[test]
    fn fake_runner_decrypt_secrets_error_propagates() {
        // Covers the map_err error closure in FakeEffectRunner::decrypt_secrets.
        let age_key = age::x25519::Identity::generate();
        let key_str = age_key.to_string().expose_secret().clone();
        let runner = FakeEffectRunner {
            barrier_err: None,
            identity_str: Ok(key_str.clone()),
            decrypt_secrets: Err("forced decrypt error".to_string()),
            run_exit_code: Ok(0),
            materialize_err: None,
        };
        let tmp = TempDir::new().unwrap();
        let event = fhsm::Event::Run {
            env: Some("dev".to_string()),
            identity: Some(key_str),
            prod: false,
            no_prompt: true,
            clear_env: false,
            pass_raw: None,
            command: vec!["true".to_string()],
        };
        let effects = fhsm::transition(&event).unwrap();
        let result = execute_effects_with(effects, tmp.path(), &runner);
        assert!(result.is_err(), "decrypt secrets error should propagate");
    }
}
