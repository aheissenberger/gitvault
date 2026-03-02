//! FHSM effect runner infrastructure and CommandOutcome type.

use std::path::Path;

use crate::error::GitvaultError;
use crate::identity::load_identity_from_source;
use crate::repo::decrypt_env_secrets;
use crate::{barrier, crypto, fhsm, materialize, run};

/// Outcome returned by the top-level command dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandOutcome {
    Success,
    Exit(i32),
}

/// Injectable side-effect executor for [`execute_effects_with`].
///
/// Each method corresponds to one [`fhsm::Effect`] variant that requires I/O.
/// Implementations receive the repo root and accumulated state as parameters.
pub(crate) trait EffectRunner {
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
        pass_vars: &[String],
    ) -> Result<i32, GitvaultError>;

    fn materialize_secrets(
        &self,
        repo_root: &Path,
        secrets: &[(String, String)],
    ) -> Result<(), GitvaultError>;
}

/// Production implementation — delegates to the real I/O functions.
pub(crate) struct DefaultRunner;

impl EffectRunner for DefaultRunner {
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
        materialize::materialize_env_file(repo_root, secrets)
    }
}

/// Execute an ordered list of FHSM [`fhsm::Effect`]s, delegating I/O to `runner`.
///
/// State (resolved identity, decrypted secrets) is accumulated across effects so
/// that later effects can depend on earlier ones.  Returns early with the
/// subprocess exit code for [`fhsm::Effect::RunCommand`].
pub(crate) fn execute_effects_with(
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
            // Decrypt a single ciphertext file to an output path or stdout.
            fhsm::Effect::DecryptFile { file, output } => {
                let identity = identity_opt.as_deref().ok_or_else(|| {
                    GitvaultError::Usage(
                        "identity not resolved before DecryptFile".to_string(),
                    )
                })?;
                let in_file = std::io::BufReader::new(
                    std::fs::File::open(&file).map_err(GitvaultError::Io)?,
                );
                match output {
                    Some(out_path) => {
                        let tmp = tempfile::NamedTempFile::new_in(
                            out_path.parent().unwrap_or(std::path::Path::new(".")),
                        )?;
                        {
                            let mut out_file = std::io::BufWriter::new(tmp.as_file());
                            crypto::decrypt_stream(identity, in_file, &mut out_file)?;
                        }
                        tmp.persist(&out_path)
                            .map_err(|e| GitvaultError::Io(e.error))?;
                    }
                    None => {
                        let mut stdout = std::io::BufWriter::new(std::io::stdout());
                        crypto::decrypt_stream(identity, in_file, &mut stdout)?;
                    }
                }
            }
        }
    }
    Ok(CommandOutcome::Success)
}

/// Execute an ordered list of FHSM [`fhsm::Effect`]s using the real I/O functions.
pub(crate) fn execute_effects(effects: Vec<fhsm::Effect>) -> Result<CommandOutcome, GitvaultError> {
    let repo_root = crate::repo::find_repo_root()?;
    execute_effects_with(effects, &repo_root, &DefaultRunner)
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
        let key_str = age_key.to_string().expose_secret().to_string();
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
        let key_str = age_key.to_string().expose_secret().to_string();
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
}
