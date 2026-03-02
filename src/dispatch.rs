//! Top-level CLI dispatch: maps parsed [`Cli`] arguments to command
//! implementations and returns a [`CommandOutcome`].
//!
//! Keeping this function in the library crate (rather than `main.rs`) lets the
//! unit-test suite exercise every dispatch arm without crossing a crate
//! boundary, and allows the test-only [`crate::commands::test_helpers`] module
//! to be gated with `#[cfg(test)]`.

#[cfg(feature = "ssm")]
use crate::cli::SsmAction;
use crate::cli::{Cli, Commands};
use crate::commands::CommandOutcome;
use crate::error::GitvaultError;

/// Dispatch a parsed [`Cli`] to the appropriate command implementation.
///
/// # Errors
///
/// Propagates any [`GitvaultError`] returned by the dispatched command.
pub fn run(mut cli: Cli) -> Result<CommandOutcome, GitvaultError> {
    cli.no_prompt = crate::output::resolve_no_prompt(cli.no_prompt);
    match cli.command {
        Commands::Encrypt {
            file,
            recipients,
            keep_path,
            fields,
            value_only,
        } => crate::commands::encrypt::cmd_encrypt(
            file, recipients, keep_path, fields, value_only, cli.json,
        ),
        Commands::Decrypt {
            file,
            identity,
            output,
            fields,
            reveal,
            value_only,
        } => crate::commands::decrypt::cmd_decrypt(crate::commands::decrypt::DecryptOptions {
            file,
            identity,
            output,
            fields,
            reveal,
            value_only,
            json: cli.json,
            no_prompt: cli.no_prompt,
            selector: cli.identity_selector.clone(),
        }),
        Commands::Materialize {
            env,
            identity,
            prod,
        } => crate::commands::materialize::cmd_materialize(
            env,
            identity,
            prod,
            cli.json,
            cli.no_prompt,
            cli.identity_selector.clone(),
        ),
        Commands::Status { fail_if_dirty } => {
            crate::commands::admin::cmd_status(cli.json, fail_if_dirty)
        }
        Commands::Harden => crate::commands::admin::cmd_harden(cli.json, cli.no_prompt),
        Commands::Run {
            env,
            identity,
            prod,
            clear_env,
            pass,
            command,
        } => crate::commands::run_cmd::cmd_run(crate::commands::run_cmd::RunOptions {
            env,
            identity,
            prod,
            clear_env,
            pass_raw: pass,
            command,
            no_prompt: cli.no_prompt,
            selector: cli.identity_selector.clone(),
        }),
        Commands::AllowProd { ttl } => crate::commands::admin::cmd_allow_prod(ttl, cli.json),
        Commands::MergeDriver { base, ours, theirs } => {
            crate::commands::admin::cmd_merge_driver(base, ours, theirs, cli.json)
        }
        Commands::Recipient { action } => {
            crate::commands::recipients::cmd_recipient(action, cli.json)
        }
        Commands::Rotate { identity } => {
            crate::commands::recipients::cmd_rotate(identity, cli.identity_selector.clone(), cli.json)
        }
        Commands::Keyring { action } => crate::commands::keyring::cmd_keyring(action, cli.json),
        Commands::Check { env, identity } => {
            crate::commands::admin::cmd_check(env, identity, cli.identity_selector.clone(), cli.json)
        }
        Commands::RevokeProd => crate::commands::admin::cmd_revoke_prod(cli.json),
        Commands::Identity { action } => {
            crate::commands::identity::cmd_identity(action, cli.json, cli.no_prompt)
        }
        #[cfg(feature = "ssm")]
        Commands::Ssm { action } => {
            dispatch_ssm(action, cli.aws_profile, cli.aws_role_arn, cli.json)
        }
    }
}

/// Dispatch SSM sub-commands, constructing the async runtime and AWS config.
#[cfg(feature = "ssm")]
fn dispatch_ssm(
    action: SsmAction,
    aws_profile: Option<String>,
    aws_role_arn: Option<String>,
    json: bool,
) -> Result<CommandOutcome, GitvaultError> {
    let aws = crate::aws_config::AwsConfig::from_cli(aws_profile, aws_role_arn);
    let repo_root = crate::repo::find_repo_root()?;
    tokio::runtime::Runtime::new()
        .map_err(|e| GitvaultError::Other(e.to_string()))?
        .block_on(async {
            match action {
                SsmAction::Pull { env } => {
                    let env = env.unwrap_or_else(|| "dev".to_string());
                    crate::ssm::cmd_ssm_pull(&repo_root, &env, &aws, json).await
                }
                SsmAction::Diff { env, reveal } => {
                    let env = env.unwrap_or_else(|| "dev".to_string());
                    crate::ssm::cmd_ssm_diff(&repo_root, &env, &aws, reveal, json).await
                }
                SsmAction::Set {
                    key,
                    value,
                    env,
                    prod,
                } => {
                    let env = env.unwrap_or_else(|| "dev".to_string());
                    crate::ssm::cmd_ssm_set(&repo_root, &env, &key, &value, &aws, json, prod).await
                }
                SsmAction::Push { env, prod } => {
                    let env = env.unwrap_or_else(|| "dev".to_string());
                    crate::ssm::cmd_ssm_push(&repo_root, &env, &aws, json, prod).await
                }
            }
        })
        .map(|()| CommandOutcome::Success)
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::cli::{Cli, Commands, KeyringAction};
    use crate::commands::CommandOutcome;
    use crate::commands::test_helpers::*;
    use crate::error::GitvaultError;
    use tempfile::TempDir;

    #[test]
    fn test_ci_env_sets_no_prompt() {
        with_env_var("CI", Some("1"), || {
            assert!(crate::output::resolve_no_prompt(false));
            assert!(crate::output::resolve_no_prompt(true));
            assert!(crate::output::ci_is_non_interactive());
        });

        with_env_var("CI", None, || {
            assert!(!crate::output::resolve_no_prompt(false));
            assert!(crate::output::resolve_no_prompt(true));
            assert!(!crate::output::ci_is_non_interactive());
        });
    }

    #[test]
    fn test_run_dispatch_check_and_status() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                identity_selector: None,
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
                identity_selector: None,
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
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                identity_selector: None,
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
    fn test_run_dispatch_encrypt_then_decrypt_arms() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            identity_selector: None,
            command: Commands::Encrypt {
                file: plain_file.to_string_lossy().to_string(),
                recipients: vec![identity.to_public().to_string()],
                keep_path: false,
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
            identity_selector: None,
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
                value_only: false,
            },
        };
        let decrypt_outcome = run(decrypt_cli).expect("decrypt dispatch should succeed");
        assert_eq!(decrypt_outcome, CommandOutcome::Success);

        let decrypted = std::fs::read_to_string(dir.path().join("dispatch.out")).unwrap();
        assert!(decrypted.contains("DISPATCH=1"));
    }

    #[test]
    fn test_run_dispatch_allow_prod_succeeds() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = Cli {
            json: true,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            identity_selector: None,
            command: Commands::AllowProd { ttl: 60 },
        };

        let outcome = run(cli).expect("allow-prod dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
        assert!(dir.path().join(".secrets/.prod-token").exists());
    }

    #[test]
    fn test_run_dispatch_rotate_succeeds() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                identity_selector: None,
                command: Commands::Rotate { identity: None },
            };

            let outcome = run(cli).expect("rotate dispatch should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });
    }

    #[test]
    fn test_run_dispatch_merge_driver_outcomes() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            identity_selector: None,
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
            identity_selector: None,
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
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = Cli {
            json: true,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            identity_selector: None,
            command: Commands::Keyring {
                action: KeyringAction::Set {
                    identity: Some("/path/that/does/not/exist".to_string()),
                },
            },
        };

        let err = run(cli).expect_err("invalid identity source should fail keyring set");
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_with_env_var_restores_existing_value() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    fn test_run_dispatch_revoke_prod_succeeds() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // Allow prod first so there's a token to revoke.
        let allow_cli = Cli {
            json: false,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            identity_selector: None,
            command: Commands::AllowProd { ttl: 60 },
        };
        run(allow_cli).expect("allow-prod should succeed");

        let revoke_cli = Cli {
            json: false,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            identity_selector: None,
            command: Commands::RevokeProd,
        };
        let outcome = run(revoke_cli).expect("revoke-prod dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
    }

    #[test]
    fn test_run_dispatch_keyring_set_exercises_dispatch() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let cli = Cli {
            json: false,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            identity_selector: None,
            command: Commands::Keyring {
                action: KeyringAction::Set {
                    identity: Some(identity_file.path().to_string_lossy().to_string()),
                },
            },
        };
        // The dispatch path is exercised regardless of whether the OS keyring
        // is available. On headless CI the real keyring returns an error; on
        // developer machines it succeeds.  Both are acceptable — we only assert
        // that the error (if any) is a Keyring error, not an unexpected panic.
        match run(cli) {
            Ok(outcome) => assert_eq!(outcome, CommandOutcome::Success),
            Err(GitvaultError::Keyring(_)) => {}
            Err(other) => panic!("Unexpected error from keyring dispatch: {other:?}"),
        }
    }

    #[test]
    fn test_run_dispatch_decrypt_nonexistent_file_propagates_error() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        let cli = Cli {
            json: false,
            no_prompt: true,
            aws_profile: None,
            aws_role_arn: None,
            identity_selector: None,
            command: Commands::Decrypt {
                file: dir
                    .path()
                    .join("no_such_file.age")
                    .to_string_lossy()
                    .to_string(),
                identity: Some(identity_file.path().to_string_lossy().to_string()),
                output: None,
                fields: None,
                reveal: false,
                value_only: false,
            },
        };
        // Decrypting a nonexistent file should propagate the error.
        let err = run(cli).expect_err("decrypt of nonexistent file should fail");
        assert!(matches!(err, GitvaultError::Io(_)));
    }
}
