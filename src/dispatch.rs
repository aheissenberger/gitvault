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

    // REQ-74: --identity-stdin — read identity key from stdin (pipe-friendly).
    // Store in a thread-local / env override so identity loading picks it up.
    if cli.identity_stdin {
        crate::identity::init_identity_from_stdin()?;
    }

    match cli.command {
        Commands::Encrypt {
            file,
            recipients,
            env,
        } => crate::commands::encrypt::cmd_encrypt(file, recipients, env, cli.json),
        Commands::Decrypt {
            file,
            identity,
            env,
            reveal,
        } => crate::commands::decrypt::cmd_decrypt(crate::commands::decrypt::DecryptOptions {
            file,
            identity,
            env,
            reveal,
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
        Commands::Harden {
            files,
            env,
            dry_run,
            delete_source,
            recipients,
        } => crate::commands::admin::cmd_harden_with_files(
            files,
            env,
            dry_run,
            delete_source,
            recipients,
            cli.json,
            cli.no_prompt,
            cli.identity_selector.clone(),
        ),
        Commands::Run {
            env,
            identity,
            prod,
            clear_env,
            keep_vars,
            command,
        } => crate::commands::run_cmd::cmd_run(crate::commands::run_cmd::RunOptions {
            env,
            identity,
            prod,
            clear_env,
            pass_raw: keep_vars,
            command,
            no_prompt: cli.no_prompt,
            selector: cli.identity_selector.clone(),
        }),
        Commands::AllowProd { ttl } => {
            let effective_ttl = if let Some(t) = ttl {
                t
            } else {
                // Resolve from config, fall back to built-in default
                let repo_root =
                    crate::repo::find_repo_root().unwrap_or_else(|_| std::path::PathBuf::from("."));
                crate::config::effective_config(&repo_root)
                    .map(|c| c.barrier.ttl_secs())
                    .unwrap_or(crate::defaults::DEFAULT_BARRIER_TTL_SECS)
            };
            crate::commands::admin::cmd_allow_prod(effective_ttl, cli.json)
        }
        Commands::MergeDriver { base, ours, theirs } => {
            crate::commands::admin::cmd_merge_driver(base, ours, theirs, cli.json)
        }
        Commands::Recipient { action } => crate::commands::recipients::cmd_recipient(
            action,
            cli.identity_selector.clone(),
            cli.json,
        ),
        Commands::Rekey {
            identity,
            env,
            dry_run,
        } => crate::commands::recipients::cmd_rekey(
            identity,
            cli.identity_selector.clone(),
            cli.json,
            env,
            dry_run,
        ),
        Commands::Keyring { action } => crate::commands::keyring::cmd_keyring(action, cli.json),
        Commands::Check {
            env,
            identity,
            skip_history_check,
        } => crate::commands::admin::cmd_check(
            env,
            identity,
            cli.identity_selector.clone(),
            cli.json,
            skip_history_check,
        ),
        Commands::RevokeProd => crate::commands::admin::cmd_revoke_prod(cli.json),
        Commands::Identity { action } => crate::commands::identity::cmd_identity(
            action,
            cli.identity_selector.clone(),
            cli.json,
            cli.no_prompt,
        ),
        Commands::Ai { action } => crate::commands::ai::cmd_ai(action, cli.json),
        Commands::Init { env, output } => {
            crate::commands::init::cmd_init(env, output, cli.json, cli.no_prompt)
        }
        Commands::Seal {
            file,
            recipients,
            env,
            fields,
        } => crate::commands::seal::cmd_seal(crate::commands::seal::SealOptions {
            file,
            recipients,
            env,
            fields,
            json: cli.json,
            no_prompt: cli.no_prompt,
            selector: cli.identity_selector.clone(),
        }),
        Commands::Unseal {
            file,
            identity,
            fields,
            reveal,
        } => crate::commands::seal::cmd_unseal(crate::commands::seal::UnsealOptions {
            file,
            identity,
            fields,
            reveal,
            json: cli.json,
            no_prompt: cli.no_prompt,
            selector: cli.identity_selector.clone(),
        }),
        Commands::Edit {
            file,
            identity,
            env,
            fields,
            editor,
        } => crate::commands::edit::cmd_edit(crate::commands::edit::EditOptions {
            file,
            identity,
            env,
            fields,
            editor,
            json: cli.json,
            no_prompt: cli.no_prompt,
            selector: cli.identity_selector.clone(),
        }),
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

    /// Build a [`Cli`] for tests, handling cfg-gated SSM fields.
    fn make_cli(json: bool, no_prompt: bool, command: Commands) -> Cli {
        #[cfg(not(feature = "ssm"))]
        let cli = Cli {
            json,
            no_prompt,
            identity_selector: None,
            identity_stdin: false,
            command,
        };
        #[cfg(feature = "ssm")]
        let cli = Cli {
            json,
            no_prompt,
            identity_selector: None,
            identity_stdin: false,
            aws_profile: None,
            aws_role_arn: None,
            command,
        };
        cli
    }

    #[test]
    fn test_ci_env_sets_no_prompt() {
        let _lock = global_test_lock().lock().unwrap();
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
            let check_cli = make_cli(
                true,
                true,
                Commands::Check {
                    env: None,
                    identity: None,
                    skip_history_check: true,
                },
            );
            let outcome = run(check_cli).expect("dispatch check should succeed");
            assert_eq!(outcome, CommandOutcome::Success);

            let status_cli = make_cli(
                false,
                true,
                Commands::Status {
                    fail_if_dirty: false,
                },
            );
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
            let cli = make_cli(
                false,
                true,
                Commands::Run {
                    env: Some("dev".to_string()),
                    identity: Some(identity_file.path().to_string_lossy().to_string()),
                    prod: false,
                    clear_env: false,
                    keep_vars: None,
                    command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
                },
            );

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

        let encrypt_cli = make_cli(
            true,
            true,
            Commands::Encrypt {
                file: plain_file.to_string_lossy().to_string(),
                recipients: vec![identity.to_public().to_string()],
                env: None,
            },
        );
        let encrypt_outcome = run(encrypt_cli).expect("encrypt dispatch should succeed");
        assert_eq!(encrypt_outcome, CommandOutcome::Success);

        let encrypted_path = dir.path().join(".gitvault/store/dev/dispatch.txt.age");
        assert!(encrypted_path.exists());

        let decrypt_cli = make_cli(
            true,
            true,
            Commands::Decrypt {
                file: encrypted_path.to_string_lossy().to_string(),
                identity: Some(identity_file.path().to_string_lossy().to_string()),
                env: None,
                reveal: true,
            },
        );
        let decrypt_outcome = run(decrypt_cli).expect("decrypt dispatch should succeed");
        assert_eq!(decrypt_outcome, CommandOutcome::Success);
    }

    #[test]
    fn test_run_dispatch_allow_prod_succeeds() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = make_cli(true, true, Commands::AllowProd { ttl: Some(60) });

        let outcome = run(cli).expect("allow-prod dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
        assert!(dir.path().join(".git/gitvault/.prod-token").exists());
    }

    #[test]
    fn test_run_dispatch_rekey_succeeds() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, identity) = setup_identity_file();

        write_encrypted_env_file(dir.path(), "dev", "rekey.env.age", &identity, "A=1\n");

        with_identity_env(identity_file.path(), || {
            let cli = make_cli(
                true,
                true,
                Commands::Rekey {
                    identity: None,
                    env: None,
                    dry_run: false,
                },
            );

            let outcome = run(cli).expect("rekey dispatch should succeed");
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

        let clean_cli = make_cli(
            false,
            true,
            Commands::MergeDriver {
                base: base.to_string_lossy().to_string(),
                ours: ours.to_string_lossy().to_string(),
                theirs: theirs.to_string_lossy().to_string(),
            },
        );
        let clean_outcome = run(clean_cli).expect("merge-driver clean dispatch should succeed");
        assert_eq!(clean_outcome, CommandOutcome::Success);

        std::fs::write(&base, "A=1\n").unwrap();
        std::fs::write(&ours, "A=2\n").unwrap();
        std::fs::write(&theirs, "A=3\n").unwrap();

        let conflict_cli = make_cli(
            false,
            true,
            Commands::MergeDriver {
                base: base.to_string_lossy().to_string(),
                ours: ours.to_string_lossy().to_string(),
                theirs: theirs.to_string_lossy().to_string(),
            },
        );
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

        let cli = make_cli(
            true,
            true,
            Commands::Keyring {
                action: KeyringAction::Set {
                    identity: Some("/path/that/does/not/exist".to_string()),
                },
            },
        );

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
        let allow_cli = make_cli(false, true, Commands::AllowProd { ttl: Some(60) });
        run(allow_cli).expect("allow-prod should succeed");

        let revoke_cli = make_cli(false, true, Commands::RevokeProd);
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

        let cli = make_cli(
            false,
            true,
            Commands::Keyring {
                action: KeyringAction::Set {
                    identity: Some(identity_file.path().to_string_lossy().to_string()),
                },
            },
        );
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

        let cli = make_cli(
            false,
            true,
            Commands::Decrypt {
                file: dir
                    .path()
                    .join("no_such_file.age")
                    .to_string_lossy()
                    .to_string(),
                identity: Some(identity_file.path().to_string_lossy().to_string()),
                env: Some("dev".to_string()),
                reveal: false,
            },
        );
        // Decrypting a nonexistent file should propagate the error.
        // The absolute path has .age extension but is NOT under .gitvault/store/,
        // so it is treated as a source path → NotFound when store file is absent.
        let err = run(cli).expect_err("decrypt of nonexistent file should fail");
        assert!(
            matches!(err, GitvaultError::NotFound(_)),
            "expected NotFound error, got: {err:?}"
        );
    }

    #[test]
    fn test_run_dispatch_harden_exercises_arm() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = make_cli(
            false,
            true,
            Commands::Harden {
                files: vec![],
                env: None,
                dry_run: false,
                delete_source: false,
                recipients: vec![],
            },
        );
        // No adapter configured, so harden should succeed with built-in hooks.
        let outcome = run(cli).expect("harden dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
    }

    #[test]
    fn test_run_dispatch_recipient_list_exercises_arm() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let cli = make_cli(
            true,
            true,
            Commands::Recipient {
                action: crate::cli::RecipientAction::List,
            },
        );
        let outcome = run(cli).expect("recipient list dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
    }

    #[test]
    fn test_run_dispatch_identity_create_exercises_arm() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        let out_file = dir.path().join("test_identity.age");
        let cli = make_cli(
            true,
            true,
            Commands::Identity {
                action: crate::cli::IdentityAction::Create {
                    profile: crate::cli::IdentityProfile::Classic,
                    output: Some(out_file.to_string_lossy().to_string()),
                    add_recipient: false,
                },
            },
        );
        // Identity create with --out should succeed regardless of keyring availability.
        match run(cli) {
            Ok(outcome) => assert_eq!(outcome, CommandOutcome::Success),
            Err(GitvaultError::Keyring(_)) => {}
            Err(other) => panic!("Unexpected error from identity create dispatch: {other:?}"),
        }
    }

    #[test]
    fn test_run_dispatch_materialize_no_secrets_succeeds() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            let cli = make_cli(
                false,
                true,
                Commands::Materialize {
                    env: Some("dev".to_string()),
                    identity: Some(identity_file.path().to_string_lossy().to_string()),
                    prod: false,
                },
            );
            // A repo with no secrets materializes nothing — should succeed.
            let outcome = run(cli).expect("materialize dispatch should succeed with no secrets");
            assert_eq!(outcome, CommandOutcome::Success);
        });
    }

    #[cfg(feature = "ssm")]
    #[test]
    fn test_run_dispatch_ssm_set_prod_without_flag_returns_barrier_error() {
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
            identity_stdin: false,
            command: Commands::Ssm {
                action: crate::cli::SsmAction::Set {
                    key: "DB_PASS".to_string(),
                    value: "secret".to_string(),
                    env: Some("prod".to_string()),
                    prod: false,
                },
            },
        };

        let err = run(cli).expect_err("ssm set in prod without --prod must fail closed");
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    #[cfg(feature = "ssm")]
    #[test]
    fn test_run_dispatch_ssm_push_prod_without_flag_returns_barrier_error() {
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
            identity_stdin: false,
            command: Commands::Ssm {
                action: crate::cli::SsmAction::Push {
                    env: Some("prod".to_string()),
                    prod: false,
                },
            },
        };

        let err = run(cli).expect_err("ssm push in prod without --prod must fail closed");
        assert!(matches!(err, GitvaultError::BarrierNotSatisfied(_)));
    }

    /// Covers `Commands::AllowProd { ttl: None }` dispatch (lines 111-115):
    /// the else branch that resolves TTL from config / built-in default.
    #[test]
    fn test_run_dispatch_allow_prod_ttl_none_uses_default() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        let _cwd = CwdGuard::enter(dir.path());

        // ttl = None exercises the else branch (config / built-in default).
        let cli = make_cli(true, true, Commands::AllowProd { ttl: None });
        let outcome = run(cli).expect("allow-prod with ttl=None should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
        assert!(dir.path().join(".git/gitvault/.prod-token").exists());
    }

    /// Covers `Commands::Ai { action }` dispatch (line 157).
    #[test]
    fn test_run_dispatch_ai_skill_arm() {
        // cmd_ai does not touch the filesystem; no git repo needed.
        let cli = make_cli(
            false,
            true,
            Commands::Ai {
                action: crate::cli::AiAction::Skill,
            },
        );
        let outcome = run(cli).expect("ai skill dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
    }

    /// Covers `Commands::Ai { action: Context }` dispatch.
    #[test]
    fn test_run_dispatch_ai_context_arm() {
        let cli = make_cli(
            false,
            true,
            Commands::Ai {
                action: crate::cli::AiAction::Context,
            },
        );
        let outcome = run(cli).expect("ai context dispatch should succeed");
        assert_eq!(outcome, CommandOutcome::Success);
    }

    /// Covers `Commands::Init { env, output }` dispatch (lines 158-159).
    #[test]
    fn test_run_dispatch_init_arm() {
        let _lock = global_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new().unwrap();
        init_git_repo(dir.path());
        // Configure git user so recipients filename derivation works.
        std::process::Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir.path())
            .status()
            .expect("git config user.name should succeed");
        std::process::Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir.path())
            .status()
            .expect("git config user.email should succeed");
        let _cwd = CwdGuard::enter(dir.path());
        let (identity_file, _identity) = setup_identity_file();

        with_identity_env(identity_file.path(), || {
            let cli = make_cli(
                true,
                true,
                Commands::Init {
                    env: None,
                    output: None,
                },
            );
            let outcome = run(cli).expect("init dispatch should succeed");
            assert_eq!(outcome, CommandOutcome::Success);
        });
    }
}
