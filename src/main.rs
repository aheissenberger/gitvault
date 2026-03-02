#[cfg(feature = "ssm")]
mod aws_config;
mod barrier;
mod cli;
mod commands;
mod crypto;
mod env;
mod error;
mod fhsm;
mod identity;
mod keyring_store;
mod materialize;
mod merge;
mod permissions;
mod output;
mod repo;
mod run;
mod structured;

use clap::Parser;
use cli::{Cli, Commands};
use commands::CommandOutcome;
use error::GitvaultError;
use std::process;

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
    cli.no_prompt = output::resolve_no_prompt(cli.no_prompt);
    match cli.command {
        Commands::Encrypt {
            file,
            recipients,
            fields,
            value_only,
        } => {
            commands::encrypt::cmd_encrypt(file, recipients, fields, value_only, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Decrypt {
            file,
            identity,
            output,
            fields,
            reveal,
        } => {
            commands::decrypt::cmd_decrypt(
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
            commands::materialize::cmd_materialize(env, identity, prod, cli.json, cli.no_prompt)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Status { fail_if_dirty } => {
            commands::admin::cmd_status(cli.json, fail_if_dirty)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Harden => {
            commands::admin::cmd_harden(cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Run {
            env,
            identity,
            prod,
            clear_env,
            pass,
            command,
        } => commands::run_cmd::cmd_run(
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
            commands::admin::cmd_allow_prod(ttl, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::MergeDriver { base, ours, theirs } => {
            commands::admin::cmd_merge_driver(base, ours, theirs, cli.json)
        }
        Commands::Recipient { action } => {
            commands::recipients::cmd_recipient(action, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Rotate { identity } => {
            commands::recipients::cmd_rotate(identity, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Keyring { action } => {
            commands::keyring::cmd_keyring(action, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::Check { env, identity } => {
            commands::admin::cmd_check(env, identity, cli.json)?;
            Ok(CommandOutcome::Success)
        }
        Commands::RevokeProd => {
            commands::admin::cmd_revoke_prod(cli.json)?;
            Ok(CommandOutcome::Success)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_helpers::*;
    use cli::{Commands, KeyringAction};
    use tempfile::TempDir;

    #[test]
    fn test_ci_env_sets_no_prompt() {
        with_env_var("CI", Some("1"), || {
            assert!(output::resolve_no_prompt(false));
            assert!(output::resolve_no_prompt(true));
            assert!(output::ci_is_non_interactive());
        });

        with_env_var("CI", None, || {
            assert!(!output::resolve_no_prompt(false));
            assert!(output::resolve_no_prompt(true));
            assert!(!output::ci_is_non_interactive());
        });
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
}
