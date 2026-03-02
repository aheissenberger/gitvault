//! Pure (no I/O) Finite Hierarchical State Machine model for core command flows.
//!
//! This module defines events, effects, and a pure transition function for the
//! run, decrypt, and materialize command flows. No I/O is performed here; callers
//! are responsible for executing the returned [`Effect`] list.

use std::path::PathBuf;

use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the pure FHSM layer (no I/O).
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FhsmError {
    /// Caller supplied invalid arguments that make the command impossible.
    #[error("usage error: {0}")]
    UsageError(String),
}

// ─── Orthogonal region enums ──────────────────────────────────────────────────

/// Where the identity key should come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySource {
    /// An explicit file path supplied by the caller.
    FilePath(String),
    /// A raw key value supplied via an environment variable.
    EnvVar(String),
    /// Read from the OS keyring (`GITVAULT_KEYRING=1`).
    Keyring,
    /// A raw inline key value (e.g. supplied directly as a string).
    #[allow(dead_code)]
    Inline(String),
    /// No source was configured at the FHSM level; the executor must resolve
    /// using the full priority chain (GITVAULT_IDENTITY env var, keyring, etc.).
    Unresolved,
}

// ─── Events ───────────────────────────────────────────────────────────────────

/// Input events that drive the FHSM transition function.
///
/// Each variant corresponds to one of the three main command flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The user requested `gitvault run`.
    Run {
        /// Target environment (defaults to `"dev"` when absent).
        env: Option<String>,
        /// Explicit identity file path.
        identity: Option<String>,
        /// `--prod` flag: the caller explicitly consents to production access.
        prod: bool,
        /// `--no-prompt` flag: interactive prompts must not be shown.
        no_prompt: bool,
        /// `--clear-env` flag: clear the subprocess environment before injecting secrets.
        clear_env: bool,
        /// Raw variables to pass through unchanged (format: `KEY=VALUE`).
        pass_raw: Option<String>,
        /// The command and its arguments to execute.
        command: Vec<String>,
    },

    /// The user requested `gitvault decrypt`.
    Decrypt {
        /// Path of the file to decrypt.
        file: String,
        /// Explicit identity file path.
        identity: Option<String>,
        /// `--no-prompt` flag.
        no_prompt: bool,
        /// Optional output file path; `None` means stdout.
        output: Option<String>,
    },

    /// The user requested `gitvault materialize`.
    Materialize {
        /// Target environment.
        env: Option<String>,
        /// Explicit identity file path.
        identity: Option<String>,
        /// `--prod` flag.
        prod: bool,
        /// `--no-prompt` flag.
        no_prompt: bool,
    },
}

// ─── Effects ─────────────────────────────────────────────────────────────────

/// Pure description of I/O work to be performed by the caller.
///
/// No I/O is executed inside this module; the caller receives a `Vec<Effect>`
/// and is responsible for running each effect in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Evaluate the production barrier before proceeding.
    CheckProdBarrier {
        /// The environment being accessed.
        env: String,
        /// Whether the `--prod` flag was supplied.
        prod: bool,
        /// Whether interactive prompts are forbidden.
        no_prompt: bool,
    },

    /// Load (or derive) the identity key from the given source.
    ResolveIdentity {
        /// How to obtain the identity key.
        source: IdentitySource,
    },

    /// Decrypt all secrets for the named environment.
    DecryptSecrets {
        /// The environment whose secrets should be decrypted.
        env: String,
    },

    /// Execute a subprocess with the decrypted secrets injected.
    RunCommand {
        /// The executable and arguments.
        command: Vec<String>,
        /// Whether to start the subprocess with a clean environment.
        clear_env: bool,
        /// Names of environment variables to pass through unchanged from the caller's environment.
        pass_vars: Vec<String>,
    },

    /// Write decrypted secrets to the working directory for the named environment.
    MaterializeSecrets {
        /// The environment whose secrets should be materialized.
        env: String,
    },

    /// Decrypt a single file to stdout or an output path.
    DecryptFile {
        /// Source ciphertext file.
        file: PathBuf,
        /// Destination file; `None` means stdout.
        output: Option<PathBuf>,
    },
}

// ─── Pure helpers ─────────────────────────────────────────────────────────────

/// Resolve the identity source from an explicit path and injected environment
/// variable values (testable without reading real env vars).
///
/// Priority order:
/// 1. Explicit `path` argument.
/// 2. `gitvault_identity_env` – value of `GITVAULT_IDENTITY` (caller supplies).
/// 3. `gitvault_keyring_env` – value of `GITVAULT_KEYRING` (caller supplies "1" to enable).
///
/// Returns [`IdentitySource::FilePath`] for explicit paths, [`IdentitySource::EnvVar`]
/// for values found in `GITVAULT_IDENTITY`, and [`IdentitySource::Keyring`] when
/// `GITVAULT_KEYRING=1`.
pub fn resolve_identity_source(
    path: Option<&str>,
    gitvault_identity_env: Option<&str>,
    gitvault_keyring_env: Option<&str>,
) -> IdentitySource {
    if let Some(p) = path {
        return IdentitySource::FilePath(p.to_owned());
    }
    if let Some(val) = gitvault_identity_env {
        return IdentitySource::EnvVar(val.to_owned());
    }
    if gitvault_keyring_env == Some("1") {
        return IdentitySource::Keyring;
    }
    // No source configured at the FHSM level — executor must resolve
    // using the full priority chain (GITVAULT_IDENTITY env var, keyring, etc.)
    IdentitySource::Unresolved
}

/// Parse raw `KEY=VALUE` pairs from an optional string, returning only the variable names.
///
/// Silently ignores entries that contain no `=`.
fn parse_pass_vars(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.trim().to_owned();
                // Require at least one '=' to be present; silently skip entries without one.
                parts.next()?;
                Some(key)
            })
            .collect()
    })
    .unwrap_or_default()
}

// ─── Transition function ──────────────────────────────────────────────────────

/// Pure state machine transition: map an [`Event`] to an ordered list of [`Effect`]s.
///
/// This function performs **no I/O** and returns an error only for structural
/// problems (e.g. an empty command vector for `RunRequested`).
///
/// # Errors
///
/// Returns [`FhsmError::UsageError`] when the event contains invalid arguments
/// that make execution impossible.
pub fn transition(event: &Event) -> Result<Vec<Effect>, FhsmError> {
    match event {
        Event::Run {
            env,
            identity,
            prod,
            no_prompt,
            clear_env,
            pass_raw,
            command,
        } => {
            if command.is_empty() {
                return Err(FhsmError::UsageError(
                    "command must not be empty".to_string(),
                ));
            }

            let resolved_env = env.as_deref().unwrap_or("dev").to_owned();
            let source = resolve_identity_source(
                identity.as_deref(),
                None, // real env vars resolved by the executor
                None,
            );
            let pass_vars = parse_pass_vars(pass_raw.as_deref());

            Ok(vec![
                Effect::CheckProdBarrier {
                    env: resolved_env.clone(),
                    prod: *prod,
                    no_prompt: *no_prompt,
                },
                Effect::ResolveIdentity { source },
                Effect::DecryptSecrets { env: resolved_env },
                Effect::RunCommand {
                    command: command.clone(),
                    clear_env: *clear_env,
                    pass_vars,
                },
            ])
        }

        Event::Materialize {
            env,
            identity,
            prod,
            no_prompt,
        } => {
            let resolved_env = env.as_deref().unwrap_or("dev").to_owned();
            let source = resolve_identity_source(identity.as_deref(), None, None);

            Ok(vec![
                Effect::CheckProdBarrier {
                    env: resolved_env.clone(),
                    prod: *prod,
                    no_prompt: *no_prompt,
                },
                Effect::ResolveIdentity { source },
                Effect::DecryptSecrets {
                    env: resolved_env.clone(),
                },
                Effect::MaterializeSecrets { env: resolved_env },
            ])
        }

        Event::Decrypt {
            file,
            identity,
            no_prompt: _, // decrypt is always non-interactive; no_prompt is not applicable
            output,
        } => {
            let source = resolve_identity_source(identity.as_deref(), None, None);

            Ok(vec![
                Effect::ResolveIdentity { source },
                Effect::DecryptFile {
                    file: PathBuf::from(file),
                    output: output.as_ref().map(PathBuf::from),
                },
            ])
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a minimal RunRequested event
    fn run_event(command: Vec<&str>) -> Event {
        Event::Run {
            env: Some("dev".to_string()),
            identity: None,
            prod: false,
            no_prompt: false,
            clear_env: false,
            pass_raw: None,
            command: command.into_iter().map(str::to_owned).collect(),
        }
    }

    // ── Table-driven: transition() ──────────────────────────────────────────

    #[test]
    fn run_requested_empty_command_returns_usage_error() {
        let event = run_event(vec![]);
        let result = transition(&event);
        assert_eq!(
            result,
            Err(FhsmError::UsageError(
                "command must not be empty".to_string()
            ))
        );
    }

    #[test]
    fn run_requested_normal_first_effect_is_check_prod_barrier() {
        let event = run_event(vec!["env"]);
        let effects = transition(&event).expect("should succeed");
        assert!(
            matches!(&effects[0], Effect::CheckProdBarrier { env, .. } if env == "dev"),
            "first effect must be CheckProdBarrier(dev), got: {:?}",
            effects[0]
        );
    }

    #[test]
    fn run_requested_normal_last_effect_is_run_command() {
        let event = run_event(vec!["env"]);
        let effects = transition(&event).expect("should succeed");
        let last = effects.last().expect("effects must not be empty");
        assert!(
            matches!(last, Effect::RunCommand { command, .. } if command[0] == "env"),
            "last effect must be RunCommand, got: {:?}",
            last
        );
    }

    #[test]
    fn materialize_requested_includes_decrypt_then_materialize_secrets() {
        let event = Event::Materialize {
            env: Some("staging".to_string()),
            identity: None,
            prod: false,
            no_prompt: false,
        };
        let effects = transition(&event).expect("should succeed");
        // DecryptSecrets must precede MaterializeSecrets so execute_effects can
        // populate secrets_opt before the materialize step consumes it.
        let decrypt_pos = effects
            .iter()
            .position(|e| matches!(e, Effect::DecryptSecrets { env } if env == "staging"));
        let materialize_pos = effects
            .iter()
            .position(|e| matches!(e, Effect::MaterializeSecrets { env } if env == "staging"));
        assert!(decrypt_pos.is_some(), "expected DecryptSecrets(staging)");
        assert!(
            materialize_pos.is_some(),
            "expected MaterializeSecrets(staging)"
        );
        assert!(
            decrypt_pos < materialize_pos,
            "DecryptSecrets must come before MaterializeSecrets"
        );
    }

    #[test]
    fn decrypt_requested_no_check_prod_barrier() {
        let event = Event::Decrypt {
            file: "secrets.age".to_string(),
            identity: None,
            no_prompt: false,
            output: None,
        };
        let effects = transition(&event).expect("should succeed");
        let has_barrier = effects
            .iter()
            .any(|e| matches!(e, Effect::CheckProdBarrier { .. }));
        assert!(
            !has_barrier,
            "DecryptRequested must not produce CheckProdBarrier"
        );
    }

    #[test]
    fn decrypt_requested_includes_resolve_identity_and_decrypt_file() {
        let event = Event::Decrypt {
            file: "foo.age".to_string(),
            identity: Some("/home/user/.age".to_string()),
            no_prompt: false,
            output: Some("foo.txt".to_string()),
        };
        let effects = transition(&event).expect("should succeed");
        let has_resolve = effects.iter().any(|e| {
            matches!(e, Effect::ResolveIdentity { source: IdentitySource::FilePath(p) }
                if p == "/home/user/.age")
        });
        let has_decrypt = effects.iter().any(|e| {
            matches!(e, Effect::DecryptFile { file, output: Some(out) }
                if file == std::path::Path::new("foo.age")
                && out == std::path::Path::new("foo.txt"))
        });
        assert!(
            has_resolve,
            "expected ResolveIdentity(FilePath) in {effects:?}"
        );
        assert!(has_decrypt, "expected DecryptFile in {effects:?}");
    }

    // ── Table-driven: resolve_identity_source() ─────────────────────────────

    #[test]
    fn resolve_identity_source_explicit_path_returns_file_path() {
        let source = resolve_identity_source(Some("/keys/id.age"), None, None);
        assert_eq!(source, IdentitySource::FilePath("/keys/id.age".to_string()));
    }

    #[test]
    fn resolve_identity_source_no_path_keyring_true_returns_keyring() {
        let source = resolve_identity_source(None, None, Some("1"));
        assert_eq!(source, IdentitySource::Keyring);
    }

    #[test]
    fn resolve_identity_source_env_var_returns_env_var() {
        let source = resolve_identity_source(None, Some("AGE-SECRET-KEY-abc123"), None);
        assert_eq!(
            source,
            IdentitySource::EnvVar("AGE-SECRET-KEY-abc123".to_string())
        );
    }

    #[test]
    fn resolve_identity_source_path_takes_priority_over_env_var() {
        let source =
            resolve_identity_source(Some("/p/id.age"), Some("AGE-SECRET-KEY-abc"), Some("1"));
        assert_eq!(source, IdentitySource::FilePath("/p/id.age".to_string()));
    }

    #[test]
    fn resolve_identity_source_env_var_takes_priority_over_keyring() {
        let source = resolve_identity_source(None, Some("AGE-SECRET-KEY-abc"), Some("1"));
        assert_eq!(
            source,
            IdentitySource::EnvVar("AGE-SECRET-KEY-abc".to_string())
        );
    }

    // ── parse_pass_vars (via transition) ────────────────────────────────────

    #[test]
    fn run_with_pass_raw_parses_valid_pairs_into_run_command() {
        let event = Event::Run {
            env: Some("dev".to_string()),
            identity: None,
            prod: false,
            no_prompt: false,
            clear_env: false,
            pass_raw: Some("KEY=value,OTHER=x".to_string()),
            command: vec!["env".to_string()],
        };
        let effects = transition(&event).expect("should succeed");
        let run_cmd = effects.iter().find_map(|e| {
            if let Effect::RunCommand { pass_vars, .. } = e {
                Some(pass_vars.clone())
            } else {
                None
            }
        });
        assert_eq!(run_cmd, Some(vec!["KEY".to_string(), "OTHER".to_string()]));
    }

    #[test]
    fn run_with_pass_raw_skips_entries_without_equals() {
        let event = Event::Run {
            env: Some("dev".to_string()),
            identity: None,
            prod: false,
            no_prompt: false,
            clear_env: false,
            pass_raw: Some("NOEQUALS,KEY=val".to_string()),
            command: vec!["env".to_string()],
        };
        let effects = transition(&event).expect("should succeed");
        let pass_vars = effects.iter().find_map(|e| {
            if let Effect::RunCommand { pass_vars, .. } = e {
                Some(pass_vars.clone())
            } else {
                None
            }
        });
        // "NOEQUALS" has no '=' so it should be silently skipped.
        assert_eq!(pass_vars, Some(vec!["KEY".to_string()]));
    }

    #[test]
    fn resolve_identity_source_none_inputs_returns_unresolved() {
        let source = resolve_identity_source(None, None, None);
        assert_eq!(source, IdentitySource::Unresolved);
    }
}
