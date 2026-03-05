use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gitvault",
    about = "Git-native secrets manager",
    after_help = "\
CONFIG FILES (override built-in defaults):
  .gitvault/config.toml          project-level (committed with the repo)
  ~/.config/gitvault/config.toml user-global personal defaults

  Sections and keys:
    [env]     default, prod_name, env_file
    [barrier] ttl_secs
    [paths]   recipients_dir, materialize_output
    [keyring] service, account
    [hooks]   adapter

  CLI flags and environment variables always take precedence over config files.
  Run `gitvault help` for the full reference or see README.md § Configuration.",
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        "\nformat-version: 1",
        "\nage-format: age-encryption.org/v1",
        "\ngit-sha: ",
        env!("GITVAULT_GIT_SHA"),
        "\ngit-commit-date: ",
        env!("GITVAULT_GIT_COMMIT_DATE")
    )
)]
pub struct Cli {
    /// Output results as JSON
    #[arg(long, global = true, help_heading = "Global Options")]
    pub json: bool,

    /// Disable interactive prompts
    #[arg(long, global = true, help_heading = "Global Options")]
    pub no_prompt: bool,

    /// Select which SSH-agent key to use, by fingerprint or comment (when multiple keys are loaded)
    #[arg(
        long,
        global = true,
        env = "GITVAULT_IDENTITY_SELECTOR",
        help_heading = "Global Options"
    )]
    pub identity_selector: Option<String>,

    /// Read identity key from stdin instead of a file path (pipe-friendly)
    #[arg(
        long,
        global = true,
        conflicts_with = "identity_selector",
        help_heading = "Global Options"
    )]
    pub identity_stdin: bool,

    /// AWS profile name for SSM backend
    #[cfg(feature = "ssm")]
    #[arg(
        long,
        global = true,
        env = "AWS_PROFILE",
        help_heading = "Global Options"
    )]
    pub aws_profile: Option<String>,

    /// AWS role ARN to assume for SSM backend
    #[cfg(feature = "ssm")]
    #[arg(
        long,
        global = true,
        env = "AWS_ROLE_ARN",
        help_heading = "Global Options"
    )]
    pub aws_role_arn: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file and archive it under .gitvault/store/<env>/ mirroring its source path. For in-place field-level encryption of JSON/YAML/TOML/.env, use 'gitvault seal'.
    Encrypt {
        /// File to encrypt
        file: String,
        /// Recipient age public key (repeat for multi-recipient; defaults to local identity if omitted)
        #[arg(short, long = "recipient", value_name = "PUBKEY")]
        recipients: Vec<String>,
        /// Environment to use (overrides `GITVAULT_ENV` and .git/gitvault/env)
        #[arg(short, long)]
        env: Option<String>,
    },
    /// Decrypt a file from the .gitvault/store/<env>/ archive. Accepts either the original source path or the .age store path. For in-place field-level decryption of JSON/YAML/TOML/.env, use 'gitvault unseal'.
    Decrypt {
        /// Original source path (e.g. services/auth/config.json) or explicit .age store path
        file: String,
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Environment for store path resolution (overrides GITVAULT_ENV and .git/gitvault/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Print decrypted content to stdout instead of writing to .git/gitvault/plain/
        #[arg(long)]
        reveal: bool,
    },
    /// Materialize secrets to root .env
    Materialize {
        /// Environment to use (overrides `GITVAULT_ENV` and .git/gitvault/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Require production barrier for prod env
        #[arg(long)]
        prod: bool,
    },
    /// Show repository safety status (gitignore, hooks, recipients, encrypted files)
    Status {
        /// Exit with code 6 if .gitvault/store/ directory has uncommitted changes
        #[arg(long)]
        fail_if_dirty: bool,
    },
    /// Interactive onboarding: set up identity, recipients, harden repo, and create config
    Init {
        /// Target environment to activate (writes to .git/gitvault/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Export the newly created identity key to this file (instead of storing in OS keyring)
        #[arg(long, alias = "out", value_name = "PATH")]
        output: Option<String>,
    },
    /// Harden repository and optionally import plain files as encrypted secrets
    Harden {
        /// Plain text file(s) to encrypt and import (supports globs, e.g. ".env*")
        /// If omitted, only repo hardening (gitignore, hooks) is performed
        files: Vec<String>,
        /// Target environment for encrypted files (e.g. --env dev)
        #[arg(short, long)]
        env: Option<String>,
        /// Print what would happen without writing any files
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// Delete source file after encrypting (default: keep source)
        #[arg(long, alias = "remove")]
        delete_source: bool,
        /// Additional recipient keys (age1...) on top of .gitvault/recipients/
        #[arg(short, long = "recipient", value_name = "PUBKEY")]
        recipients: Vec<String>,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Environment to use
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Require production barrier (pass when deploying to the prod environment)
        #[arg(long)]
        prod: bool,
        /// Start child with empty environment
        #[arg(long)]
        clear_env: bool,
        /// Comma-separated env vars to pass through when --clear-env is set
        #[arg(long, alias = "pass", value_name = "VARS")]
        keep_vars: Option<String>,
        /// Command and arguments to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Write a timed production allow token to .git/gitvault/.prod-token
    AllowProd {
        /// Token lifetime in seconds (config: barrier.ttl_secs) [default: 3600]
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Revoke the production allow token immediately
    RevokeProd,
    /// Run as git merge driver for .env files
    #[command(hide = true)]
    MergeDriver {
        /// Base version (ancestor)
        base: String,
        /// Ours version (current branch, will be overwritten with merge result)
        ours: String,
        /// Theirs version (incoming branch)
        theirs: String,
    },
    /// Manage persistent recipients
    Recipient {
        #[command(subcommand)]
        action: RecipientAction,
    },
    /// Re-encrypt all secrets with the current recipients list
    Rekey {
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Only rekey files in the given environment subtree (e.g. --env dev)
        #[arg(short, long)]
        env: Option<String>,
        /// Print what would be rekeyed without writing any files
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Manage identity key in OS keyring
    Keyring {
        #[command(subcommand)]
        action: KeyringAction,
    },
    /// Run preflight validation without side effects
    Check {
        /// Environment to validate
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Skip the committed-history plaintext leak scan
        #[arg(short = 'H', long)]
        skip_history_check: bool,
    },

    /// Manage local identity keys
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// AI tooling: print skill or context files for Copilot/agent integration
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },

    /// Encrypt string field values in a JSON/YAML/TOML/.env file in-place (REQ-112)
    Seal {
        /// File to seal (.json, .yaml, .yml, .toml, .env, .env.<suffix>)
        file: String,
        /// Additional recipient age public keys (repeat for multiple)
        #[arg(short = 'r', long = "recipient", value_name = "PUBKEY")]
        recipients: Vec<String>,
        /// Environment to use for recipient key resolution
        #[arg(short, long)]
        env: Option<String>,
        /// Only seal the listed dot-path fields (comma-separated, e.g. "db.password,api.key")
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
    },

    /// Decrypt all encrypted field values in a JSON/YAML/TOML/.env file in-place (REQ-112)
    Unseal {
        /// File to unseal
        file: String,
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Only decrypt the listed fields (comma-separated, e.g. "db.password,api.key")
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
        /// Print decrypted content to stdout instead of writing back to the file
        #[arg(long)]
        reveal: bool,
    },

    /// Open a sealed file in an editor, then re-seal on save
    Edit {
        /// File to edit
        file: String,
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
        /// Environment for recipient key resolution
        #[arg(short, long)]
        env: Option<String>,
        /// Only unseal/re-seal the listed dot-path fields (comma-separated)
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
        /// Editor command to use (overrides config and env vars)
        #[arg(long, value_name = "CMD")]
        editor: Option<String>,
    },

    /// AWS SSM Parameter Store backend
    #[cfg(feature = "ssm")]
    Ssm {
        #[command(subcommand)]
        action: SsmAction,
    },
}

#[derive(Subcommand)]
pub enum RecipientAction {
    /// Add a recipient public key
    Add {
        /// age public key (age1...)
        pubkey: String,
    },
    /// Remove a recipient public key
    Remove {
        /// age public key (age1...)
        pubkey: String,
    },
    /// List current recipients
    List,
    /// Add own public key to the recipients directory
    AddSelf,
}

#[derive(Subcommand)]
pub enum KeyringAction {
    /// Store identity key in OS keyring
    Set {
        /// Identity key file path
        #[arg(short, long, env = "GITVAULT_IDENTITY")]
        identity: Option<String>,
    },
    /// Show public key of stored identity
    Get,
    /// Remove stored identity from OS keyring
    Delete,
    /// Store the SSH identity file passphrase in the OS keyring; once stored,
    /// gitvault retrieves it automatically when loading an encrypted SSH identity.
    SetPassphrase {
        /// Passphrase value (prefer GITVAULT_IDENTITY_PASSPHRASE env var to avoid shell history exposure)
        #[arg(value_name = "PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Show whether an SSH identity passphrase is stored in the OS keyring (does not print the passphrase value)
    GetPassphrase,
    /// Remove the stored SSH identity passphrase from the OS keyring
    DeletePassphrase,
}

#[derive(Subcommand)]
pub enum IdentityAction {
    /// Create a new identity key
    Create {
        /// Identity profile: classic (age X25519) or hybrid (age X25519 key with a post-quantum-ready annotation, for future migration)
        #[arg(long, value_enum, default_value = "classic")]
        profile: IdentityProfile,
        /// Export identity to file (optional; default: store in OS keyring)
        #[arg(long, alias = "out", value_name = "PATH")]
        output: Option<String>,
        /// After creating identity, add own public key to .gitvault/recipients/ (equivalent to running `recipient add-self` afterwards)
        #[arg(long)]
        add_recipient: bool,
    },
    /// Print the age public key of the current identity
    Pubkey,
}

#[derive(clap::ValueEnum, Clone, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityProfile {
    Classic,
    Hybrid,
}

impl std::fmt::Display for IdentityProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Classic => write!(f, "classic"),
            Self::Hybrid => write!(f, "hybrid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_parses_source_path_with_env() {
        let cli = Cli::try_parse_from([
            "gitvault",
            "decrypt",
            "services/auth/config.json",
            "--env",
            "prod",
        ])
        .expect("decrypt with source path and env should parse");

        match cli.command {
            Commands::Decrypt {
                file, env, reveal, ..
            } => {
                assert_eq!(file, "services/auth/config.json");
                assert_eq!(env, Some("prod".to_string()));
                assert!(!reveal);
            }
            _ => panic!("expected decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_reveal_flag() {
        let cli = Cli::try_parse_from([
            "gitvault",
            "decrypt",
            ".gitvault/store/dev/app.env.age",
            "--reveal",
        ])
        .expect("decrypt --reveal should parse");

        match cli.command {
            Commands::Decrypt { reveal, .. } => {
                assert!(reveal);
            }
            _ => panic!("expected decrypt command"),
        }
    }

    #[test]
    fn test_identity_profile_display_classic() {
        assert_eq!(IdentityProfile::Classic.to_string(), "classic");
    }

    #[test]
    fn test_identity_profile_display_hybrid() {
        assert_eq!(IdentityProfile::Hybrid.to_string(), "hybrid");
    }
}

/// AI subcommand: choose between skill and context printing.
#[derive(Subcommand)]
pub enum AiAction {
    /// Print canonical gitvault skill content for Copilot usage
    Skill,
    /// Print concise project AI context for agent onboarding
    Context,
}

#[cfg(feature = "ssm")]
#[derive(Subcommand)]
pub enum SsmAction {
    /// Pull parameter values from SSM into local comparison
    Pull {
        #[arg(short, long)]
        env: Option<String>,
    },
    /// Show diff between local references and SSM (hide values unless --reveal)
    Diff {
        #[arg(short, long)]
        env: Option<String>,
        #[arg(long)]
        reveal: bool,
    },
    /// Set a single SSM parameter and record reference locally
    Set {
        key: String,
        value: String,
        #[arg(short, long)]
        env: Option<String>,
        /// Require production barrier (required when env=prod)
        #[arg(long)]
        prod: bool,
    },
    /// Push all local SSM references to Parameter Store
    Push {
        #[arg(short, long)]
        env: Option<String>,
        /// Require production barrier (required when env=prod)
        #[arg(long)]
        prod: bool,
    },
}
