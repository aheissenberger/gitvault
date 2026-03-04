use clap::{Parser, Subcommand};

pub const OUTPUT_KEEP_PATH_SENTINEL: &str = "__GITVAULT_KEEP_PATH__";

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
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable interactive prompts
    #[arg(long, global = true)]
    pub no_prompt: bool,

    /// Explicit identity selector for SSH-agent key disambiguation
    #[arg(long, global = true, env = "GITVAULT_IDENTITY_SELECTOR")]
    pub identity_selector: Option<String>,

    /// AWS profile name for SSM backend
    #[arg(long, global = true, env = "AWS_PROFILE")]
    pub aws_profile: Option<String>,

    /// AWS role ARN to assume for SSM backend
    #[arg(long, global = true, env = "AWS_ROLE_ARN")]
    pub aws_role_arn: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a secret file
    Encrypt {
        /// File to encrypt
        file: String,
        /// Recipient age public key (repeat for multi-recipient; defaults to local identity if omitted)
        #[arg(short, long = "recipient")]
        recipients: Vec<String>,
        /// Environment to use (overrides `GITVAULT_ENV` and .secrets/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Preserve input path relative to repo root under secrets/<env>/
        #[arg(long)]
        keep_path: bool,
        /// Fields to encrypt (comma-separated key paths, for JSON/YAML/TOML field-level encryption)
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
        /// Encrypt .env values individually instead of whole-file
        #[arg(long)]
        value_only: bool,
    },
    /// Decrypt a .age encrypted file
    Decrypt {
        /// Encrypted .age file to decrypt
        file: String,
        /// Identity key file path (or use `GITVAULT_IDENTITY` env var)
        #[arg(short, long)]
        identity: Option<String>,
        /// Output file path (default: strip .age extension)
        #[arg(
            short,
            long,
            num_args = 0..=1,
            default_missing_value = OUTPUT_KEEP_PATH_SENTINEL
        )]
        output: Option<String>,
        /// Fields to decrypt (comma-separated key paths, for JSON/YAML/TOML)
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
        /// Print decrypted content to stdout instead of writing to file
        #[arg(long)]
        reveal: bool,
        /// Decrypt .env values individually (reverse of --value-only encrypt)
        #[arg(long)]
        value_only: bool,
    },
    /// Materialize secrets to root .env
    Materialize {
        /// Environment to use (overrides `GITVAULT_ENV` and .secrets/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path
        #[arg(short, long)]
        identity: Option<String>,
        /// Require production barrier for prod env
        #[arg(long)]
        prod: bool,
    },
    /// Check repository safety status
    Status {
        /// Fail with exit code 6 if secrets/ has uncommitted changes
        #[arg(long)]
        fail_if_dirty: bool,
    },
    /// Harden repository and optionally import plain files as encrypted secrets
    Harden {
        /// Plain text file(s) to encrypt and import (supports globs, e.g. ".env*")
        /// If omitted, only repo hardening (gitignore, hooks) is performed
        files: Vec<String>,
        /// Target environment for encrypted files (e.g. --env dev)
        #[arg(long)]
        env: Option<String>,
        /// Print what would happen without writing any files
        #[arg(long)]
        dry_run: bool,
        /// Delete source file after encrypting (default: keep source)
        #[arg(long)]
        remove: bool,
        /// Additional recipient keys (age1...) on top of .secrets/recipients/
        #[arg(short, long = "recipient")]
        recipients: Vec<String>,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Environment to use
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path (or use `GITVAULT_IDENTITY` env var)
        #[arg(short, long)]
        identity: Option<String>,
        /// Require production barrier (required when env=prod)
        #[arg(long)]
        prod: bool,
        /// Start child with empty environment
        #[arg(long)]
        clear_env: bool,
        /// Comma-separated vars to pass through when --clear-env is set
        #[arg(long, value_name = "VARS")]
        pass: Option<String>,
        /// Command and arguments to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Write a timed production allow token
    AllowProd {
        /// Token lifetime in seconds (default: from [barrier].ttl_secs config, then 3600)
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Run as git merge driver for .env files
    /// Usage: git config merge.gitvault-env.driver "gitvault merge-driver %O %A %B"
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
        /// Identity key file path (or use `GITVAULT_IDENTITY` env var)
        #[arg(short, long)]
        identity: Option<String>,
        /// Only rekey files in the given environment subtree (e.g. --env dev)
        #[arg(long)]
        env: Option<String>,
        /// Print what would be rekeyed without writing any files
        #[arg(long)]
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
        /// Identity key file path (or use `GITVAULT_IDENTITY` env var)
        #[arg(short, long)]
        identity: Option<String>,
    },
    /// Revoke the production allow token immediately.
    RevokeProd,

    /// Manage local identity keys
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// AI tooling helpers (skill and context print)
    Ai {
        #[command(subcommand)]
        action: AiAction,
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
        /// Identity key file path (or use `GITVAULT_IDENTITY` env var)
        #[arg(short, long)]
        identity: Option<String>,
    },
    /// Show public key of stored identity
    Get,
    /// Remove stored identity from OS keyring
    Delete,
}

#[derive(Subcommand)]
pub enum IdentityAction {
    /// Create a new identity key
    Create {
        /// Identity profile: classic (age X25519) or hybrid (age X25519 + future PQ-ready label)
        #[arg(long, value_enum, default_value = "classic")]
        profile: IdentityProfile,
        /// Export identity to file (optional; default: store in OS keyring)
        #[arg(long, value_name = "PATH")]
        out: Option<String>,
        /// After creating identity, add own public key to .secrets/recipients/
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
    fn test_decrypt_bare_output_sets_keep_path_sentinel() {
        let cli =
            Cli::try_parse_from(["gitvault", "decrypt", "secrets/dev/app.env.age", "--output"])
                .expect("bare --output should parse");

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(OUTPUT_KEEP_PATH_SENTINEL.to_string()));
            }
            _ => panic!("expected decrypt command"),
        }
    }

    #[test]
    fn test_encrypt_keep_path_flag_parses() {
        let cli = Cli::try_parse_from([
            "gitvault",
            "encrypt",
            "app.env",
            "--recipient",
            "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7f7f3",
            "--keep-path",
        ])
        .expect("--keep-path should parse");

        match cli.command {
            Commands::Encrypt { keep_path, .. } => {
                assert!(keep_path);
            }
            _ => panic!("expected encrypt command"),
        }
    }
}

/// AI subcommand: choose between skill and context printing.
#[derive(Subcommand)]
pub enum AiAction {
    /// Print canonical gitvault skill content for Copilot usage
    Skill {
        #[command(subcommand)]
        action: AiPrintAction,
    },
    /// Print concise project AI context for agent onboarding
    Context {
        #[command(subcommand)]
        action: AiPrintAction,
    },
}

/// AI print sub-subcommand.
#[derive(Subcommand, Clone)]
pub enum AiPrintAction {
    /// Print the content
    Print,
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
