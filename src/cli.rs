use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gitvault",
    about = "Git-native secrets manager",
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
    /// Output results as JSON (REQ-45)
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable interactive prompts (REQ-46)
    #[arg(long, global = true)]
    pub no_prompt: bool,

    /// AWS profile name for SSM backend (REQ-49)
    #[arg(long, global = true, env = "AWS_PROFILE")]
    pub aws_profile: Option<String>,

    /// AWS role ARN to assume for SSM backend (REQ-49)
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
        /// Fields to encrypt (comma-separated key paths, for JSON/YAML/TOML field-level encryption; REQ-4)
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
        /// Encrypt .env values individually instead of whole-file (REQ-6)
        #[arg(long)]
        value_only: bool,
    },
    /// Decrypt a .age encrypted file
    Decrypt {
        /// Encrypted .age file to decrypt
        file: String,
        /// Identity key file path (or use GITVAULT_IDENTITY env var)
        #[arg(short, long)]
        identity: Option<String>,
        /// Output file path (default: strip .age extension)
        #[arg(short, long)]
        output: Option<String>,
        /// Fields to decrypt (comma-separated key paths, for JSON/YAML/TOML; REQ-4)
        #[arg(long, value_name = "FIELDS")]
        fields: Option<String>,
        /// Print decrypted content to stdout instead of writing to file (REQ-41)
        #[arg(long)]
        reveal: bool,
    },
    /// Materialize secrets to root .env
    Materialize {
        /// Environment to use (overrides SECRETS_ENV and .secrets/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path
        #[arg(short, long)]
        identity: Option<String>,
        /// Require production barrier for prod env (REQ-13)
        #[arg(long)]
        prod: bool,
    },
    /// Check repository safety status
    Status {
        /// Fail with exit code 3 if secrets/ has uncommitted changes (REQ-32)
        #[arg(long)]
        fail_if_dirty: bool,
    },
    /// Harden repository (update .gitignore, install hooks)
    Harden,
    /// Run a command with secrets injected as environment variables (REQ-21..25)
    Run {
        /// Environment to use
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path (or use GITVAULT_IDENTITY env var)
        #[arg(short, long)]
        identity: Option<String>,
        /// Require production barrier (required when env=prod) (REQ-13)
        #[arg(long)]
        prod: bool,
        /// Start child with empty environment (REQ-24)
        #[arg(long)]
        clear_env: bool,
        /// Comma-separated vars to pass through when --clear-env is set (REQ-24)
        #[arg(long, value_name = "VARS")]
        pass: Option<String>,
        /// Command and arguments to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Write a timed production allow token (REQ-14)
    AllowProd {
        /// Token lifetime in seconds
        #[arg(long, default_value_t = crate::barrier::DEFAULT_TOKEN_TTL_SECS)]
        ttl: u64,
    },
    /// Run as git merge driver for .env files (REQ-34)
    /// Usage: git config merge.gitvault-env.driver "gitvault merge-driver %O %A %B"
    MergeDriver {
        /// Base version (ancestor)
        base: String,
        /// Ours version (current branch, will be overwritten with merge result)
        ours: String,
        /// Theirs version (incoming branch)
        theirs: String,
    },
    /// Manage persistent recipients (REQ-37)
    Recipient {
        #[command(subcommand)]
        action: RecipientAction,
    },
    /// Re-encrypt all secrets with the current recipients list (REQ-38)
    Rotate {
        /// Identity key file path (or use GITVAULT_IDENTITY env var)
        #[arg(short, long)]
        identity: Option<String>,
    },
    /// Manage identity key in OS keyring (REQ-39)
    Keyring {
        #[command(subcommand)]
        action: KeyringAction,
    },
    /// Run preflight validation without side effects (REQ-50)
    Check {
        /// Environment to validate
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path (or use GITVAULT_IDENTITY env var)
        #[arg(short, long)]
        identity: Option<String>,
    },
    /// Revoke the production allow token immediately [REQ-14].
    RevokeProd,
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
}

#[derive(Subcommand)]
pub enum KeyringAction {
    /// Store identity key in OS keyring
    Set {
        /// Identity key file path (or use GITVAULT_IDENTITY env var)
        #[arg(short, long)]
        identity: Option<String>,
    },
    /// Show public key of stored identity
    Get,
    /// Remove stored identity from OS keyring
    Delete,
}
