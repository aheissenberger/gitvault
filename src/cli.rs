use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gitvault", about = "Git-native secrets manager", version)]
pub struct Cli {
    /// Output results as JSON (REQ-45)
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable interactive prompts (REQ-46)
    #[arg(long, global = true)]
    pub no_prompt: bool,

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
}
