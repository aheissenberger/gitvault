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
    },
    /// Materialize secrets to root .env
    Materialize {
        /// Environment to use (overrides SECRETS_ENV and .secrets/env)
        #[arg(short, long)]
        env: Option<String>,
        /// Identity key file path
        #[arg(short, long)]
        identity: Option<String>,
    },
    /// Check repository safety status
    Status,
    /// Harden repository (update .gitignore, install hooks)
    Harden,
}
