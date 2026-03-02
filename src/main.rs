use clap::Parser;
use gitvault::cli::Cli;
use gitvault::commands::CommandOutcome;
use gitvault::error;
use std::process;

fn main() {
    let cli = Cli::parse();

    let result = gitvault::dispatch::run(cli);
    match result {
        Ok(CommandOutcome::Success) => process::exit(error::EXIT_SUCCESS),
        Ok(CommandOutcome::Exit(code)) => process::exit(code),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(e.exit_code());
        }
    }
}
