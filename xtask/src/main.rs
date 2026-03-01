use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let task = args
        .first()
        .cloned()
        .unwrap_or_else(|| "verify".to_string());

    let result = match task.as_str() {
        "fmt" => run("cargo", &["fmt", "--all", "--", "--check"]),
        "clippy" => run(
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        "test" => run("cargo", &["test", "--workspace", "--all-features"]),
        "build" => run("cargo", &["build", "--workspace", "--release"]),
        "verify" => run_verify(),
        "spec-init" => run_spec_init(&args[1..]),
        "spec-verify" => run_spec_verify(),
        "wt-list" => run_worktree_list(),
        "wt-create" => run_worktree_create(&args[1..]),
        "wt-remove" => run_worktree_remove(&args[1..]),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        _ => {
            print_help();
            Err(format!("Unknown task: {task}"))
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn run_verify() -> Result<(), String> {
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run("cargo", &["test", "--workspace", "--all-features"])?;
    run("cargo", &["build", "--workspace", "--release"])?;
    Ok(())
}

fn run_spec_init(args: &[String]) -> Result<(), String> {
    let spec_name = args
        .first()
        .ok_or_else(|| "Usage: cargo xtask spec-init <SPEC_FOLDER_NAME>".to_string())?;
    run("tools/spec_init.sh", &[spec_name.as_str()])
}

fn run_spec_verify() -> Result<(), String> {
    run("tools/spec_verify.sh", &[])
}

fn run_worktree_list() -> Result<(), String> {
    run("git", &["worktree", "list"])
}

fn run_worktree_create(args: &[String]) -> Result<(), String> {
    let branch = args
        .first()
        .ok_or_else(|| "Usage: cargo xtask wt-create <branch> <dir>".to_string())?;
    let dir = args
        .get(1)
        .ok_or_else(|| "Usage: cargo xtask wt-create <branch> <dir>".to_string())?;
    run("git", &["worktree", "add", "-b", branch.as_str(), dir.as_str()])
}

fn run_worktree_remove(args: &[String]) -> Result<(), String> {
    let dir = args
        .first()
        .ok_or_else(|| "Usage: cargo xtask wt-remove <dir>".to_string())?;
    run("git", &["worktree", "remove", dir.as_str()])
}

fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|error| format!("Failed to run `{cmd}`: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Command failed: `{cmd} {}`",
            args.join(" ")
        ))
    }
}

fn print_help() {
    println!("Usage: cargo xtask <command> [args]");
    println!("  verify (default): run fmt + clippy + test + build");
    println!("  fmt|clippy|test|build");
    println!("  spec-init <SPEC_FOLDER_NAME>");
    println!("  spec-verify");
    println!("  wt-list");
    println!("  wt-create <branch> <dir>");
    println!("  wt-remove <dir>");
}