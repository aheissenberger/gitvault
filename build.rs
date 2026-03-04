use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=docs/ai/skill.md");
    println!("cargo:rerun-if-changed=docs/ai/AGENT_START.md");

    let git_sha =
        git_output(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let git_commit_date = git_output(&["show", "-s", "--format=%cI", "HEAD"])
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GITVAULT_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=GITVAULT_GIT_COMMIT_DATE={git_commit_date}");
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
