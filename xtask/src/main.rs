use std::env;
use std::fs;
use std::path::{Component, Path};
use std::process::{Command, ExitCode};

use regex::Regex;
use serde::Deserialize;
use walkdir::WalkDir;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let task = Task::from_args(&args);

    let result = task.run();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
enum Task {
    Fmt,
    Clippy,
    Test,
    Build,
    Verify,
    SpecInit { spec_name: String },
    SpecVerify,
    InstructionsLint,
    WtList,
    WtCreate { branch: String, dir: String },
    WtRemove { dir: String },
    Help,
    Unknown { task: String },
}

impl Task {
    fn from_args(args: &[String]) -> Self {
        let Some(task) = args.first().map(String::as_str) else {
            return Self::Verify;
        };

        match task {
            "fmt" => Self::Fmt,
            "clippy" => Self::Clippy,
            "test" => Self::Test,
            "build" => Self::Build,
            "verify" => Self::Verify,
            "spec-init" => {
                if let Some(spec_name) = args.get(1).cloned() {
                    Self::SpecInit { spec_name }
                } else {
                    Self::Help
                }
            }
            "spec-verify" => Self::SpecVerify,
            "instructions-lint" => Self::InstructionsLint,
            "wt-list" => Self::WtList,
            "wt-create" => {
                let branch = args.get(1).cloned();
                let dir = args.get(2).cloned();
                match (branch, dir) {
                    (Some(branch), Some(dir)) => Self::WtCreate { branch, dir },
                    _ => Self::Help,
                }
            }
            "wt-remove" => {
                if let Some(dir) = args.get(1).cloned() {
                    Self::WtRemove { dir }
                } else {
                    Self::Help
                }
            }
            "help" | "-h" | "--help" => Self::Help,
            other => Self::Unknown {
                task: other.to_string(),
            },
        }
    }

    fn run(self) -> Result<(), String> {
        match self {
            Self::Fmt => run("cargo", &["fmt", "--all", "--", "--check"]),
            Self::Clippy => run(
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
            Self::Test => run("cargo", &["test", "--workspace", "--all-features"]),
            Self::Build => run("cargo", &["build", "--workspace", "--release"]),
            Self::Verify => run_verify(),
            Self::SpecInit { spec_name } => run_spec_init(&spec_name),
            Self::SpecVerify => run_spec_verify(),
            Self::InstructionsLint => run_instructions_lint(),
            Self::WtList => run_worktree_list(),
            Self::WtCreate { branch, dir } => run_worktree_create(&branch, &dir),
            Self::WtRemove { dir } => run_worktree_remove(&dir),
            Self::Help => {
                print_help();
                Ok(())
            }
            Self::Unknown { task } => {
                print_help();
                Err(format!("Unknown task: {task}"))
            }
        }
    }
}

fn run_verify() -> Result<(), String> {
    Task::Fmt.run()?;
    Task::Clippy.run()?;
    Task::InstructionsLint.run()?;
    Task::Test.run()?;
    Task::Build.run()?;
    Ok(())
}

fn run_spec_init(spec_name: &str) -> Result<(), String> {
    validate_spec_name(spec_name)?;

    let spec_dir = Path::new("specs").join(spec_name);
    if spec_dir.exists() {
        return Err(format!("❌ Spec folder exists: {}", spec_dir.display()));
    }

    let template_path = Path::new("specs").join("_templates").join("spec.md");
    if !template_path.exists() {
        return Err(format!(
            "Missing template file: {}",
            template_path.display()
        ));
    }

    fs::create_dir_all(spec_dir.join("artifacts"))
        .map_err(|error| format!("Failed to create spec folder: {error}"))?;
    fs::copy(&template_path, spec_dir.join("00-spec.md"))
        .map_err(|error| format!("Failed to copy spec template: {error}"))?;
    fs::write(spec_dir.join("01-plan.md"), "# Plan\n\n")
        .map_err(|error| format!("Failed to create 01-plan.md: {error}"))?;
    fs::write(
        spec_dir.join("02-tasks.md"),
        "# Tasks\n\n## T1\n- Scope:\n- Files:\n- AC:\n- DoD:\n",
    )
    .map_err(|error| format!("Failed to create 02-tasks.md: {error}"))?;
    fs::write(spec_dir.join("03-decisions.md"), "# Decisions\n\n")
        .map_err(|error| format!("Failed to create 03-decisions.md: {error}"))?;
    fs::write(spec_dir.join("04-progress.md"), "# Progress\n\n- [ ] T1\n")
        .map_err(|error| format!("Failed to create 04-progress.md: {error}"))?;

    println!("✅ Created spec folder: {}", spec_dir.display());
    Ok(())
}

fn validate_spec_name(spec_name: &str) -> Result<(), String> {
    if spec_name.trim().is_empty() {
        return Err("Usage: cargo xtask spec-init <SPEC_FOLDER_NAME>".to_string());
    }

    let path = Path::new(spec_name);
    if path.has_root() || path.components().any(|component| matches!(component, Component::ParentDir)) {
        return Err("SPEC_FOLDER_NAME must be a relative path without `..` or root prefixes"
            .to_string());
    }

    Ok(())
}

fn run_spec_verify() -> Result<(), String> {
    let specs_root = Path::new("specs");
    if !specs_root.exists() {
        println!("ℹ️ No specs directory found at 'specs'");
        return Ok(());
    }

    let count = verify_specs_frontmatter(specs_root)?;
    println!("✅ Spec frontmatter verified: {count} file(s)");
    Ok(())
}

fn run_instructions_lint() -> Result<(), String> {
    lint_instructions(Path::new("."))?;
    println!("✅ Agent instructions lint passed");
    Ok(())
}

struct InstructionRequirement {
    path: &'static str,
    required_phrases: &'static [&'static str],
}

fn instruction_requirements() -> [InstructionRequirement; 4] {
    [
        InstructionRequirement {
            path: ".copilot/context.md",
            required_phrases: &[
                "Use `cargo xtask`/aliases for spec/worktree actions",
                "Do not add or use shell wrappers for spec/worktree flows.",
            ],
        },
        InstructionRequirement {
            path: ".copilot/instructions.vscode-ui.md",
            required_phrases: &[
                "Work only from the referenced spec/task.",
                "Use `cargo xtask`/aliases for spec/worktree operations.",
            ],
        },
        InstructionRequirement {
            path: ".copilot/instructions.vscode-bg.md",
            required_phrases: &[
                "Implement only the assigned Task block",
                "Run `cargo xtask spec-verify`",
            ],
        },
        InstructionRequirement {
            path: ".copilot/instructions.cli.md",
            required_phrases: &[
                "Plan first, then patch.",
                "Use `cargo xtask`/aliases for spec and worktree tasks.",
            ],
        },
    ]
}

fn lint_instructions(root: &Path) -> Result<(), String> {
    let mut violations: Vec<String> = Vec::new();

    for requirement in instruction_requirements() {
        let path = root.join(requirement.path);
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) => {
                violations.push(format!("{}: missing/unreadable file ({error})", path.display()));
                continue;
            }
        };

        for phrase in requirement.required_phrases {
            if !content.contains(phrase) {
                violations.push(format!("{}: missing required phrase: {}", path.display(), phrase));
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Instruction lint failed:\n- {}",
            violations.join("\n- ")
        ))
    }
}

fn run_worktree_list() -> Result<(), String> {
    run("git", &["worktree", "list"])
}

fn run_worktree_create(branch: &str, dir: &str) -> Result<(), String> {
    run("git", &["worktree", "add", "-b", branch, dir])
}

fn run_worktree_remove(dir: &str) -> Result<(), String> {
    run("git", &["worktree", "remove", dir])
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
    println!("  verify (default): run fmt + clippy + instructions-lint + test + build");
    println!("  fmt|clippy|test|build");
    println!("  spec-init <SPEC_FOLDER_NAME>");
    println!("  spec-verify");
    println!("  instructions-lint");
    println!("  wt-list");
    println!("  wt-create <branch> <dir>");
    println!("  wt-remove <dir>");
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpecFrontmatter {
    id: String,
    title: String,
    status: String,
    owners: Vec<String>,
    mode: Vec<String>,
    scope: Option<Scope>,
    acceptance: Vec<AcceptanceItem>,
    verification: Option<Verification>,
    risk: Option<Risk>,
    links: Option<Links>,
}

#[derive(Debug, Deserialize)]
struct Scope {
    #[serde(default)]
    #[allow(dead_code)]
    #[serde(rename = "repoAreas")]
    repo_areas: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    touch: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    avoid: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AcceptanceItem {
    id: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct Verification {
    #[serde(default)]
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Risk {
    level: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Links {
    #[allow(dead_code)]
    issue: Option<String>,
    #[allow(dead_code)]
    pr: Option<String>,
}

fn verify_specs_frontmatter(root_path: &Path) -> Result<usize, String> {
    let mut count = 0usize;

    for entry in WalkDir::new(root_path).into_iter() {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();

        if entry.file_type().is_file() && is_spec_markdown(path) {
            let markdown = fs::read_to_string(path)
                .map_err(|error| format!("Failed reading {}: {error}", path.display()))?;
            let (yaml, _) = extract_frontmatter(&markdown)
                .map_err(|error| format!("{}: frontmatter parse error: {error}", path.display()))?;
            let frontmatter: SpecFrontmatter = serde_yaml::from_str(yaml)
                .map_err(|error| format!("{}: invalid YAML frontmatter: {error}", path.display()))?;

            let _ = &frontmatter.scope;
            let _ = &frontmatter.links;
            validate_frontmatter(&frontmatter, path)?;
            count += 1;
        }
    }

    Ok(count)
}

fn is_spec_markdown(path: &Path) -> bool {
    path.extension().map(|ext| ext == "md").unwrap_or(false)
        && !path
            .components()
            .any(|component| component.as_os_str() == "_templates")
}

fn extract_frontmatter(markdown: &str) -> Result<(&str, &str), String> {
    let content = markdown.strip_prefix('\u{feff}').unwrap_or(markdown);
    if !content.starts_with("---\n") {
        return Err("Missing frontmatter: file must start with '---'".to_string());
    }

    let end = content[4..]
        .find("\n---\n")
        .ok_or_else(|| "Unterminated frontmatter: missing closing '---'".to_string())?;
    let yaml = &content[4..4 + end];
    let body = &content[4 + end + "\n---\n".len()..];

    Ok((yaml, body))
}

fn validate_frontmatter(frontmatter: &SpecFrontmatter, file: &Path) -> Result<(), String> {
    let file_name = file.display().to_string();

    if frontmatter.id.trim().len() < 4 {
        return Err(format!("{file_name}: invalid id"));
    }
    if frontmatter.title.trim().is_empty() {
        return Err(format!("{file_name}: invalid title"));
    }

    let allowed_status = ["draft", "active", "done", "archived"];
    if !allowed_status.contains(&frontmatter.status.as_str()) {
        return Err(format!(
            "{file_name}: status must be one of draft|active|done|archived"
        ));
    }

    if frontmatter.owners.is_empty()
        || frontmatter
            .owners
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(format!(
            "{file_name}: owners must be a non-empty list of strings"
        ));
    }

    let allowed_mode = ["vscode-ui", "vscode-bg", "cli"];
    if frontmatter.mode.is_empty()
        || frontmatter
            .mode
            .iter()
            .any(|item| !allowed_mode.contains(&item.as_str()))
    {
        return Err(format!(
            "{file_name}: mode must contain only vscode-ui|vscode-bg|cli"
        ));
    }

    if frontmatter.acceptance.is_empty() {
        return Err(format!("{file_name}: acceptance must be a non-empty list"));
    }

    let acceptance_id = Regex::new(r"(?i)^AC\d+$")
        .map_err(|error| format!("Invalid acceptance id regex: {error}"))?;
    for item in &frontmatter.acceptance {
        if !acceptance_id.is_match(item.id.trim()) {
            return Err(format!(
                "{file_name}: acceptance.id must look like AC1, AC2, ... (got '{}')",
                item.id
            ));
        }
        if item.text.trim().is_empty() {
            return Err(format!(
                "{file_name}: acceptance.text must be non-empty (id '{}')",
                item.id
            ));
        }
    }

    if let Some(risk) = &frontmatter.risk
        && let Some(level) = &risk.level
    {
        let allowed = ["low", "medium", "high"];
        if !allowed.contains(&level.as_str()) {
            return Err(format!("{file_name}: risk.level must be low|medium|high"));
        }
    }

    if let Some(verification) = &frontmatter.verification {
        for command in &verification.commands {
            if command.trim().is_empty() {
                return Err(format!(
                    "{file_name}: verification.commands contains an empty command"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{lint_instructions, validate_spec_name, Task};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn from_args_defaults_to_verify() {
        let parsed = Task::from_args(&[]);
        assert!(matches!(parsed, Task::Verify));
    }

    #[test]
    fn from_args_parses_spec_init() {
        let parsed = Task::from_args(&args(&["spec-init", "2026-03-01-feature-x"]));
        assert!(matches!(
            parsed,
            Task::SpecInit { spec_name } if spec_name == "2026-03-01-feature-x"
        ));
    }

    #[test]
    fn from_args_parses_worktree_create() {
        let parsed = Task::from_args(&args(&["wt-create", "feature/branch", "../wt-feature"]));
        assert!(matches!(
            parsed,
            Task::WtCreate { branch, dir }
                if branch == "feature/branch" && dir == "../wt-feature"
        ));
    }

    #[test]
    fn from_args_missing_required_args_returns_help() {
        let parsed_spec_init = Task::from_args(&args(&["spec-init"]));
        assert!(matches!(parsed_spec_init, Task::Help));

        let parsed_wt_create = Task::from_args(&args(&["wt-create", "feature/branch"]));
        assert!(matches!(parsed_wt_create, Task::Help));

        let parsed_wt_remove = Task::from_args(&args(&["wt-remove"]));
        assert!(matches!(parsed_wt_remove, Task::Help));
    }

    #[test]
    fn from_args_unknown_task_is_marked_unknown() {
        let parsed = Task::from_args(&args(&["nope"]));
        assert!(matches!(parsed, Task::Unknown { task } if task == "nope"));
    }

    #[test]
    fn from_args_parses_instructions_lint() {
        let parsed = Task::from_args(&args(&["instructions-lint"]));
        assert!(matches!(parsed, Task::InstructionsLint));
    }

    #[test]
    fn validate_spec_name_allows_relative_names() {
        assert!(validate_spec_name("2026-03-01-feature-x").is_ok());
        assert!(validate_spec_name("features/2026-03-01-feature-x").is_ok());
    }

    #[test]
    fn validate_spec_name_rejects_empty_or_traversal_or_rooted() {
        assert!(validate_spec_name("").is_err());
        assert!(validate_spec_name("   ").is_err());
        assert!(validate_spec_name("../feature").is_err());
        assert!(validate_spec_name("feature/../x").is_err());
        assert!(validate_spec_name("/absolute/path").is_err());
    }

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("xtask-{name}-{nanos}"))
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directory should be creatable");
        }
        fs::write(path, content).expect("file should be writable");
    }

    #[test]
    fn lint_instructions_passes_for_valid_files() {
        let root = unique_temp_dir("instructions-lint-pass");

        write_file(
            &root.join(".copilot/context.md"),
            "Use `cargo xtask`/aliases for spec/worktree actions\nDo not add or use shell wrappers for spec/worktree flows.\n",
        );
        write_file(
            &root.join(".copilot/instructions.vscode-ui.md"),
            "Work only from the referenced spec/task.\nUse `cargo xtask`/aliases for spec/worktree operations.\n",
        );
        write_file(
            &root.join(".copilot/instructions.vscode-bg.md"),
            "Implement only the assigned Task block\nRun `cargo xtask spec-verify`\n",
        );
        write_file(
            &root.join(".copilot/instructions.cli.md"),
            "Plan first, then patch.\nUse `cargo xtask`/aliases for spec and worktree tasks.\n",
        );

        let result = lint_instructions(&root);
        fs::remove_dir_all(&root).expect("temp directory should be removable");
        assert!(result.is_ok());
    }

    #[test]
    fn lint_instructions_fails_when_required_phrase_missing() {
        let root = unique_temp_dir("instructions-lint-fail");

        write_file(
            &root.join(".copilot/context.md"),
            "Use `cargo xtask`/aliases for spec/worktree actions\n",
        );

        let result = lint_instructions(&root);
        fs::remove_dir_all(&root).expect("temp directory should be removable");
        assert!(result.is_err());
    }
}