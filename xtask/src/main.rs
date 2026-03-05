use age::secrecy::ExposeSecret;
use cargo_metadata::MetadataCommand;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

use regex::Regex;
use serde::{Deserialize, Serialize};
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
    ReleaseCheck,
    Verify,
    SpecInit { spec_name: String },
    SpecVerify,
    InstructionsLint,
    AiIndex,
    CliHelp,
    WtList,
    WtCreate { branch: String, dir: String },
    WtRemove { dir: String },
    DevShell,
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
            "release-check" => Self::ReleaseCheck,
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
            "ai-index" => Self::AiIndex,
            "cli-help" => Self::CliHelp,
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
            "dev-shell" => Self::DevShell,
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
            Self::ReleaseCheck => run_release_check(),
            Self::Verify => run_verify(),
            Self::SpecInit { spec_name } => run_spec_init(&spec_name),
            Self::SpecVerify => run_spec_verify(),
            Self::InstructionsLint => run_instructions_lint(),
            Self::AiIndex => run_ai_index(),
            Self::CliHelp => run_cli_help(),
            Self::WtList => run_worktree_list(),
            Self::WtCreate { branch, dir } => run_worktree_create(&branch, &dir),
            Self::WtRemove { dir } => run_worktree_remove(&dir),
            Self::DevShell => run_dev_shell(),
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
    run(
        "cargo",
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    Task::InstructionsLint.run()?;
    run(
        "cargo",
        &[
            "test",
            "--locked",
            "--workspace",
            "--all-features",
            "--quiet",
        ],
    )?;
    run("cargo", &["build", "--locked", "--workspace", "--release"])?;
    Ok(())
}

fn run_release_check() -> Result<(), String> {
    let version = read_package_version(Path::new("Cargo.toml"))?;
    let expected_tag = format!("v{version}");

    let current_tag = match run_output("git", &["describe", "--tags", "--exact-match"]) {
        Ok(tag) => tag,
        Err(error) if error.contains("no tag exactly matches") => {
            return Err(format!(
                "Release check failed: HEAD is not on a tag. Create annotated tag '{expected_tag}' and rerun."
            ));
        }
        Err(error) => return Err(error),
    };
    if current_tag != expected_tag {
        return Err(format!(
            "Release check failed: current HEAD tag is '{current_tag}', expected '{expected_tag}' from Cargo.toml version {version}"
        ));
    }

    let status = run_output("git", &["status", "--porcelain"])?;
    if !status.is_empty() {
        return Err("Release check failed: working tree is dirty".to_string());
    }

    let object_type = run_output(
        "git",
        &[
            "for-each-ref",
            &format!("refs/tags/{current_tag}"),
            "--format=%(objecttype)",
        ],
    )?;
    if object_type != "tag" {
        return Err(format!(
            "Release check failed: tag '{current_tag}' is lightweight; annotated tag required"
        ));
    }

    println!(
        "✅ Release check passed: Cargo version {version} matches tag {current_tag}, tree clean, tag annotated"
    );
    Ok(())
}

fn read_package_version(path: &Path) -> Result<String, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;

    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|error| format!("Failed to parse {} as TOML: {error}", path.display()))?;

    parsed
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("Failed to locate [package].version in {}", path.display()))
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiCodeIndex {
    package_name: String,
    package_version: String,
    files_scanned: usize,
    entries: Vec<AiCodeIndexEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiCodeIndexEntry {
    path: String,
    public_functions: Vec<String>,
    public_types: Vec<String>,
    public_constants: Vec<String>,
}

/// Structured output of all CLI command help texts, for AI agent consumption.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CliHelpOutput {
    binary: String,
    version: String,
    /// Guidance note for AI agents reading this file.
    note: String,
    /// All commands (top-level and sub-commands), each with its full `--help` text.
    commands: Vec<CliCommand>,
}

/// One entry per CLI path (e.g. `["gitvault", "recipient", "add"]`).
#[derive(Debug, Serialize)]
struct CliCommand {
    /// Full command path starting with the binary name.
    path: Vec<String>,
    /// Raw `--help` output for this command path.
    help: String,
}

/// Builds the gitvault binary, then walks every command/sub-command collecting
/// `--help` output and writes the result to `docs/ai/cli-help.json`.
fn run_cli_help() -> Result<(), String> {
    run("cargo", &["build", "--bin", "gitvault"])?;
    let bin = find_gitvault_bin()?;

    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| format!("Failed to read cargo metadata: {e}"))?;
    let root = Path::new(metadata.workspace_root.as_str()).to_path_buf();
    let package = metadata
        .root_package()
        .ok_or_else(|| "Unable to resolve root package".to_string())?;

    let mut commands: Vec<CliCommand> = Vec::new();
    let root_path = vec!["gitvault".to_string()];
    collect_commands(&bin, &root_path, &mut commands)?;

    let output = CliHelpOutput {
        binary: "gitvault".to_string(),
        version: package.version.to_string(),
        note: "Generated by `cargo xtask cli-help`. \
               Read this file to understand all CLI commands before updating README.md or writing documentation."
            .to_string(),
        commands,
    };

    let out_dir = root.join("docs").join("ai");
    fs::create_dir_all(&out_dir)
        .map_err(|e| format!("Failed to create {}: {e}", out_dir.display()))?;
    let out_path = out_dir.join("cli-help.json");
    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| format!("Failed to serialize CLI help output: {e}"))?;
    fs::write(&out_path, format!("{json}\n"))
        .map_err(|e| format!("Failed writing {}: {e}", out_path.display()))?;

    println!("✅ Wrote CLI help index: {}", out_path.display());
    println!("   commands captured: {}", output.commands.len());
    Ok(())
}

/// Recursively captures `--help` for `path` and all its sub-commands.
fn collect_commands(bin: &Path, path: &[String], out: &mut Vec<CliCommand>) -> Result<(), String> {
    // Build args: everything after "gitvault" plus "--help"
    let mut args: Vec<&str> = path[1..].iter().map(String::as_str).collect();
    args.push("--help");

    let result = Command::new(bin)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to run {} {}: {e}", bin.display(), args.join(" ")))?;

    let help = String::from_utf8_lossy(&result.stdout).into_owned();
    let subcommands = parse_subcommand_names(&help);

    out.push(CliCommand {
        path: path.to_vec(),
        help,
    });

    for sub in subcommands {
        let mut sub_path = path.to_vec();
        sub_path.push(sub);
        collect_commands(bin, &sub_path, out)?;
    }
    Ok(())
}

/// Extracts sub-command names from a `--help` output block that contains a `Commands:` section.
fn parse_subcommand_names(help: &str) -> Vec<String> {
    let mut in_commands = false;
    let mut subs = Vec::new();
    for line in help.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands {
            if line.is_empty() {
                continue;
            }
            // Any non-indented line marks the start of the next section.
            if !line.starts_with(' ') {
                break;
            }
            // Sub-command lines look like "  name    description"
            if let Some(name) = line.split_whitespace().next() {
                if name != "help" {
                    subs.push(name.to_string());
                }
            }
        }
    }
    subs
}

fn run_ai_index() -> Result<(), String> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|error| format!("Failed to read cargo metadata: {error}"))?;

    let root = Path::new(metadata.workspace_root.as_str());
    let src_root = root.join("src");
    if !src_root.exists() {
        return Err(format!("Missing source directory: {}", src_root.display()));
    }

    let package = metadata
        .root_package()
        .ok_or_else(|| "Unable to resolve root package from metadata".to_string())?;

    let fn_regex = Regex::new(
        r"^\s*pub(?:\([^\)]*\))?\s+(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    .map_err(|error| format!("Failed to compile public fn regex: {error}"))?;
    let type_regex = Regex::new(
        r"^\s*pub(?:\([^\)]*\))?\s+(?:struct|enum|trait|type)\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    .map_err(|error| format!("Failed to compile public type regex: {error}"))?;
    let const_regex = Regex::new(
        r"^\s*pub(?:\([^\)]*\))?\s+(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    .map_err(|error| format!("Failed to compile public const regex: {error}"))?;

    let mut entries: Vec<AiCodeIndexEntry> = Vec::new();

    for entry in WalkDir::new(&src_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let content = fs::read_to_string(path)
            .map_err(|error| format!("Failed reading {}: {error}", path.display()))?;

        let mut public_functions: Vec<String> = Vec::new();
        let mut public_types: Vec<String> = Vec::new();
        let mut public_constants: Vec<String> = Vec::new();

        for line in content.lines() {
            if let Some(captures) = fn_regex.captures(line)
                && let Some(name) = captures.get(1)
            {
                public_functions.push(name.as_str().to_string());
                continue;
            }

            if let Some(captures) = type_regex.captures(line)
                && let Some(name) = captures.get(1)
            {
                public_types.push(name.as_str().to_string());
                continue;
            }

            if let Some(captures) = const_regex.captures(line)
                && let Some(name) = captures.get(1)
            {
                public_constants.push(name.as_str().to_string());
            }
        }

        public_functions.sort();
        public_functions.dedup();
        public_types.sort();
        public_types.dedup();
        public_constants.sort();
        public_constants.dedup();

        let rel_path = path
            .strip_prefix(root)
            .map_err(|error| format!("Failed to relativize {}: {error}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");

        entries.push(AiCodeIndexEntry {
            path: rel_path,
            public_functions,
            public_types,
            public_constants,
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let index = AiCodeIndex {
        package_name: package.name.to_string(),
        package_version: package.version.to_string(),
        files_scanned: entries.len(),
        entries,
    };

    let out_dir = root.join("docs").join("ai");
    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("Failed to create {}: {error}", out_dir.display()))?;
    let out_path = out_dir.join("code-index.json");
    let json = serde_json::to_string_pretty(&index)
        .map_err(|error| format!("Failed to serialize AI code index: {error}"))?;
    fs::write(&out_path, format!("{json}\n"))
        .map_err(|error| format!("Failed writing {}: {error}", out_path.display()))?;

    println!("✅ Wrote AI code index: {}", out_path.display());
    println!("   files scanned: {}", index.files_scanned);
    Ok(())
}

struct InstructionRequirement {
    path: &'static str,
    required_phrases: &'static [&'static str],
}

fn instruction_requirements() -> [InstructionRequirement; 4] {
    const VERIFY_RULE: &str = "Always run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.";
    const CLI_HELP_RULE: &str =
        "Run `cargo xtask cli-help` to regenerate `docs/ai/cli-help.json` before updating README.md.";
    const CLI_WORKTREE_ISOLATION_RULE: &str =
        "Never start parallel file-changing AI agent sessions in the primary worktree; create a dedicated git worktree per agent first.";

    [
        InstructionRequirement {
            path: ".copilot/context.md",
            required_phrases: &[
                "Use `cargo xtask`/aliases for spec/worktree actions",
                "Do not add or use shell wrappers for spec/worktree flows.",
                CLI_HELP_RULE,
                VERIFY_RULE,
            ],
        },
        InstructionRequirement {
            path: ".copilot/instructions.vscode-ui.md",
            required_phrases: &[
                "Work only from the referenced spec/task.",
                "Use `cargo xtask`/aliases for spec/worktree operations.",
                VERIFY_RULE,
            ],
        },
        InstructionRequirement {
            path: ".copilot/instructions.vscode-bg.md",
            required_phrases: &[
                "Implement only the assigned Task block",
                "Run `cargo xtask spec-verify`",
                CLI_WORKTREE_ISOLATION_RULE,
                VERIFY_RULE,
            ],
        },
        InstructionRequirement {
            path: ".copilot/instructions.cli.md",
            required_phrases: &[
                "Plan first, then patch.",
                "Use `cargo xtask`/aliases for spec and worktree tasks.",
                CLI_WORKTREE_ISOLATION_RULE,
                VERIFY_RULE,
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

fn run_dev_shell() -> Result<(), String> {
    // Step 1: build the gitvault binary
    println!("🔨 Building gitvault (debug)...");
    run("cargo", &["build", "--bin", "gitvault"])?;

    let bin = find_gitvault_bin()?;
    println!("✅ Binary: {}", bin.display());

    // Step 2: create temp sandbox directory
    let sandbox = std::env::temp_dir().join(format!(
        "gitvault-sandbox-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    fs::create_dir_all(&sandbox)
        .map_err(|e| format!("Failed to create sandbox dir: {e}"))?;
    println!("📁 Sandbox: {}", sandbox.display());

    // Step 3: create workspace-root symlink for VS Code access
    let workspace_root = find_workspace_root()?;
    let symlink_path = workspace_root.join("dev-shell-folder");
    let git_symlink_path = workspace_root.join("dev-shell-folder-git");
    #[cfg(unix)]
    {
        // Remove any stale symlink from a previous run
        let _ = fs::remove_file(&symlink_path);
        let _ = fs::remove_file(&git_symlink_path);
        std::os::unix::fs::symlink(&sandbox, &symlink_path)
            .map_err(|e| format!("Failed to create dev-shell-folder symlink: {e}"))?;
        println!("🔗 Symlink: {} → {}", symlink_path.display(), sandbox.display());
    }

    let result = setup_and_run_shell(&sandbox, &bin, &git_symlink_path);

    // Step 4: always clean up, regardless of shell exit code
    println!("\n🧹 Removing sandbox {}...", sandbox.display());
    if let Err(e) = fs::remove_dir_all(&sandbox) {
        eprintln!("  Warning: sandbox cleanup failed: {e}");
    }
    // Remove workspace symlink
    if symlink_path.exists() || symlink_path.read_link().is_ok() {
        if let Err(e) = fs::remove_file(&symlink_path) {
            eprintln!("  Warning: symlink cleanup failed: {e}");
        }
    }
    if git_symlink_path.exists() || git_symlink_path.read_link().is_ok() {
        if let Err(e) = fs::remove_file(&git_symlink_path) {
            eprintln!("  Warning: git symlink cleanup failed: {e}");
        }
    }
    println!("✅ Done.");

    result
}

/// Find the cargo workspace root via cargo metadata.
fn find_workspace_root() -> Result<PathBuf, String> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| format!("Failed to read cargo metadata: {e}"))?;
    Ok(metadata.workspace_root.into_std_path_buf())
}

/// Set up the `client/` + `server.git/` sandbox topology and launch the interactive shell.
fn setup_and_run_shell(sandbox: &Path, bin: &Path, git_symlink_path: &Path) -> Result<(), String> {
    let server_git = sandbox.join("server.git");
    let client = sandbox.join("client");

    // Create server.git (bare) and client git repos
    fs::create_dir_all(&server_git)
        .map_err(|e| format!("Failed to create server.git dir: {e}"))?;
    fs::create_dir_all(&client)
        .map_err(|e| format!("Failed to create client dir: {e}"))?;

    git_silent(&["init", "--bare"], &server_git)?;
    git_silent(&["init", "-b", "main"], &client)?;
    git_silent(&["config", "user.email", "dev@gitvault.local"], &client)?;
    git_silent(&["config", "user.name", "gitvault-dev"], &client)?;
    git_silent(&["remote", "add", "origin", "../server.git"], &client)?;

    // Generate an age X25519 identity for use in the sandbox
    let identity = age::x25519::Identity::generate();
    let privkey = identity.to_string(); // Secret<String>
    let pubkey = identity.to_public().to_string();

    let key_file = sandbox.join("identity.key");
    fs::write(&key_file, format!("{}\n", privkey.expose_secret()))
        .map_err(|e| format!("Failed to write identity key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_file)
            .map_err(|e| format!("Failed to stat identity.key: {e}"))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_file, perms)
            .map_err(|e| format!("Failed to chmod identity.key: {e}"))?;
    }

    // Write sample files in client/ with secret-like fields
    fs::write(
        client.join(".env"),
        format!(
            "# Sample .env — encrypt with: gitvault encrypt .env --recipient {pubkey}\n\
             DATABASE_URL=postgres://localhost:5432/myapp_dev\n\
             Password=dev-only-change-in-prod\n\
             AccessToken=sample-access-token-abc123\n\
             REDIS_URL=redis://localhost:6379/0\n"
        ),
    )
    .map_err(|e| format!("Failed to write client/.env: {e}"))?;

    let conf_dir = client.join("conf");
    fs::create_dir_all(&conf_dir)
        .map_err(|e| format!("Failed to create conf dir: {e}"))?;

    fs::write(
        conf_dir.join("dbsecrets.json"),
        "{\n  \"host\": \"localhost\",\n  \"port\": 5432,\n  \
         \"user\": \"app\",\n  \"Password\": \"super-secret-db-password\",\n  \
         \"database\": \"myapp_dev\"\n}\n",
    )
    .map_err(|e| format!("Failed to write conf/dbsecrets.json: {e}"))?;

    fs::write(
        conf_dir.join("serverless.yaml"),
        format!(
            "service: myapp\nprovider:\n  name: aws\n  region: us-east-1\n\
             environment:\n  AccessToken: {pubkey}\n  Password: serverless-secret-pw\n"
        ),
    )
    .map_err(|e| format!("Failed to write conf/serverless.yaml: {e}"))?;

    let mail_dir = conf_dir.join("mail");
    fs::create_dir_all(&mail_dir)
        .map_err(|e| format!("Failed to create conf/mail dir: {e}"))?;

    fs::write(
        mail_dir.join("acount.toml"),
        "# Mail account configuration\n\
         [smtp]\n\
         host = \"smtp.example.com\"\n\
         port = 587\n\
         user = \"alerts@example.com\"\n\
         AccessToken = \"mail-access-token-xyz789\"\n",
    )
    .map_err(|e| format!("Failed to write conf/mail/acount.toml: {e}"))?;

    // Write a .gitignore (harden will add more)
    fs::write(client.join(".gitignore"), "")
        .map_err(|e| format!("Failed to write client/.gitignore: {e}"))?;

    // Commit initial sample files and push to server.git to establish main branch
    git_silent(&["add", "."], &client)?;
    git_silent(
        &["commit", "-m", "chore: initial sandbox sample files"],
        &client,
    )?;
    git_silent(&["push", "-u", "origin", "main"], &client)?;

    #[cfg(unix)]
    {
        let client_git_dir = client.join(".git");
        std::os::unix::fs::symlink(&client_git_dir, git_symlink_path)
            .map_err(|e| format!("Failed to create dev-shell-folder-git symlink: {e}"))?;
        println!(
            "🔗 Symlink: {} → {}",
            git_symlink_path.display(),
            client_git_dir.display()
        );
    }

    // Write a shell init script that sources the user's bashrc and prints a welcome banner
    let identity_key_path = key_file.display().to_string();
    let pubkey_display = pubkey.clone();
    let client_display = client.display().to_string();
    let init_script = sandbox.join(".gitvault_shell_init.sh");
    let banner = format!(
        r#"#!/usr/bin/env bash
# Source user's existing interactive config if present
[ -f "$HOME/.bashrc" ] && source "$HOME/.bashrc" 2>/dev/null

# gitvault dev-shell environment
export GITVAULT_IDENTITY="{identity_key_path}"
export GITVAULT_SANDBOX="{sandbox_display}"

cat <<'BANNER'

╔══════════════════════════════════════════════════════╗
║           gitvault  ·  interactive dev sandbox        ║
╚══════════════════════════════════════════════════════╝

  Working dir : client/   (git repo with origin → ../server.git)
  Identity key: {identity_key_path}
  Public key  : {pubkey_display}

  Sample files in client/:
    .env                      — env vars  (Password, AccessToken)
    conf/dbsecrets.json       — JSON secrets (Password)
    conf/serverless.yaml      — YAML config  (AccessToken, Password)
    conf/mail/acount.toml     — TOML config  (AccessToken)

  Quick-start commands:
    gitvault harden
    gitvault encrypt .env --recipient {pubkey_display}
    gitvault status
    gitvault materialize
    gitvault --help

  Type 'exit' or Ctrl-D to leave (sandbox is removed on exit).

BANNER
"#,
        sandbox_display = sandbox.display(),
        identity_key_path = identity_key_path,
        pubkey_display = pubkey_display,
    );

    let mut f = fs::File::create(&init_script)
        .map_err(|e| format!("Failed to create init script: {e}"))?;
    f.write_all(banner.as_bytes())
        .map_err(|e| format!("Failed to write init script: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&init_script)
            .map_err(|e| format!("Failed to stat init script: {e}"))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&init_script, perms)
            .map_err(|e| format!("Failed to chmod init script: {e}"))?;
    }

    // Build PATH with gitvault's directory first
    let bin_dir = bin
        .parent()
        .ok_or("Could not determine binary directory")?
        .to_string_lossy()
        .to_string();
    let path = format!("{bin_dir}:{}", env::var("PATH").unwrap_or_default());

    // Launch the shell in client/ so the user is immediately in the git repo
    let shell = env::var("SHELL").unwrap_or_else(|_| "bash".to_string());
    println!("🚀 Launching shell ({}). Type 'exit' to quit.", shell);

    let status = Command::new(&shell)
        .args(["--rcfile", &init_script.to_string_lossy()])
        .current_dir(&client_display)
        .env("PATH", &path)
        .env("GITVAULT_IDENTITY", &identity_key_path)
        .env("GITVAULT_SANDBOX", sandbox.display().to_string())
        .status()
        .map_err(|e| format!("Failed to launch shell '{shell}': {e}"))?;

    if !status.success() {
        // Non-zero shell exit is normal (user typed `exit 1`), not an error for us.
        eprintln!(
            "Shell exited with status: {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

/// Find the gitvault debug binary by asking cargo for the target directory.
fn find_gitvault_bin() -> Result<PathBuf, String> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| format!("Failed to run cargo metadata: {e}"))?;

    let candidate = metadata
        .target_directory
        .into_std_path_buf()
        .join("debug")
        .join("gitvault");
    if candidate.exists() {
        return Ok(candidate);
    }

    // Fallback: check well-known locations
    for candidate in &[
        PathBuf::from("/workspaces/.cargo-target/debug/gitvault"),
        PathBuf::from("target/debug/gitvault"),
    ] {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err(
        "gitvault binary not found after build. \
         Check that `cargo build --bin gitvault` succeeded."
            .to_string(),
    )
}

/// Run a silent git command in `dir` (suppress stdout; show stderr on failure).
fn git_silent(args: &[&str], dir: &Path) -> Result<(), String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("Failed to run git {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
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

fn run_output(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|error| format!("Failed to run `{cmd}`: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "Command failed: `{cmd} {}`{}",
            args.join(" "),
            if stderr.is_empty() {
                "".to_string()
            } else {
                format!(" ({stderr})")
            }
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn print_help() {
    println!("Usage: cargo xtask <command> [args]");
    println!("  verify (default): run fmt + clippy + instructions-lint + test + build");
    println!("  fmt|clippy|test|build");
    println!("  release-check: validate tag/version parity and release hygiene");
    println!("  spec-init <SPEC_FOLDER_NAME>");
    println!("  spec-verify");
    println!("  instructions-lint");
    println!("  ai-index: generate docs/ai/code-index.json for agent reuse");
    println!("  cli-help: generate docs/ai/cli-help.json with all CLI --help texts (for README updates)");
    println!("  wt-list");
    println!("  wt-create <branch> <dir>");
    println!("  wt-remove <dir>");
    println!("  dev-shell: open an interactive sandbox shell for testing the gitvault CLI");
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
            let (frontmatter, _) = markdown_frontmatter::parse::<SpecFrontmatter>(&markdown)
                .map_err(|error| format!("{}: frontmatter parse error: {error}", path.display()))?;

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
    use super::{lint_instructions, read_package_version, validate_spec_name, Task};
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
    fn from_args_parses_ai_index() {
        let parsed = Task::from_args(&args(&["ai-index"]));
        assert!(matches!(parsed, Task::AiIndex));
    }

    #[test]
    fn from_args_parses_release_check() {
        let parsed = Task::from_args(&args(&["release-check"]));
        assert!(matches!(parsed, Task::ReleaseCheck));
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
            "Use `cargo xtask`/aliases for spec/worktree actions\nDo not add or use shell wrappers for spec/worktree flows.\nRun `cargo xtask cli-help` to regenerate `docs/ai/cli-help.json` before updating README.md.\nAlways run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.\n",
        );
        write_file(
            &root.join(".copilot/instructions.vscode-ui.md"),
            "Work only from the referenced spec/task.\nUse `cargo xtask`/aliases for spec/worktree operations.\nAlways run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.\n",
        );
        write_file(
            &root.join(".copilot/instructions.vscode-bg.md"),
            "Implement only the assigned Task block\nRun `cargo xtask spec-verify`\nNever start parallel file-changing AI agent sessions in the primary worktree; create a dedicated git worktree per agent first.\nAlways run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.\n",
        );
        write_file(
            &root.join(".copilot/instructions.cli.md"),
            "Plan first, then patch.\nUse `cargo xtask`/aliases for spec and worktree tasks.\nNever start parallel file-changing AI agent sessions in the primary worktree; create a dedicated git worktree per agent first.\nAlways run `cargo xtask verify` (or `cargo verify`) before handoff, and fix failures.\n",
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

    #[test]
    fn read_package_version_accepts_standard_toml_spacing() {
        let root = unique_temp_dir("read-package-version");
        let cargo_toml = root.join("Cargo.toml");
        write_file(
            &cargo_toml,
            "[package]\nname = \"gitvault\"\nversion = \"0.2.0\"\nedition = \"2024\"\n",
        );

        let parsed = read_package_version(&cargo_toml);
        fs::remove_dir_all(&root).expect("temp directory should be removable");

        assert!(matches!(parsed, Ok(version) if version == "0.2.0"));
    }
}