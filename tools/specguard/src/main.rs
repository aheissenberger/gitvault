use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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

fn extract_frontmatter(markdown: &str) -> Result<(&str, &str)> {
    let content = markdown.strip_prefix('\u{feff}').unwrap_or(markdown);
    if !content.starts_with("---\n") {
        bail!("Missing frontmatter: file must start with '---'");
    }

    let end = content[4..]
        .find("\n---\n")
        .ok_or_else(|| anyhow!("Unterminated frontmatter: missing closing '---'"))?;
    let yaml = &content[4..4 + end];
    let body = &content[4 + end + "\n---\n".len()..];
    Ok((yaml, body))
}

fn validate(frontmatter: &SpecFrontmatter, file: &Path) -> Result<()> {
    let file_name = file.display().to_string();

    if frontmatter.id.trim().len() < 4 {
        bail!("{file_name}: invalid id");
    }
    if frontmatter.title.trim().is_empty() {
        bail!("{file_name}: invalid title");
    }

    let allowed_status = ["draft", "active", "done", "archived"];
    if !allowed_status.contains(&frontmatter.status.as_str()) {
        bail!("{file_name}: status must be one of draft|active|done|archived");
    }

    if frontmatter.owners.is_empty() || frontmatter.owners.iter().any(|item| item.trim().is_empty()) {
        bail!("{file_name}: owners must be a non-empty list of strings");
    }

    let allowed_mode = ["vscode-ui", "vscode-bg", "cli"];
    if frontmatter.mode.is_empty()
        || frontmatter
            .mode
            .iter()
            .any(|item| !allowed_mode.contains(&item.as_str()))
    {
        bail!("{file_name}: mode must contain only vscode-ui|vscode-bg|cli");
    }

    if frontmatter.acceptance.is_empty() {
        bail!("{file_name}: acceptance must be a non-empty list");
    }

    let acceptance_id = Regex::new(r"(?i)^AC\d+$").expect("valid regex");
    for item in &frontmatter.acceptance {
        if !acceptance_id.is_match(item.id.trim()) {
            bail!(
                "{file_name}: acceptance.id must look like AC1, AC2, ... (got '{}')",
                item.id
            );
        }
        if item.text.trim().is_empty() {
            bail!(
                "{file_name}: acceptance.text must be non-empty (id '{}')",
                item.id
            );
        }
    }

    if let Some(risk) = &frontmatter.risk
        && let Some(level) = &risk.level
    {
        let allowed = ["low", "medium", "high"];
        if !allowed.contains(&level.as_str()) {
            bail!("{file_name}: risk.level must be low|medium|high");
        }
    }

    if let Some(verification) = &frontmatter.verification {
        for command in &verification.commands {
            if command.trim().is_empty() {
                bail!("{file_name}: verification.commands contains an empty command");
            }
        }
    }

    Ok(())
}

fn is_spec_markdown(path: &Path) -> bool {
    path.extension().map(|ext| ext == "md").unwrap_or(false)
        && !path.components().any(|component| component.as_os_str() == "_templates")
}

fn main() -> Result<()> {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "specs".to_string());
    let root_path = PathBuf::from(&root);

    if !root_path.exists() {
        println!("ℹ️ No specs directory found at '{root}'");
        return Ok(());
    }

    let mut count = 0usize;
    for entry in WalkDir::new(&root_path).into_iter().filter_map(|entry| entry.ok()) {
        let path = entry.path();
        if entry.file_type().is_file() && is_spec_markdown(path) {
            let markdown = fs::read_to_string(path)
                .with_context(|| format!("Failed reading {}", path.display()))?;
            let (yaml, _) = extract_frontmatter(&markdown)
                .with_context(|| format!("{}: frontmatter parse error", path.display()))?;
            let frontmatter: SpecFrontmatter = serde_yaml::from_str(yaml)
                .with_context(|| format!("{}: invalid YAML frontmatter", path.display()))?;
            let _ = &frontmatter.scope;
            let _ = &frontmatter.links;
            validate(&frontmatter, path)?;
            count += 1;
        }
    }

    println!("✅ Spec frontmatter verified: {count} file(s)");
    Ok(())
}