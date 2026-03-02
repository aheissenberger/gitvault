use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

use crate::error::GitvaultError;
use crate::permissions;

/// Entries that must be in .gitignore for safety
pub const REQUIRED_GITIGNORE_ENTRIES: &[&str] = &[".env", ".secrets/plain/"];

/// Materialize decrypted secrets to the root-level `.env` file.
///
/// REQ-16: generates root-level .env
/// REQ-17: atomic write (temp file + rename)
/// REQ-18: restricted .env permissions (0600 on Unix; restricted ACL via icacls on Windows)
/// REQ-19: deterministic output (sorted keys, canonical quoting)
/// REQ-20: ensures .env is in .gitignore first
pub fn materialize_env_file(
    repo_root: &Path,
    secrets: &[(String, String)],
) -> Result<(), GitvaultError> {
    // REQ-20: ensure .env is in .gitignore before writing
    ensure_gitignored(repo_root, &[".env", ".secrets/plain/"])?;

    let env_path = repo_root.join(".env");

    // REQ-19: sort keys deterministically
    let mut sorted: Vec<&(String, String)> = secrets.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());

    // REQ-19: canonical KEY="VALUE" format with proper quoting
    let content = format_env_content(&sorted);

    // REQ-17: atomic write using tempfile in same directory
    let mut tmp = NamedTempFile::new_in(repo_root).map_err(GitvaultError::Io)?;

    tmp.write_all(content.as_bytes())
        .map_err(GitvaultError::Io)?;

    // REQ-17: atomically rename to target (persist moves the temp file)
    tmp.persist(&env_path)
        .map_err(|e| GitvaultError::Io(std::io::Error::other(e.to_string())))?;

    // REQ-18: restrict permissions on final .env path
    enforce_restricted_env_permissions(&env_path)?;

    Ok(())
}

fn enforce_restricted_env_permissions(path: &Path) -> Result<(), GitvaultError> {
    permissions::enforce_owner_rw(path, ".env")
}

/// Format key=value pairs as canonical .env content.
/// REQ-19: sorted keys, KEY="VALUE" quoting where values are double-quoted
/// and internal double quotes and backslashes are escaped.
/// REQ-35: sorted keys minimize diff noise
fn format_env_content(pairs: &[&(String, String)]) -> String {
    let mut lines: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, escape_env_value(v)))
        .collect();
    lines.push(String::new()); // trailing newline
    lines.join("\n")
}

/// Escape a value for use in a double-quoted .env value.
/// Escapes: backslashes, double quotes, $ (to prevent variable expansion),
/// and newline/carriage-return characters.
fn escape_env_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '$' => result.push_str("\\$"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            _ => result.push(ch),
        }
    }
    result
}

/// Ensure the given entries exist in `.gitignore`. REQ-9, REQ-20
pub fn ensure_gitignored(repo_root: &Path, entries: &[&str]) -> Result<(), GitvaultError> {
    let gitignore_path = repo_root.join(".gitignore");

    let existing = if gitignore_path.exists() {
        fs::read_to_string(&gitignore_path)?
    } else {
        String::new()
    };

    if let Some(content) = merge_gitignore_entries(&existing, entries) {
        let mut tmp = NamedTempFile::new_in(repo_root).map_err(GitvaultError::Io)?;
        tmp.write_all(content.as_bytes())
            .map_err(GitvaultError::Io)?;
        tmp.persist(&gitignore_path)
            .map_err(|e| GitvaultError::Io(std::io::Error::other(e.to_string())))?;
    }

    Ok(())
}

fn merge_gitignore_entries(existing: &str, entries: &[&str]) -> Option<String> {
    let mut content = existing.to_string();
    let mut changed = false;

    for entry in entries {
        let already_present = existing.lines().any(|line| line.trim() == *entry);
        if !already_present {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(entry);
            content.push('\n');
            changed = true;
        }
    }

    if changed { Some(content) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn make_secrets(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_materialize_creates_env_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[
            ("DB_URL", "postgres://localhost/db"),
            ("API_KEY", "secret123"),
        ]);
        materialize_env_file(dir.path(), &secrets).unwrap();

        assert!(dir.path().join(".env").exists(), ".env should be created");
    }

    #[test]
    fn test_materialize_sorted_keys() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[("ZEBRA", "z"), ("ALPHA", "a"), ("MIDDLE", "m")]);
        materialize_env_file(dir.path(), &secrets).unwrap();

        let content = fs::read_to_string(dir.path().join(".env")).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();

        assert_eq!(lines[0], "ALPHA=\"a\"");
        assert_eq!(lines[1], "MIDDLE=\"m\"");
        assert_eq!(lines[2], "ZEBRA=\"z\"");
    }

    #[test]
    fn test_materialize_deterministic() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[("KEY_B", "value_b"), ("KEY_A", "value_a")]);

        materialize_env_file(dir.path(), &secrets).unwrap();
        let content1 = fs::read_to_string(dir.path().join(".env")).unwrap();

        materialize_env_file(dir.path(), &secrets).unwrap();
        let content2 = fs::read_to_string(dir.path().join(".env")).unwrap();

        assert_eq!(
            content1, content2,
            "repeated materialization should be identical"
        );
    }

    #[test]
    fn test_materialize_canonical_quoting() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[("KEY", "value with \"quotes\" and \\backslash")]);
        materialize_env_file(dir.path(), &secrets).unwrap();

        let content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(content.contains("KEY=\"value with \\\"quotes\\\" and \\\\backslash\""));
    }

    #[test]
    #[cfg(unix)]
    fn test_materialize_permissions_0600() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[("SECRET", "value")]);
        materialize_env_file(dir.path(), &secrets).unwrap();

        let meta = fs::metadata(dir.path().join(".env")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            ".env should have 0600 permissions, got {:o}",
            mode
        );
    }

    #[test]
    fn test_ensure_gitignored_adds_entries() {
        let dir = TempDir::new().unwrap();

        ensure_gitignored(dir.path(), &[".env", ".secrets/plain/"]).unwrap();

        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".env"), ".gitignore should contain .env");
        assert!(
            content.contains(".secrets/plain/"),
            ".gitignore should contain .secrets/plain/"
        );
    }

    #[test]
    fn test_ensure_gitignored_idempotent() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\n.secrets/plain/\n").unwrap();

        ensure_gitignored(dir.path(), &[".env", ".secrets/plain/"]).unwrap();

        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(
            content.matches(".env").count(),
            1,
            ".env should appear exactly once"
        );
    }

    #[test]
    fn test_ensure_gitignored_creates_file_if_missing() {
        let dir = TempDir::new().unwrap();

        ensure_gitignored(dir.path(), &[".env"]).unwrap();

        assert!(dir.path().join(".gitignore").exists());
        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".env"));
    }

    #[test]
    fn test_merge_gitignore_entries_adds_newline_before_append() {
        let merged = merge_gitignore_entries("target", &[".env"]).unwrap();
        assert_eq!(merged, "target\n.env\n");
    }

    #[test]
    fn test_merge_gitignore_entries_returns_none_when_unchanged() {
        let merged = merge_gitignore_entries(".env\n", &[".env"]);
        assert!(merged.is_none());
    }

    #[test]
    fn test_escape_env_value_escapes_control_and_dollar() {
        let escaped = escape_env_value("a$b\nc\rd");
        assert_eq!(escaped, "a\\$b\\nc\\rd");
    }
}
