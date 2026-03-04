use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

use crate::defaults;
use crate::error::GitvaultError;
use crate::permissions;

/// Entries that must be in .gitignore for safety
pub const REQUIRED_GITIGNORE_ENTRIES: &[&str] = &[defaults::MATERIALIZE_OUTPUT];

/// Materialize decrypted secrets to an output file (default: `.env`).
///
/// REQ-16: generates root-level .env
/// REQ-17: atomic write (temp file + rename)
/// REQ-18: restricted .env permissions (0600 on Unix; restricted ACL via icacls on Windows)
/// REQ-19: deterministic output (sorted keys, canonical quoting)
/// REQ-20: ensures output file is in .gitignore first
///
/// `output_filename` is the repository-relative path to write, e.g. `".env"`.
/// Use [`defaults::MATERIALIZE_OUTPUT`] or `cfg.paths.materialize_output()` as the value.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if writing the temp file or atomic rename fails,
/// or if `.gitignore` cannot be read or updated.
pub fn materialize_env_file(
    repo_root: &Path,
    secrets: &[(String, String)],
    output_filename: &str,
) -> Result<(), GitvaultError> {
    // REQ-20: ensure output file is in .gitignore before writing
    ensure_gitignored(repo_root, &[output_filename])?;

    let env_path = repo_root.join(output_filename);

    // REQ-19: sort keys deterministically
    let mut sorted: Vec<&(String, String)> = secrets.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());

    // REQ-19: canonical KEY="VALUE" format with proper quoting
    let content = format_env_content(&sorted);

    // REQ-17: atomic write using tempfile in same directory
    let mut tmp = NamedTempFile::new_in(repo_root).map_err(GitvaultError::Io)?;

    tmp.write_all(content.as_bytes())
        .map_err(GitvaultError::Io)?;

    // REQ-18: restrict permissions BEFORE persist so the rename carries the ACL.
    // This eliminates the TOCTOU window on Windows where icacls would otherwise
    // run after the file is already world-accessible at its final path.
    enforce_restricted_env_permissions(tmp.path())?;

    // REQ-17: atomically rename to target (persist moves the temp file)
    tmp.persist(&env_path)
        .map_err(|e| GitvaultError::Io(e.error))?;

    Ok(())
}

fn enforce_restricted_env_permissions(path: &Path) -> Result<(), GitvaultError> {
    permissions::enforce_owner_rw(path, defaults::MATERIALIZE_OUTPUT)
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

/// The merge driver attribute line that `harden` registers. REQ-34
pub const GITATTRIBUTES_MERGE_DRIVER_ENTRY: &str = "*.env merge=gitvault-env";

/// Ensure the `.gitattributes` file at `repo_root` contains the given lines. REQ-34
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading or writing `.gitattributes` fails.
pub fn ensure_gitattributes(repo_root: &Path, entries: &[&str]) -> Result<(), GitvaultError> {
    let gitattributes_path = repo_root.join(".gitattributes");

    let existing = if gitattributes_path.exists() {
        fs::read_to_string(&gitattributes_path)?
    } else {
        String::new()
    };

    if let Some(content) = merge_gitattributes_entries(&existing, entries) {
        let mut tmp = NamedTempFile::new_in(repo_root).map_err(GitvaultError::Io)?;
        tmp.write_all(content.as_bytes())
            .map_err(GitvaultError::Io)?;
        tmp.persist(&gitattributes_path)
            .map_err(|e| GitvaultError::Io(e.error))?;
    }

    Ok(())
}

fn merge_gitattributes_entries(existing: &str, entries: &[&str]) -> Option<String> {
    merge_file_entries(existing, entries)
}

/// Ensure the given entries exist in `.gitignore`. REQ-9, REQ-20
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if reading or writing `.gitignore` fails.
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
            .map_err(|e| GitvaultError::Io(e.error))?;
    }

    Ok(())
}

fn merge_gitignore_entries(existing: &str, entries: &[&str]) -> Option<String> {
    merge_file_entries(existing, entries)
}

/// Append any missing `entries` to `existing` content, preserving existing lines.
///
/// Returns `Some(new_content)` if anything was added, or `None` if all entries
/// were already present (so callers can skip writing when nothing changed).
fn merge_file_entries(existing: &str, entries: &[&str]) -> Option<String> {
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
        materialize_env_file(dir.path(), &secrets, defaults::MATERIALIZE_OUTPUT).unwrap();

        assert!(dir.path().join(".env").exists(), ".env should be created");
    }

    #[test]
    fn test_materialize_sorted_keys() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[("ZEBRA", "z"), ("ALPHA", "a"), ("MIDDLE", "m")]);
        materialize_env_file(dir.path(), &secrets, defaults::MATERIALIZE_OUTPUT).unwrap();

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

        materialize_env_file(dir.path(), &secrets, defaults::MATERIALIZE_OUTPUT).unwrap();
        let content1 = fs::read_to_string(dir.path().join(".env")).unwrap();

        materialize_env_file(dir.path(), &secrets, defaults::MATERIALIZE_OUTPUT).unwrap();
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
        materialize_env_file(dir.path(), &secrets, defaults::MATERIALIZE_OUTPUT).unwrap();

        let content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(content.contains("KEY=\"value with \\\"quotes\\\" and \\\\backslash\""));
    }

    #[test]
    #[cfg(unix)]
    fn test_materialize_permissions_0600() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "").unwrap();

        let secrets = make_secrets(&[("SECRET", "value")]);
        materialize_env_file(dir.path(), &secrets, defaults::MATERIALIZE_OUTPUT).unwrap();

        let meta = fs::metadata(dir.path().join(".env")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            ".env should have 0600 permissions, got {mode:o}"
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
    fn test_ensure_gitattributes_adds_merge_driver() {
        let dir = TempDir::new().unwrap();

        ensure_gitattributes(dir.path(), &[GITATTRIBUTES_MERGE_DRIVER_ENTRY]).unwrap();

        let content = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(
            content.contains("*.env merge=gitvault-env"),
            ".gitattributes should contain the merge driver entry"
        );
    }

    #[test]
    fn test_ensure_gitattributes_idempotent() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".gitattributes"),
            "*.env merge=gitvault-env\n",
        )
        .unwrap();

        ensure_gitattributes(dir.path(), &[GITATTRIBUTES_MERGE_DRIVER_ENTRY]).unwrap();

        let content = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert_eq!(
            content.matches("*.env merge=gitvault-env").count(),
            1,
            "merge driver entry should appear exactly once"
        );
    }

    #[test]
    fn test_ensure_gitattributes_creates_file_if_missing() {
        let dir = TempDir::new().unwrap();

        ensure_gitattributes(dir.path(), &["*.env merge=gitvault-env"]).unwrap();

        assert!(dir.path().join(".gitattributes").exists());
    }

    #[test]
    fn test_merge_gitattributes_entries_returns_none_when_unchanged() {
        let merged = merge_gitattributes_entries(
            "*.env merge=gitvault-env\n",
            &["*.env merge=gitvault-env"],
        );
        assert!(merged.is_none());
    }

    #[test]
    fn test_escape_env_value_escapes_control_and_dollar() {
        let escaped = escape_env_value("a$b\nc\rd");
        assert_eq!(escaped, "a\\$b\\nc\\rd");
    }

    /// REQ-18 / C7: permissions must be set on the temp file BEFORE `persist()`
    /// so that the rename carries the restricted ACL — no TOCTOU window.
    ///
    /// We intercept by calling `enforce_restricted_env_permissions` on a fresh
    /// temp file (mimicking what `materialize_env_file` does) and confirm the
    /// permissions are applied before the file is moved to its final location.
    #[test]
    #[cfg(unix)]
    fn test_permissions_applied_before_persist_no_toctou() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let mut tmp = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        tmp.write_all(b"SECRET=value\n").unwrap();

        // Permissions must be set on tmp.path() (before rename), not on the final path.
        let tmp_path = tmp.path().to_path_buf();
        enforce_restricted_env_permissions(&tmp_path).unwrap();

        // Verify the temp file already has 0600 before persist
        let meta = fs::metadata(&tmp_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "temp file must have 0600 BEFORE persist — got {mode:o}"
        );

        // Now persist — the final file should inherit the restricted permissions.
        let final_path = dir.path().join(".env");
        tmp.persist(&final_path).unwrap();
        let final_meta = fs::metadata(&final_path).unwrap();
        let final_mode = final_meta.permissions().mode() & 0o777;
        assert_eq!(
            final_mode, 0o600,
            "final .env must have 0600 after persist — got {final_mode:o}"
        );
    }
}
