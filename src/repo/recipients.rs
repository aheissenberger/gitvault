use crate::defaults;
use crate::error::GitvaultError;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

/// Directory storing persistent recipient public keys (REQ-72 AC15); re-exported from [`defaults`].
pub use defaults::RECIPIENTS_DIR;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read all persistent recipients from the recipients directory.
///
/// Scans every `*.pub` file in `recipients_dir_path` (relative to `repo_root`),
/// reads the public key line from each file (ignoring blank lines and `#` comments),
/// and returns all valid keys.  Returns an empty `Vec` when the directory does not
/// exist yet.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if a file exists but cannot be read.
/// Returns [`GitvaultError::Usage`] if a key line is not a valid age recipient.
pub fn read_recipients(
    repo_root: &Path,
    recipients_dir: &str,
) -> Result<Vec<String>, GitvaultError> {
    let dir_path = repo_root.join(recipients_dir);
    if !dir_path.exists() {
        return Ok(vec![]);
    }
    let mut keys = Vec::new();
    for entry in collect_pub_entries(&dir_path)? {
        let file_path = entry;
        let content = std::fs::read_to_string(&file_path)?;
        for (line_no, line) in content.lines().enumerate() {
            if let Some(key) = parse_recipient_line(line).map_err(|message| {
                GitvaultError::Usage(format!(
                    "Invalid recipient entry in {}:{}: {message}",
                    file_path.display(),
                    line_no + 1
                ))
            })? {
                keys.push(key);
            }
        }
    }
    Ok(keys)
}

/// Write a single recipient public key into `<name>.pub` inside the recipients directory.
///
/// `recipients_dir` is the repository-relative path to the directory.
/// `name` becomes the stem of the `.pub` file (e.g. `"alice"` → `alice.pub`).
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the directory cannot be created or the file
/// cannot be written.
pub fn write_recipients(
    repo_root: &Path,
    recipients_dir: &str,
    name: &str,
    key: &str,
) -> Result<(), GitvaultError> {
    let dir_path = repo_root.join(recipients_dir);
    std::fs::create_dir_all(&dir_path)?;
    let file_path = dir_path.join(format!("{name}.pub"));
    let content = format!("{key}\n");
    std::fs::write(&file_path, content)?;
    Ok(())
}

/// Remove the `.pub` file whose content matches `key`.
///
/// Scans all `*.pub` files in `recipients_dir` for the key string.
/// Deletes the first file that contains a matching key line.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if a file cannot be read or deleted.
/// Returns [`GitvaultError::Usage`] if no file contains the key.
pub fn remove_recipient_by_key(
    repo_root: &Path,
    recipients_dir: &str,
    key: &str,
) -> Result<(), GitvaultError> {
    let dir_path = repo_root.join(recipients_dir);
    if !dir_path.exists() {
        return Err(GitvaultError::Usage(format!(
            "Recipient not found: {key}"
        )));
    }
    for file_path in collect_pub_entries(&dir_path)? {
        let content = std::fs::read_to_string(&file_path)?;
        for line in content.lines() {
            if let Ok(Some(parsed)) = parse_recipient_line(line) {
                if parsed == key {
                    std::fs::remove_file(&file_path)?;
                    return Ok(());
                }
            }
        }
    }
    Err(GitvaultError::Usage(format!("Recipient not found: {key}")))
}

/// Remove the `.pub` file for `name` (`<name>.pub`) directly.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the file cannot be deleted.
/// Returns [`GitvaultError::Usage`] if the file does not exist.
pub fn remove_recipient_by_name(
    repo_root: &Path,
    recipients_dir: &str,
    name: &str,
) -> Result<(), GitvaultError> {
    let dir_path = repo_root.join(recipients_dir);
    let file_path = dir_path.join(format!("{name}.pub"));
    if !file_path.exists() {
        return Err(GitvaultError::Usage(format!(
            "Recipient not found: {name}"
        )));
    }
    std::fs::remove_file(&file_path)?;
    Ok(())
}

/// List all recipients as `(name, key)` pairs.
///
/// The `name` is the file stem (without `.pub` extension).
/// The `key` is the single public key read from the file.
/// Files with no valid key lines are skipped.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if a file cannot be read.
/// Returns [`GitvaultError::Usage`] if a key line is invalid.
pub fn list_recipients(
    repo_root: &Path,
    recipients_dir: &str,
) -> Result<Vec<(String, String)>, GitvaultError> {
    let dir_path = repo_root.join(recipients_dir);
    if !dir_path.exists() {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    for file_path in collect_pub_entries(&dir_path)? {
        let name = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let content = std::fs::read_to_string(&file_path)?;
        for (line_no, line) in content.lines().enumerate() {
            if let Some(key) = parse_recipient_line(line).map_err(|message| {
                GitvaultError::Usage(format!(
                    "Invalid recipient entry in {}:{}: {message}",
                    file_path.display(),
                    line_no + 1
                ))
            })? {
                result.push((name.clone(), key));
            }
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Collect all `*.pub` file paths in `dir_path`, sorted for deterministic ordering.
fn collect_pub_entries(
    dir_path: &Path,
) -> Result<Vec<std::path::PathBuf>, GitvaultError> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("pub") {
            entries.push(path);
        }
    }
    entries.sort();
    Ok(entries)
}

fn parse_recipient_line(line: &str) -> Result<Option<String>, &'static str> {
    static BLANK_OR_COMMENT_RE: OnceLock<Regex> = OnceLock::new();
    static RECIPIENT_RE: OnceLock<Regex> = OnceLock::new();

    let blank_or_comment = BLANK_OR_COMMENT_RE
        .get_or_init(|| Regex::new(r"^\s*(?:#.*)?$").expect("blank/comment regex must compile"));
    if blank_or_comment.is_match(line) {
        return Ok(None);
    }

    let recipient_re = RECIPIENT_RE.get_or_init(|| {
        Regex::new(r"^\s*(age1[0-9a-z]+)\s*(?:#.*)?$").expect("recipient regex must compile")
    });
    if let Some(captures) = recipient_re.captures(line) {
        return Ok(Some(captures[1].to_string()));
    }

    Err("expected age recipient key")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const KEY1: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
    const KEY2: &str = "age1z6j0we5lvscfzxqlqtpfwkf6p4amhjw6hv6h0x3n7lkdmkdwkjnq9x5x5v";

    #[test]
    fn test_read_recipients_empty_when_no_dir() {
        let dir = TempDir::new().unwrap();
        let recipients = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert!(recipients.is_empty());
    }

    #[test]
    fn test_write_then_read_single_recipient() {
        let dir = TempDir::new().unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "alice", KEY1).unwrap();
        let keys = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert_eq!(keys, vec![KEY1.to_string()]);
    }

    #[test]
    fn test_write_then_read_multiple_recipients() {
        let dir = TempDir::new().unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "alice", KEY1).unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "bob", KEY2).unwrap();
        let mut keys = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        keys.sort();
        let mut expected = vec![KEY1.to_string(), KEY2.to_string()];
        expected.sort();
        assert_eq!(keys, expected);
    }

    #[test]
    fn test_list_recipients() {
        let dir = TempDir::new().unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "alice", KEY1).unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "bob", KEY2).unwrap();
        let mut list = list_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(list[0], ("alice".to_string(), KEY1.to_string()));
        assert_eq!(list[1], ("bob".to_string(), KEY2.to_string()));
    }

    #[test]
    fn test_remove_recipient_by_key() {
        let dir = TempDir::new().unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "alice", KEY1).unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "bob", KEY2).unwrap();
        remove_recipient_by_key(dir.path(), defaults::RECIPIENTS_DIR, KEY1).unwrap();
        let keys = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert_eq!(keys, vec![KEY2.to_string()]);
    }

    #[test]
    fn test_remove_recipient_by_name() {
        let dir = TempDir::new().unwrap();
        write_recipients(dir.path(), defaults::RECIPIENTS_DIR, "alice", KEY1).unwrap();
        remove_recipient_by_name(dir.path(), defaults::RECIPIENTS_DIR, "alice").unwrap();
        let keys = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_remove_by_key_not_found_errors() {
        let dir = TempDir::new().unwrap();
        let err = remove_recipient_by_key(dir.path(), defaults::RECIPIENTS_DIR, KEY1)
            .unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_remove_by_name_not_found_errors() {
        let dir = TempDir::new().unwrap();
        // create dir so we hit the "file not found" branch
        std::fs::create_dir_all(dir.path().join(defaults::RECIPIENTS_DIR)).unwrap();
        let err = remove_recipient_by_name(dir.path(), defaults::RECIPIENTS_DIR, "nobody")
            .unwrap_err();
        assert!(matches!(err, GitvaultError::Usage(_)));
    }

    #[test]
    fn test_read_recipients_skips_blank_and_comment_lines() {
        let dir = TempDir::new().unwrap();
        let recipients_dir = dir.path().join(defaults::RECIPIENTS_DIR);
        std::fs::create_dir_all(&recipients_dir).unwrap();
        std::fs::write(
            recipients_dir.join("alice.pub"),
            format!("# comment\n\n{KEY1}\n   \n"),
        )
        .unwrap();
        let keys = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert_eq!(keys, vec![KEY1.to_string()]);
    }

    #[test]
    fn test_read_recipients_supports_inline_comment() {
        let dir = TempDir::new().unwrap();
        let recipients_dir = dir.path().join(defaults::RECIPIENTS_DIR);
        std::fs::create_dir_all(&recipients_dir).unwrap();
        std::fs::write(
            recipients_dir.join("alice.pub"),
            format!("{KEY1} # laptop\n"),
        )
        .unwrap();
        let keys = read_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert_eq!(keys, vec![KEY1.to_string()]);
    }

    #[test]
    fn test_read_recipients_rejects_invalid_line() {
        let dir = TempDir::new().unwrap();
        let recipients_dir = dir.path().join(defaults::RECIPIENTS_DIR);
        std::fs::create_dir_all(&recipients_dir).unwrap();
        std::fs::write(recipients_dir.join("bad.pub"), "not-a-recipient\n").unwrap();
        let result = read_recipients(dir.path(), defaults::RECIPIENTS_DIR);
        match result {
            Err(GitvaultError::Usage(message)) => {
                assert!(message.contains("Invalid recipient entry"));
            }
            other => panic!("expected usage error, got: {other:?}"),
        }
    }

    #[test]
    fn test_list_recipients_empty_when_no_dir() {
        let dir = TempDir::new().unwrap();
        let list = list_recipients(dir.path(), defaults::RECIPIENTS_DIR).unwrap();
        assert!(list.is_empty());
    }
}
