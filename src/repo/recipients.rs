use crate::defaults;
use crate::error::GitvaultError;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

/// File storing persistent recipient public keys (REQ-36); re-exported from [`defaults`].
pub use defaults::RECIPIENTS_FILE;

/// Read persistent recipients from .secrets/recipients (one pubkey per line).
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the file exists but cannot be read.
/// Returns [`GitvaultError::Usage`] if any line is not a valid age recipient key.
pub fn read_recipients(repo_root: &Path) -> Result<Vec<String>, GitvaultError> {
    let path = repo_root.join(RECIPIENTS_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&path)?;
    let mut recipients = Vec::new();
    for (line_no, line) in content.lines().enumerate() {
        if let Some(recipient) = parse_recipient_line(line).map_err(|message| {
            GitvaultError::Usage(format!(
                "Invalid recipient entry in {}:{}: {message}",
                RECIPIENTS_FILE,
                line_no + 1
            ))
        })? {
            recipients.push(recipient);
        }
    }
    Ok(recipients)
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

/// Write recipients to .secrets/recipients atomically.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the parent directory cannot be created or
/// the file cannot be written atomically.
pub fn write_recipients(repo_root: &Path, recipients: &[String]) -> Result<(), GitvaultError> {
    let path = repo_root.join(RECIPIENTS_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = recipients.join("\n") + "\n";
    let parent = path.parent().ok_or_else(|| {
        GitvaultError::Io(std::io::Error::other(format!(
            "cannot determine parent directory of {}",
            path.display()
        )))
    })?;
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    std::fs::write(tmp.path(), content)?;
    tmp.persist(&path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_read_write_recipients() {
        let dir = TempDir::new().unwrap();
        let keys = vec![
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string(),
            "age1z6j0we5lvscfzxqlqtpfwkf6p4amhjw6hv6h0x3n7lkdmkdwkjnq9x5x5v".to_string(),
        ];
        write_recipients(dir.path(), &keys).unwrap();
        let read_back = read_recipients(dir.path()).unwrap();
        assert_eq!(read_back, keys);
    }

    #[test]
    fn test_recipients_dedup_on_add() {
        let dir = TempDir::new().unwrap();
        let pubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string();

        // Write once
        write_recipients(dir.path(), std::slice::from_ref(&pubkey)).unwrap();

        // Simulate cmd_recipient Add logic (check contains before adding)
        let mut recipients = read_recipients(dir.path()).unwrap();
        if !recipients.contains(&pubkey) {
            recipients.push(pubkey.clone());
            write_recipients(dir.path(), &recipients).unwrap();
        }

        let read_back = read_recipients(dir.path()).unwrap();
        assert_eq!(
            read_back.iter().filter(|r| r.as_str() == pubkey).count(),
            1,
            "duplicate recipient should not be added"
        );
    }

    #[test]
    fn test_read_recipients_empty_when_no_file() {
        let dir = TempDir::new().unwrap();
        let recipients = read_recipients(dir.path()).unwrap();
        assert!(recipients.is_empty());
    }

    #[test]
    fn test_read_recipients_supports_inline_comment() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(RECIPIENTS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p # laptop\n",
        )
        .unwrap();

        let recipients = read_recipients(dir.path()).unwrap();
        assert_eq!(
            recipients,
            vec!["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string()]
        );
    }

    #[test]
    fn test_read_recipients_rejects_invalid_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(RECIPIENTS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not-a-recipient\n").unwrap();

        let result = read_recipients(dir.path());
        match result {
            Err(GitvaultError::Usage(message)) => {
                assert!(message.contains("Invalid recipient entry"));
                assert!(message.contains(".secrets/recipients:1"));
            }
            other => panic!("expected usage error, got: {other:?}"),
        }
    }

    /// Covers `read_recipients` with a blank / pure-comment line — exercises the
    /// `blank_or_comment.is_match(line) → Ok(None)` branch in `parse_recipient_line`.
    #[test]
    fn test_read_recipients_skips_blank_and_comment_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(RECIPIENTS_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# This is a comment\n\nage1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n   \n",
        )
        .unwrap();

        let recipients = read_recipients(dir.path()).unwrap();
        assert_eq!(recipients.len(), 1);
    }

    /// Covers the add-when-not-present branch for recipients.
    #[test]
    fn test_recipients_add_when_not_present() {
        let dir = TempDir::new().unwrap();
        let key1 = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_string();
        let key2 = "age1z6j0we5lvscfzxqlqtpfwkf6p4amhjw6hv6h0x3n7lkdmkdwkjnq9x5x5v".to_string();

        // Start with only key1.
        write_recipients(dir.path(), std::slice::from_ref(&key1)).unwrap();

        // key2 is not present — simulate the "add" branch.
        let mut recipients = read_recipients(dir.path()).unwrap();
        if !recipients.contains(&key2) {
            recipients.push(key2.clone());
            write_recipients(dir.path(), &recipients).unwrap();
        }

        let read_back = read_recipients(dir.path()).unwrap();
        assert!(read_back.contains(&key2), "key2 should have been added");
        assert_eq!(read_back.len(), 2);
    }
}
