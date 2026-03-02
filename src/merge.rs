use crate::error::GitvaultError;

/// Parse a `.env`-formatted string into a list of `(key, value)` pairs.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if the content is not valid `.env` syntax.
pub fn parse_env_pairs(content: &str) -> Result<Vec<(String, String)>, GitvaultError> {
    dotenvy::from_read_iter(content.as_bytes())
        .map(|pair| pair.map_err(|e| GitvaultError::Usage(format!("Invalid .env content: {e}"))))
        .collect()
}

/// Parse the key from a single `.env` assignment line, discarding the value.
/// Returns `None` for blank lines and comments.
#[must_use]
pub fn parse_env_key_from_line(line: &str) -> Option<String> {
    let input = format!("{line}\n");
    let mut iter = dotenvy::from_read_iter(input.as_bytes());
    match iter.next() {
        Some(Ok((key, _))) => Some(key),
        _ => None,
    }
}

/// Parse the key and value from a single `.env` assignment line, or `None` for blanks/comments.
#[must_use]
pub fn parse_env_pair_from_line(line: &str) -> Option<(String, String)> {
    let input = format!("{line}\n");
    let mut iter = dotenvy::from_read_iter(input.as_bytes());
    match iter.next() {
        Some(Ok((key, value))) => Some((key, value)),
        _ => None,
    }
}

/// Rewrite the value portion of a `.env` assignment line, preserving spacing and inline comments.
pub fn rewrite_env_assignment_line(original_line: &str, new_value: &str) -> String {
    let Some(eq_index) = original_line.find('=') else {
        return original_line.to_string();
    };

    let prefix = &original_line[..=eq_index];
    let rhs = &original_line[eq_index + 1..];
    let ws_len: usize = rhs
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .map(char::len_utf8)
        .sum();
    let leading_ws = &rhs[..ws_len];
    let suffix = rhs
        .find(" #")
        .filter(|idx| *idx >= ws_len)
        .map_or("", |idx| &rhs[idx..]);
    format!("{prefix}{leading_ws}{new_value}{suffix}")
}

/// Pure three-way merge of .env file content. Returns `(merged_content, has_conflict)`.
/// No filesystem access — all inputs are string slices.
///
/// Uses a standard three-way merge algorithm: for each key, if only one side changed
/// relative to base, take that change; if both changed identically, accept it; if both
/// changed differently, emit a conflict marker block.
///
/// # Errors
///
/// Returns [`GitvaultError::Usage`] if any input string is not valid `.env` syntax.
pub fn merge_env_content(
    base: &str,
    ours: &str,
    theirs: &str,
) -> Result<(String, bool), GitvaultError> {
    fn to_map(content: &str) -> Result<std::collections::HashMap<String, String>, GitvaultError> {
        Ok(parse_env_pairs(content)?.into_iter().collect())
    }

    let base_map = to_map(base)?;
    let ours_map = to_map(ours)?;
    let theirs_map = to_map(theirs)?;

    // Collect all keys across all three versions
    let mut all_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    all_keys.extend(base_map.keys().cloned());
    all_keys.extend(ours_map.keys().cloned());
    all_keys.extend(theirs_map.keys().cloned());

    // Three-way merge per key
    let mut merged_map: std::collections::BTreeMap<String, Option<String>> =
        std::collections::BTreeMap::new();
    let mut has_conflict = false;

    for key in &all_keys {
        let base_val = base_map.get(key).map(std::string::String::as_str);
        let ours_val = ours_map.get(key).map(std::string::String::as_str);
        let theirs_val = theirs_map.get(key).map(std::string::String::as_str);

        let base_eq_ours = base_val == ours_val;
        let base_eq_theirs = base_val == theirs_val;
        let ours_eq_theirs = ours_val == theirs_val;

        let merged = if base_eq_ours && base_eq_theirs {
            // All same → keep ours
            ours_val.map(std::string::ToString::to_string)
        } else if base_eq_ours && !base_eq_theirs {
            // Ours unchanged, theirs changed → take theirs
            theirs_val.map(std::string::ToString::to_string)
        } else if !base_eq_ours && base_eq_theirs {
            // Ours changed, theirs unchanged → keep ours
            ours_val.map(std::string::ToString::to_string)
        } else if ours_eq_theirs {
            // Both changed to same value → keep ours
            ours_val.map(std::string::ToString::to_string)
        } else {
            // All three differ → conflict marker
            has_conflict = true;
            let ours_line = ours_val.map_or_else(
                || format!("# {key} deleted in ours"),
                |v| format!("{key}={v}"),
            );
            let theirs_line = theirs_val.map_or_else(
                || format!("# {key} deleted in theirs"),
                |v| format!("{key}={v}"),
            );
            Some(format!(
                "<<<<<<< ours\n{ours_line}\n=======\n{theirs_line}\n>>>>>>> theirs"
            ))
        };
        merged_map.insert(key.clone(), merged);
    }

    // Build output preserving ours structure (comments, blanks) and replacing key-values
    let mut output_lines: Vec<String> = Vec::new();
    let mut processed_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in ours.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output_lines.push(line.to_string());
        } else if let Some(k) = parse_env_key_from_line(line) {
            if let Some(Some(val)) = merged_map.get(&k) {
                if val.starts_with("<<<<<<") {
                    output_lines.push(val.clone());
                } else if ours_map.get(&k).map(String::as_str) == Some(val.as_str()) {
                    output_lines.push(line.to_string());
                } else {
                    output_lines.push(rewrite_env_assignment_line(line, val));
                }
                // If merged is None → key was deleted, skip it
            }
            processed_keys.insert(k);
        } else {
            output_lines.push(line.to_string());
        }
    }

    // Append keys that are new (not in ours)
    for (k, val_opt) in &merged_map {
        if !processed_keys.contains(k)
            && let Some(val) = val_opt
        {
            if val.starts_with("<<<<<<") {
                output_lines.push(val.clone());
            } else {
                output_lines.push(format!("{k}={val}"));
            }
        }
    }

    Ok((output_lines.join("\n") + "\n", has_conflict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GitvaultError;

    #[test]
    fn merge_env_no_changes() {
        let base = "FOO=1\nBAR=2\n";
        let (merged, conflict) = merge_env_content(base, base, base).unwrap();
        assert!(!conflict);
        assert!(merged.contains("FOO=1"));
        assert!(merged.contains("BAR=2"));
    }

    #[test]
    fn merge_env_ours_only_change() {
        let base = "FOO=1\n";
        let ours = "FOO=2\n";
        let theirs = "FOO=1\n";
        let (merged, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict);
        assert!(merged.contains("FOO=2"));
    }

    #[test]
    fn merge_env_theirs_only_change() {
        let base = "FOO=1\n";
        let ours = "FOO=1\n";
        let theirs = "FOO=3\n";
        let (merged, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict);
        assert!(merged.contains("FOO=3"));
    }

    #[test]
    fn merge_env_both_same_change() {
        let base = "FOO=1\n";
        let ours = "FOO=9\n";
        let theirs = "FOO=9\n";
        let (merged, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict);
        assert!(merged.contains("FOO=9"));
    }

    #[test]
    fn merge_env_conflict() {
        let base = "FOO=1\n";
        let ours = "FOO=2\n";
        let theirs = "FOO=3\n";
        let (merged, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(conflict);
        assert!(merged.contains("<<<<<<<"));
    }

    #[test]
    fn merge_env_key_deleted_in_ours() {
        let base = "FOO=1\nBAR=2\n";
        let ours = "FOO=1\n"; // BAR deleted
        let theirs = "FOO=1\nBAR=2\n";
        let (merged, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict);
        // BAR deleted in ours, unchanged in theirs → keep deletion
        assert!(!merged.contains("BAR=2"));
    }

    // ─── parse_env_key_from_line ──────────────────────────────────────────────

    #[test]
    fn parse_env_key_from_line_valid_assignment_returns_key() {
        assert_eq!(
            parse_env_key_from_line("KEY=value"),
            Some("KEY".to_string())
        );
    }

    #[test]
    fn parse_env_key_from_line_comment_returns_none() {
        assert_eq!(parse_env_key_from_line("# comment"), None);
    }

    #[test]
    fn parse_env_key_from_line_blank_returns_none() {
        assert_eq!(parse_env_key_from_line(""), None);
    }

    #[test]
    fn parse_env_key_from_line_no_key_before_equals_returns_none() {
        assert_eq!(parse_env_key_from_line("=no_key"), None);
    }

    #[test]
    fn parse_env_key_from_line_key_with_underscore_and_digits() {
        assert_eq!(
            parse_env_key_from_line("MY_KEY_2=x"),
            Some("MY_KEY_2".to_string())
        );
    }

    // ─── rewrite_env_assignment_line ─────────────────────────────────────────

    #[test]
    fn rewrite_env_assignment_line_basic_replacement() {
        assert_eq!(rewrite_env_assignment_line("KEY=old", "new"), "KEY=new");
    }

    #[test]
    fn rewrite_env_assignment_line_preserves_leading_whitespace() {
        assert_eq!(rewrite_env_assignment_line("KEY= old", "new"), "KEY= new");
    }

    #[test]
    fn rewrite_env_assignment_line_preserves_inline_comment() {
        assert_eq!(
            rewrite_env_assignment_line("KEY=old # comment", "new"),
            "KEY=new # comment"
        );
    }

    #[test]
    fn rewrite_env_assignment_line_no_equals_returns_unchanged() {
        assert_eq!(rewrite_env_assignment_line("no_equals", "new"), "no_equals");
    }

    #[test]
    fn rewrite_env_assignment_line_empty_value_replaced() {
        assert_eq!(rewrite_env_assignment_line("KEY=", "new"), "KEY=new");
    }

    // ─── merge_env_content: comment/blank and new-key-from-theirs ─────────────

    #[test]
    fn merge_env_preserves_comment_and_blank_lines() {
        let base = "# header\nA=1\n\nB=2\n";
        let ours = "# header\nA=1\n\nB=2\n";
        let theirs = "# header\nA=1\n\nB=2\n";
        let (out, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict);
        assert!(out.contains("# header"));
        assert!(out.contains("\n\n") || out.contains("\nB=2"));
    }

    #[test]
    fn merge_env_new_key_from_theirs_is_appended() {
        let base = "A=1\n";
        let ours = "A=1\n";
        let theirs = "A=1\nNEW_KEY=added_by_theirs\n";
        let (out, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict);
        assert!(out.contains("NEW_KEY=added_by_theirs"));
    }

    #[test]
    fn merge_env_conflict_on_key_deleted_in_ours_changed_in_theirs() {
        let base = "A=1\nB=old\n";
        let ours = "A=1\n"; // B deleted
        let theirs = "A=1\nB=new\n"; // B changed
        let (out, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(conflict);
        assert!(out.contains("<<<<<<<"));
    }

    #[test]
    fn test_parse_env_pairs_reports_invalid_content() {
        let result = parse_env_pairs("NOT VALID\n=A");
        assert!(matches!(result, Err(GitvaultError::Usage(_))));
    }

    /// Covers line 136 (closing `}` of `if let Some(Some(val))`): when theirs deletes a key
    /// that was unchanged in ours, the merged result is `Some(None)` → key is silently omitted.
    #[test]
    fn test_merge_env_content_key_deleted_in_theirs() {
        // base has KEY; ours unchanged; theirs removes it → merged omits KEY
        let base = "KEY=value\nOTHER=keep\n";
        let ours = "KEY=value\nOTHER=keep\n";
        let theirs = "OTHER=keep\n";

        let (merged, conflict) = merge_env_content(base, ours, theirs).unwrap();
        assert!(!conflict, "delete-only merge should not conflict");
        assert!(
            !merged.contains("KEY="),
            "deleted key should not appear in merged output"
        );
        assert!(
            merged.contains("OTHER=keep"),
            "unrelated key should be preserved"
        );
    }
}
