//! Shared glob matching helpers.
//!
//! Keep path/key matching behavior centralized so all commands evaluate rules
//! consistently.

/// Match a repository-relative path against a glob pattern.
///
/// Both inputs are normalized to use `/` so matching is stable across platforms.
#[must_use]
pub fn path_matches_glob(pattern: &str, path: &str) -> bool {
    let pattern_norm = normalize_slashes(pattern);
    let path_norm = normalize_slashes(path);
    if pattern_norm == path_norm {
        return true;
    }
    glob::Pattern::new(&pattern_norm)
        .map(|p| p.matches(&path_norm))
        .unwrap_or(false)
}

/// Match a key glob against a key string.
#[must_use]
pub fn key_matches_glob(pattern: &str, key: &str) -> bool {
    if pattern == key {
        return true;
    }
    glob::Pattern::new(pattern)
        .map(|p| p.matches(key))
        .unwrap_or(false)
}

fn normalize_slashes(input: &str) -> String {
    input.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_matches_exact() {
        assert!(path_matches_glob("a/b/c.json", "a/b/c.json"));
    }

    #[test]
    fn path_matches_wildcard() {
        assert!(path_matches_glob("a/*.json", "a/c.json"));
        assert!(!path_matches_glob("a/*.json", "b/c.json"));
    }

    #[test]
    fn path_normalizes_backslashes() {
        assert!(path_matches_glob("a/*.json", "a\\c.json"));
        assert!(path_matches_glob("a\\*.json", "a/c.json"));
    }

    #[test]
    fn key_matches() {
        assert!(key_matches_glob("DB_*", "DB_PASSWORD"));
        assert!(!key_matches_glob("DB_*", "API_KEY"));
    }
}
