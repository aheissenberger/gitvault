use crate::error::GitvaultError;
use std::path::Path;

use super::armor::{decrypt_armor, encrypt_armor};
use super::helpers::{atomic_write, is_age_armor};

/// Determine the new encrypted value for a field, applying REQ-5 idempotency:
/// if the current value is already age armor, keep it unchanged.
/// Otherwise, encrypt the current plaintext value.
fn determine_encrypted_value(
    current: &str,
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    if is_age_armor(current) {
        return Ok(current.to_string());
    }
    encrypt_armor(current.as_bytes(), recipient_keys)
}

/// Navigate to a nested field in a JSON value using dot-separated path, returning mutable ref.
fn json_field_mut<'a>(
    value: &'a mut serde_json::Value,
    path: &[&str],
) -> Option<&'a mut serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    match value {
        serde_json::Value::Object(map) => map
            .get_mut(path[0])
            .and_then(|v| json_field_mut(v, &path[1..])),
        _ => None,
    }
}

/// Navigate to a nested field in a YAML value using dot-separated path, returning mutable ref.
fn yaml_field_mut<'a>(
    value: &'a mut serde_yaml::Value,
    path: &[&str],
) -> Option<&'a mut serde_yaml::Value> {
    if path.is_empty() {
        return Some(value);
    }
    match value {
        serde_yaml::Value::Mapping(map) => {
            let key = serde_yaml::Value::String(path[0].to_string());
            map.get_mut(&key)
                .and_then(|v| yaml_field_mut(v, &path[1..]))
        }
        _ => None,
    }
}

/// Navigate to a nested field in a TOML value using dot-separated path, returning mutable ref.
fn toml_field_mut<'a>(value: &'a mut toml::Value, path: &[&str]) -> Option<&'a mut toml::Value> {
    if path.is_empty() {
        return Some(value);
    }
    match value {
        toml::Value::Table(map) => map
            .get_mut(path[0])
            .and_then(|v| toml_field_mut(v, &path[1..])),
        _ => None,
    }
}

/// REQ-4: Encrypt specified fields in a JSON, YAML, or TOML file.
/// REQ-5: Idempotent — existing ciphertext is preserved when the field is already encrypted.
///
/// The `_identity` parameter is reserved for future use. Current encryption relies solely on
/// public-key `recipient_keys`; the identity is retained in the signature to support future
/// scenarios such as decryption-then-re-encryption or identity-based key derivation without
/// a breaking API change.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the file cannot be read or written.
/// Returns [`GitvaultError::Encryption`] if the file format is unsupported, JSON/YAML/TOML
/// parsing fails, a field value is not a string, or encryption fails.
pub fn encrypt_fields(
    file_path: &Path,
    fields: &[&str],
    _identity: &dyn age::Identity,
    recipient_keys: &[String],
) -> Result<(), GitvaultError> {
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| GitvaultError::Encryption(format!("Reading {}: {e}", file_path.display())))?;

    let new_content = match ext.as_str() {
        "json" => encrypt_fields_json(&content, fields, recipient_keys)?,
        "yaml" | "yml" => encrypt_fields_yaml(&content, fields, recipient_keys)?,
        "toml" => encrypt_fields_toml(&content, fields, recipient_keys)?,
        _ => {
            return Err(GitvaultError::Other(format!(
                "Unsupported file format: .{ext}"
            )));
        }
    };

    atomic_write(file_path, new_content.as_bytes())
}

fn encrypt_fields_json(
    content: &str,
    fields: &[&str],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let mut value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| GitvaultError::Encryption(format!("JSON parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = json_field_mut(&mut value, &path) {
            let current = v
                .as_str()
                .ok_or_else(|| GitvaultError::Usage(format!("field '{field}' is not a string")))?
                .to_string();
            let encrypted = determine_encrypted_value(&current, recipient_keys)?;
            *v = serde_json::Value::String(encrypted);
        }
    }
    Ok(serde_json::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Encryption(format!("JSON serialize error: {e}")))?
        + "\n")
}

fn encrypt_fields_yaml(
    content: &str,
    fields: &[&str],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| GitvaultError::Encryption(format!("YAML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = yaml_field_mut(&mut value, &path) {
            let current = v
                .as_str()
                .ok_or_else(|| GitvaultError::Usage(format!("field '{field}' is not a string")))?
                .to_string();
            let encrypted = determine_encrypted_value(&current, recipient_keys)?;
            *v = serde_yaml::Value::String(encrypted);
        }
    }
    serde_yaml::to_string(&value)
        .map_err(|e| GitvaultError::Encryption(format!("YAML serialize error: {e}")))
}

fn encrypt_fields_toml(
    content: &str,
    fields: &[&str],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let mut value: toml::Value = content
        .parse::<toml::Value>()
        .map_err(|e| GitvaultError::Encryption(format!("TOML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = toml_field_mut(&mut value, &path) {
            let current = v
                .as_str()
                .ok_or_else(|| GitvaultError::Usage(format!("field '{field}' is not a string")))?
                .to_string();
            let encrypted = determine_encrypted_value(&current, recipient_keys)?;
            *v = toml::Value::String(encrypted);
        }
    }
    toml::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Encryption(format!("TOML serialize error: {e}")))
}

/// REQ-4: Decrypt specified fields in a JSON, YAML, or TOML file.
///
/// # Errors
///
/// Returns [`GitvaultError::Io`] if the file cannot be read or written.
/// Returns [`GitvaultError::Decryption`] if the file format is unsupported,
/// parsing fails, a field value is not a string, or decryption fails.
pub fn decrypt_fields(
    file_path: &Path,
    fields: &[&str],
    identity: &dyn age::Identity,
) -> Result<(), GitvaultError> {
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| GitvaultError::Decryption(format!("Reading {}: {e}", file_path.display())))?;

    let new_content = match ext.as_str() {
        "json" => decrypt_fields_json(&content, fields, identity)?,
        "yaml" | "yml" => decrypt_fields_yaml(&content, fields, identity)?,
        "toml" => decrypt_fields_toml(&content, fields, identity)?,
        _ => {
            return Err(GitvaultError::Other(format!(
                "Unsupported file format: .{ext}"
            )));
        }
    };

    atomic_write(file_path, new_content.as_bytes())
}

fn decrypt_fields_json(
    content: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
) -> Result<String, GitvaultError> {
    let mut value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| GitvaultError::Decryption(format!("JSON parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = json_field_mut(&mut value, &path)
            && let Some(s) = v.as_str()
            && is_age_armor(s)
        {
            let plain = decrypt_armor(s, identity)?;
            *v = serde_json::Value::String(
                String::from_utf8(plain.to_vec())
                    .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?,
            );
        }
    }
    Ok(serde_json::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Decryption(format!("JSON serialize error: {e}")))?
        + "\n")
}

fn decrypt_fields_yaml(
    content: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
) -> Result<String, GitvaultError> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| GitvaultError::Decryption(format!("YAML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = yaml_field_mut(&mut value, &path)
            && let Some(s) = v.as_str()
            && is_age_armor(s)
        {
            let plain = decrypt_armor(s, identity)?;
            *v = serde_yaml::Value::String(
                String::from_utf8(plain.to_vec())
                    .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?,
            );
        }
    }
    serde_yaml::to_string(&value)
        .map_err(|e| GitvaultError::Decryption(format!("YAML serialize error: {e}")))
}

fn decrypt_fields_toml(
    content: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
) -> Result<String, GitvaultError> {
    let mut value: toml::Value = content
        .parse::<toml::Value>()
        .map_err(|e| GitvaultError::Decryption(format!("TOML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = toml_field_mut(&mut value, &path)
            && let Some(s) = v.as_str()
            && is_age_armor(s)
        {
            let plain = decrypt_armor(s, identity)?;
            *v = toml::Value::String(
                String::from_utf8(plain.to_vec())
                    .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?,
            );
        }
    }
    toml::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Decryption(format!("TOML serialize error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn gen_identity() -> x25519::Identity {
        x25519::Identity::generate()
    }

    fn identity_to_recipient_keys(identity: &x25519::Identity) -> Vec<String> {
        vec![identity.to_public().to_string()]
    }

    /// REQ-4 + REQ-5: JSON field encrypt/decrypt roundtrip
    #[test]
    fn test_json_field_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        // Use a plain file in a temp dir so atomic_write (rename) works on Windows.
        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("test.json");
        std::fs::write(&path, r#"{"password":"hunter2","user":"alice"}"#).unwrap();

        encrypt_fields(&path, &["password"], &identity, &keys).unwrap();

        let after_enc = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&after_enc).unwrap();
        let enc_val = v["password"].as_str().unwrap();
        assert!(is_age_armor(enc_val), "encrypted value should be age armor");
        assert_eq!(
            v["user"].as_str().unwrap(),
            "alice",
            "other fields unchanged"
        );

        decrypt_fields(path.as_ref(), &["password"], &identity).unwrap();

        let after_dec = std::fs::read_to_string(&path).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&after_dec).unwrap();
        assert_eq!(v2["password"].as_str().unwrap(), "hunter2");
    }

    /// REQ-5: Idempotency — re-encrypting an already-encrypted field preserves the existing ciphertext.
    #[test]
    fn test_json_field_encrypt_idempotent() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("test.json");
        std::fs::write(&path, r#"{"secret":"mysecret","other":"value"}"#).unwrap();

        encrypt_fields(&path, &["secret"], &identity, &keys).unwrap();
        let first_enc = std::fs::read_to_string(&path).unwrap();

        encrypt_fields(&path, &["secret"], &identity, &keys).unwrap();
        let second_enc = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            first_enc, second_enc,
            "Re-encrypting an already-encrypted field must preserve existing ciphertext (REQ-5)"
        );
    }

    /// REQ-4: YAML field encrypt/decrypt roundtrip
    #[test]
    fn test_yaml_field_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("test.yaml");
        std::fs::write(&path, "database_password: secret123\nhost: localhost\n").unwrap();

        encrypt_fields(&path, &["database_password"], &identity, &keys).unwrap();

        let after_enc = std::fs::read_to_string(&path).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&after_enc).unwrap();
        let enc_val = v["database_password"].as_str().unwrap();
        assert!(
            is_age_armor(enc_val),
            "YAML encrypted value should be age armor"
        );
        assert_eq!(v["host"].as_str().unwrap(), "localhost");

        decrypt_fields(path.as_ref(), &["database_password"], &identity).unwrap();

        let after_dec = std::fs::read_to_string(&path).unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(&after_dec).unwrap();
        assert_eq!(v2["database_password"].as_str().unwrap(), "secret123");
    }

    /// REQ-4: TOML field encrypt/decrypt roundtrip
    #[test]
    fn test_toml_field_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("test.toml");
        std::fs::write(&path, "api_key = \"top-secret\"\nname = \"app\"\n").unwrap();

        encrypt_fields(&path, &["api_key"], &identity, &keys).unwrap();

        let after_enc = std::fs::read_to_string(&path).unwrap();
        let v: toml::Value = after_enc.parse().unwrap();
        let enc_val = v["api_key"].as_str().unwrap();
        assert!(
            is_age_armor(enc_val),
            "TOML encrypted value should be age armor"
        );
        assert_eq!(v["name"].as_str().unwrap(), "app");

        decrypt_fields(path.as_ref(), &["api_key"], &identity).unwrap();

        let after_dec = std::fs::read_to_string(&path).unwrap();
        let v2: toml::Value = after_dec.parse().unwrap();
        assert_eq!(v2["api_key"].as_str().unwrap(), "top-secret");
    }

    /// REQ-5: Only the modified field changes when a different key is added.
    #[test]
    fn test_json_only_changed_field_re_encrypts() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("test.json");
        std::fs::write(&path, r#"{"a":"alpha","b":"beta"}"#).unwrap();

        // Encrypt both fields
        encrypt_fields(&path, &["a", "b"], &identity, &keys).unwrap();
        let both_enc = std::fs::read_to_string(&path).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&both_enc).unwrap();
        let a_enc1 = v1["a"].as_str().unwrap().to_string();

        // Now overwrite 'b' with a new value and re-encrypt
        let new_b_ciphertext = v1["b"].as_str().unwrap().to_string();
        // Manually write a JSON where 'b' is changed plaintext but 'a' keeps its ciphertext
        std::fs::write(
            &path,
            format!(
                r#"{{"a":{},"b":"new_beta"}}"#,
                serde_json::to_string(&a_enc1).unwrap()
            ),
        )
        .unwrap();

        encrypt_fields(path.as_ref(), &["a", "b"], &identity, &keys).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&after).unwrap();
        let a_enc2 = v2["a"].as_str().unwrap();

        // 'a' ciphertext should be identical (plaintext didn't change)
        assert_eq!(
            a_enc1, a_enc2,
            "ciphertext for unchanged field 'a' must be preserved (REQ-5)"
        );
        // 'b' should have a new ciphertext
        assert_ne!(
            new_b_ciphertext,
            v2["b"].as_str().unwrap(),
            "ciphertext for changed field 'b' must differ"
        );
    }

    #[test]
    fn test_encrypt_fields_unsupported_extension_errors() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(tmp, "secret=value").unwrap();

        let err = encrypt_fields(tmp.path(), &["secret"], &identity, &keys).unwrap_err();
        assert!(err.to_string().contains("Unsupported file format"));
    }

    #[test]
    fn test_decrypt_fields_unsupported_extension_errors() {
        let identity = gen_identity();

        let mut tmp = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(tmp, "secret=value").unwrap();

        let err = decrypt_fields(tmp.path(), &["secret"], &identity).unwrap_err();
        assert!(err.to_string().contains("Unsupported file format"));
    }

    #[test]
    fn test_field_mut_helpers_return_none_for_scalar_roots() {
        let mut json_value = serde_json::Value::String("x".to_string());
        assert!(json_field_mut(&mut json_value, &["a"]).is_none());

        let mut yaml_value = serde_yaml::Value::String("x".to_string());
        assert!(yaml_field_mut(&mut yaml_value, &["a"]).is_none());

        let mut toml_value = toml::Value::String("x".to_string());
        assert!(toml_field_mut(&mut toml_value, &["a"]).is_none());
    }

    #[test]
    fn test_encrypt_field_helpers_ignore_missing_paths() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let json = r#"{"outer":{"present":"x"}}"#;
        let out_json = encrypt_fields_json(json, &["outer.missing"], &keys).unwrap();
        assert!(out_json.contains("\"present\": \"x\""));

        let yaml = "outer:\n  present: x\n";
        let out_yaml = encrypt_fields_yaml(yaml, &["outer.missing"], &keys).unwrap();
        assert!(out_yaml.contains("present: x"));

        let toml = "[outer]\npresent = \"x\"\n";
        let out_toml = encrypt_fields_toml(toml, &["outer.missing"], &keys).unwrap();
        assert!(out_toml.contains("present = \"x\""));
    }

    #[test]
    fn test_decrypt_field_helpers_ignore_non_armored_values() {
        let identity = gen_identity();

        let json = r#"{"secret":"plain"}"#;
        let out_json = decrypt_fields_json(json, &["secret"], &identity).unwrap();
        assert!(out_json.contains("\"secret\": \"plain\""));

        let yaml = "secret: plain\n";
        let out_yaml = decrypt_fields_yaml(yaml, &["secret"], &identity).unwrap();
        assert!(out_yaml.contains("secret: plain"));

        let toml = "secret = \"plain\"\n";
        let out_toml = decrypt_fields_toml(toml, &["secret"], &identity).unwrap();
        assert!(out_toml.contains("secret = \"plain\""));
    }

    // ── parse-error paths ────────────────────────────────────────────────────

    #[test]
    fn test_encrypt_fields_json_parse_error() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".json").unwrap();
        write!(tmp, "not valid json {{{{").unwrap();

        let err = encrypt_fields(tmp.path(), &["key"], &identity, &keys).unwrap_err();
        assert!(err.to_string().contains("JSON parse error"));
    }

    #[test]
    fn test_encrypt_fields_yaml_parse_error() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        // YAML that is structurally invalid for mapping (tab indentation is banned)
        let mut tmp = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(tmp, "key:\n\t- bad_indent").unwrap();

        let err = encrypt_fields(tmp.path(), &["key"], &identity, &keys).unwrap_err();
        assert!(err.to_string().contains("YAML parse error"));
    }

    #[test]
    fn test_encrypt_fields_toml_parse_error() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".toml").unwrap();
        write!(tmp, "key = {{not valid toml").unwrap();

        let err = encrypt_fields(tmp.path(), &["key"], &identity, &keys).unwrap_err();
        assert!(err.to_string().contains("TOML parse error"));
    }

    #[test]
    fn test_decrypt_fields_json_parse_error() {
        let identity = gen_identity();

        let mut tmp = NamedTempFile::with_suffix(".json").unwrap();
        write!(tmp, "not valid json").unwrap();

        let err = decrypt_fields(tmp.path(), &["key"], &identity).unwrap_err();
        assert!(err.to_string().contains("JSON parse error"));
    }

    #[test]
    fn test_decrypt_fields_yaml_parse_error() {
        let identity = gen_identity();

        let mut tmp = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(tmp, "key:\n\t- bad_indent").unwrap();

        let err = decrypt_fields(tmp.path(), &["key"], &identity).unwrap_err();
        assert!(err.to_string().contains("YAML parse error"));
    }

    #[test]
    fn test_decrypt_fields_toml_parse_error() {
        let identity = gen_identity();

        let mut tmp = NamedTempFile::with_suffix(".toml").unwrap();
        write!(tmp, "key = {{not valid toml").unwrap();

        let err = decrypt_fields(tmp.path(), &["key"], &identity).unwrap_err();
        assert!(err.to_string().contains("TOML parse error"));
    }

    // ── file-not-found paths ─────────────────────────────────────────────────

    #[test]
    fn test_encrypt_fields_file_not_found() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let nonexistent = std::path::Path::new("/nonexistent/dir/secret.json");

        let err = encrypt_fields(nonexistent, &["key"], &identity, &keys).unwrap_err();
        assert!(err.to_string().contains("Reading"));
    }

    #[test]
    fn test_decrypt_fields_file_not_found() {
        let identity = gen_identity();
        let nonexistent = std::path::Path::new("/nonexistent/dir/secret.yaml");

        let err = decrypt_fields(nonexistent, &["key"], &identity).unwrap_err();
        assert!(err.to_string().contains("Reading"));
    }

    // ── yml extension alias ───────────────────────────────────────────────────

    #[test]
    fn test_yml_extension_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let tmp_dir = tempfile::tempdir().unwrap();
        let path = tmp_dir.path().join("test.yml");
        std::fs::write(&path, "token: secret_token\nenv: prod\n").unwrap();

        encrypt_fields(&path, &["token"], &identity, &keys).unwrap();
        let v: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(is_age_armor(v["token"].as_str().unwrap()));

        decrypt_fields(path.as_ref(), &["token"], &identity).unwrap();
        let v2: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v2["token"].as_str().unwrap(), "secret_token");
    }
}
