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

// ── REQ-110: Recursive collectors for auto-discover ──────────────────────────

/// Recursively collect dot-path keys for every string value in a JSON document
/// that is age ASCII-armor encrypted.
fn collect_encrypted_json(value: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_encrypted_json(v, &path, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let path = if prefix.is_empty() {
                    i.to_string()
                } else {
                    format!("{prefix}.{i}")
                };
                collect_encrypted_json(v, &path, out);
            }
        }
        serde_json::Value::String(s) if is_age_armor(s) => {
            out.push(prefix.to_string());
        }
        _ => {}
    }
}

/// Recursively collect dot-path keys for every string value in a YAML document
/// that is age ASCII-armor encrypted.
fn collect_encrypted_yaml(value: &serde_yaml::Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if let Some(key_str) = k.as_str() {
                    let path = if prefix.is_empty() {
                        key_str.to_string()
                    } else {
                        format!("{prefix}.{key_str}")
                    };
                    collect_encrypted_yaml(v, &path, out);
                }
            }
        }
        serde_yaml::Value::Sequence(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let path = if prefix.is_empty() {
                    i.to_string()
                } else {
                    format!("{prefix}.{i}")
                };
                collect_encrypted_yaml(v, &path, out);
            }
        }
        serde_yaml::Value::String(s) if is_age_armor(s) => {
            out.push(prefix.to_string());
        }
        _ => {}
    }
}

/// Recursively collect dot-path keys for every string value in a TOML document
/// that is age ASCII-armor encrypted.
fn collect_encrypted_toml(value: &toml::Value, prefix: &str, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_encrypted_toml(v, &path, out);
            }
        }
        toml::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let path = if prefix.is_empty() {
                    i.to_string()
                } else {
                    format!("{prefix}.{i}")
                };
                collect_encrypted_toml(v, &path, out);
            }
        }
        toml::Value::String(s) if is_age_armor(s) => {
            out.push(prefix.to_string());
        }
        _ => {}
    }
}

/// REQ-110: Recursively collect dot-path keys of every string value in a JSON, YAML, or TOML
/// document whose value satisfies [`is_age_armor`].
///
/// Returns an empty `Vec` (not an error) when no encrypted values are found.
///
/// # Errors
///
/// Returns [`GitvaultError`] if `content` cannot be parsed for the given `ext`.
///
/// # Examples
///
/// ```rust,ignore
/// let paths = collect_encrypted_field_paths(json_content, "json")?;
/// // paths might be ["db.password", "api.secret_key"]
/// ```
pub fn collect_encrypted_field_paths(
    content: &str,
    ext: &str,
) -> Result<Vec<String>, GitvaultError> {
    let mut out = Vec::new();
    match ext {
        "json" => {
            let value: serde_json::Value = serde_json::from_str(content)
                .map_err(|e| GitvaultError::Decryption(format!("JSON parse error: {e}")))?;
            collect_encrypted_json(&value, "", &mut out);
        }
        "yaml" | "yml" => {
            let value: serde_yaml::Value = serde_yaml::from_str(content)
                .map_err(|e| GitvaultError::Decryption(format!("YAML parse error: {e}")))?;
            collect_encrypted_yaml(&value, "", &mut out);
        }
        "toml" => {
            let value: toml::Value = content
                .parse::<toml::Value>()
                .map_err(|e| GitvaultError::Decryption(format!("TOML parse error: {e}")))?;
            collect_encrypted_toml(&value, "", &mut out);
        }
        _ => {
            return Err(GitvaultError::Other(format!(
                "Unsupported file format: .{ext}"
            )));
        }
    }
    Ok(out)
}

// ── REQ-4 / REQ-110: in-memory decrypt helpers ───────────────────────────────

/// REQ-110: Decrypt the listed fields in the document in-memory and return the result as a
/// `String` without touching any file on disk.
///
/// When `skip_undecryptable` is `true`, fields that fail decryption emit a `gitvault: warning:`
/// line to stderr and are left as-is (original ciphertext preserved). The call still succeeds
/// for all other fields.
///
/// # Errors
///
/// Returns [`GitvaultError`] on parse/serialize errors or (when `skip_undecryptable` is `false`)
/// on any field decryption failure.
pub fn decrypt_fields_content(
    content: &str,
    ext: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
    skip_undecryptable: bool,
) -> Result<String, GitvaultError> {
    match ext {
        "json" => decrypt_fields_json(content, fields, identity, skip_undecryptable),
        "yaml" | "yml" => decrypt_fields_yaml(content, fields, identity, skip_undecryptable),
        "toml" => decrypt_fields_toml(content, fields, identity, skip_undecryptable),
        _ => Err(GitvaultError::Other(format!(
            "Unsupported file format: .{ext}"
        ))),
    }
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

    let new_content = decrypt_fields_content(&content, &ext, fields, identity, false)?;
    atomic_write(file_path, new_content.as_bytes())
}

fn decrypt_fields_json(
    content: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
    skip_undecryptable: bool,
) -> Result<String, GitvaultError> {
    let mut value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| GitvaultError::Decryption(format!("JSON parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = json_field_mut(&mut value, &path)
            && let Some(s) = v.as_str()
            && is_age_armor(s)
        {
            match decrypt_armor(s, identity) {
                Ok(plain) => {
                    *v = serde_json::Value::String(
                        String::from_utf8(plain.to_vec())
                            .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?,
                    );
                }
                Err(e) if skip_undecryptable => {
                    eprintln!("gitvault: warning: could not decrypt field '{field}': {e}");
                }
                Err(e) => return Err(e),
            }
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
    skip_undecryptable: bool,
) -> Result<String, GitvaultError> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| GitvaultError::Decryption(format!("YAML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = yaml_field_mut(&mut value, &path)
            && let Some(s) = v.as_str()
            && is_age_armor(s)
        {
            match decrypt_armor(s, identity) {
                Ok(plain) => {
                    *v = serde_yaml::Value::String(
                        String::from_utf8(plain.to_vec())
                            .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?,
                    );
                }
                Err(e) if skip_undecryptable => {
                    eprintln!("gitvault: warning: could not decrypt field '{field}': {e}");
                }
                Err(e) => return Err(e),
            }
        }
    }
    serde_yaml::to_string(&value)
        .map_err(|e| GitvaultError::Decryption(format!("YAML serialize error: {e}")))
}

fn decrypt_fields_toml(
    content: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
    skip_undecryptable: bool,
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
            match decrypt_armor(s, identity) {
                Ok(plain) => {
                    *v = toml::Value::String(
                        String::from_utf8(plain.to_vec())
                            .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?,
                    );
                }
                Err(e) if skip_undecryptable => {
                    eprintln!("gitvault: warning: could not decrypt field '{field}': {e}");
                }
                Err(e) => return Err(e),
            }
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
        let out_json = decrypt_fields_json(json, &["secret"], &identity, false).unwrap();
        assert!(out_json.contains("\"secret\": \"plain\""));

        let yaml = "secret: plain\n";
        let out_yaml = decrypt_fields_yaml(yaml, &["secret"], &identity, false).unwrap();
        assert!(out_yaml.contains("secret: plain"));

        let toml = "secret = \"plain\"\n";
        let out_toml = decrypt_fields_toml(toml, &["secret"], &identity, false).unwrap();
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

    // ── REQ-110: collect_encrypted_field_paths ───────────────────────────────

    #[test]
    fn test_collect_encrypted_field_paths_json_flat() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let json = format!(
            r#"{{"name":"app","api_key":{}}}"#,
            serde_json::to_string(&enc).unwrap()
        );
        let paths = collect_encrypted_field_paths(&json, "json").unwrap();
        assert_eq!(paths, vec!["api_key"]);
    }

    #[test]
    fn test_collect_encrypted_field_paths_json_nested() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"s3cr3t", &keys).unwrap();
        let json = format!(
            r#"{{"db":{{"host":"localhost","password":{}}}}}"#,
            serde_json::to_string(&enc).unwrap()
        );
        let paths = collect_encrypted_field_paths(&json, "json").unwrap();
        assert_eq!(paths, vec!["db.password"]);
    }

    #[test]
    fn test_collect_encrypted_field_paths_json_empty_when_plain() {
        let json = r#"{"name":"app","version":"1.0"}"#;
        let paths = collect_encrypted_field_paths(json, "json").unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn test_collect_encrypted_field_paths_yaml() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"tok", &keys).unwrap();
        let yaml = format!(
            "token: |\n  {}\nenv: prod\n",
            enc.trim().replace('\n', "\n  ")
        );
        let paths = collect_encrypted_field_paths(&yaml, "yaml").unwrap();
        assert!(paths.contains(&"token".to_string()), "got: {paths:?}");
    }

    #[test]
    fn test_collect_encrypted_field_paths_toml() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"pw", &keys).unwrap();
        let mut map = toml::value::Table::new();
        map.insert("name".to_string(), toml::Value::String("app".to_string()));
        map.insert("password".to_string(), toml::Value::String(enc));
        let toml_str = toml::to_string_pretty(&toml::Value::Table(map)).unwrap();
        let paths = collect_encrypted_field_paths(&toml_str, "toml").unwrap();
        assert!(paths.contains(&"password".to_string()), "got: {paths:?}");
    }

    #[test]
    fn test_collect_encrypted_field_paths_unsupported_ext() {
        let err = collect_encrypted_field_paths("whatever", "txt").unwrap_err();
        assert!(err.to_string().contains("Unsupported file format"));
    }

    // ── REQ-110: decrypt_fields_content ─────────────────────────────────────

    #[test]
    fn test_decrypt_fields_content_json_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"topsecret", &keys).unwrap();
        let json = format!(r#"{{"key":{}}}"#, serde_json::to_string(&enc).unwrap());
        let out = decrypt_fields_content(&json, "json", &["key"], &identity, false).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["key"].as_str().unwrap(), "topsecret");
    }

    #[test]
    fn test_decrypt_fields_content_skip_undecryptable() {
        // Encrypt with one identity, try to decrypt with a different one.
        let enc_identity = gen_identity();
        let keys = identity_to_recipient_keys(&enc_identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let json = format!(r#"{{"key":{}}}"#, serde_json::to_string(&enc).unwrap());

        let wrong_identity = gen_identity();
        // skip_undecryptable=true → should succeed (field left as ciphertext), no error
        let out = decrypt_fields_content(&json, "json", &["key"], &wrong_identity, true).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        // Field value must still be the original ciphertext (not decrypted)
        assert!(is_age_armor(v["key"].as_str().unwrap()));
    }

    #[test]
    fn test_decrypt_fields_content_fail_on_undecryptable_when_strict() {
        let enc_identity = gen_identity();
        let keys = identity_to_recipient_keys(&enc_identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let json = format!(r#"{{"key":{}}}"#, serde_json::to_string(&enc).unwrap());

        let wrong_identity = gen_identity();
        // skip_undecryptable=false → must return an error
        let err =
            decrypt_fields_content(&json, "json", &["key"], &wrong_identity, false).unwrap_err();
        assert!(err.to_string().contains("Decrypt"), "got: {err}");
    }

    // ── REQ-110: array traversal in collect_encrypted_* ───────────────────

    #[test]
    fn test_collect_encrypted_field_paths_json_array_element() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        // Array inside an object: items[0] is encrypted, items[1] is plain
        let json = format!(
            r#"{{"items":[{},"plain"],"name":"app"}}"#,
            serde_json::to_string(&enc).unwrap()
        );
        let paths = collect_encrypted_field_paths(&json, "json").unwrap();
        // collect_encrypted_json traverses arrays: should report "items.0"
        assert!(
            paths.contains(&"items.0".to_string()),
            "encrypted array element should be reported as 'items.0': got {paths:?}"
        );
        // "items.1" is plain, should not appear
        assert!(
            !paths.contains(&"items.1".to_string()),
            "plain element should not be reported: got {paths:?}"
        );
    }

    #[test]
    fn test_collect_encrypted_field_paths_yaml_sequence_element() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        // Build YAML with an encrypted value inside a sequence under a key.
        // We'll put the armored value as a scalar string in a YAML sequence.
        let mut map = serde_yaml::Mapping::new();
        let seq = serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::String(enc),
            serde_yaml::Value::String("plain".to_string()),
        ]);
        map.insert(serde_yaml::Value::String("items".to_string()), seq);
        let yaml_str = serde_yaml::to_string(&serde_yaml::Value::Mapping(map)).unwrap();
        let paths = collect_encrypted_field_paths(&yaml_str, "yaml").unwrap();
        // collect_encrypted_yaml traverses sequences: should report "items.0"
        assert!(
            paths.contains(&"items.0".to_string()),
            "encrypted YAML sequence element should be reported: got {paths:?}"
        );
    }

    #[test]
    fn test_collect_encrypted_field_paths_toml_array_element() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        // Build TOML with an encrypted string inside an array.
        let mut map = toml::value::Table::new();
        map.insert(
            "items".to_string(),
            toml::Value::Array(vec![
                toml::Value::String(enc),
                toml::Value::String("plain".to_string()),
            ]),
        );
        let toml_str = toml::to_string_pretty(&toml::Value::Table(map)).unwrap();
        let paths = collect_encrypted_field_paths(&toml_str, "toml").unwrap();
        // collect_encrypted_toml traverses arrays: should report "items.0"
        assert!(
            paths.contains(&"items.0".to_string()),
            "encrypted TOML array element should be reported: got {paths:?}"
        );
    }

    // ── decrypt_fields_content: YAML and TOML skip_undecryptable ─────────

    #[test]
    fn test_decrypt_fields_content_yaml_skip_undecryptable() {
        let enc_identity = gen_identity();
        let keys = identity_to_recipient_keys(&enc_identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let yaml = format!("key: |\n  {}\n", enc.trim().replace('\n', "\n  "));

        let wrong_identity = gen_identity();
        // skip_undecryptable=true → must succeed (field stays as ciphertext)
        let out = decrypt_fields_content(&yaml, "yaml", &["key"], &wrong_identity, true).unwrap();
        // The output should contain the key but the value should still be armored (not decrypted)
        assert!(out.contains("key"), "output must contain key: {out}");
    }

    #[test]
    fn test_decrypt_fields_content_yaml_fail_on_undecryptable_strict() {
        let enc_identity = gen_identity();
        let keys = identity_to_recipient_keys(&enc_identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let yaml = format!("key: |\n  {}\n", enc.trim().replace('\n', "\n  "));

        let wrong_identity = gen_identity();
        // skip_undecryptable=false → must return error
        let err =
            decrypt_fields_content(&yaml, "yaml", &["key"], &wrong_identity, false).unwrap_err();
        assert!(err.to_string().contains("Decrypt"), "got: {err}");
    }

    #[test]
    fn test_decrypt_fields_content_toml_skip_undecryptable() {
        let enc_identity = gen_identity();
        let keys = identity_to_recipient_keys(&enc_identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let mut map = toml::value::Table::new();
        map.insert("key".to_string(), toml::Value::String(enc));
        let toml_str = toml::to_string_pretty(&toml::Value::Table(map)).unwrap();

        let wrong_identity = gen_identity();
        // skip_undecryptable=true → must succeed
        let out =
            decrypt_fields_content(&toml_str, "toml", &["key"], &wrong_identity, true).unwrap();
        assert!(out.contains("key"), "output must contain key: {out}");
    }

    #[test]
    fn test_decrypt_fields_content_toml_fail_on_undecryptable_strict() {
        let enc_identity = gen_identity();
        let keys = identity_to_recipient_keys(&enc_identity);
        let enc = super::super::armor::encrypt_armor(b"secret", &keys).unwrap();
        let mut map = toml::value::Table::new();
        map.insert("key".to_string(), toml::Value::String(enc));
        let toml_str = toml::to_string_pretty(&toml::Value::Table(map)).unwrap();

        let wrong_identity = gen_identity();
        // skip_undecryptable=false → must return error
        let err = decrypt_fields_content(&toml_str, "toml", &["key"], &wrong_identity, false)
            .unwrap_err();
        assert!(err.to_string().contains("Decrypt"), "got: {err}");
    }

    // ── decrypt_fields_content: YAML roundtrip ───────────────────────────

    #[test]
    fn test_decrypt_fields_content_yaml_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"topsecret", &keys).unwrap();
        let yaml = format!("key: |\n  {}\n", enc.trim().replace('\n', "\n  "));
        let out = decrypt_fields_content(&yaml, "yaml", &["key"], &identity, false).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["key"].as_str().unwrap().trim(), "topsecret");
    }

    // ── decrypt_fields_content: TOML roundtrip ───────────────────────────

    #[test]
    fn test_decrypt_fields_content_toml_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let enc = super::super::armor::encrypt_armor(b"topsecret", &keys).unwrap();
        let mut map = toml::value::Table::new();
        map.insert("key".to_string(), toml::Value::String(enc));
        let toml_str = toml::to_string_pretty(&toml::Value::Table(map)).unwrap();
        let out = decrypt_fields_content(&toml_str, "toml", &["key"], &identity, false).unwrap();
        let v: toml::Value = out.parse().unwrap();
        assert_eq!(v["key"].as_str().unwrap(), "topsecret");
    }
}
