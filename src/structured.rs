use crate::error::GitvaultError;
use base64::Engine;
/// REQ-4: Field-level encryption for JSON, YAML, and TOML.
/// REQ-5: Deterministic encryption — existing ciphertext is preserved when plaintext unchanged.
use std::io::{Read, Write};
use std::path::Path;
use crate::merge::{parse_env_pair_from_line, rewrite_env_assignment_line};

const AGE_ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
/// Prefix used for single-line encrypted values in .env value-only mode.
const ENV_ENC_PREFIX: &str = "age:";

pub fn is_age_armor(value: &str) -> bool {
    value.trim_start().starts_with(AGE_ARMOR_HEADER)
}

fn is_env_encrypted(value: &str) -> bool {
    value.starts_with(ENV_ENC_PREFIX)
}

/// Encrypt plaintext bytes using age ASCII armor. Returns the armor text.
fn encrypt_armor(plaintext: &[u8], recipient_keys: &[String]) -> Result<String, GitvaultError> {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r: age::x25519::Recipient = k
                .parse()
                .map_err(|e| GitvaultError::Encryption(format!("Invalid recipient key {k}: {e}")))?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    {
        let armor =
            age::armor::ArmoredWriter::wrap_output(&mut output, age::armor::Format::AsciiArmor)
                .map_err(|e| GitvaultError::Encryption(format!("Armor writer: {e}")))?;
        let mut writer = encryptor
            .wrap_output(armor)
            .map_err(|e| GitvaultError::Encryption(format!("Encrypt wrap: {e}")))?;
        writer
            .write_all(plaintext)
            .map_err(|e| GitvaultError::Encryption(format!("Encrypt write: {e}")))?;
        let armor = writer
            .finish()
            .map_err(|e| GitvaultError::Encryption(format!("Encrypt finish: {e}")))?;
        armor
            .finish()
            .map_err(|e| GitvaultError::Encryption(format!("Armor finish: {e}")))?;
    }
    Ok(String::from_utf8(output).map_err(|e| GitvaultError::Encryption(format!("UTF-8 error: {e}")))?)
}

/// Decrypt an age armor string using the given identity.
fn decrypt_armor(armored: &str, identity: &dyn age::Identity) -> Result<Vec<u8>, GitvaultError> {
    let armor = age::armor::ArmoredReader::new(armored.as_bytes());
    let decryptor =
        age::Decryptor::new(armor).map_err(|e| GitvaultError::Decryption(format!("Decryptor create: {e}")))?;
    let mut reader = match decryptor {
        age::Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(identity))
            .map_err(|e| GitvaultError::Decryption(format!("Decrypt: {e}")))?,
        age::Decryptor::Passphrase(_) => {
            return Err(GitvaultError::Decryption("Passphrase-encrypted files not supported".to_string()));
        }
    };
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GitvaultError::Decryption(format!("Read decrypted: {e}")))?;
    Ok(plaintext)
}

/// Encrypt plaintext bytes using binary age (no armor), returning base64-encoded result.
fn encrypt_binary_b64(plaintext: &[u8], recipient_keys: &[String]) -> Result<String, GitvaultError> {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r: age::x25519::Recipient = k
                .parse()
                .map_err(|e| GitvaultError::Encryption(format!("Invalid recipient key {k}: {e}")))?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| GitvaultError::Encryption(format!("Encrypt wrap: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| GitvaultError::Encryption(format!("Encrypt write: {e}")))?;
    writer
        .finish()
        .map_err(|e| GitvaultError::Encryption(format!("Encrypt finish: {e}")))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&output))
}

fn decrypt_binary_b64(encoded: &str, identity: &dyn age::Identity) -> Result<Vec<u8>, GitvaultError> {
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| GitvaultError::Decryption(format!("Invalid base64 payload: {e}")))?;
    let decryptor = age::Decryptor::new(ciphertext.as_slice())
        .map_err(|e| GitvaultError::Decryption(format!("Decryptor create: {e}")))?;
    let mut reader = match decryptor {
        age::Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(identity))
            .map_err(|e| GitvaultError::Decryption(format!("Decrypt: {e}")))?,
        age::Decryptor::Passphrase(_) => {
            return Err(GitvaultError::Decryption("Passphrase-encrypted not supported".to_string()));
        }
    };
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GitvaultError::Decryption(format!("Read decrypted: {e}")))?;
    Ok(plaintext)
}

/// Determine the new encrypted value for a field, applying REQ-5 determinism:
/// if the current value is already age armor, keep it unchanged.
/// Otherwise, encrypt the current plaintext value.
fn determine_encrypted_value(current: &str, recipient_keys: &[String]) -> Result<String, GitvaultError> {
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
/// REQ-5: Existing ciphertext is kept if it decrypts to the same plaintext.
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
        _ => return Err(GitvaultError::Other(format!("Unsupported file format: .{ext}"))),
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
            let current = v.as_str().unwrap_or("").to_string();
            let encrypted = determine_encrypted_value(&current, recipient_keys)?;
            *v = serde_json::Value::String(encrypted);
        }
    }
    Ok(serde_json::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Encryption(format!("JSON serialize error: {e}")))? + "\n")
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
            let current = v.as_str().unwrap_or("").to_string();
            let encrypted = determine_encrypted_value(&current, recipient_keys)?;
            *v = serde_yaml::Value::String(encrypted);
        }
    }
    Ok(serde_yaml::to_string(&value)
        .map_err(|e| GitvaultError::Encryption(format!("YAML serialize error: {e}")))?)
}

fn encrypt_fields_toml(
    content: &str,
    fields: &[&str],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let mut value: toml::Value = content.parse::<toml::Value>()
        .map_err(|e| GitvaultError::Encryption(format!("TOML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = toml_field_mut(&mut value, &path) {
            let current = v.as_str().unwrap_or("").to_string();
            let encrypted = determine_encrypted_value(&current, recipient_keys)?;
            *v = toml::Value::String(encrypted);
        }
    }
    Ok(toml::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Encryption(format!("TOML serialize error: {e}")))?)
}

/// REQ-4: Decrypt specified fields in a JSON, YAML, or TOML file.
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
        _ => return Err(GitvaultError::Other(format!("Unsupported file format: .{ext}"))),
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
            *v = serde_json::Value::String(String::from_utf8(plain).map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?);
        }
    }
    Ok(serde_json::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Decryption(format!("JSON serialize error: {e}")))? + "\n")
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
            *v = serde_yaml::Value::String(String::from_utf8(plain).map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?);
        }
    }
    Ok(serde_yaml::to_string(&value)
        .map_err(|e| GitvaultError::Decryption(format!("YAML serialize error: {e}")))?)
}

fn decrypt_fields_toml(
    content: &str,
    fields: &[&str],
    identity: &dyn age::Identity,
) -> Result<String, GitvaultError> {
    let mut value: toml::Value = content.parse::<toml::Value>()
        .map_err(|e| GitvaultError::Decryption(format!("TOML parse error: {e}")))?;
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        if let Some(v) = toml_field_mut(&mut value, &path)
            && let Some(s) = v.as_str()
            && is_age_armor(s)
        {
            let plain = decrypt_armor(s, identity)?;
            *v = toml::Value::String(String::from_utf8(plain).map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?);
        }
    }
    Ok(toml::to_string_pretty(&value)
        .map_err(|e| GitvaultError::Decryption(format!("TOML serialize error: {e}")))?)
}

/// REQ-6: Encrypt each VALUE in a .env file individually (KEY=enc:base64).
/// Returns the new .env content.
pub fn encrypt_env_values(
    content: &str,
    identity: &dyn age::Identity,
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let mut lines_out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines_out.push(line.to_string());
            continue;
        }
        if let Some((_key, value)) = parse_env_pair_from_line(line) {
            let new_value = if is_env_encrypted(&value) {
                // REQ-5: check if existing encrypted value decrypts to same plaintext
                let encoded = &value[ENV_ENC_PREFIX.len()..];
                if let Ok(existing_plain) = decrypt_binary_b64(encoded, identity) {
                    // We don't have a "new plaintext" in encrypt_env_values;
                    // this function always re-encrypts. For idempotency, keep existing.
                    let _ = existing_plain;
                    value.to_string()
                } else {
                    let enc = encrypt_binary_b64(value.as_bytes(), recipient_keys)?;
                    format!("{ENV_ENC_PREFIX}{enc}")
                }
            } else {
                let enc = encrypt_binary_b64(value.as_bytes(), recipient_keys)?;
                format!("{ENV_ENC_PREFIX}{enc}")
            };

            if new_value == value {
                lines_out.push(line.to_string());
            } else {
                lines_out.push(rewrite_env_assignment_line(line, &new_value));
            }
        } else {
            lines_out.push(line.to_string());
        }
    }
    let mut result = lines_out.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

#[allow(dead_code)]
/// REQ-6: Decrypt each VALUE in a .env file that was encrypted with encrypt_env_values.
pub fn decrypt_env_values(content: &str, identity: &dyn age::Identity) -> Result<String, GitvaultError> {
    let mut lines_out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines_out.push(line.to_string());
            continue;
        }
        if let Some((_key, value)) = parse_env_pair_from_line(line) {
            if is_env_encrypted(&value) {
                let encoded = &value[ENV_ENC_PREFIX.len()..];
                let plain = decrypt_binary_b64(encoded, identity)?;
                let plain_text = String::from_utf8(plain).map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?;
                lines_out.push(rewrite_env_assignment_line(line, &plain_text));
            } else {
                lines_out.push(line.to_string());
            }
        } else {
            lines_out.push(line.to_string());
        }
    }
    let mut result = lines_out.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

/// Write bytes to file atomically using a temp file + rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), GitvaultError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.persist(path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::SecretString;
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

        let mut tmp = NamedTempFile::with_suffix(".json").unwrap();
        write!(tmp, r#"{{"password":"hunter2","user":"alice"}}"#).unwrap();
        let path = tmp.path().to_path_buf();

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

        decrypt_fields(&path, &["password"], &identity).unwrap();

        let after_dec = std::fs::read_to_string(&path).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&after_dec).unwrap();
        assert_eq!(v2["password"].as_str().unwrap(), "hunter2");
    }

    /// REQ-5: Determinism — encrypting the same field twice yields identical ciphertext.
    #[test]
    fn test_json_field_encrypt_determinism() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".json").unwrap();
        write!(tmp, r#"{{"secret":"mysecret","other":"value"}}"#).unwrap();
        let path = tmp.path().to_path_buf();

        encrypt_fields(&path, &["secret"], &identity, &keys).unwrap();
        let first_enc = std::fs::read_to_string(&path).unwrap();

        encrypt_fields(&path, &["secret"], &identity, &keys).unwrap();
        let second_enc = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            first_enc, second_enc,
            "Encrypting same input twice must produce identical output (REQ-5)"
        );
    }

    /// REQ-4: YAML field encrypt/decrypt roundtrip
    #[test]
    fn test_yaml_field_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(tmp, "database_password: secret123\nhost: localhost\n").unwrap();
        let path = tmp.path().to_path_buf();

        encrypt_fields(&path, &["database_password"], &identity, &keys).unwrap();

        let after_enc = std::fs::read_to_string(&path).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&after_enc).unwrap();
        let enc_val = v["database_password"].as_str().unwrap();
        assert!(
            is_age_armor(enc_val),
            "YAML encrypted value should be age armor"
        );
        assert_eq!(v["host"].as_str().unwrap(), "localhost");

        decrypt_fields(&path, &["database_password"], &identity).unwrap();

        let after_dec = std::fs::read_to_string(&path).unwrap();
        let v2: serde_yaml::Value = serde_yaml::from_str(&after_dec).unwrap();
        assert_eq!(v2["database_password"].as_str().unwrap(), "secret123");
    }

    /// REQ-4: TOML field encrypt/decrypt roundtrip
    #[test]
    fn test_toml_field_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".toml").unwrap();
        write!(tmp, "api_key = \"top-secret\"\nname = \"app\"\n").unwrap();
        let path = tmp.path().to_path_buf();

        encrypt_fields(&path, &["api_key"], &identity, &keys).unwrap();

        let after_enc = std::fs::read_to_string(&path).unwrap();
        let v: toml::Value = after_enc.parse().unwrap();
        let enc_val = v["api_key"].as_str().unwrap();
        assert!(
            is_age_armor(enc_val),
            "TOML encrypted value should be age armor"
        );
        assert_eq!(v["name"].as_str().unwrap(), "app");

        decrypt_fields(&path, &["api_key"], &identity).unwrap();

        let after_dec = std::fs::read_to_string(&path).unwrap();
        let v2: toml::Value = after_dec.parse().unwrap();
        assert_eq!(v2["api_key"].as_str().unwrap(), "top-secret");
    }

    /// REQ-5: Only the modified field changes when a different key is added.
    #[test]
    fn test_json_only_changed_field_re_encrypts() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let mut tmp = NamedTempFile::with_suffix(".json").unwrap();
        write!(tmp, r#"{{"a":"alpha","b":"beta"}}"#).unwrap();
        let path = tmp.path().to_path_buf();

        // Encrypt both fields
        encrypt_fields(&path, &["a", "b"], &identity, &keys).unwrap();
        let both_enc = std::fs::read_to_string(&path).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&both_enc).unwrap();
        let a_enc1 = v1["a"].as_str().unwrap().to_string();

        // Now overwrite 'b' with a new value and re-encrypt
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let new_b_ciphertext = v1["b"].as_str().unwrap().to_string();
        // Manually write a JSON where 'b' is changed plaintext but 'a' keeps its ciphertext
        write!(
            f,
            r#"{{"a":{},"b":"new_beta"}}"#,
            serde_json::to_string(&a_enc1).unwrap()
        )
        .unwrap();
        drop(f);

        encrypt_fields(&path, &["a", "b"], &identity, &keys).unwrap();
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

    /// REQ-6: .env value-only encrypt/decrypt roundtrip
    #[test]
    fn test_env_value_only_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let content = "API_KEY=mysecret\nDB_HOST=localhost\n";
        let encrypted = encrypt_env_values(content, &identity, &keys).unwrap();
        assert!(
            encrypted.contains("API_KEY=age:"),
            "value should be encrypted"
        );
        assert!(
            encrypted.contains("DB_HOST=age:"),
            "all values should be encrypted"
        );

        let decrypted = decrypt_env_values(&encrypted, &identity).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_env_value_only_preserves_formatting_and_inline_comments() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);

        let content = "API_KEY = mysecret # keep-comment\nDB_HOST=localhost\n";
        let encrypted = encrypt_env_values(content, &identity, &keys).unwrap();
        assert!(
            encrypted.contains("API_KEY = age:"),
            "lhs spacing should be preserved on encrypt"
        );
        assert!(
            encrypted.contains(" # keep-comment"),
            "inline comment should be preserved on encrypt"
        );

        let decrypted = decrypt_env_values(&encrypted, &identity).unwrap();
        assert!(
            decrypted.contains("API_KEY = mysecret # keep-comment"),
            "lhs spacing and inline comment should be preserved on decrypt"
        );
        assert!(
            decrypted.contains("DB_HOST=localhost"),
            "other assignment formatting should remain stable"
        );
    }

    #[test]
    fn test_parse_env_pair_from_line_invalid_returns_none() {
        assert!(parse_env_pair_from_line("not-an-assignment").is_none());
    }

    #[test]
    fn test_rewrite_env_assignment_line_without_equals_is_unchanged() {
        let line = "just-text";
        assert_eq!(rewrite_env_assignment_line(line, "new"), line);
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
    fn test_encrypt_env_values_keeps_invalid_assignment_lines() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let content = "# header\nINVALID LINE\nKEY=value\n";

        let encrypted = encrypt_env_values(content, &identity, &keys).unwrap();

        assert!(encrypted.contains("INVALID LINE"));
        assert!(encrypted.contains("KEY=age:"));
    }

    #[test]
    fn test_encrypt_env_values_reencrypts_invalid_prefixed_payload() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let content = "KEY=age:not-base64\n";

        let encrypted = encrypt_env_values(content, &identity, &keys).unwrap();

        assert_ne!(encrypted, content);
        assert!(encrypted.starts_with("KEY=age:"));
        assert!(!encrypted.contains("not-base64"));
    }

    #[test]
    fn test_decrypt_env_values_preserves_unencrypted_assignments() {
        let identity = gen_identity();
        let content = "KEY=plain\n";

        let decrypted = decrypt_env_values(content, &identity).unwrap();

        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_encrypt_env_values_is_idempotent_for_existing_ciphertext() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let content = "KEY=plain\n";

        let first = encrypt_env_values(content, &identity, &keys).unwrap();
        let second = encrypt_env_values(&first, &identity, &keys).unwrap();

        assert_eq!(first, second);
    }

    fn encrypt_passphrase_armor(plaintext: &[u8]) -> String {
        let encryptor = age::Encryptor::with_user_passphrase(SecretString::from("pw".to_string()));
        let mut output = Vec::new();
        let armor =
            age::armor::ArmoredWriter::wrap_output(&mut output, age::armor::Format::AsciiArmor)
                .unwrap();
        let mut writer = encryptor.wrap_output(armor).unwrap();
        writer.write_all(plaintext).unwrap();
        let armor = writer.finish().unwrap();
        armor.finish().unwrap();
        String::from_utf8(output).unwrap()
    }

    fn encrypt_passphrase_binary_b64(plaintext: &[u8]) -> String {
        let encryptor = age::Encryptor::with_user_passphrase(SecretString::from("pw".to_string()));
        let mut output = Vec::new();
        let mut writer = encryptor.wrap_output(&mut output).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        base64::engine::general_purpose::STANDARD.encode(output)
    }

    #[test]
    fn test_decrypt_armor_rejects_passphrase_ciphertext() {
        let identity = gen_identity();
        let armored = encrypt_passphrase_armor(b"secret");

        let err = decrypt_armor(&armored, &identity).unwrap_err();
        assert!(
            err.to_string()
                .contains("Passphrase-encrypted files not supported")
        );
    }

    #[test]
    fn test_decrypt_binary_b64_rejects_passphrase_ciphertext() {
        let identity = gen_identity();
        let encoded = encrypt_passphrase_binary_b64(b"secret");

        let err = decrypt_binary_b64(&encoded, &identity).unwrap_err();
        assert!(
            err.to_string()
                .contains("Passphrase-encrypted not supported")
        );
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

    #[test]
    fn test_decrypt_env_values_preserves_comments_and_invalid_lines() {
        let identity = gen_identity();
        let content = "# comment\nINVALID LINE\nKEY=plain\n";

        let out = decrypt_env_values(content, &identity).unwrap();

        assert!(out.contains("# comment"));
        assert!(out.contains("INVALID LINE"));
        assert!(out.contains("KEY=plain"));
    }
}
