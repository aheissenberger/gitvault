use crate::error::GitvaultError;
use crate::merge::{parse_env_pair_from_line, rewrite_env_assignment_line};

use super::armor::{decrypt_binary_b64, encrypt_binary_b64};
use super::helpers::{ENV_ENC_PREFIX, is_env_encrypted};

/// REQ-6: Encrypt each VALUE in a .env file individually (KEY=enc:base64).
/// Returns the new .env content.
///
/// # Errors
///
/// Returns [`GitvaultError::Decryption`] if an existing encrypted value cannot be
/// decrypted by `identity`. Returns [`GitvaultError::Encryption`] if a new value
/// cannot be encrypted.
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
                    value.clone()
                } else {
                    return Err(GitvaultError::Decryption(
                        "existing ciphertext cannot be decrypted by current identity - re-encrypt from plaintext source after key rotation".to_string(),
                    ));
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

/// REQ-6: Decrypt each VALUE in a .env file that was encrypted with `encrypt_env_values`.
///
/// # Errors
///
/// Returns [`GitvaultError::Decryption`] if any encrypted value cannot be decrypted
/// by `identity` or the decrypted bytes are not valid UTF-8.
pub fn decrypt_env_values(
    content: &str,
    identity: &dyn age::Identity,
) -> Result<String, GitvaultError> {
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
                let plain_text = String::from_utf8(plain.to_vec())
                    .map_err(|e| GitvaultError::Decryption(format!("UTF-8 error: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::parse_env_pair_from_line;
    use crate::merge::rewrite_env_assignment_line;
    use age::x25519;

    fn gen_identity() -> x25519::Identity {
        x25519::Identity::generate()
    }

    fn identity_to_recipient_keys(identity: &x25519::Identity) -> Vec<String> {
        vec![identity.to_public().to_string()]
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

        let result = encrypt_env_values(content, &identity, &keys);

        assert!(
            result.is_err(),
            "should return an error when existing ciphertext cannot be decrypted"
        );
        match result.unwrap_err() {
            GitvaultError::Decryption(msg) => assert!(
                msg.contains("existing ciphertext cannot be decrypted by current identity"),
                "unexpected error message: {msg}"
            ),
            e => panic!("expected Decryption error, got {e:?}"),
        }
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
