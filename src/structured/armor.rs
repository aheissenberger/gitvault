use crate::defaults::MAX_RECIPIENTS;
use crate::error::GitvaultError;
use base64::Engine;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Truncate a recipient key to the first 8 chars + `…` for use in error messages.
/// Avoids logging full public key material while keeping the prefix identifiable.
fn truncate_key_for_log(k: &str) -> String {
    if k.len() > 8 {
        format!("{}…", &k[..8])
    } else {
        k.to_string()
    }
}

/// Encrypt plaintext bytes using age ASCII armor. Returns the armor text.
///
/// # Errors
///
/// Returns [`GitvaultError::Encryption`] if `recipient_keys` is empty, exceeds
/// [`MAX_RECIPIENTS`], contains an invalid key, or if the age encryption fails.
pub fn encrypt_armor(plaintext: &[u8], recipient_keys: &[String]) -> Result<String, GitvaultError> {
    if recipient_keys.len() > MAX_RECIPIENTS {
        return Err(GitvaultError::Encryption(format!(
            "recipient count {} exceeds limit {}",
            recipient_keys.len(),
            MAX_RECIPIENTS
        )));
    }
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r: age::x25519::Recipient = k.parse().map_err(|e| {
                GitvaultError::Encryption(format!(
                    "Invalid recipient key {}: {e}",
                    truncate_key_for_log(k)
                ))
            })?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    {
        let armor =
            age::armor::ArmoredWriter::wrap_output(&mut output, age::armor::Format::AsciiArmor)?;
        let mut writer = encryptor
            .wrap_output(armor)
            .map_err(|e| GitvaultError::Encryption(format!("age encryption wrapping: {e}")))?;
        writer.write_all(plaintext)?;
        let armor = writer.finish()?;
        armor.finish()?;
    }
    String::from_utf8(output)
        .map_err(|e| GitvaultError::Encryption(format!("age armor output is not valid UTF-8: {e}")))
}

/// Decrypt an age armor string using the given identity.
///
/// Returns the decrypted bytes in a [`Zeroizing`] wrapper so the plaintext
/// is overwritten with zeros when the value is dropped (REQ-78).
pub fn decrypt_armor(
    armored: &str,
    identity: &dyn age::Identity,
) -> Result<Zeroizing<Vec<u8>>, GitvaultError> {
    let armor = age::armor::ArmoredReader::new(armored.as_bytes());
    let decryptor = age::Decryptor::new(armor)
        .map_err(|e| GitvaultError::Decryption(format!("Decryptor create: {e}")))?;
    let mut reader = match decryptor {
        age::Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(identity))
            .map_err(|e| GitvaultError::Decryption(format!("Decrypt: {e}")))?,
        age::Decryptor::Passphrase(_) => {
            return Err(GitvaultError::Decryption(
                "Passphrase-encrypted files not supported".to_string(),
            ));
        }
    };
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GitvaultError::Decryption(format!("Read decrypted: {e}")))?;
    Ok(plaintext)
}

/// Encrypt plaintext bytes using binary age (no armor), returning base64-encoded result.
///
/// # Errors
///
/// Returns [`GitvaultError::Encryption`] if `recipient_keys` exceeds [`MAX_RECIPIENTS`],
/// contains an invalid key, or if the age encryption fails.
pub fn encrypt_binary_b64(
    plaintext: &[u8],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    if recipient_keys.len() > MAX_RECIPIENTS {
        return Err(GitvaultError::Encryption(format!(
            "recipient count {} exceeds limit {}",
            recipient_keys.len(),
            MAX_RECIPIENTS
        )));
    }
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r: age::x25519::Recipient = k.parse().map_err(|e| {
                GitvaultError::Encryption(format!(
                    "Invalid recipient key {}: {e}",
                    truncate_key_for_log(k)
                ))
            })?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| GitvaultError::Encryption(format!("age binary encryption wrapping: {e}")))?;
    writer.write_all(plaintext)?;
    writer.finish()?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&output))
}

/// Decrypt binary age (base64-encoded) using the given identity.
///
/// Returns the decrypted bytes in a [`Zeroizing`] wrapper so the plaintext
/// is overwritten with zeros when the value is dropped (REQ-78).
pub fn decrypt_binary_b64(
    encoded: &str,
    identity: &dyn age::Identity,
) -> Result<Zeroizing<Vec<u8>>, GitvaultError> {
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
            return Err(GitvaultError::Decryption(
                "Passphrase-encrypted not supported".to_string(),
            ));
        }
    };
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GitvaultError::Decryption(format!("Read decrypted: {e}")))?;
    Ok(plaintext)
}
#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::SecretString;
    use age::x25519;
    use std::io::Write;

    fn gen_identity() -> x25519::Identity {
        x25519::Identity::generate()
    }

    fn identity_to_recipient_keys(identity: &x25519::Identity) -> Vec<String> {
        vec![identity.to_public().to_string()]
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
    fn test_armor_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let plain = b"hello world";

        let armored = encrypt_armor(plain, &keys).unwrap();
        let decrypted = decrypt_armor(&armored, &identity).unwrap();
        assert_eq!(*decrypted, plain as &[u8]);
    }

    #[test]
    fn test_binary_b64_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let plain = b"hello world";

        let encoded = encrypt_binary_b64(plain, &keys).unwrap();
        let decrypted = decrypt_binary_b64(&encoded, &identity).unwrap();
        assert_eq!(*decrypted, plain as &[u8]);
    }

    // ── invalid recipient key ────────────────────────────────────────────────

    #[test]
    fn test_encrypt_armor_invalid_key_errors() {
        let keys = vec!["not-a-valid-age-key".to_string()];
        let err = encrypt_armor(b"data", &keys).unwrap_err();
        assert!(
            err.to_string().contains("Invalid recipient key"),
            "got: {err}"
        );
    }

    #[test]
    fn test_encrypt_binary_b64_invalid_key_errors() {
        let keys = vec!["not-a-valid-age-key".to_string()];
        let err = encrypt_binary_b64(b"data", &keys).unwrap_err();
        assert!(
            err.to_string().contains("Invalid recipient key"),
            "got: {err}"
        );
    }

    // ── empty recipients ─────────────────────────────────────────────────────

    #[test]
    fn test_encrypt_armor_no_recipients_errors() {
        let err = encrypt_armor(b"data", &[]).unwrap_err();
        assert!(
            err.to_string().contains("At least one recipient"),
            "got: {err}"
        );
    }

    #[test]
    fn test_encrypt_binary_b64_no_recipients_errors() {
        let err = encrypt_binary_b64(b"data", &[]).unwrap_err();
        assert!(
            err.to_string().contains("At least one recipient"),
            "got: {err}"
        );
    }

    // ── REQ-83: recipient count limit ────────────────────────────────────────

    #[test]
    fn test_encrypt_armor_over_limit_errors() {
        let identity = gen_identity();
        let key = identity_to_recipient_keys(&identity)[0].clone();
        let keys: Vec<String> = (0..=MAX_RECIPIENTS).map(|_| key.clone()).collect();
        let err = encrypt_armor(b"data", &keys).unwrap_err();
        assert!(err.to_string().contains("exceeds limit"), "got: {err}");
    }

    #[test]
    fn test_encrypt_binary_b64_over_limit_errors() {
        let identity = gen_identity();
        let key = identity_to_recipient_keys(&identity)[0].clone();
        let keys: Vec<String> = (0..=MAX_RECIPIENTS).map(|_| key.clone()).collect();
        let err = encrypt_binary_b64(b"data", &keys).unwrap_err();
        assert!(err.to_string().contains("exceeds limit"), "got: {err}");
    }

    // ── REQ-84: truncate_key_for_log ─────────────────────────────────────────

    #[test]
    fn test_truncate_key_for_log_long_key() {
        let key = "AGE-SECRET-KEY-1234567890";
        let truncated = truncate_key_for_log(key);
        assert_eq!(truncated, "AGE-SECR…");
    }

    #[test]
    fn test_truncate_key_for_log_short_key() {
        let key = "short";
        let truncated = truncate_key_for_log(key);
        assert_eq!(truncated, "short");
    }

    #[test]
    fn test_encrypt_armor_invalid_key_truncates_in_error() {
        // REQ-84: error message must NOT contain the full (long) key.
        let fake_key = format!("{:0>64}", "bad-key-padding");
        let keys = vec![fake_key.clone()];
        let err = encrypt_armor(b"data", &keys).unwrap_err();
        let msg = err.to_string();
        // The error should contain the truncated form (first 8 chars + ellipsis) not the full key.
        assert!(!msg.contains(&fake_key), "full key leaked in error: {msg}");
    }

    // ── wrong identity (decrypt with a different key) ────────────────────────

    #[test]
    fn test_decrypt_armor_wrong_identity_errors() {
        let enc_id = gen_identity();
        let keys = identity_to_recipient_keys(&enc_id);
        let wrong_id = gen_identity();

        let armored = encrypt_armor(b"secret", &keys).unwrap();
        let err = decrypt_armor(&armored, &wrong_id).unwrap_err();
        assert!(err.to_string().contains("Decrypt"), "got: {err}");
    }

    #[test]
    fn test_decrypt_binary_b64_wrong_identity_errors() {
        let enc_id = gen_identity();
        let keys = identity_to_recipient_keys(&enc_id);
        let wrong_id = gen_identity();

        let encoded = encrypt_binary_b64(b"secret", &keys).unwrap();
        let err = decrypt_binary_b64(&encoded, &wrong_id).unwrap_err();
        assert!(err.to_string().contains("Decrypt"), "got: {err}");
    }

    // ── malformed ciphertext (Decryptor::new failure) ────────────────────────

    #[test]
    fn test_decrypt_armor_malformed_input_errors() {
        let identity = gen_identity();
        // Valid base structure but garbage body — Decryptor::new must fail
        let err = decrypt_armor(
            "-----BEGIN AGE ENCRYPTED FILE-----\ngarbage\n-----END AGE ENCRYPTED FILE-----\n",
            &identity,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Decryptor create") || err.to_string().contains("Decrypt"),
            "got: {err}"
        );
    }

    #[test]
    fn test_decrypt_binary_b64_malformed_ciphertext_errors() {
        let identity = gen_identity();
        // Valid base64 of non-age data — Decryptor::new must fail
        let garbage_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"this is not age ciphertext at all");
        let err = decrypt_binary_b64(&garbage_b64, &identity).unwrap_err();
        assert!(
            err.to_string().contains("Decryptor create") || err.to_string().contains("Decrypt"),
            "got: {err}"
        );
    }
}
