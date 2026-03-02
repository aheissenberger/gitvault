use crate::error::GitvaultError;
use base64::Engine;
use std::io::{Read, Write};

/// Encrypt plaintext bytes using age ASCII armor. Returns the armor text.
pub(crate) fn encrypt_armor(
    plaintext: &[u8],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r: age::x25519::Recipient = k.parse().map_err(|e| {
                GitvaultError::Encryption(format!("Invalid recipient key {k}: {e}"))
            })?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    {
        // ArmoredWriter on a Vec<u8> is infallible; the Result is a type-system artefact.
        let armor =
            age::armor::ArmoredWriter::wrap_output(&mut output, age::armor::Format::AsciiArmor)
                .expect("ArmoredWriter on Vec<u8> is infallible");
        let mut writer = encryptor
            .wrap_output(armor)
            .expect("age encryption wrapping is infallible");
        writer
            .write_all(plaintext)
            .expect("Vec<u8> write is infallible");
        let armor = writer
            .finish()
            .expect("age encryption finalize is infallible");
        armor
            .finish()
            .expect("ArmoredWriter finalize is infallible");
    }
    // age ASCII armor is always valid UTF-8
    Ok(String::from_utf8(output).expect("age armor output is always UTF-8"))
}

/// Decrypt an age armor string using the given identity.
pub(crate) fn decrypt_armor(
    armored: &str,
    identity: &dyn age::Identity,
) -> Result<Vec<u8>, GitvaultError> {
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
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GitvaultError::Decryption(format!("Read decrypted: {e}")))?;
    Ok(plaintext)
}

/// Encrypt plaintext bytes using binary age (no armor), returning base64-encoded result.
pub(crate) fn encrypt_binary_b64(
    plaintext: &[u8],
    recipient_keys: &[String],
) -> Result<String, GitvaultError> {
    let recipients: Vec<Box<dyn age::Recipient + Send>> = recipient_keys
        .iter()
        .map(|k| {
            let r: age::x25519::Recipient = k.parse().map_err(|e| {
                GitvaultError::Encryption(format!("Invalid recipient key {k}: {e}"))
            })?;
            Ok(Box::new(r) as Box<dyn age::Recipient + Send>)
        })
        .collect::<Result<Vec<_>, GitvaultError>>()?;

    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .expect("age binary encryption wrapping is infallible");
    writer
        .write_all(plaintext)
        .expect("Vec<u8> write is infallible");
    writer
        .finish()
        .expect("age binary encryption finalize is infallible");

    Ok(base64::engine::general_purpose::STANDARD.encode(&output))
}

pub(crate) fn decrypt_binary_b64(
    encoded: &str,
    identity: &dyn age::Identity,
) -> Result<Vec<u8>, GitvaultError> {
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
    let mut plaintext = Vec::new();
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
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_binary_b64_roundtrip() {
        let identity = gen_identity();
        let keys = identity_to_recipient_keys(&identity);
        let plain = b"hello world";

        let encoded = encrypt_binary_b64(plain, &keys).unwrap();
        let decrypted = decrypt_binary_b64(&encoded, &identity).unwrap();
        assert_eq!(decrypted, plain);
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
        let err = decrypt_armor("-----BEGIN AGE ENCRYPTED FILE-----\ngarbage\n-----END AGE ENCRYPTED FILE-----\n", &identity).unwrap_err();
        assert!(
            err.to_string().contains("Decryptor create") || err.to_string().contains("Decrypt"),
            "got: {err}"
        );
    }

    #[test]
    fn test_decrypt_binary_b64_malformed_ciphertext_errors() {
        let identity = gen_identity();
        // Valid base64 of non-age data — Decryptor::new must fail
        let garbage_b64 = base64::engine::general_purpose::STANDARD.encode(b"this is not age ciphertext at all");
        let err = decrypt_binary_b64(&garbage_b64, &identity).unwrap_err();
        assert!(
            err.to_string().contains("Decryptor create") || err.to_string().contains("Decrypt"),
            "got: {err}"
        );
    }
}
