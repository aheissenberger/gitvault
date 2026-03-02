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
    String::from_utf8(output).map_err(|e| GitvaultError::Encryption(format!("UTF-8 error: {e}")))
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
        .map_err(|e| GitvaultError::Encryption(format!("Encrypt wrap: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| GitvaultError::Encryption(format!("Encrypt write: {e}")))?;
    writer
        .finish()
        .map_err(|e| GitvaultError::Encryption(format!("Encrypt finish: {e}")))?;

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
}
