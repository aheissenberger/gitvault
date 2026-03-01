use age::{x25519, Decryptor, Encryptor};
use crate::error::GitvaultError;
use std::io::{Read, Write};

/// Gitvault encrypted format version (REQ-55).
/// Increment when the encryption format changes incompatibly.
pub const GITVAULT_FORMAT_VERSION: u32 = 1;

/// Parse an age X25519 public key string into a Recipient.
pub fn parse_recipient(pubkey: &str) -> Result<x25519::Recipient, GitvaultError> {
    pubkey
        .parse::<x25519::Recipient>()
        .map_err(|e| GitvaultError::Encryption(format!("Invalid recipient key: {e}")))
}

/// Parse an age X25519 identity (private key) from a string.
pub fn parse_identity(privkey: &str) -> Result<x25519::Identity, GitvaultError> {
    privkey
        .parse::<x25519::Identity>()
        .map_err(|e| GitvaultError::Decryption(format!("Invalid identity key: {e}")))
}

/// Encrypt plaintext bytes using age format with multiple recipients.
/// REQ-1: uses age file format. REQ-2: native Rust. REQ-3: multi-recipient.
pub fn encrypt(
    recipients: Vec<Box<dyn age::Recipient + Send>>,
    plaintext: &[u8],
) -> Result<Vec<u8>, GitvaultError> {
    let encryptor = Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;

    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| GitvaultError::Encryption(format!("Failed to create encrypted writer: {e}")))?;

    writer
        .write_all(plaintext)
        .map_err(|e| GitvaultError::Encryption(format!("Failed to write plaintext: {e}")))?;
    writer
        .finish()
        .map_err(|e| GitvaultError::Encryption(format!("Failed to finalize encryption: {e}")))?;

    Ok(output)
}

/// Decrypt age-encrypted bytes using an identity.
pub fn decrypt(identity: &dyn age::Identity, ciphertext: &[u8]) -> Result<Vec<u8>, GitvaultError> {
    let decryptor = Decryptor::new(ciphertext)
        .map_err(|e| GitvaultError::Decryption(format!("Failed to create decryptor: {e}")))?;

    let mut reader = match decryptor {
        Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(identity))
            .map_err(|e| GitvaultError::Decryption(format!("Decryption failed: {e}")))?,
        Decryptor::Passphrase(_) => {
            return Err(GitvaultError::Decryption(
                "Passphrase-encrypted files not supported".to_string(),
            ));
        }
    };

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| GitvaultError::Decryption(format!("Failed to read decrypted data: {e}")))?;

    Ok(plaintext)
}

/// REQ-51: Streaming encryption from a reader to a writer.
pub fn encrypt_stream(
    recipients: Vec<Box<dyn age::Recipient + Send>>,
    reader: &mut impl std::io::Read,
    writer: &mut impl std::io::Write,
) -> Result<(), GitvaultError> {
    let encryptor = Encryptor::with_recipients(recipients)
        .ok_or_else(|| GitvaultError::Encryption("At least one recipient required".to_string()))?;
    let mut age_writer = encryptor
        .wrap_output(writer)
        .map_err(|e| GitvaultError::Encryption(format!("Failed to create encrypted writer: {e}")))?;
    std::io::copy(reader, &mut age_writer)
        .map_err(|e| GitvaultError::Encryption(format!("Failed to stream plaintext: {e}")))?;
    age_writer
        .finish()
        .map_err(|e| GitvaultError::Encryption(format!("Failed to finalize encryption: {e}")))?;
    Ok(())
}

/// REQ-51: Streaming decryption from a reader to a writer.
pub fn decrypt_stream(
    identity: &dyn age::Identity,
    reader: impl std::io::Read,
    writer: &mut impl std::io::Write,
) -> Result<(), GitvaultError> {
    let decryptor = Decryptor::new(reader)
        .map_err(|e| GitvaultError::Decryption(format!("Failed to create decryptor: {e}")))?;
    let mut age_reader = match decryptor {
        Decryptor::Recipients(d) => d
            .decrypt(std::iter::once(identity))
            .map_err(|e| GitvaultError::Decryption(format!("Decryption failed: {e}")))?,
        Decryptor::Passphrase(_) => {
            return Err(GitvaultError::Decryption(
                "Passphrase-encrypted files not supported".to_string(),
            ));
        }
    };
    std::io::copy(&mut age_reader, writer)
        .map_err(|e| GitvaultError::Decryption(format!("Failed to stream plaintext: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_identity() -> x25519::Identity {
        x25519::Identity::generate()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        let plaintext = b"SECRET_KEY=hunter2\nDB_PASSWORD=correct-horse-battery-staple";
        let ciphertext = encrypt(vec![recipient], plaintext).expect("encrypt failed");

        assert!(
            !ciphertext.windows(10).any(|w| w == b"SECRET_KEY"),
            "ciphertext should not contain plaintext"
        );

        let decrypted = decrypt(&identity, &ciphertext).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multi_recipient_encrypt_decrypt() {
        let identity1 = gen_identity();
        let identity2 = gen_identity();

        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![
            Box::new(identity1.to_public()),
            Box::new(identity2.to_public()),
        ];

        let plaintext = b"MULTI_RECIPIENT_SECRET=value";
        let ciphertext = encrypt(recipients, plaintext).expect("encrypt failed");

        let decrypted1 = decrypt(&identity1, &ciphertext).expect("identity1 decrypt failed");
        let decrypted2 = decrypt(&identity2, &ciphertext).expect("identity2 decrypt failed");

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_wrong_identity_fails() {
        let identity = gen_identity();
        let wrong_identity = gen_identity();

        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());
        let plaintext = b"SECRET=value";
        let ciphertext = encrypt(vec![recipient], plaintext).expect("encrypt failed");

        let result = decrypt(&wrong_identity, &ciphertext);
        assert!(result.is_err(), "decryption with wrong identity should fail");
    }

    #[test]
    fn test_empty_recipients_fails() {
        let plaintext = b"SECRET=value";
        let result = encrypt(vec![], plaintext);
        assert!(result.is_err(), "encryption with no recipients should fail");
    }

    #[test]
    fn test_parse_recipient_roundtrip() {
        let identity = gen_identity();
        let pubkey = identity.to_public().to_string();
        let parsed = parse_recipient(&pubkey).expect("parse failed");

        let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(parsed)];
        let plaintext = b"test";
        let ciphertext = encrypt(recipients, plaintext).expect("encrypt failed");
        let decrypted = decrypt(&identity, &ciphertext).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_stream_decrypt_stream_roundtrip() {
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        let plaintext = b"STREAM_SECRET=hunter2\nDB_PASSWORD=correct-horse";
        let mut reader = std::io::Cursor::new(plaintext.as_ref());
        let mut ciphertext = Vec::new();
        encrypt_stream(vec![recipient], &mut reader, &mut ciphertext).expect("encrypt_stream failed");

        assert!(!ciphertext.windows(10).any(|w| w == b"STREAM_SEC"), "ciphertext should not contain plaintext");

        let mut decrypted = Vec::new();
        decrypt_stream(&identity, std::io::Cursor::new(&ciphertext), &mut decrypted).expect("decrypt_stream failed");
        assert_eq!(decrypted, plaintext);
    }
}
