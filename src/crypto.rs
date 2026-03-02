use crate::error::GitvaultError;
use age::{Decryptor, Encryptor, x25519};
use std::io::Read;

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
    let mut reader = std::io::Cursor::new(plaintext);
    let mut output = Vec::new();
    encrypt_stream(recipients, &mut reader, &mut output)?;
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
    let mut age_writer = encryptor.wrap_output(writer).map_err(|e| {
        GitvaultError::Encryption(format!("Failed to create encrypted writer: {e}"))
    })?;
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
    use age::secrecy::SecretString;
    use std::io::Write;

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
        assert!(
            result.is_err(),
            "decryption with wrong identity should fail"
        );
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
        encrypt_stream(vec![recipient], &mut reader, &mut ciphertext)
            .expect("encrypt_stream failed");

        assert!(
            !ciphertext.windows(10).any(|w| w == b"STREAM_SEC"),
            "ciphertext should not contain plaintext"
        );

        let mut decrypted = Vec::new();
        decrypt_stream(&identity, std::io::Cursor::new(&ciphertext), &mut decrypted)
            .expect("decrypt_stream failed");
        assert_eq!(decrypted, plaintext);
    }

    fn encrypt_with_passphrase_binary(plaintext: &[u8]) -> Vec<u8> {
        let encryptor = Encryptor::with_user_passphrase(SecretString::from("pw".to_string()));
        let mut output = Vec::new();
        let mut writer = encryptor.wrap_output(&mut output).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        output
    }

    #[test]
    fn test_decrypt_rejects_passphrase_ciphertext() {
        let identity = gen_identity();
        let ciphertext = encrypt_with_passphrase_binary(b"secret");

        let result = decrypt(&identity, &ciphertext);
        assert!(matches!(result, Err(GitvaultError::Decryption(_))));
    }

    #[test]
    fn test_decrypt_stream_rejects_passphrase_ciphertext() {
        let identity = gen_identity();
        let ciphertext = encrypt_with_passphrase_binary(b"secret");
        let mut out = Vec::new();

        let result = decrypt_stream(&identity, std::io::Cursor::new(ciphertext), &mut out);
        assert!(matches!(result, Err(GitvaultError::Decryption(_))));
    }

    #[test]
    fn test_decrypt_stream_wrong_identity_fails() {
        let identity = gen_identity();
        let wrong_identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());

        let mut reader = std::io::Cursor::new(b"STREAM_SECRET=1\n".to_vec());
        let mut ciphertext = Vec::new();
        encrypt_stream(vec![recipient], &mut reader, &mut ciphertext)
            .expect("encrypt_stream failed");

        let mut decrypted = Vec::new();
        let result = decrypt_stream(
            &wrong_identity,
            std::io::Cursor::new(ciphertext),
            &mut decrypted,
        );
        assert!(matches!(result, Err(GitvaultError::Decryption(_))));
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("write failed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_encrypt_stream_fails_when_output_writer_errors() {
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());
        let mut reader = std::io::Cursor::new(b"x".to_vec());
        let mut writer = FailingWriter;

        let result = encrypt_stream(vec![recipient], &mut reader, &mut writer);
        assert!(matches!(result, Err(GitvaultError::Encryption(_))));
    }

    #[test]
    fn failing_writer_flush_returns_ok() {
        // Exercises the `flush` impl of FailingWriter (lines 261-263).
        use std::io::Write;
        let mut w = FailingWriter;
        assert!(w.flush().is_ok());
    }

    #[test]
    fn encrypt_empty_plaintext_roundtrip() {
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());
        let ciphertext = encrypt(vec![recipient], b"").expect("encrypt empty failed");
        let decrypted = decrypt(&identity, &ciphertext).expect("decrypt empty failed");
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn parse_recipient_invalid_key_returns_encryption_error() {
        let result = parse_recipient("not-a-valid-age-key");
        assert!(matches!(result, Err(GitvaultError::Encryption(_))));
    }

    #[test]
    fn parse_identity_invalid_key_returns_decryption_error() {
        let result = parse_identity("not-a-valid-age-identity");
        assert!(matches!(result, Err(GitvaultError::Decryption(_))));
    }

    #[test]
    fn decrypt_corrupted_ciphertext_returns_decryption_error() {
        let identity = gen_identity();
        let result = decrypt(&identity, b"this is not valid age ciphertext");
        assert!(matches!(result, Err(GitvaultError::Decryption(_))));
    }

    #[test]
    fn decrypt_stream_corrupted_ciphertext_returns_decryption_error() {
        let identity = gen_identity();
        let mut out = Vec::new();
        let result = decrypt_stream(
            &identity,
            std::io::Cursor::new(b"not valid age ciphertext".to_vec()),
            &mut out,
        );
        assert!(matches!(result, Err(GitvaultError::Decryption(_))));
    }

    #[test]
    fn encrypt_stream_empty_plaintext_roundtrip() {
        let identity = gen_identity();
        let recipient: Box<dyn age::Recipient + Send> = Box::new(identity.to_public());
        let mut reader = std::io::Cursor::new(b"".to_vec());
        let mut ciphertext = Vec::new();
        encrypt_stream(vec![recipient], &mut reader, &mut ciphertext)
            .expect("encrypt_stream empty failed");
        let mut decrypted = Vec::new();
        decrypt_stream(&identity, std::io::Cursor::new(&ciphertext), &mut decrypted)
            .expect("decrypt_stream empty failed");
        assert_eq!(decrypted, b"");
    }
}
