use zenth_crypto_service::symetric::chacha::ChachaCipher;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encryption_decryption() {
        let cipher = ChachaCipher::new_chacha20().expect("Failed to create ChaCha20 cipher");
        let plaintext = b"message secret";

        let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
        let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_xchacha20_encryption_decryption() {
        let cipher = ChachaCipher::new_xchacha20().expect("Failed to create XChaCha20 cipher");
        let plaintext = b"autre message confidentiel";

        let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
        let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_key_and_nonce_hex_format_chacha20() {
        let cipher = ChachaCipher::new_chacha20().expect("Failed to create ChaCha20 cipher");
        let key_hex = cipher.key_hex();
        let nonce_hex = cipher.nonce_hex();

        assert_eq!(key_hex.len(), 64); // 32 bytes * 2 chars
        assert_eq!(nonce_hex.len(), 24); // 12 bytes * 2 chars
    }

    #[test]
    fn test_key_and_nonce_hex_format_xchacha20() {
        let cipher = ChachaCipher::new_xchacha20().expect("Failed to create XChaCha20 cipher");
        let key_hex = cipher.key_hex();
        let nonce_hex = cipher.nonce_hex();

        assert_eq!(key_hex.len(), 64); // 32 bytes * 2 chars
        assert_eq!(nonce_hex.len(), 48); // 24 bytes * 2 chars
    }
}
