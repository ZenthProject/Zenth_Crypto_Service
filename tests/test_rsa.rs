use zenth_crypto_service::{
    asymetric::rsa4096::Rsa4096,
    encoding::base64::{EncodeImpl, EncodeSecure},
};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_rsa_encryption_decryption() {
        let rsa = Rsa4096::new();
        let message = "Hello, RSA!";
        
        let encrypted = rsa.encrypt(message.as_bytes());
        let decrypted = rsa.decrypt(&encrypted);
        
        assert_eq!(message.as_bytes(), decrypted.as_slice());
    }

    #[test]
    fn test_rsa_encrypt_decrypt_binary() {
        let rsa = Rsa4096::new();
        let mut message = [0u8; 32]; // tableau vide
        thread_rng().fill_bytes(&mut message); // le remplir aléatoirement
        let encrypted = rsa.encrypt(&message);
        let decrypted = rsa.decrypt(&encrypted);
        assert_eq!(decrypted, &message);
    }


    #[test]
    #[should_panic(expected = "Invalid base64")]
    fn test_decrypt_invalid_base64() {
        let rsa = Rsa4096::new();
        let _ = rsa.decrypt("$$$invalid-base64@@@");
    }

    #[test]
    #[should_panic(expected = "Erreur déchiffrement")]
    fn test_decrypt_with_wrong_key() {
        let rsa1 = Rsa4096::new();
        let rsa2 = Rsa4096::new();

        let msg = b"top secret";
        let encrypted = rsa1.encrypt(msg);
        let encrypted_b64 = EncodeImpl::base64encode(encrypted.as_bytes());

        let _ = rsa2.decrypt(&encrypted_b64);
    }

}
