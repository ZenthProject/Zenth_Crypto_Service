use zenth_crypto_service::{
    serpent_ctr::{SerpentCtr32, Error},
};
use rand::rngs::OsRng;

#[cfg(test)]
mod tests {
    use super::*;

    fn get_key() -> [u8; 32] {
        // 256-bit key (32 bytes)
        *b"01234567012345670123456701234567"
    }

    fn get_nonce() -> [u8; SerpentCtr32::NONCE_SIZE] {
        *b"nonce_123456" // Doit être de taille 12 (BLOCK_SIZE - 4)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = get_key();
        let nonce = get_nonce();
        let mut cipher = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();

        let plaintext = b"Secret message!".to_vec();
        let mut data = plaintext.clone();

        cipher.process(&mut data);

        // Déchiffre avec un nouveau cipher identique
        let mut decipher = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();
        decipher.process(&mut data);

        assert_eq!(plaintext, data);
    }

    #[test]
    fn test_invalid_key_size() {
        let key = [0u8; 10]; // Trop court
        let nonce = get_nonce();
        let cipher = SerpentCtr32::from_key(&key, &nonce, 0);
        assert!(matches!(cipher, Err(Error::InvalidKeySize)));
    }

    #[test]
    fn test_invalid_nonce_size() {
        let key = get_key();
        let bad_nonce = [0u8; 5];
        let cipher = SerpentCtr32::from_key(&key, &bad_nonce, 0);
        assert!(matches!(cipher, Err(Error::InvalidNonceSize)));
    }

    #[test]
    fn test_encrypt_deterministic_same_input() {
        let key = get_key();
        let nonce = get_nonce();
        let input = b"repetitive".to_vec();

        let mut c1 = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();
        let mut c2 = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();

        let mut buf1 = input.clone();
        let mut buf2 = input.clone();

        c1.process(&mut buf1);
        c2.process(&mut buf2);

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_diff_nonce_gives_diff_ciphertext() {
        let key = get_key();
        let nonce1 = get_nonce();
        let mut nonce2 = nonce1.clone();
        nonce2[0] ^= 0xAA;

        let input = b"sameplaintext".to_vec();

        let mut c1 = SerpentCtr32::from_key(&key, &nonce1, 0).unwrap();
        let mut c2 = SerpentCtr32::from_key(&key, &nonce2, 0).unwrap();

        let mut buf1 = input.clone();
        let mut buf2 = input.clone();

        c1.process(&mut buf1);
        c2.process(&mut buf2);

        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_ctr_offset() {
        let key = get_key();
        let nonce = get_nonce();
        let input = b"CTR offset test data".to_vec();

        let mut cipher = SerpentCtr32::from_key(&key, &nonce, 2).unwrap();
        let mut encrypted = input.clone();
        cipher.process(&mut encrypted);

        let mut decipher = SerpentCtr32::from_key(&key, &nonce, 2).unwrap();
        decipher.process(&mut encrypted);

        assert_eq!(encrypted, input);
    }

    #[test]
    fn test_long_input() {
        let key = get_key();
        let nonce = get_nonce();
        let mut data = vec![0xAB; 10_000];

        let mut cipher = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();
        cipher.process(&mut data);

        let mut decipher = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();
        decipher.process(&mut data);

        assert_eq!(data, vec![0xAB; 10_000]);
    }

    #[test]
    fn test_empty_input() {
        let key = get_key();
        let nonce = get_nonce();
        let mut cipher = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();

        let mut buf = vec![];
        cipher.process(&mut buf);
        assert_eq!(buf, vec![]);
    }

    #[test]
    fn test_serpent_encryption() {
        let key = [1u8; 32];
        let nonce = [2u8; SerpentCtr32::NONCE_SIZE]; 
        let plaintext = b"Hello, Serpent!".to_vec();

        let mut ctr = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();
        let mut ciphertext = plaintext.clone();
        ctr.process(&mut ciphertext);
        assert_ne!(ciphertext, plaintext);

        let mut ctr2 = SerpentCtr32::from_key(&key, &nonce, 0).unwrap();
        ctr2.process(&mut ciphertext);

        assert_eq!(ciphertext, plaintext);
    }
}
