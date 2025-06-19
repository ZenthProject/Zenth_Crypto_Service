use sha3::{Sha3_512, Keccak512, Digest};
use md5;
use crc32fast::Hasher;
use argon2::{Argon2, Params, PasswordHasher, PasswordVerifier, Algorithm, Version};
use argon2::password_hash::{SaltString, PasswordHash};
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine};



pub trait HashSecure {
    fn sha512_fun(text: &str, rounds: usize) -> String;
    fn keccak_fun(text: &str, rounds: usize) -> String;
    fn md5_fun(text: &str, rounds: usize) -> String;
    fn crc_fun(text: &str, rounds: usize) -> String;
    fn argon2id_hash(password: &str) -> String;
    fn argon2id_hash_with_client_salt(password: &str, salt_client_b64: &str) -> String;
    fn argon2id_verify(password: &str, hashed: &str) -> bool;
}

pub struct HasherImpl;

impl HashSecure for HasherImpl {
    fn sha512_fun(text: &str, rounds: usize) -> String {
        let mut result = text.as_bytes().to_vec();
        for _ in 0..rounds {
            let mut hasher = Sha3_512::new();
            hasher.update(&result);
            result = hasher.finalize().to_vec();
        }
        base64encode(&result)
    }

    fn keccak_fun(text: &str, rounds: usize) -> String {
        let mut result = text.as_bytes().to_vec();
        for _ in 0..rounds {
            let mut hasher = Keccak512::new();
            hasher.update(&result);
            result = hasher.finalize().to_vec();
        }
        base64encode(&result)
    }

    fn md5_fun(text: &str, rounds: usize) -> String {
        let mut result = text.as_bytes().to_vec();
        for _ in 0..rounds {
            result = md5::compute(&result).0.to_vec();
        }
        base64encode(&result)
    }

    fn crc_fun(text: &str, rounds: usize) -> String {
        let mut result = text.as_bytes().to_vec();
        for _ in 0..rounds {
            let mut hasher = Hasher::new();
            hasher.update(&result);
            let crc = hasher.finalize();
            result = crc.to_le_bytes().to_vec();
        }
        base64encode(&result)
    }

    fn argon2id_hash(password: &str) -> String {
        let params = Params::new(131_072, 6, 4, None).expect("Invalid Argon2 params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("argon2id hashing failed")
            .to_string()
    }

    fn argon2id_hash_with_client_salt(password: &str, salt_client_b64: &str) -> String {
        let params = Params::new(131_072, 6, 4, None).expect("Invalid Argon2 params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::new(salt_client_b64).expect("Invalid salt string");
        let hash = argon2.hash_password(password.as_bytes(), &salt).expect("Hashing failed");
        hash.to_string()
    }

    fn argon2id_verify(password: &str, hashed: &str) -> bool {
        if let Ok(parsed_hash) = PasswordHash::new(hashed) {
            Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
        } else {
            false
        }
    }
}




pub fn base64encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn base64decode(encoded_message: &str) -> Result<String, String> {
    let decoded_bytes = general_purpose::STANDARD
        .decode(encoded_message)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    String::from_utf8(decoded_bytes).map_err(|e| format!("UTF-8 decode error: {}", e))
}


pub fn base64_vecdecode(encoded_message: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(encoded_message)
        .map_err(|e| format!("Base64 decode error: {}", e))
}
