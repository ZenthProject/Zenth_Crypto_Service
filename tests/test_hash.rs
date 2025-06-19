use zenth_crypto_service::hashs::{HasherImpl, HashSecure};
use zenth_crypto_service::hash::*;
use zenth_crypto_service::hashs;
use zenth_crypto_service::hashs::base64encode;
use zenth_crypto_service::hashs::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HasherImpl;

    #[test]
    fn test_sha512() {
        let data = "test";
        let hash = HasherImpl::sha512_fun(data, 1);
        assert!(!hash.is_empty());
        assert_ne!(hash, hashs::base64encode(data.as_bytes()));
    }

    #[test]
    fn test_keccak() {
        let data = "test";
        let hash = HasherImpl::keccak_fun(data, 1);
        assert!(!hash.is_empty());
        assert_ne!(hash, hashs::base64encode(data.as_bytes()));
    }

    #[test]
    fn test_md5() {
        let data = "test";
        let hash = HasherImpl::md5_fun(data, 1);
        assert!(!hash.is_empty());
        assert_ne!(hash, hashs::base64encode(data.as_bytes()));
    }

    #[test]
    fn test_crc() {
        let data = "test";
        let hash = HasherImpl::crc_fun(data, 1);
        assert!(!hash.is_empty());
        assert_ne!(hash, hashs::base64encode(data.as_bytes()));
    }

    #[test]
    fn test_argon2id() {
        let password = "test";
        let hash = HasherImpl::argon2id_hash(password);
        assert!(HasherImpl::argon2id_verify(password, &hash));
    }

    #[test]
    fn test_sha512_basic() {
        let hash1 = HasherImpl::sha512_fun("password", 1);
        let hash2 = HasherImpl::sha512_fun("password", 1);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha512_multiple_rounds() {
        let hash1 = HasherImpl::sha512_fun("data", 1);
        let hash2 = HasherImpl::sha512_fun("data", 2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sha512_zero_round() {
        let hash = HasherImpl::sha512_fun("text", 0);
        assert_eq!(hashs::base64encode("text".as_bytes()), hash);
    }

    #[test]
    fn test_keccak_consistency() {
        let h1 = HasherImpl::keccak_fun("text", 3);
        let h2 = HasherImpl::keccak_fun("text", 3);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_keccak_diff_input() {
        let h1 = HasherImpl::keccak_fun("abc", 2);
        let h2 = HasherImpl::keccak_fun("def", 2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_md5_repeatability() {
        let h1 = HasherImpl::md5_fun("mydata", 5);
        let h2 = HasherImpl::md5_fun("mydata", 5);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_md5_empty_string() {
        let h = HasherImpl::md5_fun("", 1);
        assert!(!h.is_empty());
    }

    #[test]
    fn test_crc_variation() {
        let h1 = HasherImpl::crc_fun("1234", 1);
        let h2 = HasherImpl::crc_fun("1234", 2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_crc_repeatability() {
        let h1 = HasherImpl::crc_fun("constant", 10);
        let h2 = HasherImpl::crc_fun("constant", 10);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_argon2id_invalid_password() {
        let password = "correct";
        let wrong = "wrong";
        let hash = HasherImpl::argon2id_hash(password);
        assert!(!HasherImpl::argon2id_verify(wrong, &hash));
    }

    #[test]
    fn test_argon2id_invalid_hash_format() {
        let password = "anything";
        let bad_hash = "$argon2id$v=19$m=65536,t=2,p=1$INVALID";
        assert!(!HasherImpl::argon2id_verify(password, bad_hash));
    }

    #[test]
    fn test_argon2id_different_hashes() {
        let h1 = HasherImpl::argon2id_hash("mypassword");
        let h2 = HasherImpl::argon2id_hash("mypassword");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_all_hashes_on_same_input() {
        let input = "ALL_HASHES";
        let sha = HasherImpl::sha512_fun(input, 1);
        let keccak = HasherImpl::keccak_fun(input, 1);
        let md5 = HasherImpl::md5_fun(input, 1);
        let crc = HasherImpl::crc_fun(input, 1);
        assert_ne!(sha, keccak);
        assert_ne!(keccak, md5);
        assert_ne!(md5, crc);
    }

    #[test]
    fn test_unicode_input() {
        let input = "🐍🚀🦀";
        let sha = HasherImpl::sha512_fun(input, 1);
        let keccak = HasherImpl::keccak_fun(input, 1);
        let md5 = HasherImpl::md5_fun(input, 1);
        let crc = HasherImpl::crc_fun(input, 1);
        assert!(!sha.is_empty());
        assert!(!keccak.is_empty());
        assert!(!md5.is_empty());
        assert!(!crc.is_empty());
    }
}
