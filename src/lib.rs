#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod kdf;
pub mod errors;
pub mod hashing;
pub mod encoding;
pub mod symetric;
pub mod asymetric;
pub mod utils;
pub mod exchange;
pub mod kem;

pub use crate::utils::constant_time::ct_eq;
pub use crate::asymetric::rsa4096::Rsa4096;
pub use crate::symetric::aes_ctr::Aes256Ctr32;
pub use crate::symetric::serpent_ctr::SerpentCtr32;
pub use crate::symetric::twofish_ctr::TwofishCtr32;
pub use crate::kdf::argon2id::Argon2idHasher;
pub use crate::encoding::base64::{
    EncodeImpl, 
    EncodeSecure
};
pub use crate::encoding::hex::{
    HexEncodeImpl, 
    HexEncodeSecure
};
pub use crate::encoding::pem::{
    PemEncodeImpl, 
    PemEncodeSecure
};
pub use crate::errors::error::{
    Error, 
    Result
};

pub use crate::hashing::hash::{
    CryptographicHash,
    CryptographicMac
};

pub use crate::symetric::aes_gcm::{
    Aes256GcmDecryption, 
    Aes256GcmEncryption
};
pub use crate::symetric::aes_cbc::{
    aes_256_cbc_decrypt, 
    aes_256_cbc_encrypt, 
    DecryptionError, 
    EncryptionError
};
pub use crate::symetric::serpent_cbc::{
    serpent_256_cbc_decrypt, 
    serpent_256_cbc_encrypt, 
    SerpentDecryptionError, 
    SerpentEncryptionError
};
pub use crate::symetric::twofish_cbc::{
    twofish_256_cbc_decrypt, 
    twofish_256_cbc_encrypt,
    TwofishDecryptionError,
    TwofishEncryptionError
};