#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

pub mod hash;
pub mod error;
pub mod hashs;
pub mod aes_cbc;
pub mod aes_ctr;
pub mod aes_gcm;
pub mod rsa4096;
pub mod serpent_ctr;

// Re-export commonly used types
pub use crate::rsa4096::Rsa4096;
pub use crate::aes_ctr::Aes256Ctr32;
pub use crate::error::{Error, Result};
pub use crate::serpent_ctr::SerpentCtr32;
pub use crate::hash::{CryptographicHash, CryptographicMac};
pub use crate::aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption};
pub use crate::hashs::{HasherImpl, HashSecure, base64_vecdecode, base64decode, base64encode};
pub use crate::aes_cbc::{aes_256_cbc_decrypt, aes_256_cbc_encrypt, DecryptionError, EncryptionError};
