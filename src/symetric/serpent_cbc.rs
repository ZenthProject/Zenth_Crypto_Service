//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;

use serpent::cipher::block_padding::Pkcs7;
use serpent::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use serpent::Serpent;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum SerpentEncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum SerpentDecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str),
}

pub fn serpent_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, SerpentEncryptionError> {
    Ok(cbc::Encryptor::<Serpent>::new_from_slices(key, iv)
        .map_err(|_| SerpentEncryptionError::BadKeyOrIv)?
        .encrypt_padded_vec_mut::<Pkcs7>(ptext))
}

pub fn serpent_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, SerpentDecryptionError> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(SerpentDecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    cbc::Decryptor::<Serpent>::new_from_slices(key, iv)
        .map_err(|_| SerpentDecryptionError::BadKeyOrIv)?
        .decrypt_padded_vec_mut::<Pkcs7>(ctext)
        .map_err(|_| SerpentDecryptionError::BadCiphertext("failed to decrypt"))
}

