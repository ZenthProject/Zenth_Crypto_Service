//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;

use twofish::cipher::block_padding::Pkcs7;
use twofish::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use twofish::Twofish;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum TwofishEncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum TwofishDecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str),
}

pub fn twofish_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, TwofishEncryptionError> {
    Ok(cbc::Encryptor::<Twofish>::new_from_slices(key, iv)
        .map_err(|_| TwofishEncryptionError::BadKeyOrIv)?
        .encrypt_padded_vec_mut::<Pkcs7>(ptext))
}

pub fn twofish_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, TwofishDecryptionError> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(TwofishDecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    cbc::Decryptor::<Twofish>::new_from_slices(key, iv)
        .map_err(|_| TwofishDecryptionError::BadKeyOrIv)?
        .decrypt_padded_vec_mut::<Pkcs7>(ctext)
        .map_err(|_| TwofishDecryptionError::BadCiphertext("failed to decrypt"))
}

