//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;
use aes::Aes256;
use cipher::{
    KeyInit,
    BlockEncrypt,
    BlockDecrypt,
    generic_array::GenericArray,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Invalid key or IV")]
    BadKeyOrIv,
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Invalid key or IV")]
    BadKeyOrIv,
    #[error("Invalid ciphertext: {0}")]
    BadCiphertext(&'static str),
}

pub fn aes_256_cbc_encrypt(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    if key.len() != 32 || iv.len() != 16 {
        return Err(EncryptionError::BadKeyOrIv);
    }

    let key = GenericArray::from_slice(key);
    let mut cipher = Aes256::new(key);
    
    // Pad the plaintext to be a multiple of 16 bytes
    let mut padded = plaintext.to_vec();
    let padding = 16 - (padded.len() % 16);
    padded.extend(std::iter::repeat(padding as u8).take(padding));
    
    // CBC mode encryption
    let mut ciphertext = Vec::with_capacity(padded.len());
    let mut prev_block = iv.to_vec();
    
    for chunk in padded.chunks(16) {
        let mut block = chunk.to_vec();
        // XOR with previous block
        for (a, b) in block.iter_mut().zip(prev_block.iter()) {
            *a ^= b;
        }
        // Encrypt the block
        let mut block_array = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(&mut block_array);
        ciphertext.extend_from_slice(&block);
        prev_block = block;
    }
    
    Ok(ciphertext)
}

pub fn aes_256_cbc_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if key.len() != 32 || iv.len() != 16 || ciphertext.len() % 16 != 0 {
        return Err(DecryptionError::BadKeyOrIv);
    }

    let key = GenericArray::from_slice(key);
    let mut cipher = Aes256::new(key);
    
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = iv.to_vec();
    
    for chunk in ciphertext.chunks(16) {
        let mut block = chunk.to_vec();
        let mut block_array = GenericArray::from_mut_slice(&mut block);
        cipher.decrypt_block(&mut block_array);
        
        // XOR with previous block
        for (a, b) in block.iter_mut().zip(prev_block.iter()) {
            *a ^= b;
        }
        
        plaintext.extend_from_slice(&block);
        prev_block = chunk.to_vec();
    }
    
    // Remove padding
    if let Some(&padding) = plaintext.last() {
        if padding as usize <= plaintext.len() {
            plaintext.truncate(plaintext.len() - padding as usize);
            Ok(plaintext)
        } else {
            Err(DecryptionError::BadCiphertext("invalid padding"))
        }
    } else {
        Err(DecryptionError::BadCiphertext("empty ciphertext"))
    }
}

#[cfg(test)]
mod test {
    use const_str::hex;
    use super::*;

    #[test]
    fn aes_cbc_test() {
        let key = hex!("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e");
        let iv = hex!("6f8a557ddc0a140c878063a6d5f31d3d");
        let ptext = hex!("30736294a124482a4159");

        let ctext = aes_256_cbc_encrypt(&ptext, &key, &iv).expect("valid key and IV");
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = aes_256_cbc_decrypt(&ctext, &key, &iv).expect("valid");
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());
        assert!(aes_256_cbc_decrypt(&ctext, &key, &ctext).is_err());

        // bitflip the IV to cause a change in the recovered text
        let bad_iv = hex!("ef8a557ddc0a140c878063a6d5f31d3d");
        let recovered = aes_256_cbc_decrypt(&ctext, &key, &bad_iv).expect("still valid");
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");
    }
}
