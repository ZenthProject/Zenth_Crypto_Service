//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//


use zenth_crypto_service::symetric::aes_ctr::Aes256Ctr32;

#[test]
fn test_aes_ctr_encryption() {
    let key = [1u8; 32];
    let nonce = [2u8; Aes256Ctr32::NONCE_SIZE];
    
    let mut ctr = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
    let mut data = b"Hello, AES-CTR!".to_vec();
    ctr.process(&mut data);
    
    let mut ctr2 = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
    ctr2.process(&mut data);
    
    assert_eq!(data, b"Hello, AES-CTR!");
}
