//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zenth_crypto_service::symetric::aes_gcm::{Aes256GcmEncryption, Aes256GcmDecryption};

#[test]
fn test_aes_gcm_encryption() {
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    
    let mut enc = Aes256GcmEncryption::new(&key, &nonce, &[]).unwrap();
    let mut data = b"Hello, AES-GCM!".to_vec();
    enc.encrypt(&mut data);
    let tag = enc.compute_tag();
    
    let mut dec = Aes256GcmDecryption::new(&key, &nonce, b"").unwrap();
    dec.decrypt(&mut data);
    dec.verify_tag(&tag).unwrap();
    
    assert_eq!(data, b"Hello, AES-GCM!");
}
