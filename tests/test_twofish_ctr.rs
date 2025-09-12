use zenth_crypto_service::symetric::twofish_ctr::TwofishCtr32;
use rand::RngCore;

#[test]
fn test_aes_ctr_encryption() {
    let key = [1u8; 32];
    println!("Key: {:?}", key);
    let nonce = [2u8; TwofishCtr32::NONCE_SIZE];
    
    let mut ctr = TwofishCtr32::from_key(&key, &nonce, 0).unwrap();
    let mut data = b"Hello, AES-CTR!".to_vec();
    ctr.process(&mut data);
    
    let mut ctr2 = TwofishCtr32::from_key(&key, &nonce, 0).unwrap();
    println!("Data before second process: {:?}", data);
    ctr2.process(&mut data);
    
    assert_eq!(data, b"Hello, AES-CTR!");
}

#[test]
fn test_twofish_ctr_random_key_roundtrip() {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    println!("Random key: {:?}", key);
    let mut nonce = [0u8; TwofishCtr32::NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    println!("Random nonce: {:?}", nonce);

    let plaintext = b"Hello, random Twofish-CTR!".to_vec();
    let mut ctr_enc = TwofishCtr32::from_key(&key, &nonce, 0).unwrap();
    let mut ciphertext = plaintext.clone();
    ctr_enc.process(&mut ciphertext);
    println!("Ciphertext: {:?}", ciphertext);

    let mut ctr_dec = TwofishCtr32::from_key(&key, &nonce, 0).unwrap();
    let mut decrypted = ciphertext.clone();
    ctr_dec.process(&mut decrypted);
    println!("Decrypted: {:?}", decrypted);

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_twofish_ctr_fixed_key_and_nonce() {
    let key = [1u8; 32];
    let nonce = [2u8; TwofishCtr32::NONCE_SIZE];
    let plaintext = b"Hello, deterministic test!".to_vec();
    let mut ctr_enc = TwofishCtr32::from_key(&key, &nonce, 0).unwrap();
    let mut ciphertext = plaintext.clone();
    ctr_enc.process(&mut ciphertext);
    println!("Fixed ciphertext: {:?}", ciphertext);

    let expected: Vec<u8> = ciphertext.clone();
    let mut ctr_dec = TwofishCtr32::from_key(&key, &nonce, 0).unwrap();
    let mut decrypted = ciphertext.clone();
    ctr_dec.process(&mut decrypted);

    assert_eq!(decrypted, plaintext);
    assert_eq!(ciphertext, expected);
}