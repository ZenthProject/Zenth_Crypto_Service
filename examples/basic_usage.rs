use zenth_crypto_service::{
    symetric::aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption},
    asymetric::rsa4096::Rsa4096,
    hashing::hash::CryptographicHash,
    encoding::base64::{EncodeImpl, EncodeSecure}
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: AES-GCM Encryption
    println!("=== AES-GCM Encryption Example ===");
    let key = [1u8; 32];
    let nonce = [2u8; 12];
    let plaintext = b"Hello, this is a secret message!";
    
    let mut enc = Aes256GcmEncryption::new(&key, &nonce, &[]).unwrap();
    let mut buffer = plaintext.to_vec();
    enc.encrypt(&mut buffer);
    let tag = enc.compute_tag();
    
    println!("Encrypted: {}", EncodeImpl::base64encode(&buffer));
    println!("Tag: {}", EncodeImpl::base64encode(&tag));
    
    let mut dec = Aes256GcmDecryption::new(&key, &nonce, b"")?;
    dec.decrypt(&mut buffer);
    dec.verify_tag(&tag)?;
    
    println!("Decrypted: {}", String::from_utf8(buffer)?);
    
    // Example 2: RSA Encryption
    println!("\n=== RSA Encryption Example ===");
    let rsa = Rsa4096::new();
    let message = "Secret RSA message";
    
    let encrypted = rsa.encrypt(message.as_bytes());
    println!("RSA Encrypted: {}", encrypted);
    
    let decrypted = rsa.decrypt(&encrypted);
    println!("RSA Decrypted: {}", String::from_utf8(decrypted)?);
    
    // Example 3: Hashing
    println!("\n=== Hashing Example ===");
    let data = "Data to hash".as_bytes();
    let mut sha256_hash = CryptographicHash::new("SHA-512", 1).unwrap();
    sha256_hash.update(data);
    println!("SHA-256: {:?}", EncodeImpl::base64encode(&sha256_hash.finalize()));

    Ok(())
} 