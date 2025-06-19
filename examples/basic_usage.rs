use zenth_crypto_service::{
    aes_gcm::{Aes256GcmEncryption, Aes256GcmDecryption},
    rsa4096::Rsa4096,
    hashs::{HasherImpl, HashSecure},
    hashs::base64encode,
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
    
    println!("Encrypted: {}", base64encode(&buffer));
    println!("Tag: {}", base64encode(&tag));
    
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
    let data = "Data to hash";
    let sha256_hash = HasherImpl::sha512_fun(data, 1);
    println!("SHA-256: {}", sha256_hash);
    
    Ok(())
} 