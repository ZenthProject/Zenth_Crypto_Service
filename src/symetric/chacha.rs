use chacha20poly1305::{
    aead::{self , Aead, KeyInit},
    ChaCha20Poly1305, XChaCha20Poly1305, Key, Nonce, XNonce
};
use rand_core::{OsRng, TryRngCore};
use hex;

pub enum ChachaVariant {
    ChaCha20([u8; 12]),
    XChaCha20([u8; 24]),
}

pub struct ChachaCipher {
    key: [u8; 32],
    variant: ChachaVariant,
}

impl ChachaCipher {
    pub fn new_chacha20() -> Result<Self, aead::Error> {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).map_err(|_| aead::Error)?;

        let mut nonce = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| aead::Error)?;

        Ok(Self {
            key,
            variant: ChachaVariant::ChaCha20(nonce),
        })
    }

    pub fn new_xchacha20() -> Result<Self, aead::Error> {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).map_err(|_| aead::Error)?;

        let mut nonce = [0u8; 24];
        OsRng.try_fill_bytes(&mut nonce).map_err(|_| aead::Error)?;

        Ok(Self {
            key,
            variant: ChachaVariant::XChaCha20(nonce),
        })
    }

    pub fn key_hex(&self) -> String {
        hex::encode(&self.key)
    }

    pub fn nonce_hex(&self) -> String {
        match &self.variant {
            ChachaVariant::ChaCha20(nonce) => hex::encode(nonce),
            ChachaVariant::XChaCha20(nonce) => hex::encode(nonce),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        match &self.variant {
            ChachaVariant::ChaCha20(nonce) => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
                cipher.encrypt(Nonce::from_slice(nonce), plaintext)
            }
            ChachaVariant::XChaCha20(nonce) => {
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
                cipher.encrypt(XNonce::from_slice(nonce), plaintext)
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
        match &self.variant {
            ChachaVariant::ChaCha20(nonce) => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
                cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
            }
            ChachaVariant::XChaCha20(nonce) => {
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
                cipher.decrypt(XNonce::from_slice(nonce), ciphertext)
            }
        }
    }
}
