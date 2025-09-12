use crate::encoding::base64::{
    EncodeImpl, 
    EncodeSecure
};
use rsa::{
    RsaPrivateKey, 
    RsaPublicKey
};
use rsa::Oaep;
use rand::rngs::OsRng;
use sha2::Sha512;

pub struct Rsa4096 {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl Rsa4096 {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let bits = 4096;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .expect("Erreur génération clé privée");
        let public_key = RsaPublicKey::from(&private_key);

        Rsa4096 {
            private_key,
            public_key,
        }
    }
    pub fn encrypt(&self, message: &[u8]) -> String {
        let mut rng = OsRng;
        let padding = Oaep::new::<Sha512>();
        let encrypted = self.public_key
            .encrypt(&mut rng, padding, message)
            .expect("Erreur chiffrement");
        EncodeImpl::base64encode(&encrypted)
    }

    pub fn decrypt(&self, encrypted_string: &str) -> Vec<u8> {
        let encrypted_bytes = EncodeImpl::base64_vecdecode(encrypted_string)
            .expect("Invalid base64");
        let padding = Oaep::new::<Sha512>();
        self.private_key
            .decrypt(padding, &encrypted_bytes)
            .unwrap_or_else(|_| panic!("Erreur déchiffrement"))
    }
}
