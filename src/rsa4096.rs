use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::Oaep;
use rand::rngs::OsRng;
use sha2::Sha512;
use crate::hashs::{ base64encode, base64_vecdecode };



pub struct Rsa4096 {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl Rsa4096 {
    /// Crée une nouvelle instance avec génération de clés RSA 4096 bits
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

    /// Chiffre un message avec la clé publique
    pub fn encrypt(&self, message: &[u8]) -> String {
        let mut rng = OsRng;
        let padding = Oaep::new::<Sha512>();
        let encrypted = self.public_key
            .encrypt(&mut rng, padding, message)
            .expect("Erreur chiffrement");
        base64encode(&encrypted)
    }





    /// Déchiffre un message encodé en base64 avec la clé privée
    pub fn decrypt(&self, encrypted_string: &str) -> Vec<u8> {
        let encrypted_bytes = base64_vecdecode(encrypted_string)
            .expect("Invalid base64");
        let padding = Oaep::new::<Sha512>();
        self.private_key
            .decrypt(padding, &encrypted_bytes)
            .unwrap_or_else(|_| panic!("Erreur déchiffrement"))
    }


}
