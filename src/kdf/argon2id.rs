use argon2::{
    password_hash::{
        SaltString, 
        PasswordHash, 
        PasswordHasher, 
        PasswordVerifier
    },
    Argon2, 
    Params, 
    Algorithm, 
    Version,
};
use rand::rngs::OsRng;

pub struct Argon2idHasher<'a> {
    argon2: Argon2<'a>,
}

impl<'a> Argon2idHasher<'a> {
    pub fn new() -> Result<Self, argon2::password_hash::Error> {
        let params = Params::new(131_072, 6, 4, None)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Ok(Self { argon2 })
    }

    pub fn hash(&self, password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    pub fn hash_with_client_salt(
        &self,
        password: &str,
        salt_b64: &str,
    ) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::new(salt_b64)?;
        let hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    pub fn verify(&self, password: &str, hashed: &str) -> Result<bool, argon2::password_hash::Error> {
        match PasswordHash::new(hashed) {
            Ok(parsed_hash) => Ok(self.argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()),
            Err(e) => Err(e),
        }
    }

}

