use twofish::Twofish;
use cipher::{
    KeyInit,
    StreamCipher,
    StreamCipherSeek,
    BlockSizeUser,
    InnerIvInit,
};
use ctr::{CtrCore, Ctr32BE};
use cipher::typenum::Unsigned;


/// Erreur simplifiée
#[derive(Debug)]
pub enum Error {
    InvalidKeySize,
    InvalidNonceSize,
}

pub type Result<T> = core::result::Result<T, Error>;

pub struct TwofishCtr32(Ctr32BE<Twofish>);

impl TwofishCtr32 {
    pub const NONCE_SIZE: usize = <Twofish as BlockSizeUser>::BlockSize::USIZE - 4;

    pub fn new(cipher: Twofish, nonce: &[u8], init_ctr: u32) -> Result<Self> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }

        let mut nonce_block = [0u8; <Twofish as BlockSizeUser>::BlockSize::USIZE];
        nonce_block[..Self::NONCE_SIZE].copy_from_slice(nonce);

        let core = CtrCore::inner_iv_init(cipher, &nonce_block.into());
        let mut ctr = Ctr32BE::from_core(core);

        ctr.seek(
            (<Twofish as BlockSizeUser>::BlockSize::USIZE as u64) * (init_ctr as u64)
        );

        Ok(Self(ctr))
    }

    pub fn from_key(key: &[u8], nonce: &[u8], init_ctr: u32) -> Result<Self> {
        let cipher = Twofish::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?;
        Self::new(cipher, nonce, init_ctr)
    }

    pub fn process(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }

    
}

