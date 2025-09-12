//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Keccak512, Sha3_256, Sha3_512};
use crc32fast::Hasher;
use crate::errors::error::{ 
    Error, 
    Result 
};


#[derive(Clone)]
pub enum CryptographicMac {
    HmacSha256(Hmac<Sha256>),
    HmacSha1(Hmac<Sha1>),
    HmacSha3_256(Hmac<Sha3_256>),
    HmacSha3_512(Hmac<Sha3_512>),
}

impl CryptographicMac {
    pub fn new(algo: &str, key: &[u8]) -> Result<Self> {
        match algo {
            "HMACSha1" | "HmacSha1" => Ok(Self::HmacSha1(
                Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha256" | "HmacSha256" => Ok(Self::HmacSha256(
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha3-256" | "HmacSha3-256" => Ok(Self::HmacSha3_256(
                Hmac::<Sha3_256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha3-512" | "HmacSha3-512" => Ok(Self::HmacSha3_512(
                Hmac::<Sha3_512>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            _ => Err(Error::UnknownAlgorithm("MAC", algo.to_string())),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::HmacSha1(sha1) => sha1.update(input),
            Self::HmacSha256(sha256) => sha256.update(input),
            Self::HmacSha3_256(sha3_256) => sha3_256.update(input),
            Self::HmacSha3_512(sha3_512) => sha3_512.update(input),
        }
    }

    pub fn update_and_get(&mut self, input: &[u8]) -> &mut Self {
        self.update(input);
        self
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::HmacSha1(sha1) => sha1.clone().finalize().into_bytes().to_vec(),
            Self::HmacSha256(sha256) => sha256.clone().finalize().into_bytes().to_vec(),
            Self::HmacSha3_256(sha3_256) => sha3_256.clone().finalize().into_bytes().to_vec(),
            Self::HmacSha3_512(sha3_512) => sha3_512.clone().finalize().into_bytes().to_vec(),
        }
    }
}

#[derive(Clone)]
pub enum CryptographicHash {
    Sha1 { hasher: Sha1, rounds: usize, buffer: Vec<u8> },
    Sha256 { hasher: Sha256, rounds: usize, buffer: Vec<u8> },
    Sha512 { hasher: Sha512, rounds: usize, buffer: Vec<u8> },
    Sha3_256 { hasher: Sha3_256, rounds: usize, buffer: Vec<u8> },
    Sha3_512 { hasher: Sha3_512, rounds: usize, buffer: Vec<u8> },
    Keccak512 { hasher: Keccak512, rounds: usize, buffer: Vec<u8> },
    Md5 { rounds: usize, buffer: Vec<u8> },
    CRC32 { rounds: usize, buffer: Vec<u8> },
}


impl CryptographicHash {
    pub fn new(algo: &str, rounds: usize) -> Result<Self> {
        match algo {
            "SHA-1" | "SHA1" | "Sha1" => Ok(Self::Sha1 { hasher: Sha1::new(), rounds, buffer: vec![] }),
            "SHA-256" | "SHA256" | "Sha256" => Ok(Self::Sha256 { hasher: Sha256::new(), rounds, buffer: vec![] }),
            "SHA-512" | "SHA512" | "Sha512" => Ok(Self::Sha512 { hasher: Sha512::new(), rounds, buffer: vec![] }),
            "SHA3-256" | "SHA3_256" | "Sha3-256" | "Sha3_256" => Ok(Self::Sha3_256 { hasher: Sha3_256::new(), rounds, buffer: vec![] }),
            "SHA3-512" | "Sha3_512" => Ok(Self::Sha3_512 { hasher: Sha3_512::new(), rounds, buffer: vec![] }),
            "Keccak512" | "KECCAK512" | "Keccak-512" | "KECCAK-512" => Ok(Self::Keccak512 { hasher: Keccak512::new(), rounds, buffer: vec![] }),
            "MD5" | "Md5" | "MD-5" | "Md-5" => Ok(Self::Md5 { rounds, buffer: vec![] }),
            "CRC32" | "CRC-32" | "Crc32" | "Crc-32" => Ok(Self::CRC32 { rounds, buffer: vec![] }),
            _ => Err(Error::UnknownAlgorithm("digest", algo.to_string())),
        }
    }



    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::Sha1 { buffer, .. } |
            Self::Sha256 { buffer, .. } |
            Self::Sha512 { buffer, .. } |
            Self::Sha3_256 { buffer, .. } |
            Self::Sha3_512 { buffer, .. } |
            Self::Keccak512 { buffer, .. } |
            Self::Md5 { buffer, .. } |
            Self::CRC32 { buffer, .. } => buffer.extend_from_slice(input),
        }
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::Sha1 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha1::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha256 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha256::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha512 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha512::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha3_256 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha3_256::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha3_512 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha3_512::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Keccak512 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Keccak512::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Md5 { rounds, buffer } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    result = md5::compute(&result).0.to_vec();
                }
                result
            }
            Self::CRC32 { rounds, buffer } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut hasher = Hasher::new();
                    hasher.update(&result);
                    let crc = hasher.finalize();
                    result = crc.to_le_bytes().to_vec();
                }
                result
            }
        }
    }
}



