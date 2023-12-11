use std::fmt::Display;
use std::mem::size_of;

use aes::cipher::Unsigned;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Buffer;
use aes_gcm::aead::Payload;
use aes_gcm::AeadCore;
use aes_gcm::AeadInPlace;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use chacha20poly1305::ChaCha20Poly1305;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CipherKind {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aead2022Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aead2022Blake3Aes256Gcm,
}

impl CipherKind {
    pub fn to_aead_cipher(&self, key: &[u8]) -> Box<dyn CipherMethod> {
        match self {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => Box::new(Aes128GcmCipher::new(&key)),
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm => Box::new(Aes256GcmCipher::new(&key)),
            CipherKind::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(&key)),
        }
    }

    pub fn is_aead_2022(&self) -> bool {
        match self {
            CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm => true,
            _ => false,
        }
    }
}

pub trait CipherMethod: Send {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer);
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer);
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
    fn ciphertext_overhead(&self) -> usize;
}

macro_rules! aead_impl {
    ($name:ident, $cipher:ty) => {
        pub struct $name {
            cipher: $cipher,
        }

        impl $name {
            pub const NONCE_SIZE: usize = <$cipher as AeadCore>::NonceSize::USIZE;
            pub const TAG_SIZE: usize = <$cipher as AeadCore>::TagSize::USIZE;
            pub const CIPHERTEXT_OVERHEAD: usize = <$cipher as AeadCore>::CiphertextOverhead::USIZE;

            pub fn new(key: &[u8]) -> Self {
                Self { cipher: <$cipher>::new_from_slice(key).unwrap() }
            }
        }

        impl CipherMethod for $name {
            fn encrypt(&self, nonce: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
                self.cipher.encrypt(nonce.into(), Payload { msg, aad }).unwrap()
            }

            fn decrypt(&self, nonce: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
                self.cipher.decrypt(nonce.into(), Payload { msg, aad }).expect("Invalid cipher text")
            }

            fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) {
                self.cipher.encrypt_in_place(nonce.into(), aad, buffer).unwrap()
            }

            fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) {
                self.cipher.decrypt_in_place(nonce.into(), aad, buffer).expect("Invalid cipher text")
            }

            fn nonce_size(&self) -> usize {
                $name::NONCE_SIZE
            }

            fn tag_size(&self) -> usize {
                $name::TAG_SIZE
            }

            fn ciphertext_overhead(&self) -> usize {
                $name::CIPHERTEXT_OVERHEAD
            }
        }
    };
}

aead_impl!(Aes128GcmCipher, Aes128Gcm);
aead_impl!(Aes256GcmCipher, Aes256Gcm);
aead_impl!(ChaCha20Poly1305Cipher, ChaCha20Poly1305);

#[derive(PartialEq, Eq)]
pub enum PaddingLengthGenerator {
    Empty,
    Shake,
}

pub enum BytesGenerator {
    Counting(CountingNonceGenerator),
    Increasing(IncreasingNonceGenerator),
    Empty,
    Static,
}

pub struct CountingNonceGenerator {
    count: u16,
    nonce_size: usize,
}

impl CountingNonceGenerator {
    pub fn new(nonce_size: usize) -> Self {
        Self { count: 0, nonce_size }
    }
}

impl CountingNonceGenerator {
    pub fn generate(&mut self, nonce: &mut [u8]) -> Vec<u8> {
        nonce[..size_of::<u16>()].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.overflowing_add(1).0;
        nonce[..self.nonce_size].to_vec()
    }
}

impl Display for CountingNonceGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "count={}", self.count)
    }
}

pub struct IncreasingNonceGenerator {
    nonce: Vec<u8>,
}

impl IncreasingNonceGenerator {
    pub fn init() -> Self {
        Self { nonce: vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] }
    }

    pub fn generate(&mut self) -> Vec<u8> {
        for i in 0..self.nonce.len() {
            self.nonce[i] = self.nonce[i].overflowing_add(1).0;
            if self.nonce[i] != 0 {
                break;
            }
        }
        return self.nonce.to_vec();
    }
}

#[cfg(test)]
mod test {
    use base64ct::Encoding;

    use super::CipherKind;
    use super::CountingNonceGenerator;
    use crate::common::codec::aead::IncreasingNonceGenerator;

    #[test]
    fn test_json_serialize() {
        let vec = vec![CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];
        let str = serde_json::to_string(&vec).unwrap();
        assert_eq!("[\"aes-128-gcm\",\"aes-256-gcm\",\"chacha20-poly1305\"]", str);
        let ciphers: Vec<CipherKind> = serde_json::from_str(str.as_str()).unwrap();
        assert_eq!(vec, ciphers);
    }

    #[test]
    fn test_generate_increasing_nonce() {
        let nonce = vec![0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut generator: IncreasingNonceGenerator = IncreasingNonceGenerator { nonce };
        assert_eq!(generator.generate(), [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_initial_aead_nonce() {
        assert_eq!(IncreasingNonceGenerator::init().generate(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_counting_nonce() {
        let mut nonce: [u8; 16] = [0; 16];
        let mut generator = CountingNonceGenerator::new(12);
        let mut generated = Vec::new();
        for _ in 0..65536 {
            generated = generator.generate(&mut nonce);
        }
        assert_eq!("//8AAAAAAAAAAAAA", base64ct::Base64::encode_string(&generated[..]));
        assert_eq!("//8AAAAAAAAAAAAAAAAAAA==", base64ct::Base64::encode_string(&nonce));
    }
}
