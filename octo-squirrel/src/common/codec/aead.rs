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
use chacha20poly1305::ChaCha20Poly1305;
use digest::InvalidLength;
use serde::Deserialize;
use serde::Serialize;

pub trait CipherMethod: Send {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, aead::Error>;
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, aead::Error>;
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) -> Result<(), aead::Error>;
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) -> Result<(), aead::Error>;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
    fn ciphertext_overhead(&self) -> usize;
}

pub trait KeyInit: Sized {
    fn init(key: &[u8]) -> Result<Self, InvalidLength>;
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

            pub fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
                use aes_gcm::KeyInit;
                Ok(Self { cipher: <$cipher>::new_from_slice(key)? })
            }
        }

        impl CipherMethod for $name {
            fn encrypt(&self, nonce: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, aead::Error> {
                self.cipher.encrypt(nonce.into(), Payload { msg, aad })
            }

            fn decrypt(&self, nonce: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, aead::Error> {
                self.cipher.decrypt(nonce.into(), Payload { msg, aad })
            }

            fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) -> Result<(), aead::Error> {
                self.cipher.encrypt_in_place(nonce.into(), aad, buffer)
            }

            fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut dyn Buffer) -> Result<(), aead::Error> {
                self.cipher.decrypt_in_place(nonce.into(), aad, buffer)
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

        impl KeyInit for $name {
            fn init(key: &[u8]) -> Result<Self, InvalidLength> {
                $name::new_from_slice(key)
            }
        }
    };
}

aead_impl!(Aes128GcmCipher, Aes128Gcm);
aead_impl!(Aes256GcmCipher, Aes256Gcm);
aead_impl!(ChaCha20Poly1305Cipher, ChaCha20Poly1305);

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
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
    #[default]
    Unknown,
}

macro_rules! match_method_const {
    ($self:ident, $const:ident) => {
        match $self {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => Aes128GcmCipher::$const,
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm => Aes256GcmCipher::$const,
            CipherKind::ChaCha20Poly1305 => ChaCha20Poly1305Cipher::$const,
            _ => unreachable!(),
        }
    };
}

impl CipherKind {
    pub fn to_cipher_method(&self, key: &[u8]) -> Result<Box<dyn CipherMethod>, InvalidLength> {
        match self {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => Ok(Box::new(Aes128GcmCipher::new_from_slice(key)?)),
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm => Ok(Box::new(Aes256GcmCipher::new_from_slice(key)?)),
            CipherKind::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Cipher::new_from_slice(key)?)),
            _ => unreachable!(),
        }
    }

    pub fn is_aead_2022(&self) -> bool {
        matches!(self, CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm)
    }

    pub fn support_eih(&self) -> bool {
        self.is_aead_2022()
    }

    pub fn tag_size(&self) -> usize {
        match_method_const!(self, TAG_SIZE)
    }

    pub fn ciphertext_overhead(&self) -> usize {
        match_method_const!(self, CIPHERTEXT_OVERHEAD)
    }
}

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

    pub fn generate(&mut self) -> &[u8] {
        for i in 0..self.nonce.len() {
            self.nonce[i] = self.nonce[i].overflowing_add(1).0;
            if self.nonce[i] != 0 {
                break;
            }
        }
        &self.nonce
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
