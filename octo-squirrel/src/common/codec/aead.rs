use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::size_of;

use aead::Key;
use aead::KeyInit;
use aead::KeySizeUser;
use aes::cipher::Unsigned;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Buffer;
use aes_gcm::aead::Payload;
use aes_gcm::AeadCore;
use aes_gcm::AeadInPlace;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use serde::Deserialize;
use serde::Serialize;

macro_rules! method_match_aead {
    ($self:ident, $trait:ident, $type:ident) => {
        match $self {
            Self::Aes128Gcm(_) => <Aes128Gcm as $trait>::$type::USIZE,
            Self::Aes256Gcm(_) => <Aes256Gcm as $trait>::$type::USIZE,
            Self::ChaCha20Poly1305(_) => <ChaCha20Poly1305 as $trait>::$type::USIZE,
        }
    };
}

#[allow(clippy::large_enum_variant)]
pub enum CipherMethod {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl CipherMethod {
    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        match kind {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                let key = &key[..<Aes128Gcm as KeySizeUser>::KeySize::USIZE];
                Self::Aes128Gcm(Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key)))
            }
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm => {
                let key = &key[..<Aes256Gcm as KeySizeUser>::KeySize::USIZE];
                Self::Aes256Gcm(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
            }
            CipherKind::ChaCha20Poly1305 => {
                let key = &key[..<ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE];
                Self::ChaCha20Poly1305(ChaCha20Poly1305::new(Key::<ChaCha20Poly1305>::from_slice(key)))
            }
            _ => unreachable!(),
        }
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, aead::Error> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt(nonce.into(), Payload { msg: plaintext, aad: associated_data }),
            Self::Aes256Gcm(cipher) => cipher.encrypt(nonce.into(), Payload { msg: plaintext, aad: associated_data }),
            Self::ChaCha20Poly1305(cipher) => cipher.encrypt(nonce.into(), Payload { msg: plaintext, aad: associated_data }),
        }
    }

    pub fn encrypt_in_place(&self, nonce: &[u8], associated_data: &[u8], plaintext: &mut dyn Buffer) -> Result<(), aead::Error> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.encrypt_in_place(nonce.into(), associated_data, plaintext),
            Self::Aes256Gcm(cipher) => cipher.encrypt_in_place(nonce.into(), associated_data, plaintext),
            Self::ChaCha20Poly1305(cipher) => cipher.encrypt_in_place(nonce.into(), associated_data, plaintext),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, aead::Error> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad: associated_data }),
            Self::Aes256Gcm(cipher) => cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad: associated_data }),
            Self::ChaCha20Poly1305(cipher) => cipher.decrypt(nonce.into(), Payload { msg: ciphertext, aad: associated_data }),
        }
    }

    pub fn decrypt_in_place(&self, nonce: &[u8], associated_data: &[u8], ciphertext: &mut dyn Buffer) -> Result<(), aead::Error> {
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt_in_place(nonce.into(), associated_data, ciphertext),
            Self::Aes256Gcm(cipher) => cipher.decrypt_in_place(nonce.into(), associated_data, ciphertext),
            Self::ChaCha20Poly1305(cipher) => cipher.decrypt_in_place(nonce.into(), associated_data, ciphertext),
        }
    }

    pub const fn nonce_size(&self) -> usize {
        method_match_aead!(self, AeadCore, NonceSize)
    }

    pub const fn tag_size(&self) -> usize {
        method_match_aead!(self, AeadCore, TagSize)
    }

    pub const fn ciphertext_overhead(&self) -> usize {
        method_match_aead!(self, AeadCore, CiphertextOverhead)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

macro_rules! kind_match_aead {
    ($self:ident, $trait:ident, $type:ident) => {
        match $self {
            Self::Aes128Gcm | Self::Aead2022Blake3Aes128Gcm => <Aes128Gcm as $trait>::$type::USIZE,
            Self::Aes256Gcm | Self::Aead2022Blake3Aes256Gcm => <Aes256Gcm as $trait>::$type::USIZE,
            Self::ChaCha20Poly1305 => <ChaCha20Poly1305 as $trait>::$type::USIZE,
            _ => unreachable!(),
        }
    };
}

impl CipherKind {
    pub const fn is_aead_2022(&self) -> bool {
        matches!(self, CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm)
    }

    pub const fn support_eih(&self) -> bool {
        self.is_aead_2022()
    }

    pub const fn tag_size(&self) -> usize {
        kind_match_aead!(self, AeadCore, TagSize)
    }

    pub const fn ciphertext_overhead(&self) -> usize {
        kind_match_aead!(self, AeadCore, CiphertextOverhead)
    }
}

impl Display for CipherKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherKind::Aes128Gcm => write!(f, "aes-128-gcm"),
            CipherKind::Aes256Gcm => write!(f, "aes-256-gcm"),
            CipherKind::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
            CipherKind::Aead2022Blake3Aes128Gcm => write!(f, "2022-blake3-aes-128-gcm"),
            CipherKind::Aead2022Blake3Aes256Gcm => write!(f, "2022-blake3-aes-256-gcm"),
            CipherKind::Unknown => write!(f, "?"),
        }
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
    pub fn generate<'a>(&mut self, nonce: &'a mut [u8]) -> &'a [u8] {
        nonce[..size_of::<u16>()].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.overflowing_add(1).0;
        &nonce[..self.nonce_size]
    }
}

impl Display for CountingNonceGenerator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "count={}", self.count)
    }
}

pub struct IncreasingNonceGenerator {
    nonce: [u8; 12],
}

impl IncreasingNonceGenerator {
    pub fn init() -> Self {
        Self { nonce: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] }
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
    use super::IncreasingNonceGenerator;

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
        let nonce = [0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
        const NONCE_SIZE: usize = 12;
        let mut generator = CountingNonceGenerator::new(NONCE_SIZE);
        let mut generated = [0; NONCE_SIZE];
        for _ in 0..65536 {
            let res = generator.generate(&mut nonce);
            generated.copy_from_slice(res);
        }
        assert_eq!("//8AAAAAAAAAAAAA", base64ct::Base64::encode_string(&generated[..]));
        assert_eq!("//8AAAAAAAAAAAAAAAAAAA==", base64ct::Base64::encode_string(&nonce));
    }
}
