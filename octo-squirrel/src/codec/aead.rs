use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::size_of;

use aead::generic_array::GenericArray;
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
use chacha20poly1305::ChaCha8Poly1305;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XChaCha8Poly1305;
use serde::Deserialize;
use serde::Serialize;

#[allow(clippy::large_enum_variant)]
pub enum CipherMethod {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha8Poly1305(ChaCha8Poly1305),
    ChaCha20Poly1305(ChaCha20Poly1305),
    XChaCha8Poly1305(XChaCha8Poly1305),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

macro_rules! method_match_aead_trait {
    ($self:ident, $trait:ident, $type:ident) => {
        match $self {
            Self::Aes128Gcm(_) => <Aes128Gcm as $trait>::$type::USIZE,
            Self::Aes256Gcm(_) => <Aes256Gcm as $trait>::$type::USIZE,
            Self::ChaCha8Poly1305(_) => <ChaCha8Poly1305 as $trait>::$type::USIZE,
            Self::ChaCha20Poly1305(_) => <ChaCha20Poly1305 as $trait>::$type::USIZE,
            Self::XChaCha8Poly1305(_) => <XChaCha8Poly1305 as $trait>::$type::USIZE,
            Self::XChaCha20Poly1305(_) => <XChaCha20Poly1305 as $trait>::$type::USIZE,
        }
    };
}

macro_rules! method_match_aead_fn {
    ($self:ident, $fn:ident, $param:tt) => {
        match $self {
            Self::Aes128Gcm(cipher) => cipher.$fn$param,
            Self::Aes256Gcm(cipher) => cipher.$fn$param,
            Self::ChaCha8Poly1305(cipher) => cipher.$fn$param,
            Self::ChaCha20Poly1305(cipher) => cipher.$fn$param,
            Self::XChaCha8Poly1305(cipher) => cipher.$fn$param,
            Self::XChaCha20Poly1305(cipher) => cipher.$fn$param,
        }
    };
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
            CipherKind::ChaCha20Poly1305 | CipherKind::Aead2022Blake3ChaCha20Poly1305 => {
                let key = &key[..<ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE];
                Self::ChaCha20Poly1305(ChaCha20Poly1305::new(Key::<ChaCha20Poly1305>::from_slice(key)))
            }
            CipherKind::Aead2022Blake3ChaCha8Poly1305 => {
                let key = &key[..<ChaCha8Poly1305 as KeySizeUser>::KeySize::USIZE];
                Self::ChaCha8Poly1305(ChaCha8Poly1305::new(Key::<ChaCha8Poly1305>::from_slice(key)))
            }
            CipherKind::Unknown => panic!("unknown cipher kind"),
        }
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, aead::Error> {
        method_match_aead_fn!(self, encrypt, (nonce.into(), Payload { msg: plaintext, aad: associated_data }))
    }

    pub fn encrypt_in_place(&self, nonce: &[u8], associated_data: &[u8], plaintext: &mut dyn Buffer) -> Result<(), aead::Error> {
        method_match_aead_fn!(self, encrypt_in_place, (nonce.into(), associated_data, plaintext))
    }

    pub fn encrypt_in_place_detached(&self, nonce: &[u8], associated_data: &[u8], plaintext: &mut [u8]) -> Result<(), aead::Error> {
        let (buffer, tag) = plaintext.split_at_mut(plaintext.len() - self.tag_size());
        let _tag = method_match_aead_fn!(self, encrypt_in_place_detached, (nonce.into(), associated_data, buffer))?;
        tag.copy_from_slice(_tag.as_slice());
        Ok(())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, aead::Error> {
        method_match_aead_fn!(self, decrypt, (nonce.into(), Payload { msg: ciphertext, aad: associated_data }))
    }

    pub fn decrypt_in_place(&self, nonce: &[u8], associated_data: &[u8], ciphertext: &mut dyn Buffer) -> Result<(), aead::Error> {
        method_match_aead_fn!(self, decrypt_in_place, (nonce.into(), associated_data, ciphertext))
    }

    pub fn decrypt_in_place_detached(&self, nonce: &[u8], associated_data: &[u8], ciphertext: &mut [u8]) -> Result<(), aead::Error> {
        let (buffer, tag) = ciphertext.split_at_mut(ciphertext.len() - self.tag_size());
        method_match_aead_fn!(self, decrypt_in_place_detached, (nonce.into(), associated_data, buffer, GenericArray::from_mut_slice(tag)))
    }

    pub const fn nonce_size(&self) -> usize {
        method_match_aead_trait!(self, AeadCore, NonceSize)
    }

    pub const fn tag_size(&self) -> usize {
        method_match_aead_trait!(self, AeadCore, TagSize)
    }

    pub const fn ciphertext_overhead(&self) -> usize {
        method_match_aead_trait!(self, AeadCore, CiphertextOverhead)
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
    #[serde(rename = "2022-blake3-chacha8-poly1305")]
    Aead2022Blake3ChaCha8Poly1305,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Aead2022Blake3ChaCha20Poly1305,
    #[default]
    Unknown,
}

macro_rules! kind_match_aead {
    ($self:ident, $trait:ident, $type:ident) => {
        match $self {
            Self::Aes128Gcm | Self::Aead2022Blake3Aes128Gcm => <Aes128Gcm as $trait>::$type::USIZE,
            Self::Aes256Gcm | Self::Aead2022Blake3Aes256Gcm => <Aes256Gcm as $trait>::$type::USIZE,
            Self::ChaCha20Poly1305 | Self::Aead2022Blake3ChaCha20Poly1305 => <ChaCha20Poly1305 as $trait>::$type::USIZE,
            Self::Aead2022Blake3ChaCha8Poly1305 => <ChaCha8Poly1305 as $trait>::$type::USIZE,
            Self::Unknown => panic!("unknown cipher kind"),
        }
    };
}

impl CipherKind {
    pub const fn is_aead_2022(&self) -> bool {
        matches!(
            self,
            Self::Aead2022Blake3Aes128Gcm
                | Self::Aead2022Blake3Aes256Gcm
                | Self::Aead2022Blake3ChaCha8Poly1305
                | Self::Aead2022Blake3ChaCha20Poly1305
        )
    }

    pub const fn support_eih(&self) -> bool {
        matches!(self, Self::Aead2022Blake3Aes128Gcm | Self::Aead2022Blake3Aes256Gcm)
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
            CipherKind::Aead2022Blake3ChaCha8Poly1305 => write!(f, "2022-blake3-chacha8-poly1305"),
            CipherKind::Aead2022Blake3ChaCha20Poly1305 => write!(f, "2022-blake3-chacha20-poly1305"),
            CipherKind::Unknown => write!(f, "?"),
        }
    }
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
        Self { nonce: [u8::MAX; 12] }
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
    fn test_json_serialize() -> serde_json::error::Result<()> {
        let vec = vec![CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];
        let str = serde_json::to_string(&vec)?;
        assert_eq!("[\"aes-128-gcm\",\"aes-256-gcm\",\"chacha20-poly1305\"]", str);
        let ciphers: Vec<CipherKind> = serde_json::from_str(str.as_str())?;
        assert_eq!(vec, ciphers);
        Ok(())
    }

    #[test]
    fn test_generate_increasing_nonce() {
        let nonce = [0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut generator = IncreasingNonceGenerator { nonce };
        assert_eq!(generator.generate(), [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_initial_aead_nonce() {
        assert_eq!(IncreasingNonceGenerator::init().generate(), [0; 12])
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
