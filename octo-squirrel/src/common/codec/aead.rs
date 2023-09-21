use std::io;
use std::mem::size_of;

use aes::cipher::Unsigned;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::AeadCore;
use aes_gcm::Aes128Gcm;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use bytes::BytesMut;
use chacha20poly1305::ChaCha20Poly1305;
use serde::Deserialize;
use serde::Serialize;

use super::chunk::ChunkSizeCodec;
use super::BytesGenerator;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SupportedCipher {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl SupportedCipher {
    pub const VALUES: [SupportedCipher; 3] = [SupportedCipher::Aes128Gcm, SupportedCipher::Aes256Gcm, SupportedCipher::ChaCha20Poly1305];

    pub fn to_aead_cipher(&self, key: &[u8]) -> Box<dyn Cipher> {
        match self {
            SupportedCipher::Aes128Gcm => Box::new(Aes128GcmCipher::new(&key)),
            SupportedCipher::Aes256Gcm => Box::new(Aes256GcmCipher::new(&key)),
            SupportedCipher::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(&key)),
        }
    }
}

pub trait Cipher: Send {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Vec<u8>;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
    fn overhead(&self) -> usize;
}

macro_rules! aead_impl {
    ($name:ident, $cipher:ty) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
        }

        impl $name {
            pub const NONCE_SIZE: usize = <$cipher as AeadCore>::NonceSize::USIZE;
            pub const TAG_SIZE: usize = <$cipher as AeadCore>::TagSize::USIZE;
            pub const OVERHEAD: usize = <$cipher as AeadCore>::CiphertextOverhead::USIZE;

            pub fn new(key: &[u8]) -> Self {
                Self { cipher: <$cipher>::new_from_slice(key).unwrap() }
            }
        }

        impl Cipher for $name {
            fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
                let payload = Payload { msg: plaintext, aad };
                self.cipher.encrypt(nonce.into(), payload).unwrap()
            }

            fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
                let payload = Payload { msg: ciphertext, aad };
                self.cipher.decrypt(nonce.into(), payload).expect("Invalid cipher text")
            }

            fn nonce_size(&self) -> usize {
                $name::NONCE_SIZE
            }

            fn tag_size(&self) -> usize {
                $name::TAG_SIZE
            }

            fn overhead(&self) -> usize {
                $name::OVERHEAD
            }
        }
    };
}

aead_impl!(Aes128GcmCipher, Aes128Gcm);
aead_impl!(Aes256GcmCipher, Aes256Gcm);
aead_impl!(ChaCha20Poly1305Cipher, ChaCha20Poly1305);

pub struct Authenticator {
    cipher: Box<dyn Cipher>,
    nonce_generator: Box<dyn BytesGenerator>,
    associated_text_generator: Box<dyn BytesGenerator>,
}

impl Authenticator {
    pub fn new(cipher: Box<dyn Cipher>, nonce_generator: Box<dyn BytesGenerator>, associated_text_generator: Box<dyn BytesGenerator>) -> Self {
        Self { cipher, nonce_generator, associated_text_generator }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.cipher.encrypt(&self.nonce_generator.generate(), plaintext, &self.associated_text_generator.generate())
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.cipher.decrypt(&self.nonce_generator.generate(), ciphertext, &self.associated_text_generator.generate())
    }

    pub fn overhead(&self) -> usize {
        self.cipher.tag_size()
    }
}

impl ChunkSizeCodec for Authenticator {
    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.overhead()
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        let bytes = ((size - self.overhead()) as u16).to_be_bytes();
        let sealed = self.seal(&bytes);
        sealed
    }

    fn decode_size(&mut self, data: &[u8]) -> usize {
        let mut opened: [u8; size_of::<u16>()] = [0; size_of::<u16>()];
        opened.copy_from_slice(&self.open(data));
        let size = u16::from_be_bytes(opened);
        size as usize + self.overhead()
    }
}

pub trait CipherEncoder: Send {
    fn encode_payload(&mut self, src: BytesMut, dst: &mut BytesMut);
    fn encode_packet(&mut self, src: BytesMut, dst: &mut BytesMut);
}

pub trait CipherDecoder: Send {
    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error>;
    fn decode_payload(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error>;
}

#[cfg(test)]
mod test {
    use super::SupportedCipher;

    #[test]
    fn test_json_serialize() {
        let vec = vec![SupportedCipher::Aes128Gcm, SupportedCipher::Aes256Gcm, SupportedCipher::ChaCha20Poly1305];
        let str = serde_json::to_string(&vec).unwrap();
        assert_eq!("[\"aes-128-gcm\",\"aes-256-gcm\",\"chacha20-poly1305\"]", str);
        let ciphers: Vec<SupportedCipher> = serde_json::from_str(str.as_str()).unwrap();
        assert_eq!(vec, ciphers);
    }
}
