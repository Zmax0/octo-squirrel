use std::io;
use std::sync::{Arc, Mutex};

use aes::cipher::Unsigned;
use aes_gcm::{aead::{Aead, Payload}, AeadCore, Aes128Gcm, Aes256Gcm, KeyInit};
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use log::trace;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::{chunk::ChunkSizeCodec, BytesGenerator, PaddingLengthGenerator};

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

    pub fn to_aead_cipher(&self, key: &[u8]) -> Box<dyn AEADCipher> {
        match self {
            SupportedCipher::Aes128Gcm => Box::new(Aes128GcmCipher::new(&key)),
            SupportedCipher::Aes256Gcm => Box::new(Aes256GcmCipher::new(&key)),
            SupportedCipher::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(&key)),
        }
    }
}

pub trait AEADCipher: Send + Sync {
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

        impl AEADCipher for $name {
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
    cipher: Box<dyn AEADCipher>,
    nonce_generator: Box<dyn BytesGenerator>,
    associated_text_generator: Box<dyn BytesGenerator>,
}

impl Authenticator {
    pub fn new(cipher: Box<dyn AEADCipher>, nonce_generator: Box<dyn BytesGenerator>, associated_text_generator: Box<dyn BytesGenerator>) -> Self {
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

pub struct PayloadDecoder {
    payload_length: Option<usize>,
    padding_length: Option<usize>,
    pub auth: Arc<Mutex<Authenticator>>,
    size_codec: Box<dyn ChunkSizeCodec>,
    padding: Box<dyn PaddingLengthGenerator>,
}

impl PayloadDecoder {
    pub fn new(auth: Arc<Mutex<Authenticator>>, size_codec: Box<dyn ChunkSizeCodec>, padding: Box<dyn PaddingLengthGenerator>) -> Self {
        Self { payload_length: None, padding_length: None, auth, size_codec, padding }
    }

    pub fn decode_payload(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let size_bytes = self.size_codec.size_bytes();
        let mut dst = Vec::new();
        while src.remaining() >= if self.payload_length.is_none() { size_bytes } else { self.payload_length.unwrap() } {
            if self.padding_length.is_none() {
                let padding_length = self.padding.next_padding_length();
                trace!("Decode payload; padding length={:?}", padding_length);
                self.padding_length = Some(padding_length);
            }
            let padding_length = self.padding_length.unwrap();
            if let Some(payload_length) = self.payload_length {
                let mut payload_btyes = self.auth.lock().unwrap().open(&src.split_to(payload_length - padding_length));
                dst.append(&mut payload_btyes);
                src.advance(padding_length);
                self.payload_length = None;
                self.padding_length = None;
            } else {
                let payload_length_bytes = src.split_to(size_bytes);
                let payload_length = self.size_codec.decode(&payload_length_bytes).unwrap();
                trace!("Decode payload; payload length={:?}", payload_length);
                self.payload_length = Some(payload_length);
            }
        }
        if dst.is_empty() {
            Ok(None)
        } else {
            Ok(Some(BytesMut::from(&dst[..])))
        }
    }

    pub fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let padding_length = self.padding.next_padding_length();
        let packet_length = self.size_codec.decode(&src.split_to(self.size_codec.size_bytes())).unwrap();
        let packet_sealed_bytes = src.split_to(packet_length - padding_length);
        let packet_bytes = self.auth.lock().unwrap().open(&packet_sealed_bytes);
        Ok(Some(BytesMut::from(&packet_bytes[..])))
    }
}

pub struct PayloadEncoder {
    payload_limit: usize,
    pub auth: Arc<Mutex<Authenticator>>,
    size_codec: Box<dyn ChunkSizeCodec>,
    padding: Box<dyn PaddingLengthGenerator>,
}

impl PayloadEncoder {
    pub fn new(
        payload_limit: usize,
        auth: Arc<Mutex<Authenticator>>,
        size_codec: Box<dyn ChunkSizeCodec>,
        padding: Box<dyn PaddingLengthGenerator>,
    ) -> Self {
        Self { payload_limit, auth, size_codec, padding }
    }

    pub fn encode_payload(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        while src.has_remaining() {
            self.seal(src, dst);
        }
    }

    pub fn encode_packet(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        self.seal(src, dst);
    }

    fn seal(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        let padding_length = self.padding.next_padding_length();
        trace!("Encode payload; padding length={}", padding_length);
        let overhead = self.auth.lock().unwrap().overhead();
        let encrypted_size = src.remaining().min(self.payload_limit - overhead - self.size_codec.size_bytes() - padding_length);
        trace!("Encode payload; payload length={}", encrypted_size);
        let encrypted_size_bytes = self.size_codec.encode(encrypted_size + padding_length + overhead).unwrap();
        dst.put_slice(&encrypted_size_bytes);
        let payload_bytes = src.split_to(encrypted_size);
        dst.put_slice(&self.auth.lock().unwrap().seal(&payload_bytes));
        let mut padding_bytes: Vec<u8> = vec![0; padding_length];
        rand::thread_rng().fill(&mut padding_bytes[..]);
        dst.put(&padding_bytes[..]);
    }
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
