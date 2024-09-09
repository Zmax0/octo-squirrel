mod aead;
mod aead_2022;
pub mod tcp;
pub mod udp;

use std::fmt::Display;
use std::mem::size_of;

use ::aead::Buffer;
use base64ct::Base64;
use base64ct::Encoding;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::trace;

use super::aead::CipherKind;
use super::aead::CipherMethod;
use super::aead::IncreasingNonceGenerator;
use super::aead::KeyInit;

enum NonceGenerator {
    Increasing(IncreasingNonceGenerator),
    Static(Box<[u8]>),
}

impl NonceGenerator {
    pub fn generate(&mut self) -> &[u8] {
        match self {
            NonceGenerator::Increasing(ref mut inner) => inner.generate(),
            NonceGenerator::Static(nonce) => nonce,
        }
    }
}

pub enum ChunkSizeParser {
    Auth,
    Empty,
}

pub struct Authenticator<CM> {
    method: CM,
    nonce_generator: NonceGenerator,
}

impl<CM: CipherMethod + KeyInit> Authenticator<CM> {
    fn new(method: CM, nonce_generator: NonceGenerator) -> Self {
        Self { method, nonce_generator }
    }

    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.method.tag_size()
    }

    fn encode_size(&mut self, size: usize) -> Result<Vec<u8>, ::aead::Error> {
        let mut bytes = ((size - self.method.tag_size()) as u16).to_be_bytes().to_vec();
        self.seal(&mut bytes)?;
        Ok(bytes)
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> Result<usize, ::aead::Error> {
        self.open(data)?;
        let size = data.get_u16();
        Ok(size as usize + self.method.tag_size())
    }

    fn seal(&mut self, plaintext: &mut dyn Buffer) -> Result<(), ::aead::Error> {
        self.method.encrypt_in_place(self.nonce_generator.generate(), b"", plaintext)
    }

    fn open(&mut self, ciphertext: &mut dyn Buffer) -> Result<(), ::aead::Error> {
        self.method.decrypt_in_place(self.nonce_generator.generate(), b"", ciphertext)
    }
}

pub struct ChunkEncoder<CM> {
    payload_limit: usize,
    auth: Authenticator<CM>,
    chunk: ChunkSizeParser,
}

impl<CM: CipherMethod + KeyInit> ChunkEncoder<CM> {
    fn new(payload_limit: usize, auth: Authenticator<CM>, chunk: ChunkSizeParser) -> Self {
        Self { payload_limit, auth, chunk }
    }

    fn encode_chunk(&mut self, src: &mut BytesMut, dst: &mut BytesMut) -> Result<(), ::aead::Error> {
        let tag_size = self.auth.method.tag_size();
        let encrypted_size = src.remaining().min(self.payload_limit - tag_size - self.size_bytes());
        trace!("Encode payload; payload length={}", encrypted_size);
        let encrypted_size_bytes = self.encode_size(encrypted_size + tag_size)?;
        dst.extend_from_slice(&encrypted_size_bytes);
        let mut payload_bytes = src.split_to(encrypted_size);
        self.auth.seal(&mut payload_bytes)?;
        dst.put(payload_bytes);
        Ok(())
    }

    fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut) -> Result<(), ::aead::Error> {
        while src.has_remaining() {
            self.encode_chunk(&mut src, dst)?;
        }
        Ok(())
    }

    fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut) -> Result<(), ::aead::Error> {
        self.auth.seal(&mut src)?;
        dst.put(src);
        Ok(())
    }

    fn size_bytes(&self) -> usize {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.size_bytes(),
            ChunkSizeParser::Empty => 0,
        }
    }

    fn encode_size(&mut self, size: usize) -> Result<Vec<u8>, ::aead::Error> {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.encode_size(size),
            ChunkSizeParser::Empty => Ok(Vec::with_capacity(0)),
        }
    }
}

pub struct ChunkDecoder<CM> {
    payload_length: Option<usize>,
    auth: Authenticator<CM>,
    chunk: ChunkSizeParser,
}

impl<CM: CipherMethod + KeyInit> ChunkDecoder<CM> {
    fn new(auth: Authenticator<CM>, chunk: ChunkSizeParser) -> Self {
        Self { payload_length: None, auth, chunk }
    }

    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, ::aead::Error> {
        let mut opening = src.split_off(0);
        self.auth.open(&mut opening)?;
        Ok(Some(opening))
    }

    fn decode_payload(&mut self, src: &mut BytesMut, dst: &mut BytesMut) -> Result<(), ::aead::Error> {
        let size_bytes = self.size_bytes();
        while src.remaining() >= if self.payload_length.is_none() { size_bytes } else { self.payload_length.unwrap() } {
            if let Some(payload_length) = self.payload_length {
                let mut payload_btyes = src.split_to(payload_length);
                self.auth.open(&mut payload_btyes)?;
                dst.put(payload_btyes);
                self.payload_length = None;
            } else {
                let payload_length = self.decode_size(&mut src.split_to(size_bytes))?;
                trace!("Decode payload; payload length={}", payload_length);
                self.payload_length = Some(payload_length);
            }
        }
        Ok(())
    }

    fn size_bytes(&self) -> usize {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.size_bytes(),
            ChunkSizeParser::Empty => 0,
        }
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> Result<usize, ::aead::Error> {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.decode_size(data),
            ChunkSizeParser::Empty => Ok(data.len()),
        }
    }
}

struct Keys<const N: usize> {
    enc_key: [u8; N],
    identity_keys: Vec<[u8; N]>,
}

impl<const N: usize> Keys<N> {
    fn new(enc_key: [u8; N], identity_keys: Vec<[u8; N]>) -> Self {
        Self { enc_key, identity_keys }
    }

    fn from(kind: CipherKind, password: &str) -> Result<Keys<N>, base64ct::Error> {
        if kind.is_aead_2022() {
            aead_2022::password_to_keys(password)
        } else {
            let enc_key = aead::openssl_bytes_to_key(password.as_bytes());
            Ok(Keys { enc_key, identity_keys: Vec::with_capacity(0) })
        }
    }
}

impl<const N: usize> Display for Keys<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EK: {}, IKS: {:#?}", Base64::encode_string(&self.enc_key), self.identity_keys)
    }
}
