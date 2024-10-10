pub mod aead;
pub mod aead_2022;
pub mod tcp;
pub mod udp;

use std::mem::size_of;

use ::aead::Buffer;
use bytes::Buf;
use bytes::BytesMut;
use log::trace;

use super::aead::CipherMethod;
use super::aead::IncreasingNonceGenerator;

pub enum ChunkSizeParser {
    Auth,
    Empty,
}

pub struct Authenticator {
    method: CipherMethod,
    nonce_generator: IncreasingNonceGenerator,
}

impl Authenticator {
    fn new(method: CipherMethod) -> Self {
        Self { method, nonce_generator: IncreasingNonceGenerator::init() }
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

pub struct ChunkEncoder {
    payload_limit: usize,
    auth: Authenticator,
    chunk: ChunkSizeParser,
}

impl ChunkEncoder {
    fn new(payload_limit: usize, auth: Authenticator, chunk: ChunkSizeParser) -> Self {
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
        dst.extend_from_slice(&payload_bytes);
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
        dst.extend_from_slice(&src);
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

enum DecodeState {
    Length,
    Payload(usize),
}

pub struct ChunkDecoder {
    auth: Authenticator,
    chunk: ChunkSizeParser,
    state: DecodeState,
}

impl ChunkDecoder {
    fn new(auth: Authenticator, chunk: ChunkSizeParser) -> Self {
        Self { auth, chunk, state: DecodeState::Length }
    }

    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<BytesMut, ::aead::Error> {
        let mut opening = src.split_off(0);
        self.auth.open(&mut opening)?;
        Ok(opening)
    }

    fn decode_payload(&mut self, src: &mut BytesMut, dst: &mut BytesMut) -> Result<(), ::aead::Error> {
        loop {
            match self.state {
                DecodeState::Length => {
                    let size_bytes = self.size_bytes();
                    if src.remaining() < size_bytes {
                        return Ok(());
                    }
                    let len = self.decode_size(&mut src.split_to(size_bytes))?;
                    trace!("Decode payload; payload length={}", len);
                    self.state = DecodeState::Payload(len);
                }
                DecodeState::Payload(len) => {
                    if src.remaining() < len {
                        return Ok(());
                    }
                    dst.reserve(len);
                    let mut payload_btyes = src.split_to(len);
                    self.auth.open(&mut payload_btyes)?;
                    dst.extend_from_slice(&payload_btyes);
                    self.state = DecodeState::Length;
                }
            }
        }
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
