pub mod aead;
pub mod aead_2022;
pub mod tcp;
pub mod udp;

use core::slice;
use std::mem::size_of;

use ::aead::Buffer;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::trace;

use super::aead::CipherMethod;
use super::aead::IncreasingNonceGenerator;

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

    fn encode_size(&mut self, bytes: &mut [u8]) -> Result<(), ::aead::Error> {
        self.method.encrypt_in_place_detached(self.nonce_generator.generate(), &[], bytes)
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> Result<usize, ::aead::Error> {
        self.open(data)?;
        let size = data.get_u16();
        Ok(size as usize + self.method.tag_size())
    }

    fn seal(&mut self, plaintext: &mut dyn Buffer) -> Result<(), ::aead::Error> {
        self.method.encrypt_in_place(self.nonce_generator.generate(), &[], plaintext)
    }

    fn open(&mut self, ciphertext: &mut dyn Buffer) -> Result<(), ::aead::Error> {
        self.method.decrypt_in_place(self.nonce_generator.generate(), &[], ciphertext)
    }
}

pub struct ChunkEncoder {
    payload_limit: usize,
    auth: Authenticator,
}

impl ChunkEncoder {
    fn new(payload_limit: usize, auth: Authenticator) -> Self {
        Self { payload_limit, auth }
    }

    fn encode_chunk(&mut self, src: &mut BytesMut, dst: &mut BytesMut) -> Result<(), ::aead::Error> {
        let tag_size = self.auth.method.tag_size();
        let encrypted_len = src.remaining().min(self.payload_limit - tag_size - self.size_bytes());
        trace!("Encode payload; payload length={}", encrypted_len);
        dst.reserve(2 + tag_size);
        let encrypted_size_bytes = &mut dst.chunk_mut()[..2 + tag_size];
        let encrypted_size_bytes = unsafe { slice::from_raw_parts_mut(encrypted_size_bytes.as_mut_ptr(), encrypted_size_bytes.len()) };
        dst.put_u16(encrypted_len as u16);
        self.encode_size(encrypted_size_bytes)?;
        unsafe { dst.advance_mut(tag_size) };
        let mut payload_bytes = src.split_to(encrypted_len);
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
        self.auth.size_bytes()
    }

    fn encode_size(&mut self, size_bytes: &mut [u8]) -> Result<(), ::aead::Error> {
        self.auth.encode_size(size_bytes)
    }
}

enum DecodeState {
    Length,
    Payload(usize),
}

pub struct ChunkDecoder {
    auth: Authenticator,
    state: DecodeState,
}

impl ChunkDecoder {
    fn new(auth: Authenticator) -> Self {
        Self { auth, state: DecodeState::Length }
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
                    let mut payload_bytes = src.split_to(len);
                    self.auth.open(&mut payload_bytes)?;
                    dst.extend_from_slice(&payload_bytes);
                    self.state = DecodeState::Length;
                }
            }
        }
    }

    fn size_bytes(&self) -> usize {
        self.auth.size_bytes()
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> Result<usize, ::aead::Error> {
        self.auth.decode_size(data)
    }
}
