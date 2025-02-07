pub mod aead;
pub mod aead_2022;
pub mod tcp;
pub mod udp;

use core::slice;
use std::mem::size_of;

use aes_gcm::aead::Buffer;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::trace;
use tokio_util::bytes;

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

    fn encode_size(&mut self, bytes: &mut [u8]) -> Result<(), ::aes_gcm::aead::Error> {
        self.method.encrypt_in_place_detached(self.nonce_generator.generate(), &[], bytes)
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> Result<usize, ::aes_gcm::aead::Error> {
        self.open(data)?;
        let size = data.get_u16();
        Ok(size as usize + self.method.tag_size())
    }

    fn seal(&mut self, plaintext: &mut dyn Buffer) -> Result<(), ::aes_gcm::aead::Error> {
        self.method.encrypt_in_place(self.nonce_generator.generate(), &[], plaintext)
    }

    fn open(&mut self, ciphertext: &mut dyn Buffer) -> Result<(), ::aes_gcm::aead::Error> {
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

    fn encode_chunk(&mut self, src: &mut BytesMut, len: usize, dst: &mut BytesMut) -> Result<(), ::aes_gcm::aead::Error> {
        trace!("Encode chunk; len={}", len);
        let tag_size = self.auth.method.tag_size();
        dst.reserve(2 + tag_size);
        let temp = &mut dst.chunk_mut()[..2 + tag_size];
        let temp = unsafe { slice::from_raw_parts_mut(temp.as_mut_ptr(), temp.len()) };
        dst.put_u16(len as u16);
        self.encode_size(temp)?;
        unsafe { dst.advance_mut(tag_size) };
        let mut temp = src.split_to(len);
        self.auth.seal(&mut temp)?;
        dst.extend_from_slice(&temp);
        Ok(())
    }

    fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut) -> Result<(), ::aes_gcm::aead::Error> {
        let limit = self.payload_limit - self.auth.method.tag_size() - self.size_bytes();
        while src.has_remaining() {
            let len = src.remaining().min(limit);
            self.encode_chunk(&mut src, len, dst)?;
        }
        Ok(())
    }

    fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut) -> Result<(), ::aes_gcm::aead::Error> {
        self.auth.seal(&mut src)?;
        dst.extend_from_slice(&src);
        Ok(())
    }

    fn size_bytes(&self) -> usize {
        self.auth.size_bytes()
    }

    fn encode_size(&mut self, size_bytes: &mut [u8]) -> Result<(), ::aes_gcm::aead::Error> {
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

    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<BytesMut, ::aes_gcm::aead::Error> {
        let mut opening = src.split_off(0);
        self.auth.open(&mut opening)?;
        Ok(opening)
    }

    fn decode_payload(&mut self, src: &mut BytesMut, dst: &mut BytesMut) -> Result<(), ::aes_gcm::aead::Error> {
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

    fn decode_size(&mut self, data: &mut BytesMut) -> Result<usize, ::aes_gcm::aead::Error> {
        self.auth.decode_size(data)
    }
}
