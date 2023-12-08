pub mod aead;
pub mod aead_2022;

use std::io::Cursor;
use std::mem::size_of;

use ::aead::Buffer;
use anyhow::bail;
use anyhow::Ok;
use anyhow::Result;
use base64ct::Base64;
use base64ct::Encoding;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::trace;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::aead::CipherKind;
use super::aead::CipherMethod;
use super::aead::IncreasingNonceGenerator;
use crate::common::network::DatagramPacket;
use crate::common::network::Network;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::Context;
use crate::common::protocol::shadowsocks::StreamType;
use crate::common::protocol::socks5::address::AddressCodec;
use crate::common::util::Dice;

enum NonceGenerator {
    Increasing(IncreasingNonceGenerator),
    Empty,
}

impl NonceGenerator {
    pub fn generate(&mut self) -> Vec<u8> {
        match self {
            NonceGenerator::Increasing(ref mut inner) => inner.generate(),
            NonceGenerator::Empty => Vec::new(),
        }
    }
}

pub enum ChunkSizeParser {
    Auth,
    Empty,
}

pub struct Authenticator {
    method: Box<dyn CipherMethod>,
    nonce_generator: NonceGenerator,
}

impl Authenticator {
    fn new(method: Box<dyn CipherMethod>, nonce_generator: NonceGenerator) -> Self {
        Self { method, nonce_generator }
    }

    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.method.tag_size()
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        let mut bytes = ((size - self.method.tag_size()) as u16).to_be_bytes().to_vec();
        self.seal(&mut bytes);
        bytes
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> usize {
        self.open(data);
        let size = data.get_u16();
        size as usize + self.method.tag_size()
    }

    fn seal(&mut self, plaintext: &mut dyn Buffer) {
        self.method.encrypt_in_place(&self.nonce_generator.generate(), b"", plaintext)
    }

    fn open(&mut self, ciphertext: &mut dyn Buffer) {
        self.method.decrypt_in_place(&self.nonce_generator.generate(), b"", ciphertext)
    }
}

pub struct ChunkEncoder {
    payload_limit: usize,
    auth: Authenticator,
    chunk: ChunkSizeParser,
}

impl ChunkEncoder {
    pub fn new(payload_limit: usize, auth: Authenticator, chunk: ChunkSizeParser) -> Self {
        Self { payload_limit, auth, chunk }
    }

    fn encode_chunk(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        let tag_size = self.auth.method.tag_size();
        let encrypted_size = src.remaining().min(self.payload_limit - tag_size - self.auth.size_bytes());
        trace!("Encode payload; payload length={}", encrypted_size);
        let encrypted_size_bytes = self.encode_size(encrypted_size + tag_size);
        dst.put_slice(&encrypted_size_bytes);
        let mut payload_bytes = src.split_to(encrypted_size);
        self.auth.seal(&mut payload_bytes);
        dst.put(payload_bytes);
    }

    fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut) {
        while src.has_remaining() {
            self.encode_chunk(&mut src, dst);
        }
    }

    fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut) {
        self.auth.seal(&mut src);
        dst.put(src);
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.encode_size(size),
            ChunkSizeParser::Empty => Vec::with_capacity(0),
        }
    }
}

pub struct ChunkDecoder {
    payload_length: Option<usize>,
    auth: Authenticator,
    chunk: ChunkSizeParser,
}

impl ChunkDecoder {
    pub fn new(auth: Authenticator, chunk: ChunkSizeParser) -> Self {
        Self { payload_length: None, auth, chunk }
    }
}

impl ChunkDecoder {
    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        let mut opened = src.split_off(0);
        self.auth.open(&mut opened);
        Ok(Some(opened))
    }

    fn decode_payload(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        let size_bytes = self.auth.size_bytes();
        let mut dst = Vec::new();
        while src.remaining() >= if self.payload_length.is_none() { size_bytes } else { self.payload_length.unwrap() } {
            if let Some(payload_length) = self.payload_length {
                let mut payload_btyes = src.split_to(payload_length);
                self.auth.open(&mut payload_btyes);
                dst.put(payload_btyes);
                self.payload_length = None;
            } else {
                let payload_length = self.auth.decode_size(&mut src.split_to(size_bytes));
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

    fn decode_size(&mut self, data: &mut BytesMut) -> usize {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.decode_size(data),
            ChunkSizeParser::Empty => data.len(),
        }
    }
}

pub struct AEADCipherCodec {
    kind: CipherKind,
    key: Box<[u8]>,
    request_salt: Box<[u8]>,
    pub(self) encoder: Option<ChunkEncoder>,
    pub(self) decoder: Option<ChunkDecoder>,
}

impl AEADCipherCodec {
    pub fn new(cipher: CipherKind, password: &[u8]) -> Result<Self> {
        match cipher {
            CipherKind::Aes128Gcm => {
                let key: [u8; 16] = aead::generate_key(password);
                Ok(Self { kind: cipher, key: Box::new(key), request_salt: Box::new([0; 16]), encoder: None, decoder: None })
            }
            CipherKind::Aes256Gcm => {
                let key: [u8; 32] = aead::generate_key(password);
                Ok(Self { kind: cipher, key: Box::new(key), request_salt: Box::new([0; 32]), encoder: None, decoder: None })
            }
            CipherKind::ChaCha20Poly1305 => {
                let key: [u8; 32] = aead::generate_key(password);
                Ok(Self { kind: cipher, key: Box::new(key), request_salt: Box::new([0; 32]), encoder: None, decoder: None })
            }
            CipherKind::Aead2022Blake3Aes128Gcm => {
                let key = aead_2022::generate_key(password, 16)?;
                Ok(Self { kind: cipher, key: key.into_boxed_slice(), request_salt: Box::new([0; 16]), encoder: None, decoder: None })
            }
            CipherKind::Aead2022Blake3Aes256Gcm => {
                let key = aead_2022::generate_key(password, 32)?;
                Ok(Self { kind: cipher, key: key.into_boxed_slice(), request_salt: Box::new([0; 32]), encoder: None, decoder: None })
            }
        }
    }

    fn encode(&mut self, context: &Context, mut item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        match context.network {
            Network::TCP => {
                if self.encoder.is_none() {
                    self.init_tcp_payload_encoder(dst);
                    item = self.handle_header(context, item, dst)?;
                }
                self.encoder.as_mut().unwrap().encode_payload(item, dst);
                Ok(())
            }
            Network::UDP => {
                let salt = Dice::roll_bytes(self.key.len());
                dst.put(&salt[..]);
                self.new_encoder(&salt).encode_packet(item, dst);
                Ok(())
            }
        }
    }

    fn init_tcp_payload_encoder(&mut self, dst: &mut BytesMut) {
        let salt = Dice::roll_bytes(self.key.len());
        trace!("New request salt; {}", Base64::encode_string(&salt));
        dst.put_slice(&salt[..]);
        self.encoder = Some(self.new_encoder(&salt));
    }

    fn handle_header(&mut self, context: &Context, mut msg: BytesMut, dst: &mut BytesMut) -> Result<BytesMut> {
        match context.stream_type {
            StreamType::Request(ref addr) => {
                let mut temp = BytesMut::new();
                AddressCodec::encode(addr, &mut temp)?;
                let is_aead_2022 = self.kind.is_aead_2022();
                if is_aead_2022 {
                    let padding = aead_2022::next_padding_length(&msg);
                    temp.put_u16(padding);
                    temp.put_slice(&Dice::roll_bytes(padding as usize))
                }
                temp.put(msg);
                if is_aead_2022 {
                    let (fix, via) = aead_2022::Tcp::new_header(&mut self.encoder.as_mut().unwrap().auth, &mut temp, &context.stream_type, None);
                    dst.put(fix);
                    dst.put(via);
                }
                Ok(temp)
            }
            StreamType::Response => {
                if self.kind.is_aead_2022() {
                    aead_2022::Tcp::new_header(&mut self.encoder.as_mut().unwrap().auth, &mut msg, &context.stream_type, Some(&self.request_salt));
                }
                Ok(msg)
            }
        }
    }

    fn decode(&mut self, context: &Context, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.is_empty() {
            return Ok(None);
        }
        match context.network {
            Network::TCP => {
                let mut res = BytesMut::new();
                if self.decoder.is_none() {
                    // res.put(self.init_tcp_payload_decoder(context, src)?);
                    if self.decoder.is_none() {
                        return Ok(None);
                    }
                }
                self.decoder.as_mut().unwrap().decode_payload(src)
            }
            Network::UDP => {
                if src.remaining() < self.key.len() {
                    return Ok(None);
                }
                let salt = src.split_to(self.key.len());
                self.new_decoder(&salt).decode_packet(src)
            }
        }
    }

    fn init_tcp_payload_decoder(&mut self, context: &Context, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.remaining() < self.request_salt.len() {
            return Ok(None);
        }
        let mut salt = BytesMut::with_capacity(self.request_salt.len());
        let mut cursor = Cursor::new(src);
        let pos = cursor.position();
        cursor.copy_to_slice(&mut salt);
        trace!("Get request salt {}", Base64::encode_string(&salt));
        if self.kind.is_aead_2022() {
            if let Some(msg) = self.init_aead_2022_tcp_payload_decoder(context, &salt, &mut cursor)? {
                Ok(Some(msg))
            } else {
                cursor.set_position(pos);
                Ok(None)
            }
        } else {
            self.init_aead_tcp_payload_decoder(&salt);
            Ok(None)
        }
    }

    fn new_encoder(&self, salt: &[u8]) -> ChunkEncoder {
        if self.kind.is_aead_2022() {
            aead_2022::Tcp::new_encoder(self.kind, &self.key, salt)
        } else {
            aead::new_encoder(self.kind, &self.key, salt)
        }
    }

    fn new_decoder(&self, salt: &BytesMut) -> ChunkDecoder {
        if self.kind.is_aead_2022() {
            aead_2022::Tcp::new_decoder(self.kind, &self.key, salt)
        } else {
            aead::new_decoder(self.kind, &self.key, salt)
        }
    }

    fn init_aead_tcp_payload_decoder(&mut self, salt: &[u8]) {
        let decoder = aead::new_decoder(self.kind, &self.key, salt);
        self.decoder = Some(decoder);
    }

    fn init_aead_2022_tcp_payload_decoder(&mut self, context: &Context, salt: &[u8], cursor: &mut Cursor<&mut BytesMut>) -> Result<Option<BytesMut>> {
        let mut decoder = aead_2022::Tcp::new_decoder(self.kind, &self.key, salt);
        let tag_size = decoder.auth.method.tag_size();
        let salt_size = match context.stream_type {
            StreamType::Request(_) => self.request_salt.len(),
            StreamType::Response => 0,
        };
        let mut header_bytes = BytesMut::with_capacity(1 + 8 + salt_size + 2 + tag_size);
        cursor.copy_to_slice(&mut header_bytes);
        decoder.auth.open(&mut header_bytes);
        let stream_type_byte = header_bytes.get_u8();
        let expect_stream_type_byte = context.stream_type.expect_u8();
        if stream_type_byte != expect_stream_type_byte {
            bail!("invalid stream type, expecting {}, but found {}", expect_stream_type_byte, stream_type_byte)
        }
        aead_2022::validate_timestamp(cursor.get_u64())?;
        match context.stream_type {
            StreamType::Request(_) => header_bytes.copy_to_slice(&mut self.request_salt),
            StreamType::Response => header_bytes.advance(salt_size),
        };
        let length = header_bytes.get_u16() as usize;
        if cursor.remaining() < length + tag_size {
            return Ok(None);
        }
        let mut payload_bytes = BytesMut::with_capacity(length + tag_size);
        decoder.auth.open(&mut payload_bytes);
        self.decoder = Some(decoder);
        Ok(Some(payload_bytes))
    }
}

pub struct DatagramPacketCodec {
    cipher: AEADCipherCodec,
}

impl DatagramPacketCodec {
    pub fn new(cipher: AEADCipherCodec) -> Self {
        Self { cipher }
    }
}

impl Encoder<DatagramPacket> for DatagramPacketCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<()> {
        let addr = Address::from(item.1);
        let mut temp = BytesMut::with_capacity(item.0.len() + AddressCodec::length(&addr));
        AddressCodec::encode(&addr, &mut temp)?;
        temp.put(item.0);
        let context = Context::udp(StreamType::Request(addr));
        self.cipher.encode(&context, temp, dst)
    }
}

impl Decoder for DatagramPacketCodec {
    type Item = DatagramPacket;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let context = Context::udp(StreamType::Response);
        if let Some(mut content) = self.cipher.decode(&context, src)? {
            let recipient = AddressCodec::decode(&mut content)?;
            Ok(Some((content.split_off(0), recipient.into())))
        } else {
            Ok(None)
        }
    }
}

pub struct CilentCodec {
    context: Context,
    cipher: AEADCipherCodec,
}

impl CilentCodec {
    pub fn new(context: Context, cipher: AEADCipherCodec) -> Self {
        Self { context, cipher }
    }
}

impl Encoder<BytesMut> for CilentCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, mut item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        if self.cipher.encoder.is_none() {
            if let StreamType::Request(ref addr) = self.context.stream_type {
                let mut addr_bytes = BytesMut::with_capacity(AddressCodec::length(addr));
                AddressCodec::encode(addr, &mut addr_bytes)?;
                addr_bytes.put(item);
                item = addr_bytes;
            }
        }
        self.cipher.encode(&self.context, item, dst)
    }
}

impl Decoder for CilentCodec {
    type Item = BytesMut;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.cipher.decode(&self.context, src)
    }
}
