mod aead;
mod aead_2022;

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
use bytes::Bytes;
use bytes::BytesMut;
use log::trace;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use self::aead_2022::tcp;
use super::aead::CipherKind;
use super::aead::CipherMethod;
use super::aead::IncreasingNonceGenerator;
use crate::common::codec::shadowsocks::aead_2022::udp;
use crate::common::network::DatagramPacket;
use crate::common::network::Network;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::Context;
use crate::common::protocol::shadowsocks::StreamType;
use crate::common::protocol::socks5::address::AddressCodec;
use crate::common::util::Dice;

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
        let encrypted_size = src.remaining().min(self.payload_limit - tag_size - self.size_bytes());
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

    fn size_bytes(&self) -> usize {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.size_bytes(),
            ChunkSizeParser::Empty => 0,
        }
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

    fn decode_payload(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        let size_bytes = self.size_bytes();
        while src.remaining() >= if self.payload_length.is_none() { size_bytes } else { self.payload_length.unwrap() } {
            if let Some(payload_length) = self.payload_length {
                let mut payload_btyes = src.split_to(payload_length);
                self.auth.open(&mut payload_btyes);
                dst.put(payload_btyes);
                self.payload_length = None;
            } else {
                let payload_length = self.decode_size(&mut src.split_to(size_bytes));
                trace!("Decode payload; payload length={:?}", payload_length);
                self.payload_length = Some(payload_length);
            }
        }
    }

    fn size_bytes(&self) -> usize {
        match self.chunk {
            ChunkSizeParser::Auth => self.auth.size_bytes(),
            ChunkSizeParser::Empty => 0,
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

    fn encode(&mut self, context: &mut Context, mut item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        match context.network {
            Network::TCP => {
                if let None = self.encoder {
                    self.init_payload_encoder(dst);
                    item = self.handle_payload_header(context, item, dst)?;
                }
                self.encoder.as_mut().unwrap().encode_payload(item, dst);
                Ok(())
            }
            Network::UDP => self.encode_packet(context, item, dst),
        }
    }

    fn encode_packet(&self, context: &mut Context, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        if self.kind.is_aead_2022() {
            let padding_length = aead_2022::next_padding_length(&item);
            let nonce_length = udp::nonce_length(self.kind)?;
            let tag_size = self.kind.tag_size();
            let mut temp = BytesMut::with_capacity(
                nonce_length
                    + 8
                    + 8
                    + 1
                    + 8
                    + 2
                    + padding_length as usize
                    + AddressCodec::length(context.address.as_ref().unwrap())
                    + item.remaining()
                    + tag_size,
            );
            temp.put_u64(0);
            context.session.packet_id += 1;
            temp.put_u64(context.session.packet_id);
            temp.put_u8(context.stream_type.to_u8());
            temp.put_u64(aead_2022::now());
            temp.put_u16(padding_length);
            temp.put(&Dice::roll_bytes(padding_length as usize)[..]);
            if matches!(context.stream_type, StreamType::Response) {
                temp.put_u64(context.session.client_session_id);
            }
            AddressCodec::encode(context.address.as_ref().unwrap(), &mut temp)?;
            temp.put(item);
            let mut nonce: [u8; 12] = [0; 12];
            nonce.copy_from_slice(&temp[4..16]);
            let mut header: [u8; 16] = [0; 16];
            header.copy_from_slice(&temp.split_to(16));
            udp::encrypt_packet_header(self.kind, &self.key, &mut header)?;
            dst.put(&header[..]);
            udp::new_encoder(self.kind, &self.key, 0, nonce).encode_packet(temp, dst);
        } else {
            let salt = Dice::roll_bytes(self.key.len());
            dst.put(&salt[..]);
            let address = context.address.as_ref().unwrap();
            let mut temp = BytesMut::with_capacity(AddressCodec::length(address) + item.remaining());
            AddressCodec::encode(address, &mut temp)?;
            temp.put(item);
            self.new_encoder(&salt).encode_packet(temp, dst);
        }
        Ok(())
    }

    fn init_payload_encoder(&mut self, dst: &mut BytesMut) {
        let salt = Dice::roll_bytes(self.key.len());
        trace!("New request salt; {}", Base64::encode_string(&salt));
        dst.put(&salt[..]);
        self.encoder = Some(self.new_encoder(&salt));
    }

    fn handle_payload_header(&mut self, context: &Context, mut msg: BytesMut, dst: &mut BytesMut) -> Result<BytesMut> {
        match context.stream_type {
            StreamType::Request => {
                let mut temp = BytesMut::new();
                AddressCodec::encode(context.address.as_ref().unwrap(), &mut temp)?;
                let is_aead_2022 = self.kind.is_aead_2022();
                if is_aead_2022 {
                    let padding = aead_2022::next_padding_length(&msg);
                    temp.put_u16(padding);
                    temp.put(&Dice::roll_bytes(padding as usize)[..])
                }
                temp.put(msg);
                if is_aead_2022 {
                    let (fix, via) = tcp::new_header(&mut self.encoder.as_mut().unwrap().auth, &mut temp, &context.stream_type, None);
                    dst.put(fix);
                    dst.put(via);
                }
                Ok(temp)
            }
            StreamType::Response => {
                if self.kind.is_aead_2022() {
                    tcp::new_header(&mut self.encoder.as_mut().unwrap().auth, &mut msg, &context.stream_type, Some(&self.request_salt));
                }
                Ok(msg)
            }
        }
    }

    fn decode(&mut self, context: &mut Context, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.is_empty() {
            return Ok(None);
        }
        match context.network {
            Network::TCP => {
                let mut dst = BytesMut::new();
                if let None = self.decoder {
                    self.init_payload_decoder(context, src, &mut dst)?;
                }
                if let None = self.decoder {
                    return Ok(None);
                }
                self.decoder.as_mut().unwrap().decode_payload(src, &mut dst);
                if dst.has_remaining() {
                    Ok(Some(dst))
                } else {
                    Ok(None)
                }
            }
            Network::UDP => Ok(Some(self.decode_packet(context, src)?)),
        }
    }

    fn decode_packet(&self, context: &mut Context, src: &mut BytesMut) -> Result<BytesMut> {
        if self.kind.is_aead_2022() {
            let nonce_length = udp::nonce_length(self.kind)?;
            let tag_size = self.kind.tag_size();
            let header_length = nonce_length + tag_size + 8 + 8 + 1 + 8 + 2;
            if src.remaining() < header_length {
                bail!("Packet too short, at least {} bytes, but found {} bytes", header_length, src.remaining());
            }
            let mut header: [u8; 16] = [0; 16];
            header.copy_from_slice(&src.split_to(16));
            udp::decrypt_packet_header(self.kind, &self.key, &mut header)?;
            let mut nonce: [u8; 12] = [0; 12];
            nonce.copy_from_slice(&header[4..16]);
            let mut header = Bytes::from(header.to_vec());
            let server_session_id = header.get_u64();
            header.get_u64(); // pack id
            let mut packet = udp::new_decoder(self.kind, &self.key, server_session_id, nonce).decode_packet(src)?.unwrap();
            packet.get_u8(); // stream type
            aead_2022::validate_timestamp(packet.get_u64())?;
            let padding_length = packet.get_u16();
            if padding_length > 0 {
                packet.advance(padding_length as usize);
            }
            if matches!(context.stream_type, StreamType::Request) {
                context.session.client_session_id = packet.get_u64();
            }
            context.address = Some(AddressCodec::decode(&mut packet)?);
            Ok(packet)
        } else {
            if src.remaining() < self.key.len() {
                bail!("Invalid packet length");
            }
            let salt = src.split_to(self.key.len());
            let mut packet = self.new_payload_decoder(&salt).decode_packet(src)?.unwrap();
            context.address = Some(AddressCodec::decode(&mut packet)?);
            Ok(packet)
        }
    }

    fn init_payload_decoder(&mut self, context: &Context, src: &mut BytesMut, dst: &mut BytesMut) -> Result<()> {
        if src.remaining() < self.request_salt.len() {
            return Ok(());
        }
        let mut cursor = Cursor::new(src);
        let salt = cursor.copy_to_bytes(self.request_salt.len());
        trace!("Get request salt {}", Base64::encode_string(&salt));
        if self.kind.is_aead_2022() {
            self.init_aead_2022_payload_decoder(context, &salt, &mut cursor, dst)?
        } else {
            self.decoder = Some(aead::new_decoder(self.kind, &self.key, &salt));
        }
        let pos = cursor.position();
        cursor.into_inner().advance(pos as usize);
        Ok(())
    }

    fn new_encoder(&self, salt: &[u8]) -> ChunkEncoder {
        if self.kind.is_aead_2022() {
            tcp::new_encoder(self.kind, &self.key, salt)
        } else {
            aead::new_encoder(self.kind, &self.key, salt)
        }
    }

    fn new_payload_decoder(&self, salt: &BytesMut) -> ChunkDecoder {
        if self.kind.is_aead_2022() {
            tcp::new_decoder(self.kind, &self.key, salt)
        } else {
            aead::new_decoder(self.kind, &self.key, salt)
        }
    }

    fn init_aead_2022_payload_decoder(&mut self, context: &Context, salt: &[u8], src: &mut Cursor<&mut BytesMut>, dst: &mut BytesMut) -> Result<()> {
        let mut decoder = tcp::new_decoder(self.kind, &self.key, salt);
        let tag_size = decoder.auth.method.tag_size();
        let salt_size = match context.stream_type {
            StreamType::Request => self.request_salt.len(),
            StreamType::Response => 0,
        };
        let mut fixed = vec![0; 1 + 8 + salt_size + 2 + tag_size];
        src.copy_to_slice(&mut fixed);
        decoder.auth.open(&mut fixed);
        let mut fixed = Bytes::from(fixed);
        let stream_type_byte = fixed.get_u8();
        let expect_stream_type_byte = context.stream_type.expect_u8();
        if stream_type_byte != expect_stream_type_byte {
            bail!("Invalid stream type, expecting {}, but found {}", expect_stream_type_byte, stream_type_byte)
        }
        aead_2022::validate_timestamp(fixed.get_u64())?;
        if matches!(context.stream_type, StreamType::Request) {
            fixed.copy_to_slice(&mut self.request_salt);
            trace!("Get request header salt {}", Base64::encode_string(&self.request_salt));
        };
        let length = fixed.get_u16() as usize;
        if src.remaining() < length + tag_size {
            bail!("Invalid via request header length")
        }
        let mut via = vec![0; length + tag_size];
        src.copy_to_slice(&mut via);
        decoder.auth.open(&mut via);
        self.decoder = Some(decoder);
        dst.put(&via[..]);
        Ok(())
    }
}

pub struct DatagramPacketCodec {
    context: Context,
    cipher: AEADCipherCodec,
}

impl DatagramPacketCodec {
    pub fn new(context: Context, cipher: AEADCipherCodec) -> Self {
        Self { context, cipher }
    }
}

impl Encoder<DatagramPacket> for DatagramPacketCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<()> {
        self.context.address = Some(Address::from(item.1));
        self.cipher.encode(&mut self.context, item.0, dst)
    }
}

impl Decoder for DatagramPacketCodec {
    type Item = DatagramPacket;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if let Some(content) = self.cipher.decode(&mut self.context, src)? {
            Ok(Some((content, self.context.address.take().unwrap().into())))
        } else {
            Ok(None)
        }
    }
}

pub struct PayloadCodec {
    context: Context,
    cipher: AEADCipherCodec,
}

impl PayloadCodec {
    pub fn new(context: Context, cipher: AEADCipherCodec) -> Self {
        Self { context, cipher }
    }
}

impl Encoder<BytesMut> for PayloadCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        self.cipher.encode(&mut self.context, item, dst)
    }
}

impl Decoder for PayloadCodec {
    type Item = BytesMut;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.cipher.decode(&mut self.context, src)
    }
}
