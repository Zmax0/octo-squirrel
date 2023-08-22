use std::io::Error;
use std::sync::{Arc, Mutex};

use digest::core_api::XofReaderCoreWrapper;
use digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128ReaderCore};

use super::aead::PayloadDecoder;
use super::chunk::BYTES;
use super::{aead::{AEADCipher, Aes128GcmCipher, Authenticator, ChaCha20Poly1305Cipher, PayloadEncoder}, chunk::{AEADChunkSizeParser, ChunkSizeCodec}, CountingNonceGenerator, EmptyBytesGenerator, PaddingLengthGenerator};
use crate::common::codec::EmptyPaddingLengthGenerator;
use crate::common::protocol::vmess::encoding::{ClientSession, ServerSession};
use crate::common::protocol::vmess::header::{CHUNK_MASKING, GLOBAL_PADDING};
use crate::common::protocol::vmess::{aead::KDF, encoding::{Auth, Session}, header::{RequestHeader, SecurityType, AUTHENTICATED_LENGTH, CHACHA20_POLY1305}};

const AUTH_LEN: &[u8] = b"auth_len";

pub trait Init {
    fn init_encoder(&self) -> (&[u8], Arc<Mutex<[u8]>>);
    fn init_decoder(&self) -> (&[u8], Arc<Mutex<[u8]>>);
}

impl Init for ClientSession {
    fn init_encoder(&self) -> (&[u8], Arc<Mutex<[u8]>>) {
        (self.request_body_key(), self.request_body_iv())
    }

    fn init_decoder(&self) -> (&[u8], Arc<Mutex<[u8]>>) {
        (self.response_body_key(), self.response_body_iv())
    }
}

impl Init for ServerSession {
    fn init_encoder(&self) -> (&[u8], Arc<Mutex<[u8]>>) {
        (self.response_body_key(), self.response_body_iv())
    }

    fn init_decoder(&self) -> (&[u8], Arc<Mutex<[u8]>>) {
        (self.request_body_key(), self.request_body_iv())
    }
}

pub trait SessionInit: Session + Init {}

impl SessionInit for ClientSession {}

impl SessionInit for ServerSession {}

pub struct AEADBodyCodec;

impl AEADBodyCodec {
    pub fn encoder(header: &RequestHeader, session: Box<dyn SessionInit>) -> PayloadEncoder {
        let (key, iv) = session.init_encoder();
        let (mut size_codec, padding) = Self::default(header, iv.clone());
        let security = header.security;
        if security == CHACHA20_POLY1305 {
            if header.option.contains(&AUTHENTICATED_LENGTH) {
                size_codec = Self::chunk_size_codec(
                    Self::aead_cipher(security, &Auth::generate_chacha20_poly1305_key(&session.request_body_key())),
                    session.request_body_iv(),
                );
            }
            return PayloadEncoder::new(
                2048,
                Self::auth(Self::aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key)), iv.clone()),
                size_codec,
                padding,
            );
        }
        if header.option.contains(&AUTHENTICATED_LENGTH) {
            size_codec = Self::chunk_size_codec(
                Self::aead_cipher(security, &KDF::kdf16(&session.request_body_key(), vec![AUTH_LEN])),
                session.request_body_iv(),
            );
        }
        PayloadEncoder::new(2048, Self::auth(Self::aead_cipher(security, key), iv.clone()), size_codec, padding)
    }

    pub fn decoder(header: &RequestHeader, session: Box<dyn SessionInit>) -> PayloadDecoder {
        let (key, iv) = session.init_decoder();
        let (mut size_codec, padding) = Self::default(header, iv.clone());
        let security = header.security;
        if security == CHACHA20_POLY1305 {
            if header.option.contains(&AUTHENTICATED_LENGTH) {
                size_codec = Self::chunk_size_codec(
                    Self::aead_cipher(security, &Auth::generate_chacha20_poly1305_key(&session.request_body_key())),
                    session.request_body_iv(),
                );
            }
            return PayloadDecoder::new(
                Self::auth(Self::aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key)), iv.clone()),
                size_codec,
                padding,
            );
        }
        if header.option.contains(&AUTHENTICATED_LENGTH) {
            size_codec = Self::chunk_size_codec(
                Self::aead_cipher(security, &KDF::kdf16(&session.request_body_key(), vec![AUTH_LEN])),
                session.request_body_iv(),
            );
        }
        PayloadDecoder::new(Self::auth(Self::aead_cipher(security, key), iv.clone()), size_codec, padding)
    }

    fn aead_cipher(security: SecurityType, key: &[u8]) -> Box<dyn AEADCipher> {
        if security == CHACHA20_POLY1305 {
            Box::new(ChaCha20Poly1305Cipher::new(&key))
        } else {
            Box::new(Aes128GcmCipher::new(&key))
        }
    }

    fn auth(cipher: Box<dyn AEADCipher>, nonce: Arc<Mutex<[u8]>>) -> Arc<Mutex<Authenticator>> {
        Arc::new(Mutex::new(Authenticator::new(cipher, Box::new(CountingNonceGenerator::new(nonce, 12)), Box::new(EmptyBytesGenerator))))
    }

    fn chunk_size_codec(cipher: Box<dyn AEADCipher>, nonce: Arc<Mutex<[u8]>>) -> Box<dyn ChunkSizeCodec> {
        Box::new(AEADChunkSizeParser(Self::auth(cipher, nonce)))
    }

    fn default(header: &RequestHeader, iv: Arc<Mutex<[u8]>>) -> (Box<dyn ChunkSizeCodec>, Box<dyn PaddingLengthGenerator>) {
        let mut size_codec: Box<dyn ChunkSizeCodec> = Box::new(PlainChunkSizeParser);
        let mut padding: Box<dyn PaddingLengthGenerator> = Box::new(EmptyPaddingLengthGenerator);
        if header.option.contains(&CHUNK_MASKING) {
            size_codec = Box::new(ShakeSizeParser::new(&iv.lock().unwrap()));
        }
        if header.option.contains(&GLOBAL_PADDING) {
            padding = Box::new(ShakeSizeParser::new(&iv.lock().unwrap()));
        }
        (size_codec, padding)
    }
}

pub struct PlainChunkSizeParser;

impl ChunkSizeCodec for PlainChunkSizeParser {
    fn size_bytes(&self) -> usize {
        BYTES
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, std::io::Error> {
        Ok((size as u16).to_be_bytes().to_vec())
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        let mut bytes = [0; BYTES];
        bytes.copy_from_slice(&data[..BYTES]);
        Ok(u16::from_be_bytes(bytes) as usize)
    }
}

pub struct ShakeSizeParser {
    reader: XofReaderCoreWrapper<Shake128ReaderCore>,
    buffer: [u8; 2],
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(nonce);
        let reader = hasher.finalize_xof();
        Self { reader, buffer: [0; 2] }
    }

    fn next(&mut self) -> usize {
        self.reader.read(&mut self.buffer);
        u16::from_be_bytes(self.buffer) as usize
    }
}

impl ChunkSizeCodec for ShakeSizeParser {
    fn size_bytes(&self) -> usize {
        BYTES
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        let mask = (self.next() ^ size) as u16;
        Ok(mask.to_be_bytes().to_vec())
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(&data[..2]);
        let size = u16::from_be_bytes(bytes);
        Ok(self.next() ^ size as usize)
    }
}

impl PaddingLengthGenerator for ShakeSizeParser {
    fn next_padding_length(&mut self) -> usize {
        self.next() % 64
    }
}

#[cfg(test)]
mod test {
    use bytes::{Buf, BufMut, BytesMut};
    use rand::{random, Rng};

    use super::AEADBodyCodec;
    use crate::common::codec::chunk::ChunkSizeCodec;
    use crate::common::codec::vmess::ShakeSizeParser;
    use crate::common::codec::PaddingLengthGenerator;
    use crate::common::protocol::socks5::message::Socks5CommandRequest;
    use crate::common::protocol::socks5::DOMAIN;
    use crate::common::protocol::vmess::encoding::{ClientSession, ServerSession};
    use crate::common::protocol::vmess::header::{RequestHeader, SecurityType, CHACHA20_POLY1305, TCP};

    #[test]
    fn test_next_padding_length() {
        let mut parser = new_parser();
        assert_eq!(30, parser.next_padding_length());
        assert_eq!(11, parser.next_padding_length());
        assert_eq!(35, parser.next_padding_length());
        assert_eq!(8, parser.next_padding_length());
    }

    #[test]
    fn test_encode_and_decode() {
        let mut p1 = new_parser();
        let mut p2 = new_parser();
        let size = rand::thread_rng().gen_range(32768..65535);
        let bytes = p1.encode(size);
        assert_eq!(size, p2.decode(&bytes.unwrap()[..]).unwrap())
    }

    fn new_parser() -> ShakeSizeParser {
        ShakeSizeParser::new( b"fn bubble_sort<T: Ord>(arr: &mut [T]) {let mut swapped = true;while swapped {swapped = false;for i in 1..arr.len() {if arr[i - 1] > arr[i] {arr.swap(i - 1, i);swapped = true;}}}}")
    }

    #[test]
    fn test_aead_codec() {
        test_by_security(CHACHA20_POLY1305);
    }

    fn test_by_security(security: SecurityType) {
        let address = Socks5CommandRequest::connect(DOMAIN, "localhost".to_owned(), random());
        let header: RequestHeader = RequestHeader::default(TCP, security, address, uuid::Uuid::new_v4().to_string());
        test_by_header(header);
    }

    fn test_by_header(header: RequestHeader) {
        let client_session = ClientSession::new();
        let server_session: ServerSession = client_session.clone().into();
        let client_session = Box::new(client_session);
        let server_session = Box::new(server_session);
        let mut client_encoder = AEADBodyCodec::encoder(&header, client_session.clone());
        let mut client_decoder = AEADBodyCodec::decoder(&header, client_session.clone());
        let mut server_encoder = AEADBodyCodec::encoder(&header, server_session.clone());
        let mut server_decoder = AEADBodyCodec::decoder(&header, server_session.clone());
        let mut msg = BytesMut::new();
        msg.put("Hello World!".as_bytes());
        let mut dst = BytesMut::new();
        client_encoder.encode_payload(&mut msg, &mut dst);
        let mut dst = server_decoder.decode_payload(&mut dst).unwrap().unwrap();
        let mut temp = BytesMut::new();
        server_encoder.encode_payload(&mut dst, &mut temp);
        let dst = client_decoder.decode_payload(&mut temp).unwrap().unwrap();
        let res = dst.get(0..dst.remaining()).unwrap();
        println!("{:?}", String::from_utf8(res.to_vec()).unwrap())
    }
}
