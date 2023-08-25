use std::io::Error;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use base64ct::{Base64, Encoding};
use digest::core_api::XofReaderCoreWrapper;
use digest::{ExtendableOutput, Update, XofReader};
use log::trace;
use sha3::{Shake128, Shake128ReaderCore};

use super::aead::PayloadDecoder;
use super::{aead::{AEADCipher, Aes128GcmCipher, Authenticator, ChaCha20Poly1305Cipher, PayloadEncoder}, chunk::{AEADChunkSizeParser, ChunkSizeCodec}, CountingNonceGenerator, EmptyBytesGenerator, PaddingLengthGenerator};
use crate::common::codec::EmptyPaddingLengthGenerator;
use crate::common::protocol::vmess::header::RequestOption;
use crate::common::protocol::vmess::session::{ClientSession, ServerSession, Session};
use crate::common::protocol::vmess::{aead::KDF, encoding::Auth, header::{RequestHeader, SecurityType}};

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
    pub fn encoder(header: &RequestHeader, session: Arc<Mutex<dyn SessionInit>>) -> PayloadEncoder {
        let session = session.lock().unwrap();
        let (key, iv) = session.init_encoder();
        let (mut size_codec, padding) = Self::default(header, iv.clone());
        let security = header.security;
        if header.option.contains(&RequestOption::AUTHENTICATED_LENGTH) {
            size_codec = Self::aead_chunk_size_codec(security, session.request_body_key(), session.request_body_iv());
        }
        PayloadEncoder::new(2048, Self::auth(Self::aead_cipher(security, key), iv), size_codec, padding)
    }

    pub fn decoder(header: &RequestHeader, session: Arc<Mutex<dyn SessionInit>>) -> PayloadDecoder {
        let session = session.lock().unwrap();
        let (key, iv) = session.init_decoder();
        let (mut size_codec, padding) = Self::default(header, iv.clone());
        let security = header.security;
        if header.option.contains(&RequestOption::AUTHENTICATED_LENGTH) {
            size_codec = Self::aead_chunk_size_codec(security, session.request_body_key(), session.request_body_iv());
        }
        PayloadDecoder::new(Self::auth(Self::aead_cipher(security, key), iv), size_codec, padding)
    }

    fn aead_cipher(security: SecurityType, key: &[u8]) -> Box<dyn AEADCipher> {
        if security == SecurityType::CHACHA20_POLY1305 {
            Box::new(ChaCha20Poly1305Cipher::new(&Auth::generate_chacha20_poly1305_key(key)))
        } else {
            Box::new(Aes128GcmCipher::new(&key))
        }
    }

    fn auth(cipher: Box<dyn AEADCipher>, nonce: Arc<Mutex<[u8]>>) -> Arc<Mutex<Authenticator>> {
        let nonce_size = cipher.nonce_size();
        Arc::new(Mutex::new(Authenticator::new(cipher, Box::new(CountingNonceGenerator::new(nonce, nonce_size)), Box::new(EmptyBytesGenerator))))
    }

    fn aead_chunk_size_codec(security: SecurityType, key: &[u8], nonce: Arc<Mutex<[u8]>>) -> Box<dyn ChunkSizeCodec> {
        let cipher;
        let key = &KDF::kdf16(key, vec![AUTH_LEN]);
        if security == SecurityType::CHACHA20_POLY1305 {
            cipher = Self::aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key));
        } else {
            cipher = Self::aead_cipher(security, key);
        }
        Box::new(AEADChunkSizeParser(Self::auth(cipher, nonce)))
    }

    fn default(header: &RequestHeader, iv: Arc<Mutex<[u8]>>) -> (Box<dyn ChunkSizeCodec>, Box<dyn PaddingLengthGenerator>) {
        let mut size_codec: Box<dyn ChunkSizeCodec> = Box::new(PlainChunkSizeParser);
        let mut padding: Box<dyn PaddingLengthGenerator> = Box::new(EmptyPaddingLengthGenerator);
        let core = Arc::new(Mutex::new(ShakeSizeParser::new(&iv.lock().unwrap())));
        if header.option.contains(&RequestOption::CHUNK_MASKING) {
            size_codec = Box::new(SharedShakeSizeParser(core.clone()));
        }
        if header.option.contains(&RequestOption::GLOBAL_PADDING) {
            padding = Box::new(SharedShakeSizeParser(core));
        }
        (size_codec, padding)
    }
}

pub struct PlainChunkSizeParser;

impl ChunkSizeCodec for PlainChunkSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>()
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        Ok((size as u16).to_be_bytes().to_vec())
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, Error> {
        const LEN: usize = size_of::<u16>();
        let mut bytes = [0; LEN];
        bytes.copy_from_slice(&data[..LEN]);
        Ok(u16::from_be_bytes(bytes) as usize)
    }
}

pub struct ShakeSizeParser {
    reader: XofReaderCoreWrapper<Shake128ReaderCore>,
    buffer: [u8; size_of::<u16>()],
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        trace!("New parser; nonce={}", Base64::encode_string(nonce));
        let mut hasher = Shake128::default();
        hasher.update(nonce);
        Self { reader: hasher.finalize_xof(), buffer: [0; size_of::<u16>()] }
    }

    fn next(&mut self) -> u16 {
        self.reader.read(&mut self.buffer);
        u16::from_be_bytes(self.buffer)
    }
}

impl ChunkSizeCodec for ShakeSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>()
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        let mask = self.next() ^ size as u16;
        Ok(mask.to_be_bytes().to_vec())
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mask = self.next();
        let mut bytes = [0; 2];
        bytes.copy_from_slice(&data);
        let size = u16::from_be_bytes(bytes);
        Ok((mask ^ size) as usize)
    }
}

impl PaddingLengthGenerator for ShakeSizeParser {
    fn next_padding_length(&mut self) -> usize {
        (self.next() % 64) as usize
    }
}

pub struct SharedShakeSizeParser(pub Arc<Mutex<ShakeSizeParser>>);

impl ChunkSizeCodec for SharedShakeSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>()
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        self.0.lock().unwrap().encode(size)
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.0.lock().unwrap().decode(data)
    }
}

impl PaddingLengthGenerator for SharedShakeSizeParser {
    fn next_padding_length(&mut self) -> usize {
        self.0.lock().unwrap().next_padding_length()
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use bytes::{Buf, BufMut, BytesMut};
    use rand::{random, Rng};

    use super::AEADBodyCodec;
    use crate::common::codec::chunk::ChunkSizeCodec;
    use crate::common::codec::vmess::ShakeSizeParser;
    use crate::common::codec::PaddingLengthGenerator;
    use crate::common::protocol::socks5::message::Socks5CommandRequest;
    use crate::common::protocol::socks5::Socks5AddressType;
    use crate::common::protocol::vmess::header::*;
    use crate::common::protocol::vmess::session::{ClientSession, ServerSession};
    use crate::common::protocol::vmess::{ID, VERSION};

    #[test]
    fn test_parser() {
        fn new_parser() -> ShakeSizeParser {
            ShakeSizeParser::new( b"fn bubble_sort<T: Ord>(arr: &mut [T]) {let mut swapped = true;while swapped {swapped = false;for i in 1..arr.len() {if arr[i - 1] > arr[i] {arr.swap(i - 1, i);swapped = true;}}}}")
        }

        let mut parser = new_parser();
        assert_eq!(30, parser.next_padding_length());
        assert_eq!(11, parser.next_padding_length());
        assert_eq!(35, parser.next_padding_length());
        assert_eq!(8, parser.next_padding_length());

        let mut p1 = new_parser();
        let mut p2 = new_parser();
        for _ in 0..100 {
            let size = rand::thread_rng().gen_range(32768..65535);
            let bytes = p1.encode(size);
            assert_eq!(size, p2.decode(&bytes.unwrap()[..]).unwrap())
        }
    }

    #[test]
    fn test_aead_codec() {
        fn new_address() -> Socks5CommandRequest {
            Socks5CommandRequest::connect(Socks5AddressType::DOMAIN, "localhost".to_owned(), random())
        }

        fn test_by_security(security: SecurityType) {
            let header = RequestHeader::default(RequestCommand::TCP, security, new_address(), uuid::Uuid::new_v4().to_string());
            test_by_header(header);
        }

        fn test_by_command(command: RequestCommand) {
            let header = RequestHeader::default(command, SecurityType::CHACHA20_POLY1305, new_address(), uuid::Uuid::new_v4().to_string());
            test_by_header(header);
        }

        fn test_by_option_masks() {
            test_by_option_mask(RequestOption::CHUNK_STREAM.0);
            test_by_option_mask(RequestOption::CHUNK_STREAM.0 | RequestOption::CHUNK_MASKING.0);
            test_by_option_mask(RequestOption::CHUNK_STREAM.0 | RequestOption::GLOBAL_PADDING.0);
            test_by_option_mask(RequestOption::CHUNK_STREAM.0 | RequestOption::CHUNK_MASKING.0 | RequestOption::GLOBAL_PADDING.0);
            test_by_option_mask(RequestOption::CHUNK_STREAM.0 | RequestOption::AUTHENTICATED_LENGTH.0);
            test_by_option_mask(RequestOption::CHUNK_STREAM.0 | RequestOption::GLOBAL_PADDING.0 | RequestOption::AUTHENTICATED_LENGTH.0);
            test_by_option_mask(
                RequestOption::CHUNK_STREAM.0
                    | RequestOption::CHUNK_MASKING.0
                    | RequestOption::GLOBAL_PADDING.0
                    | RequestOption::AUTHENTICATED_LENGTH.0,
            );
        }

        fn test_by_option_mask(mask: u8) {
            let header = RequestHeader {
                version: VERSION,
                command: RequestCommand::TCP,
                option: RequestOption::from_mask(mask),
                security: SecurityType::CHACHA20_POLY1305,
                address: new_address(),
                id: ID::new_id(uuid::Uuid::new_v4().to_string()),
            };
            test_by_header(header);
            let header = RequestHeader {
                version: VERSION,
                command: RequestCommand::UDP,
                option: RequestOption::from_mask(mask),
                security: SecurityType::AES128_GCM,
                address: new_address(),
                id: ID::new_id(uuid::Uuid::new_v4().to_string()),
            };
            test_by_header(header);
        }

        fn test_by_header(header: RequestHeader) {
            let client_session = ClientSession::new();
            let server_session: ServerSession = client_session.clone().into();
            let client_session = Arc::new(Mutex::new(client_session));
            let server_session = Arc::new(Mutex::new(server_session));
            let mut client_encoder = AEADBodyCodec::encoder(&header, client_session.clone());
            let mut client_decoder = AEADBodyCodec::decoder(&header, client_session.clone());
            let mut server_encoder = AEADBodyCodec::encoder(&header, server_session.clone());
            let mut server_decoder = AEADBodyCodec::decoder(&header, server_session.clone());
            let msg = "Hello World!";
            let mut src = BytesMut::new();
            src.put(msg.as_bytes());
            let mut dst = BytesMut::new();
            client_encoder.encode_payload(&mut src, &mut dst);
            let mut dst = server_decoder.decode_payload(&mut dst).unwrap().unwrap();
            let mut temp = BytesMut::new();
            server_encoder.encode_payload(&mut dst, &mut temp);
            let dst = client_decoder.decode_payload(&mut temp).unwrap().unwrap();
            let res = dst.get(0..dst.remaining()).unwrap();
            assert_eq!(msg, String::from_utf8(res.to_vec()).unwrap())
        }

        test_by_security(SecurityType::AES128_GCM);
        test_by_security(SecurityType::CHACHA20_POLY1305);
        test_by_security(SecurityType::LEGACY);
        test_by_security(SecurityType::AUTO);
        test_by_security(SecurityType::UNKNOWN);
        test_by_security(SecurityType::NONE);
        test_by_security(SecurityType::ZERO);
        test_by_command(RequestCommand::TCP);
        test_by_command(RequestCommand::UDP);
        test_by_option_masks();
    }
}
