use std::io;
use std::mem::size_of;
use std::sync::Arc;

use base64ct::Base64;
use base64ct::Encoding;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use digest::core_api::XofReaderCoreWrapper;
use digest::ExtendableOutput;
use digest::Update;
use digest::XofReader;
use log::log_enabled;
use log::trace;
use log::Level::Trace;
use rand::Rng;
use sha3::Shake128;
use sha3::Shake128ReaderCore;

use super::aead::Aes128GcmCipher;
use super::aead::Authenticator;
use super::aead::ChaCha20Poly1305Cipher;
use super::aead::Cipher;
use super::aead::CipherDecoder;
use super::aead::CipherEncoder;
use super::chunk::ChunkSizeCodec;
use super::chunk::PlainChunkSizeParser;
use super::CountingNonceGenerator;
use super::EmptyBytesGenerator;
use super::EmptyPaddingLengthGenerator;
use super::PaddingLengthGenerator;
use crate::common::protocol::vmess::aead::KDF;
use crate::common::protocol::vmess::encoding::Auth;
use crate::common::protocol::vmess::header::RequestHeader;
use crate::common::protocol::vmess::header::RequestOption;
use crate::common::protocol::vmess::header::SecurityType;
use crate::common::protocol::vmess::session::AtomicU8Array;
use crate::common::protocol::vmess::session::ClientSession;
use crate::common::protocol::vmess::session::ServerSession;
use crate::common::protocol::vmess::session::Session;

const AUTH_LEN: &[u8] = b"auth_len";

pub trait Init {
    fn init_encoder(&self) -> (&[u8], Arc<AtomicU8Array<16>>);
    fn init_decoder(&self) -> (&[u8], Arc<AtomicU8Array<16>>);
}

impl Init for ClientSession {
    fn init_encoder(&self) -> (&[u8], Arc<AtomicU8Array<16>>) {
        (self.request_body_key(), self.request_body_iv())
    }
    fn init_decoder(&self) -> (&[u8], Arc<AtomicU8Array<16>>) {
        (self.response_body_key(), self.response_body_iv())
    }
}

impl Init for ServerSession {
    fn init_encoder(&self) -> (&[u8], Arc<AtomicU8Array<16>>) {
        (self.response_body_key(), self.response_body_iv())
    }
    fn init_decoder(&self) -> (&[u8], Arc<AtomicU8Array<16>>) {
        (self.request_body_key(), self.request_body_iv())
    }
}

pub trait SessionInit: Session + Init {}

impl SessionInit for ClientSession {}

impl SessionInit for ServerSession {}

pub struct AEADBodyCodec;

impl AEADBodyCodec {
    pub fn encoder(header: &RequestHeader, session: &dyn SessionInit) -> Box<dyn CipherEncoder> {
        let (key, iv) = session.init_encoder();
        let (mut size_codec, padding) = Self::default_option(&header.option, &iv.load());
        let security = header.security;
        if header.option.contains(&RequestOption::AUTHENTICATED_LENGTH) {
            size_codec = Self::new_aead_chunk_size_parser(security, session.request_body_key(), session.request_body_iv());
        }
        if security == SecurityType::CHACHA20_POLY1305 {
            Box::new(CipherEncoderImpl::new(
                2048,
                Self::new_auth(Self::new_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key)), iv),
                size_codec,
                padding,
            ))
        } else {
            Box::new(CipherEncoderImpl::new(2048, Self::new_auth(Self::new_aead_cipher(security, key), iv), size_codec, padding))
        }
    }

    pub fn decoder(header: &RequestHeader, session: &dyn SessionInit) -> Box<dyn CipherDecoder> {
        let (key, iv) = session.init_decoder();
        let (mut size_codec, padding) = Self::default_option(&header.option, &iv.load());
        let security = header.security;
        if header.option.contains(&RequestOption::AUTHENTICATED_LENGTH) {
            size_codec = Self::new_aead_chunk_size_parser(security, session.request_body_key(), session.request_body_iv());
        }
        if security == SecurityType::CHACHA20_POLY1305 {
            Box::new(CipherDecoderImpl::new(
                Self::new_auth(Self::new_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key)), iv),
                size_codec,
                padding,
            ))
        } else {
            Box::new(CipherDecoderImpl::new(Self::new_auth(Self::new_aead_cipher(security, key), iv), size_codec, padding))
        }
    }

    fn new_aead_chunk_size_parser(security: SecurityType, key: &[u8], nonce: Arc<AtomicU8Array<16>>) -> Box<dyn ChunkSizeCodec> {
        let key = &KDF::kdf16(key, vec![AUTH_LEN]);
        let cipher;
        if security == SecurityType::CHACHA20_POLY1305 {
            cipher = Self::new_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key));
        } else {
            cipher = Self::new_aead_cipher(security, key);
        }
        Box::new(Self::new_auth(cipher, nonce))
    }

    fn new_aead_cipher(security: SecurityType, key: &[u8]) -> Box<dyn Cipher> {
        if security == SecurityType::CHACHA20_POLY1305 {
            Box::new(ChaCha20Poly1305Cipher::new(key))
        } else {
            Box::new(Aes128GcmCipher::new(key))
        }
    }

    fn new_auth(cipher: Box<dyn Cipher>, nonce: Arc<AtomicU8Array<16>>) -> Authenticator {
        let nonce_size = cipher.nonce_size();
        Authenticator::new(cipher, Box::new(CountingNonceGenerator::new(nonce, nonce_size)), Box::new(EmptyBytesGenerator))
    }

    fn default_option(option: &Vec<RequestOption>, iv: &[u8]) -> (Box<dyn ChunkSizeCodec>, Box<dyn PaddingLengthGenerator>) {
        let mut size_codec: Box<dyn ChunkSizeCodec> = Box::new(PlainChunkSizeParser);
        let mut padding: Box<dyn PaddingLengthGenerator> = Box::new(EmptyPaddingLengthGenerator);
        let shake_size_parser = ShakeSizeParser::new(iv);
        if option.contains(&RequestOption::CHUNK_MASKING) {
            size_codec = Box::new(shake_size_parser.clone());
        }
        if option.contains(&RequestOption::GLOBAL_PADDING) {
            padding = Box::new(shake_size_parser);
        }
        (size_codec, padding)
    }
}

struct CipherEncoderImpl {
    payload_limit: usize,
    auth: Authenticator,
    size_codec: Box<dyn ChunkSizeCodec>,
    padding: Box<dyn PaddingLengthGenerator>,
}

impl CipherEncoderImpl {
    pub fn new(payload_limit: usize, auth: Authenticator, size_codec: Box<dyn ChunkSizeCodec>, padding: Box<dyn PaddingLengthGenerator>) -> Self {
        Self { payload_limit, auth, size_codec, padding }
    }

    fn seal(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        let padding_length = self.padding.next_padding_length();
        trace!("Encode payload; padding length={}", padding_length);
        let overhead = self.auth.overhead();
        let encrypted_size = src.remaining().min(self.payload_limit - overhead - self.size_codec.size_bytes() - padding_length);
        trace!("Encode payload; payload length={}", encrypted_size);
        let encrypted_size_bytes = self.size_codec.encode_size(encrypted_size + padding_length + overhead);
        dst.put_slice(&encrypted_size_bytes);
        let payload_bytes = src.split_to(encrypted_size);
        dst.put_slice(&self.auth.seal(&payload_bytes));
        let mut padding_bytes: Vec<u8> = vec![0; padding_length];
        rand::thread_rng().fill(&mut padding_bytes[..]);
        dst.put(&padding_bytes[..]);
    }
}

impl CipherEncoder for CipherEncoderImpl {
    fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut) {
        while src.has_remaining() {
            self.seal(&mut src, dst);
        }
    }
    fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut) {
        self.seal(&mut src, dst);
    }
}

struct CipherDecoderImpl {
    payload_length: Option<usize>,
    padding_length: Option<usize>,
    auth: Authenticator,
    size_codec: Box<dyn ChunkSizeCodec>,
    padding: Box<dyn PaddingLengthGenerator>,
}

impl CipherDecoderImpl {
    pub fn new(auth: Authenticator, size_codec: Box<dyn ChunkSizeCodec>, padding: Box<dyn PaddingLengthGenerator>) -> Self {
        Self { payload_length: None, padding_length: None, auth, size_codec, padding }
    }
}

impl CipherDecoder for CipherDecoderImpl {
    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let padding_length = self.padding.next_padding_length();
        let packet_length = self.size_codec.decode_size(&src.split_to(self.size_codec.size_bytes())) - padding_length;
        let packet_sealed_bytes = src.split_to(packet_length);
        let packet_bytes = self.auth.open(&packet_sealed_bytes);
        src.advance(padding_length);
        Ok(Some(BytesMut::from(&packet_bytes[..])))
    }

    fn decode_payload(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
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
                let mut payload_btyes = self.auth.open(&src.split_to(payload_length - padding_length));
                dst.append(&mut payload_btyes);
                src.advance(padding_length);
                self.payload_length = None;
                self.padding_length = None;
            } else {
                let payload_length_bytes = src.split_to(size_bytes);
                let payload_length = self.size_codec.decode_size(&payload_length_bytes);
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
}

#[derive(Clone)]
pub struct ShakeSizeParser {
    reader: XofReaderCoreWrapper<Shake128ReaderCore>,
    buffer: Arc<AtomicU8Array<2>>,
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        if log_enabled!(Trace) {
            trace!("New ShakeSizeParser; nonce={}", Base64::encode_string(nonce));
        }
        let mut hasher = Shake128::default();
        hasher.update(nonce);
        Self { reader: hasher.finalize_xof(), buffer: Arc::new(AtomicU8Array::new()) }
    }

    fn next(&mut self) -> u16 {
        let temp: [u8; size_of::<u16>()] = self.buffer.update(|x| self.reader.read(x));
        u16::from_be_bytes(temp)
    }
}

impl ChunkSizeCodec for ShakeSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>()
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        let mask = self.next() ^ size as u16;
        mask.to_be_bytes().to_vec()
    }

    fn decode_size(&mut self, data: &[u8]) -> usize {
        let mask = self.next();
        let mut bytes = [0; 2];
        bytes.copy_from_slice(&data);
        let size = u16::from_be_bytes(bytes);
        (mask ^ size) as usize
    }
}

impl PaddingLengthGenerator for ShakeSizeParser {
    fn next_padding_length(&mut self) -> usize {
        (self.next() % 64) as usize
    }
}

#[cfg(test)]
mod test {
    use bytes::Buf;
    use bytes::BufMut;
    use bytes::BytesMut;
    use rand::random;
    use rand::Rng;

    use super::AEADBodyCodec;
    use crate::common::codec::chunk::ChunkSizeCodec;
    use crate::common::codec::vmess::ShakeSizeParser;
    use crate::common::codec::PaddingLengthGenerator;
    use crate::common::protocol::socks5::message::Socks5CommandRequest;
    use crate::common::protocol::socks5::Socks5AddressType;
    use crate::common::protocol::vmess::header::*;
    use crate::common::protocol::vmess::session::ClientSession;
    use crate::common::protocol::vmess::session::ServerSession;
    use crate::common::protocol::vmess::ID;
    use crate::common::protocol::vmess::VERSION;

    #[test]
    fn test_share_size_parser() {
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
            let bytes = p1.encode_size(size);
            assert_eq!(size, p2.decode_size(&bytes[..]))
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
            let mut client_encoder = AEADBodyCodec::encoder(&header, &client_session);
            let mut client_decoder = AEADBodyCodec::decoder(&header, &client_session);
            let mut server_encoder = AEADBodyCodec::encoder(&header, &server_session);
            let mut server_decoder = AEADBodyCodec::decoder(&header, &server_session);
            let msg = "Hello World!";
            let mut src = BytesMut::new();
            src.put(msg.as_bytes());
            let mut dst = BytesMut::new();
            client_encoder.encode_payload(src, &mut dst);
            let dst = server_decoder.decode_payload(&mut dst).unwrap().unwrap();
            let mut temp = BytesMut::new();
            server_encoder.encode_payload(dst, &mut temp);
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
