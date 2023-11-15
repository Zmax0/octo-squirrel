use std::io;
use std::mem::size_of;

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
use super::aead::ChaCha20Poly1305Cipher;
use super::aead::Cipher;
use super::chunk::PlainSizeParser;
use super::CountingNonceGenerator;
use super::PaddingLengthGenerator;
use crate::common::protocol::vmess::aead::KDF;
use crate::common::protocol::vmess::encoding::Auth;
use crate::common::protocol::vmess::header::RequestHeader;
use crate::common::protocol::vmess::header::RequestOption;
use crate::common::protocol::vmess::header::SecurityType;
use crate::common::protocol::vmess::session::Session;

const AUTH_LEN: &[u8] = b"auth_len";

pub struct AEADBodyCodec {
    auth: Authenticator,
    chunk: ChunkSizeParser,
    padding: PaddingLengthGenerator,
    shake: Option<ShakeSizeParser>,
    payload_limit: usize,
    payload_length: Option<usize>,
    padding_length: Option<usize>,
}

macro_rules! new_aead_body_codec {
    ($name:ident, $key:ident, $nonce:ident) => {
        pub fn $name(header: &RequestHeader, session: &mut dyn Session) -> Self {
            let mut chunk = ChunkSizeParser::Plain(PlainSizeParser);
            let mut padding = PaddingLengthGenerator::Empty;
            if header.option.contains(&RequestOption::CHUNK_MASKING) {
                chunk = ChunkSizeParser::Shake;
            }
            if header.option.contains(&RequestOption::GLOBAL_PADDING) {
                padding = PaddingLengthGenerator::Shake;
            }
            let mut shake = None;
            if matches!(padding, PaddingLengthGenerator::Shake) || matches!(chunk, ChunkSizeParser::Shake) {
                shake = Some(ShakeSizeParser::new(session.$nonce()));
            }
            if header.option.contains(&RequestOption::AUTHENTICATED_LENGTH) {
                chunk = ChunkSizeParser::Auth(Self::new_aead_chunk_size_cipher(header.security, session.chunk_key()));
            }
            let cipher;
            if header.security == SecurityType::CHACHA20_POLY1305 {
                cipher = Self::new_aead_cipher(header.security, &Auth::generate_chacha20_poly1305_key(session.$key()));
            } else {
                cipher = Self::new_aead_cipher(header.security, session.$key());
            }
            Self { auth: Authenticator::new(cipher), chunk, padding, shake, payload_limit: 2048, payload_length: None, padding_length: None }
        }
    };
}

impl AEADBodyCodec {
    new_aead_body_codec!(encoder, encoder_key, encoder_nonce);
    new_aead_body_codec!(decoder, decoder_key, decoder_nonce);

    fn new_aead_chunk_size_cipher(security: SecurityType, key: &[u8]) -> Authenticator {
        let key = &KDF::kdf16(key, vec![AUTH_LEN]);
        if security == SecurityType::CHACHA20_POLY1305 {
            Authenticator::new(Self::new_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key)))
        } else {
            Authenticator::new(Self::new_aead_cipher(security, key))
        }
    }

    fn new_aead_cipher(security: SecurityType, key: &[u8]) -> Box<dyn Cipher> {
        if security == SecurityType::CHACHA20_POLY1305 {
            Box::new(ChaCha20Poly1305Cipher::new(key))
        } else {
            Box::new(Aes128GcmCipher::new(key))
        }
    }

    fn encode_message(&mut self, src: &mut BytesMut, dst: &mut BytesMut, session: &mut dyn Session) {
        let padding_length = self.next_padding_length();
        trace!("Encode payload; padding length={}", padding_length);
        let tag_size = self.auth.cipher.tag_size();
        let encrypted_size = src.remaining().min(self.payload_limit - tag_size - self.size_bytes() - padding_length);
        trace!("Encode payload; payload length={}", encrypted_size - tag_size);
        let encrypted_size_bytes = self.encode_size(encrypted_size + padding_length + tag_size, session.chunk_nonce());
        dst.put_slice(&encrypted_size_bytes);
        let payload_bytes = src.split_to(encrypted_size);
        dst.put_slice(&self.auth.seal(&payload_bytes, session.encoder_nonce()));
        let mut padding_bytes: Vec<u8> = vec![0; padding_length];
        rand::thread_rng().fill(&mut padding_bytes[..]);
        dst.put(&padding_bytes[..]);
    }

    fn next_padding_length(&mut self) -> usize {
        match self.padding {
            PaddingLengthGenerator::Empty => 0,
            PaddingLengthGenerator::Shake => self.shake.as_mut().unwrap().next_padding_length(),
        }
    }

    fn encode_size(&mut self, size: usize, nonce: &mut [u8]) -> Vec<u8> {
        match self.chunk {
            ChunkSizeParser::Plain(ref mut parser) => parser.encode_size(size),
            ChunkSizeParser::Auth(ref mut parser) => parser.encode_size(size, nonce),
            ChunkSizeParser::Shake => self.shake.as_mut().unwrap().encode_size(size),
        }
    }

    fn size_bytes(&self) -> usize {
        match self.chunk {
            ChunkSizeParser::Plain(_) => PlainSizeParser::size_bytes(),
            ChunkSizeParser::Auth(ref parser) => parser.size_bytes(),
            ChunkSizeParser::Shake => ShakeSizeParser::size_bytes(),
        }
    }

    fn decode_size(&mut self, data: &BytesMut, nonce: &mut [u8]) -> usize {
        match self.chunk {
            ChunkSizeParser::Plain(ref mut parser) => parser.decode_size(data),
            ChunkSizeParser::Auth(ref mut parser) => parser.decode_size(data, nonce),
            ChunkSizeParser::Shake => self.shake.as_mut().unwrap().decode_size(data),
        }
    }

    pub fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut, session: &mut dyn Session) {
        while src.has_remaining() {
            self.encode_message(&mut src, dst, session);
        }
    }

    pub fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut, session: &mut dyn Session) {
        self.encode_message(&mut src, dst, session);
    }

    pub fn decode_packet(&mut self, src: &mut BytesMut, session: &mut dyn Session) -> Result<Option<BytesMut>, io::Error> {
        let padding_length = self.next_padding_length();
        let packet_length = self.decode_size(&src.split_to(self.size_bytes()), session.chunk_nonce()) - padding_length;
        let packet_sealed_bytes = src.split_to(packet_length);
        let packet_bytes = self.auth.open(&packet_sealed_bytes, session.decoder_nonce());
        src.advance(padding_length);
        Ok(Some(BytesMut::from(&packet_bytes[..])))
    }

    pub fn decode_payload(&mut self, src: &mut BytesMut, session: &mut dyn Session) -> Result<Option<BytesMut>, io::Error> {
        let size_bytes = self.size_bytes();
        let mut dst = Vec::new();
        while src.remaining() >= if self.payload_length.is_none() { size_bytes } else { self.payload_length.unwrap() } {
            if self.padding_length.is_none() {
                let padding_length = self.next_padding_length();
                trace!("Decode payload; padding length={:?}", padding_length);
                self.padding_length = Some(padding_length);
            }
            let padding_length = self.padding_length.unwrap();
            if let Some(payload_length) = self.payload_length {
                let mut payload_btyes = self.auth.open(&src.split_to(payload_length - padding_length), session.decoder_nonce());
                dst.append(&mut payload_btyes);
                src.advance(padding_length);
                self.payload_length = None;
                self.padding_length = None;
            } else {
                let payload_length_bytes = src.split_to(size_bytes);
                let payload_length = self.decode_size(&payload_length_bytes, session.chunk_nonce());
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

enum ChunkSizeParser {
    Plain(PlainSizeParser),
    Auth(Authenticator),
    Shake,
}

struct Authenticator {
    cipher: Box<dyn Cipher>,
    counting: CountingNonceGenerator,
}

impl Authenticator {
    fn new(cipher: Box<dyn Cipher>) -> Self {
        let nonce_size = cipher.nonce_size();
        Self { cipher, counting: CountingNonceGenerator::new(nonce_size) }
    }

    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.cipher.tag_size()
    }

    fn encode_size(&mut self, size: usize, nonce: &mut [u8]) -> Vec<u8> {
        let plaintext = ((size - self.cipher.tag_size()) as u16).to_be_bytes();
        self.seal(&plaintext, nonce)
    }

    fn decode_size(&mut self, ciphertext: &[u8], nonce: &mut [u8]) -> usize {
        let plaintext = self.open(ciphertext, nonce);
        let mut opened: [u8; size_of::<u16>()] = [0; size_of::<u16>()];
        opened.copy_from_slice(&plaintext);
        let size = u16::from_be_bytes(opened);
        size as usize + self.cipher.tag_size()
    }

    fn seal(&mut self, plaintext: &[u8], nonce: &mut [u8]) -> Vec<u8> {
        self.cipher.encrypt(&self.counting.generate(nonce), plaintext, &[])
    }

    fn open(&mut self, ciphertext: &[u8], nonce: &mut [u8]) -> Vec<u8> {
        self.cipher.decrypt(&self.counting.generate(nonce), ciphertext, &[])
    }
}

struct ShakeSizeParser {
    reader: XofReaderCoreWrapper<Shake128ReaderCore>,
    buffer: [u8; 2],
}

impl ShakeSizeParser {
    fn new(nonce: &[u8]) -> Self {
        if log_enabled!(Trace) {
            trace!("New ShakeSizeParser; nonce={}", Base64::encode_string(nonce));
        }
        let mut hasher = Shake128::default();
        hasher.update(nonce);
        Self { reader: hasher.finalize_xof(), buffer: [0; 2] }
    }

    fn next(&mut self) -> u16 {
        self.reader.read(&mut self.buffer);
        u16::from_be_bytes(self.buffer)
    }

    fn size_bytes() -> usize {
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

impl ShakeSizeParser {
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

    use crate::common::codec::vmess::AEADBodyCodec;
    use crate::common::codec::vmess::ShakeSizeParser;
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
            let mut client_session = ClientSession::new();
            let mut server_session: ServerSession = client_session.clone().into();
            let mut client_encoder = AEADBodyCodec::encoder(&header, &mut client_session);
            let mut client_decoder = AEADBodyCodec::encoder(&header, &mut client_session);
            let mut server_encoder = AEADBodyCodec::decoder(&header, &mut server_session);
            let mut server_decoder = AEADBodyCodec::decoder(&header, &mut server_session);
            let msg = "Hello World!";
            let mut src = BytesMut::new();
            src.put(msg.as_bytes());
            let mut dst = BytesMut::new();
            client_encoder.encode_payload(src, &mut dst, &mut client_session);
            let dst = server_decoder.decode_payload(&mut dst, &mut server_session).unwrap().unwrap();
            let mut temp = BytesMut::new();
            server_encoder.encode_payload(dst, &mut temp, &mut server_session);
            let dst = client_decoder.decode_payload(&mut temp, &mut client_session).unwrap().unwrap();
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
