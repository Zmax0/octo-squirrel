use std::mem::size_of;

use aes_gcm::aead::Buffer;
use base64ct::Base64;
use base64ct::Encoding;
use digest::ExtendableOutput;
use digest::InvalidLength;
use digest::Update;
use digest::XofReader;
use digest::core_api::XofReaderCoreWrapper;
use log::trace;
use sha3::Shake128;
use sha3::Shake128ReaderCore;
use tokio_util::bytes::Buf;
use tokio_util::bytes::BytesMut;

use crate::codec::aead::CipherKind;
use crate::codec::aead::CipherMethod;
use crate::codec::aead::CountingNonceGenerator;
use crate::codec::chunk::PlainSizeParser;
use crate::protocol::vmess::aead::kdf;
use crate::protocol::vmess::auth;
use crate::protocol::vmess::header::RequestHeader;
use crate::protocol::vmess::header::RequestOption;
use crate::protocol::vmess::header::SecurityType;
use crate::protocol::vmess::session::Session;
use crate::util::dice;

const AUTH_LEN: &[u8] = b"auth_len";

pub struct AEADBodyCodec {
    auth: Authenticator,
    chunk: ChunkSizeParser,
    padding: PaddingLengthGenerator,
    shake: ShakeSizeParser,
    payload_limit: usize,
    state: DecodeState,
}

impl AEADBodyCodec {
    fn new(
        header: &RequestHeader,
        session: &mut dyn Session,
        key: impl FnOnce(&dyn Session) -> &[u8],
        nonce: impl FnOnce(&dyn Session) -> &[u8],
    ) -> Result<Self, InvalidLength> {
        let mut chunk = ChunkSizeParser::Plain;
        let mut padding = PaddingLengthGenerator::Empty;
        if header.option.contains(&RequestOption::ChunkMasking) {
            chunk = ChunkSizeParser::Shake;
        }
        if header.option.contains(&RequestOption::GlobalPadding) {
            padding = PaddingLengthGenerator::Shake;
        }
        if header.option.contains(&RequestOption::AuthenticatedLength) {
            let key = session.chunk_key();
            chunk = ChunkSizeParser::Auth(new_aead_chunk_size_cipher(header.security, key)?);
        }
        let key: &[u8] = key(session);
        let cipher = match header.security {
            SecurityType::Chacha20Poly1305 => new_aead_cipher(header.security, &auth::generate_chacha20_poly1305_key(key)),
            _ => new_aead_cipher(header.security, key),
        };
        let nonce = nonce(session);
        let shake = ShakeSizeParser::new(nonce);
        Ok(Self { auth: Authenticator::new(cipher), chunk, padding, shake, payload_limit: 2048, state: DecodeState::Padding })
    }

    pub fn new_encoder(header: &RequestHeader, session: &mut dyn Session) -> Result<Self, InvalidLength> {
        Self::new(header, session, |s| s.encoder_key(), |s| s.encoder_nonce())
    }

    pub fn new_decoder(header: &RequestHeader, session: &mut dyn Session) -> Result<Self, InvalidLength> {
        Self::new(header, session, |s| s.decoder_key(), |s| s.decoder_nonce())
    }

    fn encode_chunk(&mut self, src: &mut BytesMut, dst: &mut BytesMut, session: &mut dyn Session) -> Result<(), aead::Error> {
        let padding_length = self.next_padding_length();
        trace!("Encode payload; padding length={}", padding_length);
        let tag_size = self.auth.cipher.tag_size();
        let encrypted_size = src.remaining().min(self.payload_limit - tag_size - self.chunk.size_bytes() - padding_length);
        let encrypted_size_bytes = self.encode_size(encrypted_size + padding_length + tag_size, session.chunk_nonce())?;
        dst.extend_from_slice(&encrypted_size_bytes);
        let mut payload_bytes = src.split_to(encrypted_size);
        self.auth.seal(&mut payload_bytes, session.encoder_nonce_mut())?;
        dst.extend_from_slice(&payload_bytes);
        let mut padding_bytes: Vec<u8> = vec![0; padding_length];
        dice::fill_bytes(&mut padding_bytes);
        dst.extend_from_slice(&padding_bytes);
        Ok(())
    }

    fn next_padding_length(&mut self) -> usize {
        match self.padding {
            PaddingLengthGenerator::Empty => 0,
            PaddingLengthGenerator::Shake => self.shake.next_padding_length(),
        }
    }

    fn encode_size(&mut self, size: usize, nonce: &mut [u8]) -> Result<Vec<u8>, aead::Error> {
        match self.chunk {
            ChunkSizeParser::Plain => Ok(PlainSizeParser::encode_size(size)),
            ChunkSizeParser::Auth(ref mut parser) => parser.encode_size(size, nonce),
            ChunkSizeParser::Shake => Ok(self.shake.encode_size(size)),
        }
    }

    pub fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut, session: &mut dyn Session) -> Result<(), aead::Error> {
        while src.has_remaining() {
            self.encode_chunk(&mut src, dst, session)?;
        }
        Ok(())
    }

    pub fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut, session: &mut dyn Session) -> Result<(), aead::Error> {
        self.encode_chunk(&mut src, dst, session)
    }

    pub fn decode_packet(&mut self, src: &mut BytesMut, session: &mut dyn Session) -> Result<Option<BytesMut>, aead::Error> {
        let padding_length = self.next_padding_length();
        let packet_length = self.decode_size(&mut src.split_to(self.chunk.size_bytes()), session.chunk_nonce())? - padding_length;
        let mut packet_bytes = src.split_to(packet_length);
        self.auth.open(&mut packet_bytes, session.decoder_nonce_mut())?;
        src.advance(padding_length);
        Ok(Some(packet_bytes))
    }

    pub fn decode_payload(&mut self, src: &mut BytesMut, session: &mut dyn Session) -> Result<Option<BytesMut>, aead::Error> {
        let mut dst = BytesMut::new();
        loop {
            match self.state {
                DecodeState::Padding => {
                    let padding = self.next_padding_length();
                    trace!("Decode payload; padding length={}", padding);
                    self.state = DecodeState::Length(padding)
                }
                DecodeState::Length(padding) => {
                    let size_bytes = self.chunk.size_bytes();
                    if src.remaining() < size_bytes {
                        break;
                    }
                    let length = self.decode_size(&mut src.split_to(size_bytes), session.chunk_nonce())?;
                    trace!("Decode payload; payload length={}", length);
                    self.state = DecodeState::Body(padding, length)
                }
                DecodeState::Body(padding, length) => {
                    if src.remaining() < length {
                        break;
                    }
                    dst.reserve(length);
                    let mut payload_bytes = src.split_to(length - padding);
                    self.auth.open(&mut payload_bytes, session.decoder_nonce_mut())?;
                    dst.extend_from_slice(&payload_bytes);
                    src.advance(padding);
                    self.state = DecodeState::Padding
                }
            }
        }
        if dst.is_empty() { Ok(None) } else { Ok(Some(dst)) }
    }

    fn decode_size(&mut self, data: &mut BytesMut, nonce: &mut [u8]) -> Result<usize, aead::Error> {
        match self.chunk {
            ChunkSizeParser::Plain => Ok(PlainSizeParser::decode_size(data)),
            ChunkSizeParser::Auth(ref mut parser) => parser.decode_size(data, nonce),
            ChunkSizeParser::Shake => Ok(self.shake.decode_size(data)),
        }
    }
}

fn new_aead_chunk_size_cipher(security: SecurityType, key: &[u8]) -> Result<Authenticator, InvalidLength> {
    let key = &kdf::kdf16(key, vec![AUTH_LEN]);
    match security {
        SecurityType::Chacha20Poly1305 => Ok(Authenticator::new(new_aead_cipher(security, &auth::generate_chacha20_poly1305_key(key)))),
        _ => Ok(Authenticator::new(new_aead_cipher(security, key))),
    }
}

fn new_aead_cipher(security: SecurityType, key: &[u8]) -> CipherMethod {
    match security {
        SecurityType::Chacha20Poly1305 => CipherMethod::new(CipherKind::ChaCha20Poly1305, key),
        _ => CipherMethod::new(CipherKind::Aes128Gcm, key),
    }
}

enum DecodeState {
    Padding,
    Length(usize),
    Body(usize, usize),
}

#[allow(clippy::large_enum_variant)]
enum ChunkSizeParser {
    Plain,
    Auth(Authenticator),
    Shake,
}

impl ChunkSizeParser {
    fn size_bytes(&self) -> usize {
        match self {
            ChunkSizeParser::Plain => PlainSizeParser::size_bytes(),
            ChunkSizeParser::Auth(parser) => parser.size_bytes(),
            ChunkSizeParser::Shake => ShakeSizeParser::size_bytes(),
        }
    }
}

#[derive(PartialEq, Eq)]
enum PaddingLengthGenerator {
    Empty,
    Shake,
}

struct Authenticator {
    cipher: CipherMethod,
    counting: CountingNonceGenerator,
}

impl Authenticator {
    fn new(cipher: CipherMethod) -> Self {
        let counting = CountingNonceGenerator::new(cipher.nonce_size());
        Self { cipher, counting }
    }

    const fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.cipher.tag_size()
    }

    fn encode_size(&mut self, size: usize, nonce: &mut [u8]) -> Result<Vec<u8>, aead::Error> {
        let mut buffer = ((size - self.cipher.tag_size()) as u16).to_be_bytes().to_vec();
        self.seal(&mut buffer, nonce)?;
        Ok(buffer)
    }

    fn decode_size(&mut self, buffer: &mut BytesMut, nonce: &mut [u8]) -> Result<usize, aead::Error> {
        self.open(buffer, nonce)?;
        Ok(buffer.get_u16() as usize + self.cipher.tag_size())
    }

    fn seal(&mut self, buffer: &mut dyn Buffer, nonce: &mut [u8]) -> Result<(), aead::Error> {
        self.cipher.encrypt_in_place(self.counting.generate(nonce), &[], buffer)
    }

    fn open(&mut self, buffer: &mut dyn Buffer, nonce: &mut [u8]) -> Result<(), aead::Error> {
        self.cipher.decrypt_in_place(self.counting.generate(nonce), &[], buffer)
    }
}

struct ShakeSizeParser {
    reader: XofReaderCoreWrapper<Shake128ReaderCore>,
    buffer: [u8; 2],
}

impl ShakeSizeParser {
    fn new(nonce: &[u8]) -> Self {
        trace!("New ShakeSizeParser; nonce={}", Base64::encode_string(nonce));
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
        bytes.copy_from_slice(data);
        let size = u16::from_be_bytes(bytes);
        (mask ^ size) as usize
    }

    fn next_padding_length(&mut self) -> usize {
        (self.next() % 64) as usize
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use anyhow::anyhow;
    use rand::Rng;
    use rand::random;
    use tokio_util::bytes::BytesMut;

    use crate::codec::vmess::aead::AEADBodyCodec;
    use crate::codec::vmess::aead::ShakeSizeParser;
    use crate::protocol::address::Address;
    use crate::protocol::vmess::VERSION;
    use crate::protocol::vmess::header::*;
    use crate::protocol::vmess::id;
    use crate::protocol::vmess::session::ClientSession;
    use crate::protocol::vmess::session::ServerSession;

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
            let size = rand::rng().random_range(32768..65535);
            let bytes = p1.encode_size(size);
            assert_eq!(size, p2.decode_size(&bytes[..]))
        }
    }

    #[test]
    fn test_aead_codec() -> Result<()> {
        fn new_address() -> Address {
            Address::Domain("localhost".to_owned(), random())
        }

        fn test_by_security(security: SecurityType) -> Result<()> {
            let header = RequestHeader::default(RequestCommand::TCP, security, new_address(), &uuid::Uuid::new_v4().to_string())?;
            test_by_header(header)
        }

        fn test_by_command(command: RequestCommand) -> Result<()> {
            let header = RequestHeader::default(command, SecurityType::Chacha20Poly1305, new_address(), &uuid::Uuid::new_v4().to_string())?;
            test_by_header(header)
        }

        fn test_by_option_masks() -> Result<()> {
            test_by_option_mask(RequestOption::ChunkStream as u8)?;
            test_by_option_mask(RequestOption::ChunkStream as u8 | RequestOption::ChunkMasking as u8)?;
            test_by_option_mask(RequestOption::ChunkStream as u8 | RequestOption::GlobalPadding as u8)?;
            test_by_option_mask(RequestOption::ChunkStream as u8 | RequestOption::ChunkMasking as u8 | RequestOption::GlobalPadding as u8)?;
            test_by_option_mask(RequestOption::ChunkStream as u8 | RequestOption::AuthenticatedLength as u8)?;
            test_by_option_mask(RequestOption::ChunkStream as u8 | RequestOption::GlobalPadding as u8 | RequestOption::AuthenticatedLength as u8)?;
            test_by_option_mask(
                RequestOption::ChunkStream as u8
                    | RequestOption::ChunkMasking as u8
                    | RequestOption::GlobalPadding as u8
                    | RequestOption::AuthenticatedLength as u8,
            )?;
            Ok(())
        }

        fn test_by_option_mask(mask: u8) -> Result<()> {
            let header = RequestHeader {
                version: VERSION,
                command: RequestCommand::TCP,
                option: RequestOption::from_mask(mask),
                security: SecurityType::Chacha20Poly1305,
                address: new_address(),
                id: id::from_uuid(uuid::Uuid::new_v4()),
            };
            test_by_header(header)?;
            let header = RequestHeader {
                version: VERSION,
                command: RequestCommand::UDP,
                option: RequestOption::from_mask(mask),
                security: SecurityType::Aes128Gcm,
                address: new_address(),
                id: id::from_uuid(uuid::Uuid::new_v4()),
            };
            test_by_header(header)?;
            Ok(())
        }

        fn test_by_header(header: RequestHeader) -> Result<()> {
            let mut client_session = ClientSession::new();
            let mut server_session: ServerSession = client_session.clone().into();
            let mut client_encoder = AEADBodyCodec::new_encoder(&header, &mut client_session)?;
            let mut client_decoder = AEADBodyCodec::new_decoder(&header, &mut client_session)?;
            let mut server_encoder = AEADBodyCodec::new_encoder(&header, &mut server_session)?;
            let mut server_decoder = AEADBodyCodec::new_decoder(&header, &mut server_session)?;
            let mut msg = [0; 2048];
            rand::rng().fill(&mut msg);
            let mut src = BytesMut::new();
            src.extend_from_slice(&msg);
            let mut dst = BytesMut::new();
            client_encoder.encode_payload(src, &mut dst, &mut client_session).map_err(|e| anyhow!(e))?;
            let dst = server_decoder.decode_payload(&mut dst, &mut server_session).map_err(|e| anyhow!(e))?.unwrap();
            let mut temp = BytesMut::new();
            server_encoder.encode_payload(dst, &mut temp, &mut server_session).map_err(|e| anyhow!(e))?;
            let dst = client_decoder.decode_payload(&mut temp, &mut client_session).map_err(|e| anyhow!(e))?.unwrap();
            assert_eq!(msg, *dst);
            Ok(())
        }

        test_by_security(SecurityType::Aes128Gcm)?;
        test_by_security(SecurityType::Chacha20Poly1305)?;
        test_by_security(SecurityType::Legacy)?;
        test_by_security(SecurityType::Auto)?;
        test_by_security(SecurityType::Unknown)?;
        test_by_security(SecurityType::None)?;
        test_by_security(SecurityType::Zero)?;
        test_by_command(RequestCommand::TCP)?;
        test_by_command(RequestCommand::UDP)?;
        test_by_option_masks()?;
        Ok(())
    }
}
