use std::io::Error;
use std::sync::{Arc, Mutex};

use digest::core_api::XofReaderCoreWrapper;
use digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128ReaderCore};

use super::{aead::{AEADCipher, Aes128GcmCipher, Authenticator, ChaCha20Poly1305Cipher, PayloadEncoder}, chunk::{AEADChunkSizeParser, ChunkSizeCodec}, CountingNonceGenerator, EmptyBytesGenerator, PaddingLengthGenerator};
use crate::common::codec::EmptyPaddingLengthGenerator;
use crate::common::protocol::vmess::header::{CHUNK_MASKING, GLOBAL_PADDING};
use crate::common::protocol::vmess::{aead::KDF, encoding::{Auth, Session}, header::{RequestHeader, SecurityType, AUTHENTICATED_LENGTH, CHACHA20_POLY1305}};

const AUTH_LEN: &[u8] = b"auth_len";
pub struct AEADBodyCodec {}

impl AEADBodyCodec {
    pub fn get_body_encoder(header: &RequestHeader, session: &Session, mapper: fn(session: &Session) -> (&[u8], Arc<Mutex<[u8]>>)) -> PayloadEncoder {
        let (key, iv) = mapper(session);
        let security = header.security;
        let (mut size_codec, padding) = Self::init_default(header, key, iv.clone());
        let cipher = Self::get_aead_cipher(header.security, key);
        if security == CHACHA20_POLY1305 {
            if header.option.contains(&AUTHENTICATED_LENGTH) {
                size_codec = Self::new_chunk_size_codec(
                    Self::get_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(&session.request_body_key)),
                    Arc::new(Mutex::new(session.request_body_iv)),
                );
            }
            return PayloadEncoder::new(
                2048,
                Self::new_auth(Self::get_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(key)), iv.clone()),
                size_codec,
                padding,
            );
        }
        if header.option.contains(&AUTHENTICATED_LENGTH) {
            size_codec = Self::new_chunk_size_codec(
                Self::get_aead_cipher(security, &KDF::kdf16(&session.request_body_key, vec![AUTH_LEN])),
                Arc::new(Mutex::new(session.request_body_iv)),
            );
        }
        PayloadEncoder::new(2048, Self::new_auth(cipher, iv.clone()), size_codec, padding)
    }

    fn get_aead_cipher(security: SecurityType, key: &[u8]) -> Box<dyn AEADCipher> {
        if security == CHACHA20_POLY1305 {
            Box::new(ChaCha20Poly1305Cipher::new(&key))
        } else {
            Box::new(Aes128GcmCipher::new(&key))
        }
    }

    fn new_auth(cipher: Box<dyn AEADCipher>, nonce: Arc<Mutex<[u8]>>) -> Arc<Mutex<Authenticator>> {
        Arc::new(Mutex::new(Authenticator::new(cipher, Box::new(CountingNonceGenerator::new(nonce, 12)), Box::new(EmptyBytesGenerator))))
    }

    fn new_chunk_size_codec(cipher: Box<dyn AEADCipher>, nonce: Arc<Mutex<[u8]>>) -> Box<dyn ChunkSizeCodec> {
        Box::new(AEADChunkSizeParser(Self::new_auth(cipher, nonce)))
    }

    fn init_default(header: &RequestHeader, key: &[u8], iv: Arc<Mutex<[u8]>>) -> (Box<dyn ChunkSizeCodec>, Box<dyn PaddingLengthGenerator>) {
        let cipher = Self::get_aead_cipher(header.security, key);
        let mut size_codec: Box<dyn ChunkSizeCodec> = Box::new(AEADChunkSizeParser(Self::new_auth(cipher, iv.clone())));
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
        2
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
    use rand::Rng;

    use crate::common::codec::chunk::ChunkSizeCodec;
    use crate::common::codec::vmess::ShakeSizeParser;
    use crate::common::codec::PaddingLengthGenerator;

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
}
