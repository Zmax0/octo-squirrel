use std::sync::{Arc, Mutex};

use super::{aead::{AEADCipher, Aes128GcmCipher, Authenticator, ChaCha20Poly1305Cipher, PayloadEncoder}, chunk::{AEADChunkSizeParser, ChunkSizeCodec}, CountingNonceGenerator, EmptyBytesGenerator, IncreasingNonceGenerator, PaddingLengthGenerator};
use crate::common::protocol::vmess::{encoding, header::{RequestHeader, RequestOption, SecurityType, AUTHENTICATED_LENGTH, CHACHA20_POLY1305}};

pub struct AEADBodyCodecInit<'a> {
    key: &'a [u8],
    iv: &'a [u8],
    size_codec: Box<dyn ChunkSizeCodec>,
    padding: Box<dyn PaddingLengthGenerator>,
}
pub struct AEADBodyCodec {}

impl AEADBodyCodec {
    pub fn get_body_encoder(header: RequestHeader, init: AEADBodyCodecInit) -> PayloadEncoder {
        let security = header.security;
        let cipher = Self::get_aead_cipher(security, init.key);
        let size_codec = init.size_codec;
        if security == CHACHA20_POLY1305 {
            if header.option.contains(&AUTHENTICATED_LENGTH) {}
        }
        todo!()
    }

    fn get_aead_cipher(security: SecurityType, key: &[u8]) -> Box<dyn AEADCipher> {
        if security == CHACHA20_POLY1305 {
            Box::new(ChaCha20Poly1305Cipher::new(&key))
        } else {
            Box::new(Aes128GcmCipher::new(&key))
        }
    }

    fn new_auth(cipher: Box<dyn AEADCipher>, init: AEADBodyCodecInit) -> Arc<Mutex<Authenticator>> {
        // Arc::new(Mutex::new(Authenticator::new(cipher, Box::new(CountingNonceGenerator { count: 0 }), Box::new(EmptyBytesGenerator {}))))
        todo!()
    }

    fn new_chunc_size_codec() {
        // AEADChunkSizeParser();
        todo!()
    }
}
