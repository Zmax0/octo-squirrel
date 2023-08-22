use std::sync::{Arc, Mutex};

use super::{
    aead::{AEADCipher, Aes128GcmCipher, Authenticator, ChaCha20Poly1305Cipher, PayloadEncoder},
    chunk::{AEADChunkSizeParser, ChunkSizeCodec},
    CountingNonceGenerator, EmptyBytesGenerator, IncreasingNonceGenerator, PaddingLengthGenerator,
};
use crate::common::protocol::vmess::{
    aead::KDF,
    encoding::{self, Auth, Session},
    header::{RequestHeader, RequestOption, SecurityType, AUTHENTICATED_LENGTH, CHACHA20_POLY1305},
};

pub struct AEADBodyCodecInit<'a> {
    key: &'a [u8],
    iv: Arc<Mutex<[u8]>>,
    size_codec: Box<dyn ChunkSizeCodec>,
    padding: Box<dyn PaddingLengthGenerator>,
    session: Session,
}

const AUTH_LEN: &[u8] = b"auth_len";
pub struct AEADBodyCodec {}

impl AEADBodyCodec {
    pub fn get_body_encoder(header: RequestHeader, init: AEADBodyCodecInit) -> PayloadEncoder {
        let security = header.security;
        let mut size_codec = init.size_codec;
        let cipher = Self::get_aead_cipher(security, init.key);
        if security == CHACHA20_POLY1305 {
            if header.option.contains(&AUTHENTICATED_LENGTH) {
                size_codec = Self::new_chunc_size_codec(
                    Self::get_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(&init.session.request_body_key)),
                    Arc::new(Mutex::new(init.session.request_body_iv)),
                );
            }
            return PayloadEncoder::new(
                2048,
                Self::new_auth(Self::get_aead_cipher(security, &Auth::generate_chacha20_poly1305_key(init.key)), init.iv),
                size_codec,
                init.padding,
            );
        }
        if header.option.contains(&AUTHENTICATED_LENGTH) {
            size_codec = Self::new_chunc_size_codec(
                Self::get_aead_cipher(security, &KDF::kdf16(&init.session.request_body_key, vec![AUTH_LEN])),
                Arc::new(Mutex::new(init.session.request_body_iv)),
            );
        }
        PayloadEncoder::new(2048, Self::new_auth(cipher, init.iv), size_codec, init.padding)
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

    fn new_chunc_size_codec(cipher: Box<dyn AEADCipher>, nonce: Arc<Mutex<[u8]>>) -> Box<dyn ChunkSizeCodec> {
        Box::new(AEADChunkSizeParser(Self::new_auth(cipher, nonce)))
    }
}
