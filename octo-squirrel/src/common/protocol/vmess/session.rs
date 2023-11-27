use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use base64ct::Encoding;
use rand::random;
use rand::Rng;
use sha2::Digest;
use sha2::Sha256;

macro_rules! session_impl {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            pub request_body_iv: [u8; 16],
            pub request_body_key: [u8; 16],
            pub response_body_iv: [u8; 16],
            pub response_body_key: [u8; 16],
            pub response_header: u8,
        }

        impl $name {
            fn init(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
                let mut hasher = Sha256::new();
                hasher.update(request_body_iv);
                let res = hasher.finalize_reset();
                let mut response_body_iv = [0; 16];
                response_body_iv.copy_from_slice(&res[..16]);
                hasher.update(request_body_key);
                let res = hasher.finalize_reset();
                let mut response_body_key = [0; 16];
                response_body_key.copy_from_slice(&res[..16]);
                Self { request_body_iv, request_body_key, response_body_iv, response_body_key, response_header }
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "[RK:{}, RI:{}, SK:{}, SI:{}, SH:{}]",
                    base64ct::Base64::encode_string(&self.request_body_key),
                    base64ct::Base64::encode_string(&self.request_body_iv),
                    base64ct::Base64::encode_string(&self.response_body_key),
                    base64ct::Base64::encode_string(&self.response_body_iv),
                    &self.response_header
                )
            }
        }
    };
}

session_impl!(ClientSession);
session_impl!(ServerSession);

impl ClientSession {
    pub fn new() -> Self {
        let mut request_body_iv: [u8; 16] = [0; 16];
        let mut request_body_key: [u8; 16] = [0; 16];
        let response_header = random();
        rand::thread_rng().fill(&mut request_body_iv[..]);
        rand::thread_rng().fill(&mut request_body_key[..]);
        Self::init(request_body_iv, request_body_key, response_header)
    }
}

impl From<&[u8]> for ClientSession {
    fn from(value: &[u8]) -> Self {
        let mut request_body_iv: [u8; 16] = [0; 16];
        let mut request_body_key: [u8; 16] = [0; 16];
        request_body_iv.copy_from_slice(&value[0..16]);
        request_body_key.copy_from_slice(&value[16..32]);
        Self::init(request_body_iv, request_body_key, value[32])
    }
}

impl ServerSession {
    pub fn new(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
        Self::init(request_body_iv, request_body_key, response_header)
    }
}

impl From<ClientSession> for ServerSession {
    fn from(value: ClientSession) -> Self {
        Self {
            request_body_iv: value.request_body_iv,
            request_body_key: value.request_body_key,
            response_body_iv: value.response_body_iv,
            response_body_key: value.response_body_key,
            response_header: value.response_header,
        }
    }
}

pub trait Session: Display {
    fn encoder_key(&self) -> &[u8];
    fn encoder_nonce(&mut self) -> &mut [u8];
    fn decoder_key(&self) -> &[u8];
    fn decoder_nonce(&mut self) -> &mut [u8];
    fn chunk_key(&self) -> &[u8];
    fn chunk_nonce(&mut self) -> &mut [u8];
}

impl Session for ClientSession {
    fn encoder_key(&self) -> &[u8] {
        &self.request_body_key
    }
    fn encoder_nonce(&mut self) -> &mut [u8] {
        &mut self.request_body_iv
    }
    fn decoder_key(&self) -> &[u8] {
        &self.response_body_key
    }
    fn decoder_nonce(&mut self) -> &mut [u8] {
        &mut self.response_body_iv
    }
    fn chunk_key(&self) -> &[u8] {
        &self.request_body_key
    }
    fn chunk_nonce(&mut self) -> &mut [u8] {
        &mut self.request_body_iv
    }
}

impl Session for ServerSession {
    fn encoder_key(&self) -> &[u8] {
        &self.response_body_key
    }
    fn encoder_nonce(&mut self) -> &mut [u8] {
        &mut self.response_body_iv
    }
    fn decoder_key(&self) -> &[u8] {
        &self.request_body_key
    }
    fn decoder_nonce(&mut self) -> &mut [u8] {
        &mut self.request_body_iv
    }
    fn chunk_key(&self) -> &[u8] {
        &self.request_body_key
    }
    fn chunk_nonce(&mut self) -> &mut [u8] {
        &mut self.request_body_iv
    }
}
