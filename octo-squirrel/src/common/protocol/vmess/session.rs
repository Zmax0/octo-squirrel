use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::Acquire;
use std::sync::atomic::Ordering::Release;
use std::sync::Arc;

use base64ct::Encoding;
use rand::random;
use rand::Rng;
use sha2::Digest;
use sha2::Sha256;

pub trait Session {
    fn request_body_iv(&self) -> [u8; 16];
    fn request_body_iv_ptr(&self) -> Arc<AtomicU8Array<16>>;
    fn request_body_key(&self) -> &[u8];
    fn response_body_iv(&self) -> [u8; 16];
    fn response_body_iv_ptr(&self) -> Arc<AtomicU8Array<16>>;
    fn response_body_key(&self) -> &[u8];
    fn response_header(&self) -> u8;
}

macro_rules! session_impl {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            request_body_iv: Arc<AtomicU8Array<16>>,
            request_body_key: [u8; 16],
            response_body_iv: Arc<AtomicU8Array<16>>,
            response_body_key: [u8; 16],
            response_header: u8,
        }

        impl $name {
            fn init(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
                let mut hasher = Sha256::new();
                hasher.update(request_body_iv);
                let res = hasher.finalize_reset();
                let mut response_body_iv = [0; 16];
                response_body_iv.clone_from_slice(&res[..16]);
                hasher.update(request_body_key);
                let res = hasher.finalize_reset();
                let mut response_body_key = [0; 16];
                response_body_key.clone_from_slice(&res[..16]);
                Self {
                    request_body_iv: Arc::new(AtomicU8Array::from(request_body_iv)),
                    request_body_key,
                    response_body_iv: Arc::new(AtomicU8Array::from(response_body_iv)),
                    response_body_key,
                    response_header,
                }
            }
        }

        impl Session for $name {
            fn request_body_iv(&self) -> [u8; 16] {
                self.request_body_iv.load::<16>()
            }

            fn request_body_iv_ptr(&self) -> Arc<AtomicU8Array<16>> {
                self.request_body_iv.clone()
            }

            fn request_body_key(&self) -> &[u8] {
                &self.request_body_key
            }

            fn response_body_iv(&self) -> [u8; 16] {
                self.response_body_iv.load::<16>()
            }

            fn response_body_iv_ptr(&self) -> Arc<AtomicU8Array<16>> {
                self.response_body_iv.clone()
            }

            fn response_body_key(&self) -> &[u8] {
                &self.response_body_key
            }

            fn response_header(&self) -> u8 {
                self.response_header
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "[REQ: {}, {}; RESP: {}, {}, {}]",
                    base64ct::Base64::encode_string(&self.request_body_key),
                    base64ct::Base64::encode_string(&self.request_body_iv()),
                    base64ct::Base64::encode_string(&self.response_body_key),
                    base64ct::Base64::encode_string(&self.response_body_iv()),
                    self.response_header()
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

pub struct AtomicU8Array<const LEN: usize> {
    buf: [AtomicU8; LEN],
}

impl<const LEN: usize> AtomicU8Array<LEN> {
    const DEFAULT: AtomicU8 = AtomicU8::new(0);

    pub fn new() -> Self {
        let buf: [AtomicU8; LEN] = [Self::DEFAULT; LEN];
        Self { buf }
    }

    pub fn load<const OFFSET: usize>(&self) -> [u8; OFFSET] {
        let mut res = [0; OFFSET];
        for i in 0..OFFSET {
            res[i] = self.buf[i].load(Acquire);
        }
        res
    }

    pub fn store(&self, value: &[u8]) {
        for i in 0..value.len() {
            self.buf[i].store(value[i], Release)
        }
    }

    pub fn update<F, const OFFSET: usize>(&self, mut f: F) -> [u8; OFFSET]
    where
        F: FnMut(&mut [u8]),
    {
        let mut value: [u8; OFFSET] = self.load();
        f(&mut value);
        for i in 0..value.len() {
            self.buf[i].fetch_update(Release, Acquire, |_| Some(value[i])).unwrap();
        }
        value
    }
}

impl<const LEN: usize> From<[u8; LEN]> for AtomicU8Array<LEN> {
    fn from(value: [u8; LEN]) -> Self {
        let arr = AtomicU8Array::<LEN>::new();
        arr.store(&value);
        arr
    }
}

impl<const LEN: usize> Debug for AtomicU8Array<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.load::<LEN>())
    }
}

#[cfg(test)]
mod test {
    use super::AtomicU8Array;
    use crate::common::protocol::vmess::session::ClientSession;
    use crate::common::protocol::vmess::session::Session;

    #[test]
    fn test_session() {
        let session = ClientSession::new();
        let iv1 = session.request_body_iv_ptr();
        let iv2 = session.request_body_iv_ptr();
        iv1.store(&[255, 255]);
        let vec1 = iv1.load::<16>().to_vec();
        let vec2 = iv2.load::<16>().to_vec();
        assert_eq!(vec1, vec2)
    }

    #[test]
    fn test_atomic_array() {
        let arr = AtomicU8Array::<16>::new();
        let count: u16 = 1;
        arr.store(&count.to_be_bytes());
        let value: [u8; 2] = arr.load();
        assert_eq!([0, 1], value)
    }
}
