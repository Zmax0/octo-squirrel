use digest::Digest;
use md5::Md5;
use rand::{random, Rng};
use sha2::Sha256;

pub struct Auth;

impl Auth {
    pub fn generate_chacha20_poly1305_key(raw: &[u8]) -> [u8; 32] {
        let mut key = [0; 32];
        let mut hasher = Md5::new();
        hasher.update(raw);
        let res = hasher.finalize_reset();
        key[..16].copy_from_slice(&res[..]);
        hasher.update(&res[..16]);
        let res = hasher.finalize();
        key[16..].copy_from_slice(&res[..]);
        key
    }
}

pub struct Session {
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
    pub response_header: u8,
}

impl Session {
    pub fn new(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&request_body_iv);
        let res = hasher.finalize_reset();
        let mut response_body_iv = [0; 16];
        response_body_iv.clone_from_slice(&res[..]);
        hasher.update(&request_body_key);
        let res = hasher.finalize_reset();
        let mut response_body_key = [0; 16];
        response_body_key.clone_from_slice(&res[..]);
        Self { request_body_iv, request_body_key, response_body_iv, response_body_key, response_header }
    }
}

pub struct ClientSession(pub Session);

impl ClientSession {
    pub fn new() -> Self {
        let mut request_body_iv: [u8; 16] = [0; 16];
        let mut request_body_key: [u8; 16] = [0; 16];
        let response_header = random();
        rand::thread_rng().fill(&mut request_body_iv[..]);
        rand::thread_rng().fill(&mut request_body_key[..]);
        let session = Session::new(request_body_iv, request_body_key, response_header);
        ClientSession(session)
    }
}

impl From<&[u8]> for ClientSession {
    fn from(value: &[u8]) -> Self {
        let mut request_body_iv: [u8; 16] = [0; 16];
        let mut request_body_key: [u8; 16] = [0; 16];
        request_body_iv.copy_from_slice(&value[0..16]);
        request_body_key.copy_from_slice(&value[16..32]);
        let session = Session::new(request_body_iv, request_body_key, value[32]);
        ClientSession(session)
    }
}

pub struct ServerSession(pub Session);

impl ServerSession {
    pub fn new(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
        let session = Session::new(request_body_iv, request_body_key, response_header);
        ServerSession(session)
    }
}

impl From<Session> for ServerSession {
    fn from(value: Session) -> Self {
        ServerSession(value)
    }
}

impl From<ClientSession> for ServerSession {
    fn from(value: ClientSession) -> Self {
        ServerSession::from(value.0)
    }
}

#[test]
fn test_generate_chacha20_poly1305_key() {
    use base64ct::{Base64, Encoding};
    let data = b"fn bubble_sort<T: Ord>(arr: &mut [T]) {let mut swapped = true;while swapped {swapped = false;for i in 1..arr.len() {if arr[i - 1] > arr[i] {arr.swap(i - 1, i);swapped = true;}}}}";
    let res = Auth::generate_chacha20_poly1305_key(data);
    assert_eq!("UDKJ9PJ4zh6hDio6vuw0UhcSqk8njawoEziFz405238=", Base64::encode_string(&res));
}
