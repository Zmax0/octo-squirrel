use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use base64ct::Encoding;
use rand::{random, Rng};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
struct BaseSession {
    request_body_iv: [u8; 16],
    request_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_header: u8,
}

impl BaseSession {
    fn new(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&request_body_iv);
        let res = hasher.finalize_reset();
        let mut response_body_iv = [0; 16];
        response_body_iv.clone_from_slice(&res[..16]);
        hasher.update(&request_body_key);
        let res = hasher.finalize_reset();
        let mut response_body_key = [0; 16];
        response_body_key.clone_from_slice(&res[..16]);
        Self { request_body_iv, request_body_key, response_body_iv, response_body_key, response_header }
    }
}

#[derive(Clone, Debug)]
pub struct ClientSession(BaseSession);

impl ClientSession {
    pub fn new() -> Self {
        let mut request_body_iv: [u8; 16] = [0; 16];
        let mut request_body_key: [u8; 16] = [0; 16];
        let response_header = random();
        rand::thread_rng().fill(&mut request_body_iv[..]);
        rand::thread_rng().fill(&mut request_body_key[..]);
        let session = BaseSession::new(request_body_iv, request_body_key, response_header);
        ClientSession(session)
    }
}

impl From<&[u8]> for ClientSession {
    fn from(value: &[u8]) -> Self {
        let mut request_body_iv: [u8; 16] = [0; 16];
        let mut request_body_key: [u8; 16] = [0; 16];
        request_body_iv.copy_from_slice(&value[0..16]);
        request_body_key.copy_from_slice(&value[16..32]);
        let session: BaseSession = BaseSession::new(request_body_iv, request_body_key, value[32]);
        ClientSession(session)
    }
}

impl Display for ClientSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RK:{}, RI:{}, SK:{}, SI:{}, SH:{}",
            base64ct::Base64::encode_string(self.request_body_key()),
            base64ct::Base64::encode_string(&self.request_body_iv().lock().unwrap()),
            base64ct::Base64::encode_string(self.response_body_key()),
            base64ct::Base64::encode_string(&self.response_body_iv().lock().unwrap()),
            self.response_header()
        )
    }
}

#[derive(Clone)]
pub struct ServerSession(BaseSession);

impl ServerSession {
    pub fn new(request_body_iv: [u8; 16], request_body_key: [u8; 16], response_header: u8) -> Self {
        let session = BaseSession::new(request_body_iv, request_body_key, response_header);
        ServerSession(session)
    }
}

impl From<BaseSession> for ServerSession {
    fn from(value: BaseSession) -> Self {
        ServerSession(value)
    }
}

impl From<ClientSession> for ServerSession {
    fn from(value: ClientSession) -> Self {
        ServerSession::from(value.0)
    }
}

pub trait Session {
    fn request_body_iv(&self) -> Arc<Mutex<[u8]>>;
    fn request_body_key(&self) -> &[u8];
    fn response_body_iv(&self) -> Arc<Mutex<[u8]>>;
    fn response_body_key(&self) -> &[u8];
    fn response_header(&self) -> u8;
}

impl Session for ClientSession {
    fn request_body_iv(&self) -> Arc<Mutex<[u8]>> {
        Arc::new(Mutex::new(self.0.request_body_iv))
    }

    fn request_body_key(&self) -> &[u8] {
        &self.0.request_body_key
    }

    fn response_body_iv(&self) -> Arc<Mutex<[u8]>> {
        Arc::new(Mutex::new(self.0.response_body_iv))
    }

    fn response_body_key(&self) -> &[u8] {
        &self.0.response_body_key
    }

    fn response_header(&self) -> u8 {
        self.0.response_header
    }
}

impl Session for ServerSession {
    fn request_body_iv(&self) -> Arc<Mutex<[u8]>> {
        Arc::new(Mutex::new(self.0.request_body_iv))
    }

    fn request_body_key(&self) -> &[u8] {
        &self.0.request_body_key
    }

    fn response_body_iv(&self) -> Arc<Mutex<[u8]>> {
        Arc::new(Mutex::new(self.0.response_body_iv))
    }

    fn response_body_key(&self) -> &[u8] {
        &self.0.response_body_key
    }

    fn response_header(&self) -> u8 {
        self.0.response_header
    }
}

#[test]
fn test() {
    let session = ClientSession::new();
    println!("{}", session);
}
