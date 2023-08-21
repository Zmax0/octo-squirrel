use std::sync::{Arc, Mutex};

pub mod aead;
pub mod chunk;
pub mod shadowsocks;
pub mod vmess;

pub trait PaddingLengthGenerator: Send + Sync {
    fn next_padding_length(&self) -> usize;
}

pub trait BytesGenerator: Send + Sync {
    fn generate(&mut self) -> Vec<u8>;
}

pub struct EmptyPaddingLengthGenerator;

impl PaddingLengthGenerator for EmptyPaddingLengthGenerator {
    fn next_padding_length(&self) -> usize {
        0
    }
}

pub struct EmptyBytesGenerator;

impl BytesGenerator for EmptyBytesGenerator {
    fn generate(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

pub struct CountingNonceGenerator {
    count: u16,
    nonce: Arc<Mutex<Vec<u8>>>,
}

impl CountingNonceGenerator {
    pub fn new(nonce: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { count: 0, nonce }
    }
}

impl BytesGenerator for CountingNonceGenerator {
    fn generate(&mut self) -> Vec<u8> {
        let mut nonce = self.nonce.lock().unwrap();
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.overflowing_add(1).0;
        return nonce.clone();
    }
}

pub struct StaticBytesGenerator {
    nonce: Vec<u8>,
}

impl BytesGenerator for StaticBytesGenerator {
    fn generate(&mut self) -> Vec<u8> {
        self.nonce.to_vec()
    }
}

pub struct IncreasingNonceGenerator {
    nonce: Vec<u8>,
}

impl BytesGenerator for IncreasingNonceGenerator {
    fn generate(&mut self) -> Vec<u8> {
        for i in 0..self.nonce.len() {
            self.nonce[i] = self.nonce[i].overflowing_add(1).0;
            if self.nonce[i] != 0 {
                break;
            }
        }
        return self.nonce.to_vec();
    }
}

impl IncreasingNonceGenerator {
    pub fn generate_initial_aead_nonce() -> Self {
        Self { nonce: vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};
    use base64ct::Encoding;

    use rand::random;

    use super::CountingNonceGenerator;
    use crate::common::codec::{BytesGenerator, IncreasingNonceGenerator, StaticBytesGenerator};

    #[test]
    fn test_generate_increasing_nonce() {
        let nonce = vec![0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut generator: IncreasingNonceGenerator = IncreasingNonceGenerator { nonce };
        assert_eq!(generator.generate(), [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_initial_aead_nonce() {
        assert_eq!(IncreasingNonceGenerator::generate_initial_aead_nonce().generate(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_static_nonce() {
        let nonce: [u8; 12] = random();
        let mut generator = StaticBytesGenerator { nonce: nonce.to_vec() };
        assert_eq!(nonce.to_vec(), generator.generate())
    }

    #[test]
    fn test_foo() {
        let nonce = Arc::new(Mutex::new(vec![0u8; 12]));
        let mut generator = CountingNonceGenerator::new(nonce.clone());
        let mut generated = None;
        for _ in 0..65536 {
            generated.replace(generator.generate());
        }
        assert_eq!("//8AAAAAAAAAAAAA", base64ct::Base64::encode_string(&generated.unwrap()));
        assert_eq!("//8AAAAAAAAAAAAA", base64ct::Base64::encode_string(&nonce.lock().unwrap()));
    }
}
