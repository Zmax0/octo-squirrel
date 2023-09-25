use std::cell::RefCell;
use std::fmt::Display;
use std::rc::Rc;

pub mod aead;
pub mod chunk;
pub mod shadowsocks;
pub mod vmess;

pub trait PaddingLengthGenerator: Send {
    fn next_padding_length(&mut self) -> usize;
}

pub trait BytesGenerator: Send {
    fn generate(&mut self) -> Vec<u8>;
}

pub struct EmptyPaddingLengthGenerator;

impl PaddingLengthGenerator for EmptyPaddingLengthGenerator {
    fn next_padding_length(&mut self) -> usize {
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
    nonce: Rc<RefCell<[u8]>>,
    nonce_size: usize,
}

unsafe impl Send for CountingNonceGenerator {}

impl CountingNonceGenerator {
    pub fn new(nonce: Rc<RefCell<[u8]>>, nonce_size: usize) -> Self {
        Self { count: 0, nonce, nonce_size }
    }
}

impl BytesGenerator for CountingNonceGenerator {
    fn generate(&mut self) -> Vec<u8> {
        let mut nonce = self.nonce.borrow_mut();
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.overflowing_add(1).0;
        nonce[..self.nonce_size].to_vec()
    }
}

impl Display for CountingNonceGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "count={}, nonce={:?}", self.count, self.nonce.borrow())
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use base64ct::Encoding;
    use rand::random;

    use super::CountingNonceGenerator;
    use crate::common::codec::BytesGenerator;
    use crate::common::codec::IncreasingNonceGenerator;
    use crate::common::codec::StaticBytesGenerator;

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
    fn test_generate_counting_nonce() {
        let nonce = Rc::new(RefCell::new([0u8; 16]));
        let mut generator = CountingNonceGenerator::new(nonce.clone(), 12);
        let mut generated = Vec::new();
        for _ in 0..65536 {
            generated = generator.generate();
        }
        assert_eq!("//8AAAAAAAAAAAAA", base64ct::Base64::encode_string(&generated[..]));
        assert_eq!("//8AAAAAAAAAAAAAAAAAAA==", base64ct::Base64::encode_string(&nonce.borrow()[..]));
    }
}
