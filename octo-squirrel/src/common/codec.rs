use std::fmt::Display;
use std::mem::size_of;

pub mod aead;
pub mod chunk;
pub mod shadowsocks;
pub mod vmess;

#[derive(PartialEq, Eq)]
pub enum PaddingLengthGenerator {
    Empty,
    Shake,
}

pub enum BytesGenerator {
    Counting(CountingNonceGenerator),
    Increasing(IncreasingNonceGenerator),
    Empty,
    Static,
}

pub struct CountingNonceGenerator {
    count: u16,
    nonce_size: usize,
}

impl CountingNonceGenerator {
    pub fn new(nonce_size: usize) -> Self {
        Self { count: 0, nonce_size }
    }
}

impl CountingNonceGenerator {
    fn generate(&mut self, nonce: &mut [u8]) -> Vec<u8> {
        nonce[..size_of::<u16>()].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.overflowing_add(1).0;
        nonce[..self.nonce_size].to_vec()
    }
}

impl Display for CountingNonceGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "count={}", self.count)
    }
}

pub struct IncreasingNonceGenerator {
    nonce: Vec<u8>,
}

impl IncreasingNonceGenerator {
    pub fn generate(&mut self) -> Vec<u8> {
        for i in 0..self.nonce.len() {
            self.nonce[i] = self.nonce[i].overflowing_add(1).0;
            if self.nonce[i] != 0 {
                break;
            }
        }
        return self.nonce.to_vec();
    }

    pub fn generate_initial_aead_nonce() -> Self {
        Self { nonce: vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] }
    }
}

#[cfg(test)]
mod test {
    use base64ct::Encoding;

    use super::CountingNonceGenerator;
    use crate::common::codec::IncreasingNonceGenerator;

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
    fn test_generate_counting_nonce() {
        let mut nonce: [u8; 16] = [0; 16];
        let mut generator = CountingNonceGenerator::new(12);
        let mut generated = Vec::new();
        for _ in 0..65536 {
            generated = generator.generate(&mut nonce);
        }
        assert_eq!("//8AAAAAAAAAAAAA", base64ct::Base64::encode_string(&generated[..]));
        assert_eq!("//8AAAAAAAAAAAAAAAAAAA==", base64ct::Base64::encode_string(&nonce));
    }
}
