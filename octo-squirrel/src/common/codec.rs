pub mod aead;
pub mod chunk;
pub mod shadowsocks;

pub trait PaddingLengthGenerator: Send + Sync {
    fn next_padding_length(&self) -> usize;
}

pub trait BytesGenerator: Send + Sync {
    fn genenrate(&mut self) -> Vec<u8>;
}

pub struct EmptyPaddingLengthGenerator;

impl PaddingLengthGenerator for EmptyPaddingLengthGenerator {
    fn next_padding_length(&self) -> usize {
        0
    }
}

pub struct EmptyBytesGenerator;

impl BytesGenerator for EmptyBytesGenerator {
    fn genenrate(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

pub struct CountingNonceGenerator {
    count: u16,
}

impl BytesGenerator for CountingNonceGenerator {
    fn genenrate(&mut self) -> Vec<u8> {
        let mut nonce = Vec::new();
        nonce[..8].copy_from_slice(&self.count.to_be_bytes());
        self.count += 1;
        return nonce;
    }
}

pub struct StaticBytesGenerator {
    nonce: Vec<u8>,
}

impl BytesGenerator for StaticBytesGenerator {
    fn genenrate(&mut self) -> Vec<u8> {
        self.nonce.to_vec()
    }
}

pub struct IncreasingNonceGenerator {
    nonce: Vec<u8>,
}

impl BytesGenerator for IncreasingNonceGenerator {
    fn genenrate(&mut self) -> Vec<u8> {
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
    use rand::random;

    use crate::common::codec::{BytesGenerator, IncreasingNonceGenerator, StaticBytesGenerator};

    #[test]
    fn test_generate_increasing_nonce() {
        let nonce = vec![0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut generator: IncreasingNonceGenerator = IncreasingNonceGenerator { nonce };
        assert_eq!(generator.genenrate(), [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_initial_aead_nonce() {
        assert_eq!(IncreasingNonceGenerator::generate_initial_aead_nonce().genenrate(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn test_generate_static_nonce() {
        let nonce: [u8; 12] = random();
        let mut generator = StaticBytesGenerator { nonce: nonce.to_vec() };
        assert_eq!(nonce.to_vec(), generator.genenrate())
    }
}
