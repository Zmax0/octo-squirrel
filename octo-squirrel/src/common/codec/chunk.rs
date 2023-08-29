use std::{io, mem::size_of, sync::{Arc, Mutex}};

use super::aead::Authenticator;

pub trait ChunkSizeCodec: Send + Sync {
    fn size_bytes(&self) -> usize;
    fn encode(&mut self, size: usize) -> Result<Vec<u8>, io::Error>;
    fn decode(&mut self, data: &[u8]) -> Result<usize, io::Error>;
}

pub struct AEADChunkSizeParser {
    pub auth: Arc<Mutex<Authenticator>>,
}

impl AEADChunkSizeParser {
    pub fn new(auth: Arc<Mutex<Authenticator>>) -> Self {
        Self { auth }
    }
}

impl ChunkSizeCodec for AEADChunkSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.auth.lock().unwrap().overhead()
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, io::Error> {
        let mut auth = self.auth.lock().unwrap();
        let bytes = ((size - auth.overhead()) as u16).to_be_bytes();
        let sealed = auth.seal(&bytes);
        Ok(sealed)
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        let mut opened: [u8; size_of::<u16>()] = [0; size_of::<u16>()];
        let mut auth = self.auth.lock().unwrap();
        opened.copy_from_slice(&auth.open(data));
        let size = u16::from_be_bytes(opened);
        Ok(size as usize + auth.overhead())
    }
}

pub struct PlainChunkSizeParser;

impl ChunkSizeCodec for PlainChunkSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>()
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, io::Error> {
        Ok((size as u16).to_be_bytes().to_vec())
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        let mut bytes = [0; size_of::<u16>()];
        bytes.copy_from_slice(&data[..size_of::<u16>()]);
        Ok(u16::from_be_bytes(bytes) as usize)
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use rand::{random, Rng};

    use crate::common::codec::aead::ChaCha20Poly1305Cipher;
    use crate::common::codec::{aead::{Aes128GcmCipher, Authenticator}, chunk::{AEADChunkSizeParser, ChunkSizeCodec}, CountingNonceGenerator, EmptyBytesGenerator, IncreasingNonceGenerator};
    use crate::common::protocol::vmess::encoding::Auth;

    #[test]
    fn test_shadowsocks_aead_chunk_size_codec() {
        let mut key: [u8; 16] = [0; 16];
        rand::thread_rng().fill(&mut key);
        let auth1 = Authenticator::new(
            Box::new(Aes128GcmCipher::new(&key)),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        );
        let mut encoder = AEADChunkSizeParser::new(Arc::new(Mutex::new(auth1)));
        let size1: u16 = random();
        let encoded = encoder.encode(size1 as usize).unwrap();
        let auth2 = Authenticator::new(
            Box::new(Aes128GcmCipher::new(&key)),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        );
        let mut decoder = AEADChunkSizeParser::new(Arc::new(Mutex::new(auth2)));
        let size2 = decoder.decode(&encoded).unwrap();
        assert_eq!(size1, size2 as u16)
    }

    #[test]
    fn test_vemss_aead_chunk_size_codec() {
        let key: [u8; 16] = random();
        let iv: [u8; 16] = random();
        let auth1 = Authenticator::new(
            Box::new(ChaCha20Poly1305Cipher::new(&Auth::generate_chacha20_poly1305_key(&key))),
            Box::new(CountingNonceGenerator::new(Arc::new(Mutex::new(iv)), Aes128GcmCipher::NONCE_SIZE)),
            Box::new(EmptyBytesGenerator {}),
        );
        let auth2 = Authenticator::new(
            Box::new(ChaCha20Poly1305Cipher::new(&Auth::generate_chacha20_poly1305_key(&key))),
            Box::new(CountingNonceGenerator::new(Arc::new(Mutex::new(iv)), Aes128GcmCipher::NONCE_SIZE)),
            Box::new(EmptyBytesGenerator {}),
        );
        let mut encoder = AEADChunkSizeParser::new(Arc::new(Mutex::new(auth1)));
        let mut decoder = AEADChunkSizeParser::new(Arc::new(Mutex::new(auth2)));
        for _ in 0..100 {
            let size1: u16 = random();
            let size2 = codec(size1, &mut encoder, &mut decoder);
            assert_eq!(size1, size2 as u16)
        }

        fn codec(size1: u16, encoder: &mut AEADChunkSizeParser, decoder: &mut AEADChunkSizeParser) -> usize {
            let encoded = encoder.encode(size1 as usize).unwrap();
            let size2 = decoder.decode(&encoded).unwrap();
            size2
        }
    }
}
