use std::{io, mem, sync::{Arc, Mutex}};

use super::aead::Authenticator;

pub const BYTES: usize = mem::size_of::<u16>();

pub trait ChunkSizeCodec: Send + Sync {
    fn size_bytes(&self) -> usize;
    fn encode(&mut self, size: usize) -> Result<Vec<u8>, io::Error>;
    fn decode(&mut self, data: &[u8]) -> Result<usize, io::Error>;
}

pub struct AEADChunkSizeParser(pub Arc<Mutex<Authenticator>>);

impl ChunkSizeCodec for AEADChunkSizeParser {
    fn size_bytes(&self) -> usize {
        BYTES + self.0.lock().unwrap().overhead()
    }

    fn encode(&mut self, size: usize) -> Result<Vec<u8>, io::Error> {
        let mut auth = self.0.lock().unwrap();
        let bytes = ((size - auth.overhead()) as u16).to_be_bytes();
        let sealed = auth.seal(&bytes);
        Ok(sealed)
    }

    fn decode(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        let mut opened: [u8; BYTES] = [0; BYTES];
        let mut auth: std::sync::MutexGuard<'_, Authenticator> = self.0.lock().unwrap();
        opened.copy_from_slice(&auth.open(data));
        let size = u16::from_be_bytes(opened);
        Ok(size as usize + auth.overhead())
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use rand::{random, Rng};

    use crate::common::codec::{aead::{Aes128GcmCipher, Authenticator}, chunk::{AEADChunkSizeParser, ChunkSizeCodec}, EmptyBytesGenerator, IncreasingNonceGenerator};

    #[test]
    fn test_aead_chunk_size_parser() {
        let mut key: [u8; 16] = [0; 16];
        rand::thread_rng().fill(&mut key);
        let auth1 = Authenticator::new(
            Box::new(Aes128GcmCipher::new(&key)),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        );
        let mut encoder = AEADChunkSizeParser(Arc::new(Mutex::new(auth1)));
        let size1: u16 = random();
        let encoded = encoder.encode(size1 as usize).unwrap();
        let auth2 = Authenticator::new(
            Box::new(Aes128GcmCipher::new(&key)),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        );
        let mut decoder = AEADChunkSizeParser(Arc::new(Mutex::new(auth2)));
        let size2 = decoder.decode(&encoded).unwrap();
        assert_eq!(size1, size2 as u16)
    }
}
