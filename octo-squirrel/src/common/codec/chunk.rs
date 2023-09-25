use std::mem::size_of;

pub trait ChunkSizeCodec: Send {
    fn size_bytes(&self) -> usize;
    fn encode_size(&mut self, size: usize) -> Vec<u8>;
    fn decode_size(&mut self, data: &[u8]) -> usize;
}

pub struct PlainChunkSizeParser;

impl ChunkSizeCodec for PlainChunkSizeParser {
    fn size_bytes(&self) -> usize {
        size_of::<u16>()
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        (size as u16).to_be_bytes().to_vec()
    }

    fn decode_size(&mut self, data: &[u8]) -> usize {
        let mut bytes = [0; size_of::<u16>()];
        bytes.copy_from_slice(&data[..size_of::<u16>()]);
        u16::from_be_bytes(bytes) as usize
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::rc::Rc;

    use rand::random;
    use rand::Rng;

    use crate::common::codec::aead::Aes128GcmCipher;
    use crate::common::codec::aead::Authenticator;
    use crate::common::codec::aead::ChaCha20Poly1305Cipher;
    use crate::common::codec::chunk::ChunkSizeCodec;
    use crate::common::codec::CountingNonceGenerator;
    use crate::common::codec::EmptyBytesGenerator;
    use crate::common::codec::IncreasingNonceGenerator;
    use crate::common::protocol::vmess::encoding::Auth;

    #[test]
    fn test_shadowsocks_aead_chunk_size_codec() {
        let mut key: [u8; 16] = [0; 16];
        rand::thread_rng().fill(&mut key);
        let mut auth1 = Authenticator::new(
            Box::new(Aes128GcmCipher::new(&key)),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        );
        let size1: u16 = random();
        let encoded = auth1.encode_size(size1 as usize);
        let mut auth2 = Authenticator::new(
            Box::new(Aes128GcmCipher::new(&key)),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        );
        let size2 = auth2.decode_size(&encoded);
        assert_eq!(size1, size2 as u16)
    }

    #[test]
    fn test_vemss_aead_chunk_size_codec() {
        let key: [u8; 16] = random();
        let iv: [u8; 16] = random();
        let mut auth1 = Authenticator::new(
            Box::new(ChaCha20Poly1305Cipher::new(&Auth::generate_chacha20_poly1305_key(&key))),
            Box::new(CountingNonceGenerator::new(Rc::new(RefCell::new(iv)), Aes128GcmCipher::NONCE_SIZE)),
            Box::new(EmptyBytesGenerator {}),
        );
        let mut auth2 = Authenticator::new(
            Box::new(ChaCha20Poly1305Cipher::new(&Auth::generate_chacha20_poly1305_key(&key))),
            Box::new(CountingNonceGenerator::new(Rc::new(RefCell::new(iv)), Aes128GcmCipher::NONCE_SIZE)),
            Box::new(EmptyBytesGenerator {}),
        );
        for _ in 0..100 {
            let size1: u16 = random();
            let size2 = codec(size1, &mut auth1, &mut auth2);
            assert_eq!(size1, size2 as u16)
        }

        fn codec(size1: u16, encoder: &mut Authenticator, decoder: &mut Authenticator) -> usize {
            let encoded = encoder.encode_size(size1 as usize);
            let size2 = decoder.decode_size(&encoded);
            size2
        }
    }
}
