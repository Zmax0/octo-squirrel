use aead::KeyInit;
use aes::cipher::BlockDecrypt;
use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes::Aes256;
use aes::Block;
use anyhow::bail;
use anyhow::Result;

use crate::common::codec::aead::CipherKind;
use crate::common::codec::shadowsocks::Authenticator;
use crate::common::codec::shadowsocks::ChunkDecoder;
use crate::common::codec::shadowsocks::ChunkEncoder;
use crate::common::codec::shadowsocks::ChunkSizeParser;
use crate::common::codec::shadowsocks::NonceGenerator;

pub fn nonce_length(kind: CipherKind) -> Result<usize> {
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm => Ok(0),
        _ => bail!("{:?} is not an AEAD 2022 cipher", kind),
    }
}

pub fn new_encoder(kind: CipherKind, key: &[u8], session_id: u64, nonce: [u8; 12]) -> ChunkEncoder {
    let key = session_sub_key(key, session_id);
    let auth = Authenticator::new(kind.to_cipher_method(&key), NonceGenerator::Static(Box::new(nonce)));
    ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Empty)
}

pub fn new_decoder(kind: CipherKind, key: &[u8], session_id: u64, nonce: [u8; 12]) -> ChunkDecoder {
    let key = session_sub_key(key, session_id);
    let auth = Authenticator::new(kind.to_cipher_method(&key), NonceGenerator::Static(Box::new(nonce)));
    ChunkDecoder::new(auth, ChunkSizeParser::Empty)
}

fn session_sub_key(key: &[u8], session_id: u64) -> [u8; 32] {
    super::session_sub_key(key, &session_id.to_be_bytes())
}

pub fn encrypt_packet_header(kind: CipherKind, key: &[u8], header: &mut [u8]) -> Result<()> {
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key).expect("AES-128 init");
            let block = Block::from_mut_slice(header);
            cipher.encrypt_block(block);
            Ok(())
        }
        CipherKind::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key).expect("AES-256 init");
            let block = Block::from_mut_slice(header);
            cipher.encrypt_block(block);
            Ok(())
        }
        _ => bail!("{:?} is not an AEAD 2022 cipher", kind),
    }
}

pub fn decrypt_packet_header(kind: CipherKind, key: &[u8], header: &mut [u8]) -> Result<()> {
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key).expect("AES-128 init");
            let block = Block::from_mut_slice(header);
            cipher.decrypt_block(block);
            Ok(())
        }
        CipherKind::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key).expect("AES-128 init");
            let block = Block::from_mut_slice(header);
            cipher.decrypt_block(block);
            Ok(())
        }
        _ => bail!("{:?} is not an AEAD 2022 cipher", kind),
    }
}
