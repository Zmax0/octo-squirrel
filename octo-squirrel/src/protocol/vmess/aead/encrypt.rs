use std::io::Cursor;

use aes::cipher::Unsigned;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::Aead;
use aes_gcm::aead::AeadCore;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::Payload;
use anyhow::Result;
use anyhow::anyhow;
use rand::random;
use tokio_util::bytes::Buf;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::BytesMut;

use super::auth_id;
use super::kdf;
use crate::protocol::vmess::timestamp;

const NONCE_SIZE: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;
const TAG_SIZE: usize = <Aes128Gcm as AeadCore>::TagSize::USIZE;

pub fn seal_header(key: &[u8], header: Bytes) -> Result<Vec<u8>> {
    let auth_id = auth_id::create(key, timestamp(30)?);
    let connection_nonce: [u8; 8] = random();
    let length = (header.len() as u16).to_be_bytes();
    let length_key = kdf::kdf16(key, vec![kdf::SALT_LENGTH_KEY, &auth_id, &connection_nonce]);
    let length_iv: [u8; NONCE_SIZE] = kdf::kdfn(key, vec![kdf::SALT_LENGTH_IV, &auth_id, &connection_nonce]);
    let length_encrypted =
        Aes128Gcm::new_from_slice(&length_key)?.encrypt(&length_iv.into(), Payload { msg: &length, aad: &auth_id }).map_err(|e| anyhow!(e))?;
    let header_key = kdf::kdf16(key, vec![kdf::SALT_PAYLOAD_KEY, &auth_id, &connection_nonce]);
    let header_iv: [u8; NONCE_SIZE] = kdf::kdfn(key, vec![kdf::SALT_PAYLOAD_IV, &auth_id, &connection_nonce]);
    let header_encrypted =
        Aes128Gcm::new_from_slice(&header_key)?.encrypt(&header_iv.into(), Payload { msg: &header, aad: &auth_id }).map_err(|e| anyhow!(e))?;
    let mut res = Vec::new();
    res.extend_from_slice(&auth_id); // 16
    res.extend_from_slice(&length_encrypted); // 2 + TAG_SIZE
    res.extend_from_slice(&connection_nonce); // 8
    res.extend_from_slice(&header_encrypted); // payload + TAG_SIZE
    Ok(res)
}

pub fn open_header(key: &[u8], src: &mut BytesMut) -> Result<Option<Vec<u8>>> {
    let mut cursor = Cursor::new(src);
    if cursor.remaining() < TAG_SIZE + 2 + TAG_SIZE + 8 + TAG_SIZE {
        return Ok(None);
    }
    let mut auth_id = [0; TAG_SIZE];
    let mut length_encrypted = [0; 2 + TAG_SIZE];
    let mut nonce = [0; 8];
    cursor.copy_to_slice(&mut auth_id);
    cursor.copy_to_slice(&mut length_encrypted);
    cursor.copy_to_slice(&mut nonce);
    let length_key = kdf::kdf16(key, vec![kdf::SALT_LENGTH_KEY, &auth_id, &nonce]);
    let length_iv: [u8; NONCE_SIZE] = kdf::kdfn(key, vec![kdf::SALT_LENGTH_IV, &auth_id, &nonce]);
    let length_bytes = Aes128Gcm::new_from_slice(&length_key)?
        .decrypt(&length_iv.into(), Payload { msg: &length_encrypted, aad: &auth_id })
        .map_err(|e| anyhow!(e))?;
    let length = u16::from_be_bytes(length_bytes.try_into().map_err(|_| anyhow!("parse length bytes failed"))?) as usize;
    if cursor.remaining() < length {
        return Ok(None);
    }
    let header_key = kdf::kdf16(key, vec![kdf::SALT_PAYLOAD_KEY, &auth_id, &nonce]);
    let header_iv: [u8; NONCE_SIZE] = kdf::kdfn(key, vec![kdf::SALT_PAYLOAD_IV, &auth_id, &nonce]);
    let header_encrypted = cursor.copy_to_bytes(length + TAG_SIZE);
    let header_bytes = Aes128Gcm::new_from_slice(&header_key)?
        .decrypt(&header_iv.into(), Payload { msg: &header_encrypted, aad: &auth_id })
        .map_err(|e| anyhow!(e))?;
    let pos = cursor.position();
    cursor.into_inner().advance(pos as usize);
    Ok(Some(header_bytes))
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_header() -> Result<()> {
        let header = Bytes::from_static(b"Test Header");
        let key = kdf::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
        let mut sealed = BytesMut::from(&seal_header(&key, header.clone())?[..]);
        let opened = open_header(&key, &mut sealed)?.unwrap();
        assert_eq!(header, &opened);
        assert!(!sealed.has_remaining());
        Ok(())
    }
}
