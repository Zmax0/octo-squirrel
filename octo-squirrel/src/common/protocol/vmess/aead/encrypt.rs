use std::io::Cursor;

use anyhow::anyhow;
use anyhow::Result;
use bytes::Buf;
use bytes::Bytes;
use bytes::BytesMut;
use rand::random;

use super::AuthID;
use super::Encrypt;
use super::KDF;
use crate::common::codec::aead::Aes128GcmCipher;
use crate::common::codec::aead::CipherMethod;
use crate::common::protocol::vmess::timestamp;

impl Encrypt {
    pub fn seal_header(key: &[u8], header: Bytes) -> Result<Vec<u8>> {
        let auth_id = AuthID::create(key, timestamp(30));
        let connection_nonce: [u8; 8] = random();
        let length = (header.len() as u16).to_be_bytes();
        let length_key = KDF::kdf16(key, vec![KDF::SALT_LENGTH_KEY, &auth_id, &connection_nonce]);
        let length_iv: [u8; Aes128GcmCipher::NONCE_SIZE] = KDF::kdfn(key, vec![KDF::SALT_LENGTH_IV, &auth_id, &connection_nonce]);
        let length_encrypted = Aes128GcmCipher::new_from_slice(&length_key)?.encrypt(&length_iv, &length, &auth_id).map_err(|e| anyhow!(e))?;
        let header_key = KDF::kdf16(key, vec![KDF::SALT_PAYLOAD_KEY, &auth_id, &connection_nonce]);
        let header_iv: [u8; Aes128GcmCipher::NONCE_SIZE] = KDF::kdfn(key, vec![KDF::SALT_PAYLOAD_IV, &auth_id, &connection_nonce]);
        let header_encrypted = Aes128GcmCipher::new_from_slice(&header_key)?.encrypt(&header_iv, &header, &auth_id).map_err(|e| anyhow!(e))?;
        let mut res = Vec::new();
        res.extend_from_slice(&auth_id); // 16
        res.extend_from_slice(&length_encrypted); // 2 + TAG_SIZE
        res.extend_from_slice(&connection_nonce); // 8
        res.extend_from_slice(&header_encrypted); // payload + TAG_SIZE
        Ok(res)
    }

    pub fn open_header(key: &[u8], src: &mut BytesMut) -> Result<Option<Vec<u8>>> {
        let mut cursor = Cursor::new(src);
        if cursor.remaining() < Aes128GcmCipher::TAG_SIZE + 2 + Aes128GcmCipher::TAG_SIZE + 8 + Aes128GcmCipher::TAG_SIZE {
            return Ok(None);
        }
        let position = cursor.position();
        let mut auth_id = [0; Aes128GcmCipher::TAG_SIZE];
        let mut length_encrypted = [0; 2 + Aes128GcmCipher::TAG_SIZE];
        let mut nonce = [0; 8];
        cursor.copy_to_slice(&mut auth_id);
        cursor.copy_to_slice(&mut length_encrypted);
        cursor.copy_to_slice(&mut nonce);
        let length_key = KDF::kdf16(key, vec![KDF::SALT_LENGTH_KEY, &auth_id, &nonce]);
        let length_iv: [u8; Aes128GcmCipher::NONCE_SIZE] = KDF::kdfn(key, vec![KDF::SALT_LENGTH_IV, &auth_id, &nonce]);
        let length_bytes = Aes128GcmCipher::new_from_slice(&length_key)?.decrypt(&length_iv, &length_encrypted, &auth_id).map_err(|e| anyhow!(e))?;
        let mut length = [0; 2];
        length.copy_from_slice(&length_bytes);
        let length = u16::from_be_bytes(length) as usize;
        if cursor.remaining() < length {
            cursor.set_position(position);
            return Ok(None);
        }
        let header_key = KDF::kdf16(key, vec![KDF::SALT_PAYLOAD_KEY, &auth_id, &nonce]);
        let header_iv: [u8; Aes128GcmCipher::NONCE_SIZE] = KDF::kdfn(key, vec![KDF::SALT_PAYLOAD_IV, &auth_id, &nonce]);
        let header_encrypted = cursor.copy_to_bytes(length + Aes128GcmCipher::TAG_SIZE);
        let header_bytes = Aes128GcmCipher::new_from_slice(&header_key)?.decrypt(&header_iv, &header_encrypted, &auth_id).map_err(|e| anyhow!(e))?;
        Ok(Some(header_bytes))
    }
}

#[cfg(test)]
#[test]
fn test_header() -> Result<()> {
    let header = Bytes::from_static(b"Test Header");
    let key = KDF::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
    let mut sealed = BytesMut::from(&Encrypt::seal_header(&key, header.clone())?[..]);
    let opened = Encrypt::open_header(&key, &mut sealed);
    assert_eq!(header, &opened?.unwrap()[..]);
    Ok(())
}
