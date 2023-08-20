use std::io::Cursor;

use aes::cipher::Unsigned;
use aes_gcm::{aead::KeyInit, AeadCore, Aes128Gcm};
use bytes::{Buf, BytesMut};
use rand::random;

use super::{AuthID, Encrypt, KDF};
use crate::common::{codec::aead::{AEADCipher, Aes128GcmCipher}, protocol::vmess::timestamp};

const KDF_SALT_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_LENGTH_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const TAG_SIZE: usize = <Aes128Gcm as AeadCore>::TagSize::USIZE;
const NONCE_SIZE: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;

impl Encrypt {
    pub fn seal_header(key: &[u8], header: &[u8]) -> Option<BytesMut> {
        let auth_id = AuthID::create(key, timestamp(30));
        let connection_nonce: [u8; 8] = random();
        let length = (header.len() as u16).to_be_bytes();
        let length_key = KDF::kdf16(key, vec![KDF_SALT_LENGTH_KEY, &auth_id, &connection_nonce]);
        let length_iv: [u8; NONCE_SIZE] = KDF::kdfn(key, vec![KDF_SALT_LENGTH_IV, &auth_id, &connection_nonce]);
        let length_encrypted = Aes128GcmCipher(Aes128Gcm::new_from_slice(&length_key).unwrap()).encrypt(&length_iv, &length, &auth_id);
        let header_key = KDF::kdf16(key, vec![KDF_SALT_PAYLOAD_KEY, &auth_id, &connection_nonce]);
        let header_iv: [u8; NONCE_SIZE] = KDF::kdfn(key, vec![KDF_SALT_PAYLOAD_IV, &auth_id, &connection_nonce]);
        let header_encrypted = Aes128GcmCipher(Aes128Gcm::new_from_slice(&header_key).unwrap()).encrypt(&header_iv, &header, &auth_id);
        let mut res = BytesMut::new();
        res.extend_from_slice(&auth_id); // 16
        res.extend_from_slice(&length_encrypted); // 2 + TAG_SIZE
        res.extend_from_slice(&connection_nonce); // 8
        res.extend_from_slice(&header_encrypted); // payload + TAG_SIZE
        Some(res)
    }

    pub fn open_header(key: &[u8], src: &mut BytesMut) -> Option<Vec<u8>> {
        let mut cursor = Cursor::new(src);
        if cursor.remaining() < TAG_SIZE + 2 + TAG_SIZE + 8 + TAG_SIZE {
            return None;
        }
        let position = cursor.position();
        let mut auth_id = [0; TAG_SIZE];
        let mut length_encrypted = [0; 2 + TAG_SIZE];
        let mut nonce = [0; 8];
        cursor.copy_to_slice(&mut auth_id);
        cursor.copy_to_slice(&mut length_encrypted);
        cursor.copy_to_slice(&mut nonce);
        let length_key = KDF::kdf16(key, vec![KDF_SALT_LENGTH_KEY, &auth_id, &nonce]);
        let length_iv: [u8; NONCE_SIZE] = KDF::kdfn(key, vec![KDF_SALT_LENGTH_IV, &auth_id, &nonce]);
        let length_bytes = Aes128GcmCipher(Aes128Gcm::new_from_slice(&length_key).unwrap()).decrypt(&length_iv, &length_encrypted, &auth_id);
        let mut length = [0; 2];
        length.copy_from_slice(&length_bytes);
        let length = u16::from_be_bytes(length) as usize;
        if cursor.remaining() < length {
            cursor.set_position(position);
            return None;
        }
        let header_key = KDF::kdf16(key, vec![KDF_SALT_PAYLOAD_KEY, &auth_id, &nonce]);
        let header_iv: [u8; NONCE_SIZE] = KDF::kdfn(key, vec![KDF_SALT_PAYLOAD_IV, &auth_id, &nonce]);
        let header_encrypted = cursor.copy_to_bytes(length + 16);
        let header_bytes = Aes128GcmCipher(Aes128Gcm::new_from_slice(&header_key).unwrap()).decrypt(&header_iv, &header_encrypted, &auth_id);
        Some(header_bytes)
    }
}

#[test]
fn test_header() {
    let header = b"Test Header";
    let key = KDF::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
    let mut sealed = Encrypt::seal_header(&key, header).unwrap();
    let opened = Encrypt::open_header(&key, &mut sealed);
    assert_eq!(header, &opened.unwrap()[..]);
}
