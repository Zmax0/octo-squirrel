use std::time::SystemTimeError;

use bytes::BufMut;
use bytes::BytesMut;
use rand::random;

use super::kdf;
use crate::common::crypto::Aes128EcbNoPadding;
use crate::common::protocol::vmess;

pub fn create(key: &[u8], time: i64) -> [u8; 16] {
    let mut auth_id = [0; 16];
    let mut buf = BytesMut::new();
    buf.put_i64(time);
    buf.put_u32(random());
    let crc32 = vmess::crc32(&buf);
    buf.put_i32(crc32 as i32);
    auth_id.copy_from_slice(&buf);
    Aes128EcbNoPadding::encrypt(&kdf::kdf16(key, vec![b"AES Auth ID Encryption"]), &mut auth_id, 16);
    auth_id
}

pub fn matching(authid: &[u8], keys: &Vec<[u8; 16]>) -> Result<Option<[u8; 16]>, SystemTimeError> {
    for key in keys {
        let mut cur = [0; 16];
        cur.copy_from_slice(authid);
        Aes128EcbNoPadding::decrypt(&kdf::kdf16(key, vec![b"AES Auth ID Encryption"]), &mut cur);
        let crc32 = vmess::crc32(&cur[..12]);
        let (l, r) = cur.split_at(12);
        let now = i64::from_be_bytes(l[..8].try_into().unwrap());
        if i32::from_be_bytes(r.try_into().unwrap()) == crc32 as i32 && (now - vmess::now()?).abs() <= 120 {
            return Ok(Some(*key));
        }
    }
    Ok(None)
}

#[test]
fn test_cipher() {
    let key = kdf::kdf16(b"Demo Key for Auth ID Test", vec![b"Demo Path for Auth ID Test"]);
    let text = b"Hello world!";
    let buf = &mut [0; 16];
    buf[0..text.len()].copy_from_slice(text);
    let expected = buf.clone();
    Aes128EcbNoPadding::encrypt(&key, buf, 16);
    Aes128EcbNoPadding::decrypt(&key, buf);
    assert_eq!(expected, *buf);
}
