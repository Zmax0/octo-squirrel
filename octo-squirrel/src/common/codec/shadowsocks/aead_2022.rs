use std::io::Cursor;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use anyhow::Result;
use base64ct::Base64;
use base64ct::Encoding;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use rand::Rng;

use super::ChunkDecoder;
use super::ChunkEncoder;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::IncreasingNonceGenerator;
use crate::common::codec::shadowsocks::Authenticator;
use crate::common::codec::shadowsocks::ChunkSizeParser;
use crate::common::codec::shadowsocks::NonceGenerator;
use crate::common::protocol::shadowsocks::StreamType;

const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;
const MIN_PADDING_LENGTH: u16 = 0;
const MAX_PADDING_LENGTH: u16 = 900;

pub(super) fn generate_key(password: &[u8], expect_len: usize) -> Result<Vec<u8>> {
    let res = Base64::decode_vec(std::str::from_utf8(password)?).map_err(|e| e.to_string());
    match res {
        Ok(key) => {
            if key.len() != expect_len {
                bail!("Expecting a {} bytes key, but password: {:?} ({} bytes after decode))", expect_len, password, key.len())
            }
            Ok(key)
        }
        Err(msg) => bail!("Decode password failed: {}", msg),
    }
}

fn session_sub_key(key: &[u8], salt: &[u8]) -> [u8; 32] {
    let key_material = [key, salt].concat();
    blake3::derive_key("shadowsocks 2022 session subkey", &key_material)
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn validate_timestamp(timestamp: u64) -> Result<()> {
    let now = now();
    let diff = now.abs_diff(timestamp);
    if diff > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
        bail!("invalid abs_diff(timestamp: {}, now: {}) = {}", timestamp, now, diff);
    }
    Ok(())
}

pub fn next_padding_length(msg: &BytesMut) -> u16 {
    if msg.has_remaining() {
        0
    } else {
        rand::thread_rng().gen_range(MIN_PADDING_LENGTH..=MAX_PADDING_LENGTH)
    }
}

pub struct Header {
    pub fixed: Bytes,
    pub variable: Bytes,
}

pub struct Tcp;

impl Tcp {
    pub fn new_header(auth: &mut Authenticator, msg: &mut BytesMut, stream_type: &StreamType, request_salt: Option<&[u8]>) -> (Bytes, Bytes) {
        let mut salt_len = 0;
        if let Some(request_salt) = request_salt {
            salt_len = request_salt.len();
        }
        let mut fixed = BytesMut::with_capacity(1 + 8 + salt_len + 2);
        fixed.put_u8(stream_type.to_u8());
        fixed.put_u64(now());
        if let Some(request_salt) = request_salt {
            fixed.put_slice(request_salt);
        }
        let len = msg.remaining().min(0xffff - salt_len - 1 - 8);
        let mut via = msg.split_to(len);
        fixed.put_u16((1 + 8 + salt_len + len) as u16);
        auth.seal(&mut fixed);
        auth.seal(&mut via);
        (fixed.freeze(), via.freeze())
    }

    pub fn session_sub_key(key: &[u8], salt: &[u8]) -> [u8; 32] {
        session_sub_key(key, salt)
    }

    pub fn new_encoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkEncoder {
        let key = session_sub_key(key, salt);
        let auth = Authenticator::new(kind.to_aead_cipher(&key), NonceGenerator::Increasing(IncreasingNonceGenerator::init()));
        ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth)
    }

    pub fn new_decoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkDecoder {
        let key = session_sub_key(key, salt);
        let auth = Authenticator::new(kind.to_aead_cipher(&key), NonceGenerator::Increasing(IncreasingNonceGenerator::init()));
        ChunkDecoder::new(auth, ChunkSizeParser::Auth)
    }
}

pub struct Udp;

impl Udp {
    pub fn session_sub_key(key: &[u8], session_id: u64) -> [u8; 32] {
        session_sub_key(key, &session_id.to_be_bytes())
    }
}

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;
    use bytes::BytesMut;

    use super::now;
    use super::session_sub_key;
    use super::SERVER_STREAM_TIMESTAMP_MAX_DIFF;
    use crate::common::codec::shadowsocks::aead_2022::next_padding_length;
    use crate::common::codec::shadowsocks::aead_2022::validate_timestamp;

    #[test]
    fn test_session_sub_key() {
        let key = Base64::decode_vec("Lc3tTx0BY6ZJ/fCwOx3JvF0I/anhwJBO5p2+FA5Vce4=").unwrap();
        let salt = Base64::decode_vec("3oFO0VyLyGI4nFN0M9P+62vPND/L6v8IingaPJWTbJA=").unwrap();
        let session_sub_key = session_sub_key(&key, &salt);
        assert_eq!("EdNE+4U8dVnHT0+poAFDK2bdlwfrHT61sUNr9WYPh+E=", Base64::encode_string(&session_sub_key))
    }

    #[test]
    fn test_validate_timestamp() {
        let timestamp = now() + 2 * SERVER_STREAM_TIMESTAMP_MAX_DIFF;
        assert!(validate_timestamp(timestamp).is_err())
    }

    #[test]
    fn test_next_padding_length() {
        assert!(next_padding_length(&BytesMut::new()) > 0)
    }
}
