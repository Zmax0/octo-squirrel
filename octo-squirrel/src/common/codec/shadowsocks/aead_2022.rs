pub(super) mod tcp;
pub(super) mod udp;

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use anyhow::Result;
use base64ct::Base64;
use base64ct::Encoding;
use bytes::Buf;
use bytes::BytesMut;
use rand::Rng;

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
