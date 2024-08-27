pub(super) mod tcp;
pub(super) mod udp;

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64ct::Base64;
use base64ct::Encoding;
use bytes::Buf;
use bytes::BytesMut;
use rand::Rng;

use super::Keys;

const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;
const MIN_PADDING_LENGTH: u16 = 0;
const MAX_PADDING_LENGTH: u16 = 900;

pub fn generate_key<const N: usize>(password: &[u8]) -> Result<[u8; N], base64ct::Error> {
    let mut key = [0; N];
    Base64::decode(password, &mut key)?;
    Ok(key)
}

fn session_sub_key(key: &[u8], salt: &[u8]) -> [u8; blake3::OUT_LEN] {
    let key_material = [key, salt].concat();
    blake3::derive_key("shadowsocks 2022 session subkey", &key_material)
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn validate_timestamp(timestamp: u64) -> Result<(), String> {
    let now = now();
    let diff = now.abs_diff(timestamp);
    if diff > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
        Err(format!("invalid abs_diff(timestamp: {}, now: {}) = {}", timestamp, now, diff))
    } else {
        Ok(())
    }
}

pub fn next_padding_length(msg: &BytesMut) -> u16 {
    if msg.has_remaining() {
        0
    } else {
        rand::thread_rng().gen_range(MIN_PADDING_LENGTH..=MAX_PADDING_LENGTH)
    }
}

pub fn password_to_keys<const N: usize>(password: &str) -> Result<Keys<N>, base64ct::Error> {
    let split = password.split(':');
    let mut identity_keys = Vec::new();
    for s in split {
        let mut bytes = [0; N];
        Base64::decode(s, &mut bytes)?;
        identity_keys.push(bytes);
    }
    let enc_key = identity_keys.remove(identity_keys.len() - 1);
    Ok(Keys::new(enc_key, identity_keys))
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
