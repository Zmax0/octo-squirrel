pub(super) mod tcp;
pub(super) mod udp;

use std::time::SystemTime;
use std::time::SystemTimeError;
use std::time::UNIX_EPOCH;

use bytes::Buf;
use bytes::BytesMut;
use rand::Rng;

use super::Authenticator;
use super::ChunkDecoder;
use super::ChunkEncoder;
use super::ChunkSizeParser;
use crate::codec::aead::CipherKind;
use crate::codec::aead::CipherMethod;

const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;
const MIN_PADDING_LENGTH: u16 = 0;
const MAX_PADDING_LENGTH: u16 = 900;

fn session_sub_key(key: &[u8], salt: &[u8]) -> [u8; blake3::OUT_LEN] {
    let key_material = [key, salt].concat();
    blake3::derive_key("shadowsocks 2022 session subkey", &key_material)
}

pub fn now() -> Result<u64, SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn validate_timestamp(timestamp: u64) -> Result<(), String> {
    let now = now().map_err(|e| e.to_string())?;
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

pub fn new_encoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkEncoder {
    let key = session_sub_key(key, salt);
    let auth = Authenticator::new(CipherMethod::new(kind, &key));
    ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth)
}

pub fn new_decoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkDecoder {
    let key = session_sub_key(key, salt);
    let auth = Authenticator::new(CipherMethod::new(kind, &key));
    ChunkDecoder::new(auth, ChunkSizeParser::Auth)
}

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;
    use bytes::BytesMut;

    use super::next_padding_length;
    use super::now;
    use super::session_sub_key;
    use super::validate_timestamp;
    use super::SERVER_STREAM_TIMESTAMP_MAX_DIFF;

    #[test]
    fn test_session_sub_key() -> Result<(), base64ct::Error> {
        let key = Base64::decode_vec("Lc3tTx0BY6ZJ/fCwOx3JvF0I/anhwJBO5p2+FA5Vce4=")?;
        let salt = Base64::decode_vec("3oFO0VyLyGI4nFN0M9P+62vPND/L6v8IingaPJWTbJA=")?;
        let session_sub_key = session_sub_key(&key, &salt);
        Ok(assert_eq!("EdNE+4U8dVnHT0+poAFDK2bdlwfrHT61sUNr9WYPh+E=", Base64::encode_string(&session_sub_key)))
    }

    #[test]
    fn test_validate_timestamp() -> anyhow::Result<()> {
        let timestamp = now()? + 2 * SERVER_STREAM_TIMESTAMP_MAX_DIFF;
        Ok(assert!(validate_timestamp(timestamp).is_err()))
    }

    #[test]
    fn test_next_padding_length() {
        assert!(next_padding_length(&BytesMut::new()) > 0)
    }
}
