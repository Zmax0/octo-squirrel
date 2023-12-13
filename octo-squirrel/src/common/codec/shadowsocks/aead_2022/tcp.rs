use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;

use super::now;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::IncreasingNonceGenerator;
use crate::common::codec::shadowsocks::Authenticator;
use crate::common::codec::shadowsocks::ChunkDecoder;
use crate::common::codec::shadowsocks::ChunkEncoder;
use crate::common::codec::shadowsocks::ChunkSizeParser;
use crate::common::codec::shadowsocks::NonceGenerator;
use crate::common::protocol::shadowsocks::StreamType;

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
    let len = msg.remaining().min(0xffff);
    let mut via = msg.split_to(len);
    fixed.put_u16(len as u16);
    auth.seal(&mut fixed);
    auth.seal(&mut via);
    (fixed.freeze(), via.freeze())
}

pub fn session_sub_key(key: &[u8], salt: &[u8]) -> [u8; 32] {
    super::session_sub_key(key, salt)
}

pub fn new_encoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkEncoder {
    let key = session_sub_key(key, salt);
    let auth = Authenticator::new(kind.to_cipher_method(&key), NonceGenerator::Increasing(IncreasingNonceGenerator::init()));
    ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth)
}

pub fn new_decoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkDecoder {
    let key = session_sub_key(key, salt);
    let auth = Authenticator::new(kind.to_cipher_method(&key), NonceGenerator::Increasing(IncreasingNonceGenerator::init()));
    ChunkDecoder::new(auth, ChunkSizeParser::Auth)
}
