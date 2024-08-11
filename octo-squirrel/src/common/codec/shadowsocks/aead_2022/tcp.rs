use anyhow::bail;
use byte_string::ByteStr;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use log::trace;

use super::now;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::IncreasingNonceGenerator;
use crate::common::codec::shadowsocks::tcp::Identity;
use crate::common::codec::shadowsocks::Authenticator;
use crate::common::codec::shadowsocks::ChunkDecoder;
use crate::common::codec::shadowsocks::ChunkEncoder;
use crate::common::codec::shadowsocks::ChunkSizeParser;
use crate::common::codec::shadowsocks::Keys;
use crate::common::codec::shadowsocks::NonceGenerator;
use crate::common::crypto::Aes128EcbNoPadding;
use crate::common::crypto::Aes256EcbNoPadding;
use crate::common::manager::shadowsocks::ServerUserManager;
use crate::common::protocol::shadowsocks::Mode;

pub(crate) fn new_header(auth: &mut Authenticator, msg: &mut BytesMut, stream_type: &Mode, request_salt: Option<&[u8]>) -> (Bytes, Bytes) {
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

pub(crate) fn session_sub_key(key: &[u8], salt: &[u8]) -> [u8; 32] {
    super::session_sub_key(key, salt)
}

pub(crate) fn new_encoder<const N: usize>(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkEncoder {
    let key = session_sub_key(key, salt);
    let auth = Authenticator::new(kind.to_cipher_method(&key[..N]), NonceGenerator::Increasing(IncreasingNonceGenerator::init()));
    ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth)
}

pub(crate) fn new_decoder<const N: usize>(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkDecoder {
    let key = session_sub_key(key, salt);
    let auth = Authenticator::new(kind.to_cipher_method(&key[..N]), NonceGenerator::Increasing(IncreasingNonceGenerator::init()));
    ChunkDecoder::new(auth, ChunkSizeParser::Auth)
}

pub(crate) fn new_decoder_with_eih<const N: usize>(
    kind: CipherKind,
    key: &[u8],
    salt: &[u8],
    mut user_hash: [u8; 16],
    identity: &mut Identity<N>,
    user_manager: &ServerUserManager<N>,
) -> anyhow::Result<ChunkDecoder> {
    let identity_sub_key = blake3::derive_key("shadowsocks 2022 identity subkey", &[key, salt].concat());
    let eih = user_hash.clone();
    Aes128EcbNoPadding::decrypt(&identity_sub_key, &mut user_hash);
    trace!("server EIH {:?}, hash: {:?}", eih, user_hash);
    if let Some(user) = user_manager.get_user_by_hash(&user_hash) {
        trace!("{} chosen by EIH", user);
        identity.user = Some(user.clone());
        Ok(new_decoder::<N>(kind, &user.key, salt))
    } else {
        bail!("invalid client user identity {:?}", user_hash)
    }
}

pub(crate) fn with_eih<const N: usize>(kind: &CipherKind, keys: &Keys<N>, salt: &[u8], dst: &mut BytesMut) {
    let mut sub_key: Option<[u8; blake3::OUT_LEN]> = None;
    for ipsk in keys.identity_keys.iter() {
        if let Some(sub_key) = sub_key {
            make_eih(kind, &sub_key, ipsk, dst)
        }
        let key_material = [ipsk, salt].concat();
        sub_key = Some(blake3::derive_key("shadowsocks 2022 identity subkey", &key_material))
    }
    if let Some(sub_key) = sub_key {
        make_eih(kind, &sub_key, &keys.enc_key, dst)
    }
}

fn make_eih(kind: &CipherKind, sub_key: &[u8], ipsk: &[u8], out: &mut BytesMut) {
    let ipsk_hash = blake3::hash(ipsk);
    let ipsk_plain_text = &ipsk_hash.as_bytes()[..16];
    let mut ipsk_encrypt_text = [0; 16];
    ipsk_encrypt_text.copy_from_slice(ipsk_plain_text);
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => Aes128EcbNoPadding::encrypt(sub_key, &mut ipsk_encrypt_text, 16),
        CipherKind::Aead2022Blake3Aes256Gcm => Aes256EcbNoPadding::encrypt(sub_key, &mut ipsk_encrypt_text, 16),
        _ => unreachable!("{:?} doesn't support EIH", kind),
    }
    trace!("client EIH:{:?}, hash:{:?}", ByteStr::new(&ipsk_encrypt_text), ByteStr::new(&ipsk_plain_text));
    out.put_slice(&ipsk_encrypt_text);
}

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;
    use bytes::BytesMut;

    use super::with_eih;
    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::shadowsocks::aead_2022::password_to_keys;

    #[test]
    fn test() {
        let ipsk = "leWhlhIIhjHhGeaGVpqpRA==";
        let upsk = "BomScdlR6tXdKxm4FyZg9g==";
        let keys = password_to_keys::<16>(&format!("{}:{}", ipsk, upsk)).unwrap();
        let salt = Base64::decode_vec("/xyg1YnI2gNuMydqgt8MgbfT0zDMougbi64SbDsVn1Q=").unwrap();
        let dst = &mut BytesMut::new();
        with_eih(&CipherKind::Aead2022Blake3Aes256Gcm, &keys, &salt, dst);
        assert_eq!(upsk, Base64::encode_string(&keys.enc_key));
        assert_eq!(ipsk, Base64::encode_string(&keys.identity_keys[0]));
        assert_eq!("jGIxVuv1qqwcBYak0kGGaA==", Base64::encode_string(dst));
    }
}
