use anyhow::anyhow;
use anyhow::bail;
use byte_string::ByteStr;
use log::trace;
use tokio_util::bytes::Buf;
use tokio_util::bytes::BufMut;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::BytesMut;

use super::now;
use crate::codec::aead::CipherKind;
use crate::codec::shadowsocks::tcp::Identity;
use crate::codec::shadowsocks::Authenticator;
use crate::codec::shadowsocks::ChunkDecoder;
use crate::crypto::Aes128EcbNoPadding;
use crate::crypto::Aes256EcbNoPadding;
use crate::manager::shadowsocks::ServerUserManager;
use crate::protocol::shadowsocks::Mode;

pub fn new_header(auth: &mut Authenticator, msg: &mut BytesMut, stream_type: &Mode, request_salt: Option<&[u8]>) -> anyhow::Result<(Bytes, Bytes)> {
    let mut salt_len = 0;
    if let Some(request_salt) = request_salt {
        salt_len = request_salt.len();
    }
    let mut fixed = BytesMut::with_capacity(1 + 8 + salt_len + 2);
    fixed.put_u8(stream_type.to_u8());
    fixed.put_u64(now()?);
    if let Some(request_salt) = request_salt {
        fixed.extend_from_slice(request_salt);
    }
    let len = msg.remaining().min(0xffff);
    let mut via = msg.split_to(len);
    fixed.put_u16(len as u16);
    auth.seal(&mut fixed).map_err(|e| anyhow!(e))?;
    auth.seal(&mut via).map_err(|e| anyhow!(e))?;
    Ok((fixed.freeze(), via.freeze()))
}

pub fn new_decoder_with_eih<const N: usize>(
    kind: CipherKind,
    key: &[u8],
    salt: &[u8],
    eih: &[u8],
    identity: &mut Identity<N>,
    user_manager: &ServerUserManager<N>,
) -> Result<ChunkDecoder, anyhow::Error> {
    let identity_sub_key = blake3::derive_key("shadowsocks 2022 identity subkey", &[key, salt].concat());
    let user_hash = &mut [0; 16];
    user_hash.copy_from_slice(&eih[..16]);
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => Aes128EcbNoPadding::decrypt(&identity_sub_key, user_hash),
        CipherKind::Aead2022Blake3Aes256Gcm => Aes256EcbNoPadding::decrypt(&identity_sub_key, user_hash),
        _ => bail!("{} doesn't support EIH", kind),
    }
    trace!("server EIH {:?}, hash: {:?}", ByteStr::new(eih), ByteStr::new(user_hash));
    if let Some(user) = user_manager.get_user_by_hash(user_hash) {
        trace!("{} chosen by EIH", user);
        identity.user = Some(user.clone());
        Ok(super::new_decoder(kind, &user.key, salt))
    } else {
        bail!("invalid client user identity {:?}", ByteStr::new(user_hash))
    }
}

pub fn with_eih<const N: usize>(kind: &CipherKind, key: &[u8], identity_keys: &[[u8; N]], salt: &[u8], dst: &mut BytesMut) {
    let mut sub_key: Option<[u8; blake3::OUT_LEN]> = None;
    for ipsk in identity_keys.iter() {
        if let Some(sub_key) = sub_key {
            make_eih(kind, &sub_key, ipsk, dst)
        }
        let key_material = [ipsk, salt].concat();
        sub_key = Some(blake3::derive_key("shadowsocks 2022 identity subkey", &key_material))
    }
    if let Some(sub_key) = sub_key {
        make_eih(kind, &sub_key, key, dst)
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
        _ => unreachable!("{} doesn't support EIH", kind),
    }
    trace!("client EIH:{:?}, hash:{:?}", ByteStr::new(&ipsk_encrypt_text), ByteStr::new(ipsk_plain_text));
    out.extend_from_slice(&ipsk_encrypt_text);
}

#[cfg(test)]
mod test {
    use base64ct::Base64;
    use base64ct::Encoding;
    use tokio_util::bytes::BytesMut;

    use super::with_eih;
    use crate::codec::aead::CipherKind;
    use crate::protocol::shadowsocks::aead_2022::password_to_keys;

    #[test]
    fn test() {
        let ipsk = "leWhlhIIhjHhGeaGVpqpRA==";
        let upsk = "BomScdlR6tXdKxm4FyZg9g==";
        let (key, identity_keys) = password_to_keys::<16>(&format!("{}:{}", ipsk, upsk)).unwrap();
        let salt = Base64::decode_vec("/xyg1YnI2gNuMydqgt8MgbfT0zDMougbi64SbDsVn1Q=").unwrap();
        let dst = &mut BytesMut::new();
        with_eih(&CipherKind::Aead2022Blake3Aes256Gcm, &key, &identity_keys, &salt, dst);
        assert_eq!(upsk, Base64::encode_string(&key));
        assert_eq!(ipsk, Base64::encode_string(&identity_keys[0]));
        assert_eq!("jGIxVuv1qqwcBYak0kGGaA==", Base64::encode_string(dst));
    }
}
