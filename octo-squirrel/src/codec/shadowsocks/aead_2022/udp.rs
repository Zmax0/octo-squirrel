use aes::Aes128;
use aes::Aes256;
use aes::Block;
use aes::cipher::BlockCipherDecrypt;
use aes::cipher::BlockCipherEncrypt;
use aes_gcm::aead::AeadCore;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::KeySizeUser;
use aes_gcm::aead::array::typenum::Unsigned;
use anyhow::bail;
use byte_string::ByteStr;
use chacha20poly1305::XChaCha8Poly1305;
use chacha20poly1305::XChaCha20Poly1305;
use log::trace;
use tokio_util::bytes::BytesMut;

use crate::codec::aead::CipherKind;
use crate::codec::aead::CipherMethod;

pub fn nonce_length(kind: CipherKind) -> usize {
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm => 0,
        CipherKind::Aead2022Blake3ChaCha8Poly1305 => <XChaCha8Poly1305 as AeadCore>::NonceSize::USIZE,
        CipherKind::Aead2022Blake3ChaCha20Poly1305 => <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE,
        _ => unreachable!("{} is not an AEAD 2022 cipher", kind),
    }
}

pub fn new_cipher(kind: CipherKind, key: &[u8], session_id: u64) -> CipherMethod {
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm => {
            let key = super::session_sub_key(key, &session_id.to_be_bytes());
            CipherMethod::new(kind, &key)
        }
        CipherKind::Aead2022Blake3ChaCha8Poly1305 => CipherMethod::XChaCha8Poly1305(
            XChaCha8Poly1305::new_from_slice(&key[..XChaCha8Poly1305::key_size()]).expect("invalid XChaCha8-Poly1305 key length"),
        ),
        CipherKind::Aead2022Blake3ChaCha20Poly1305 => CipherMethod::XChaCha20Poly1305(
            XChaCha20Poly1305::new_from_slice(&key[..XChaCha20Poly1305::key_size()]).expect("invalid XChaCha20-Poly1305 key length"),
        ),
        _ => unreachable!("{} is not an AEAD 2022 cipher", kind),
    }
}

pub fn aes_encrypt_in_place(kind: CipherKind, key: &[u8], header: &mut [u8]) -> anyhow::Result<()> {
    use aes_gcm::aead::KeyInit;
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key)?;
            let block = <&mut Block>::try_from(header)?;
            cipher.encrypt_block(block);
            Ok(())
        }
        CipherKind::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key)?;
            let block = <&mut Block>::try_from(header)?;
            cipher.encrypt_block(block);
            Ok(())
        }
        _ => bail!("{} is not an AEAD 2022 cipher", kind),
    }
}

pub fn aes_decrypt_in_place(kind: CipherKind, key: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
    use aes_gcm::aead::KeyInit;
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key)?;
            let block = <&mut Block>::try_from(buf)?;
            cipher.decrypt_block(block);
            Ok(())
        }
        CipherKind::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key)?;
            let block = <&mut Block>::try_from(buf)?;
            cipher.decrypt_block(block);
            Ok(())
        }
        _ => bail!("{} is not an AEAD 2022 cipher", kind),
    }
}

pub fn with_eih<const N: usize>(
    kind: CipherKind,
    key: &[u8],
    identity_keys: &[[u8; N]],
    session_id_packet_id: &[u8],
    dst: &mut BytesMut,
) -> anyhow::Result<()> {
    let len = identity_keys.len();
    for i in 0..len {
        let mut identity_header = [0; 16];
        if i != len - 1 {
            make_eih(kind, &identity_keys[i], &identity_keys[i + 1], session_id_packet_id, &mut identity_header)?;
        } else {
            make_eih(kind, &identity_keys[i], key, session_id_packet_id, &mut identity_header)?;
        }
        dst.extend_from_slice(&identity_header);
    }
    Ok(())
}

fn make_eih(kind: CipherKind, ipsk: &[u8], ipskn: &[u8], session_id_packet_id: &[u8], identity_header: &mut [u8; 16]) -> anyhow::Result<()> {
    let hash = blake3::hash(ipskn);
    let plain_text = &hash.as_bytes()[..16];
    identity_header.copy_from_slice(plain_text);
    identity_header.iter_mut().zip(session_id_packet_id).for_each(|(l, r)| *l ^= r);
    let res = aes_encrypt_in_place(kind, ipsk, identity_header);
    trace!("client EIH:{:?}, hash:{:?}", ByteStr::new(identity_header), ByteStr::new(plain_text));
    res
}
