use aes::cipher::BlockDecrypt;
use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes::Aes256;
use aes::Block;
use anyhow::bail;
use byte_string::ByteStr;
use bytes::BytesMut;
use log::trace;

use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::CipherMethod;
use crate::common::codec::shadowsocks::Keys;

pub fn nonce_length(kind: CipherKind) -> Result<usize, String> {
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm | CipherKind::Aead2022Blake3Aes256Gcm => Ok(0),
        _ => Err(format!("{:?} is not an AEAD 2022 cipher", kind)),
    }
}

pub fn aes_encrypt_in_place(kind: CipherKind, key: &[u8], header: &mut [u8]) -> anyhow::Result<()> {
    use aead::KeyInit;
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key)?;
            let block = Block::from_mut_slice(header);
            cipher.encrypt_block(block);
            Ok(())
        }
        CipherKind::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key)?;
            let block = Block::from_mut_slice(header);
            cipher.encrypt_block(block);
            Ok(())
        }
        _ => bail!("{:?} is not an AEAD 2022 cipher", kind),
    }
}

pub fn aes_decrypt_in_place(kind: CipherKind, key: &[u8], buf: &mut [u8]) -> anyhow::Result<()> {
    use aead::KeyInit;
    match kind {
        CipherKind::Aead2022Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(key)?;
            let block = Block::from_mut_slice(buf);
            cipher.decrypt_block(block);
            Ok(())
        }
        CipherKind::Aead2022Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(key)?;
            let block = Block::from_mut_slice(buf);
            cipher.decrypt_block(block);
            Ok(())
        }
        _ => bail!("{:?} is not an AEAD 2022 cipher", kind),
    }
}

pub fn with_eih<const N: usize>(kind: CipherKind, keys: &Keys<N>, session_id_packet_id: &[u8], dst: &mut BytesMut) -> anyhow::Result<()> {
    for i in 0..keys.identity_keys.len() {
        let mut identity_header = [0; 16];
        if i != keys.identity_keys.len() - 1 {
            make_eih(kind, &keys.identity_keys[i], &keys.identity_keys[i + 1], session_id_packet_id, &mut identity_header)?;
        } else {
            make_eih(kind, &keys.identity_keys[i], &keys.enc_key, session_id_packet_id, &mut identity_header)?;
        }
        dst.extend_from_slice(&identity_header);
    }
    Ok(())
}

fn make_eih(kind: CipherKind, ipsk: &[u8], ipskn: &[u8], session_id_packet_id: &[u8], identity_header: &mut [u8; 16]) -> anyhow::Result<()> {
    let hash = blake3::hash(ipskn);
    let plain_text = &hash.as_bytes()[..16];
    identity_header.copy_from_slice(plain_text);
    for i in 0..16 {
        identity_header[i] ^= session_id_packet_id[i];
    }
    let res = aes_encrypt_in_place(kind, ipsk, identity_header);
    trace!("client EIH:{:?}, hash:{:?}", ByteStr::new(identity_header), ByteStr::new(plain_text));
    res
}

pub fn init_cipher(kind: CipherKind, key: &[u8], session_id: u64) -> CipherMethod {
    let key = super::session_sub_key(key, &session_id.to_be_bytes());
    CipherMethod::new(kind, &key)
}
