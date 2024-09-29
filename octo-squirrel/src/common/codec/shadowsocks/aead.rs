use hkdf::Hkdf;
use hkdf::InvalidLength;
use sha1::Sha1;

use super::Authenticator;
use super::ChunkDecoder;
use super::ChunkEncoder;
use super::ChunkSizeParser;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::CipherMethod;

pub fn new_encoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> Result<ChunkEncoder, InvalidLength> {
    let key = hkdfsha1(key, salt)?;
    let auth = new_auth(kind, &key);
    Ok(ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth))
}

pub fn new_decoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> Result<ChunkDecoder, InvalidLength> {
    let key = hkdfsha1(key, salt)?;
    let auth = new_auth(kind, &key);
    Ok(ChunkDecoder::new(auth, ChunkSizeParser::Auth))
}

fn hkdfsha1(ikm: &[u8], salt: &[u8]) -> Result<Vec<u8>, InvalidLength> {
    let hk = Hkdf::<Sha1>::new(Some(salt), ikm);
    let mut okm = vec![0; salt.len()];
    hk.expand(b"ss-subkey", &mut okm)?;
    Ok(okm)
}

fn new_auth(kind: CipherKind, key: &[u8]) -> Authenticator {
    let method = CipherMethod::new(kind, key);
    Authenticator::new(method)
}
