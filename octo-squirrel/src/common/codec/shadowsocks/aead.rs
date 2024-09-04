use hkdf::Hkdf;
use md5::Digest;
use md5::Md5;
use sha1::Sha1;

use super::Authenticator;
use super::ChunkDecoder;
use super::ChunkEncoder;
use super::ChunkSizeParser;
use super::NonceGenerator;
use crate::common::codec::aead::CipherMethod;
use crate::common::codec::aead::IncreasingNonceGenerator;
use crate::common::codec::aead::KeyInit;

pub fn openssl_bytes_to_key<const N: usize>(password: &[u8]) -> [u8; N] {
    let mut encoded: [u8; N] = [0; N];
    let size = encoded.len();
    let mut hasher = Md5::new();
    hasher.update(password);
    let mut password_digest = hasher.finalize_reset();
    let mut container: Vec<u8> = vec![0; password.len() + password_digest.len()];
    let len = size.min(password_digest.len());
    encoded[..len].copy_from_slice(&password_digest);
    let mut index = password_digest.len();
    while index < size {
        let len = password_digest.len();
        container[..len].copy_from_slice(&password_digest);
        container[len..].copy_from_slice(password);
        hasher.update(&container);
        password_digest = hasher.finalize_reset();
        encoded[index..].copy_from_slice(&password_digest[..password_digest.len().min(size - index)]);
        index += password_digest.len();
    }
    encoded
}

pub fn new_encoder<CM: CipherMethod + KeyInit>(key: &[u8], salt: &[u8]) -> Result<ChunkEncoder<CM>, String> {
    let key = hkdfsha1(key, salt)?;
    let auth = new_auth(&key).map_err(|e| e.to_string())?;
    Ok(ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth))
}

pub fn new_decoder<CM: CipherMethod + KeyInit>(key: &[u8], salt: &[u8]) -> Result<ChunkDecoder<CM>, String> {
    let key = hkdfsha1(key, salt)?;
    let auth = new_auth(&key).map_err(|e| e.to_string())?;
    Ok(ChunkDecoder::new(auth, ChunkSizeParser::Auth))
}

fn hkdfsha1(ikm: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha1>::new(Some(salt), ikm);
    let okm = &mut vec![0; salt.len()];
    hk.expand(b"ss-subkey", okm).map_err(|e| e.to_string())?;
    Ok(okm.to_vec())
}

fn new_auth<CM: CipherMethod + KeyInit>(key: &[u8]) -> Result<Authenticator<CM>, digest::InvalidLength> {
    let method = CM::init(key)?;
    Ok(Authenticator::new(method, NonceGenerator::Increasing(IncreasingNonceGenerator::init())))
}

#[cfg(test)]
mod test {
    use base64ct::Encoding;

    use crate::common::codec::shadowsocks::aead::openssl_bytes_to_key;

    #[test]
    fn test_generate_key() {
        let password = b"Personal search-enabled assistant for programmers";
        let key: [u8; 16] = openssl_bytes_to_key(password);
        assert_eq!("zsWfM5hwvmTusK6sGOop5w==", base64ct::Base64::encode_string(&key));
        let key: [u8; 32] = openssl_bytes_to_key(password);
        assert_eq!("zsWfM5hwvmTusK6sGOop57hBNhUblVO/PpBKSm34Vu4=", base64ct::Base64::encode_string(&key));
    }
}
