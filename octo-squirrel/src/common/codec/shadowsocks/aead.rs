use hkdf::Hkdf;
use md5::Digest;
use md5::Md5;
use sha1::Sha1;

use super::Authenticator;
use super::ChunkDecoder;
use super::ChunkEncoder;
use super::ChunkSizeParser;
use super::NonceGenerator;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::IncreasingNonceGenerator;

pub(super) fn generate_key<const N: usize>(password: &[u8]) -> [u8; N] {
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
        container[len..].copy_from_slice(&password);
        hasher.update(&container);
        password_digest = hasher.finalize_reset();
        encoded[index..].copy_from_slice(&password_digest[..password_digest.len().min(size - index)]);
        index += password_digest.len();
    }
    encoded
}

pub(super) fn new_encoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkEncoder {
    let key = hkdfsha1(key, salt);
    let auth: Authenticator = new_auth(kind, &key);
    ChunkEncoder::new(0xffff, auth, ChunkSizeParser::Auth)
}

pub(super) fn new_decoder(kind: CipherKind, key: &[u8], salt: &[u8]) -> ChunkDecoder {
    let key = hkdfsha1(key, salt);
    let auth = new_auth(kind, &key);
    ChunkDecoder::new(auth, ChunkSizeParser::Auth)
}

fn hkdfsha1(ikm: &[u8], salt: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), ikm);
    let okm = &mut vec![0; salt.len()];
    hk.expand(b"ss-subkey", okm).unwrap();
    okm.to_vec()
}

fn new_auth(kind: CipherKind, key: &[u8]) -> Authenticator {
    let method = kind.to_aead_cipher(key);
    Authenticator::new(method, NonceGenerator::Increasing(IncreasingNonceGenerator::init()))
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use base64ct::Encoding;
    use bytes::BytesMut;
    use rand::distributions::Alphanumeric;
    use rand::random;
    use rand::Rng;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::shadowsocks::aead::generate_key;
    use crate::common::codec::shadowsocks::AEADCipherCodec;
    use crate::common::codec::shadowsocks::DatagramPacketCodec;
    use crate::common::protocol::shadowsocks::Context;
    use crate::common::protocol::shadowsocks::StreamType;

    #[test]
    fn test_generate_key() {
        let password = b"Personal search-enabled assistant for programmers";
        let key: [u8; 16] = generate_key(password);
        assert_eq!("zsWfM5hwvmTusK6sGOop5w==", base64ct::Base64::encode_string(&key));
        let key: [u8; 32] = generate_key(password);
        assert_eq!("zsWfM5hwvmTusK6sGOop57hBNhUblVO/PpBKSm34Vu4=", base64ct::Base64::encode_string(&key));
    }

    #[test]
    fn test_tcp() {
        fn test_tcp(cipher: CipherKind) {
            let context = Context::tcp(StreamType::Response);
            let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
            rand::thread_rng().fill(&mut password[..]);
            let mut codec = AEADCipherCodec::new(cipher, &password[..]).unwrap();
            let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff * 10).map(char::from).collect();
            let src = BytesMut::from(expect.as_str());
            let mut dst = BytesMut::new();
            codec.encode(&context, src, &mut dst).unwrap();
            let actual = codec.decode(&context, &mut dst).unwrap().unwrap();
            let actual = String::from_utf8(actual.freeze().to_vec()).unwrap();
            assert_eq!(expect, actual);
        }

        CipherKind::VALUES.into_iter().for_each(test_tcp);
    }

    #[test]
    fn test_udp() {
        fn test_udp(cipher: CipherKind) {
            let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
            rand::thread_rng().fill(&mut password[..]);
            let codec = AEADCipherCodec::new(cipher, &password[..]).unwrap();
            let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff).map(char::from).collect();
            let mut codec = DatagramPacketCodec::new(codec);
            let mut dst = BytesMut::new();
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, random()));
            codec.encode((expect.as_bytes().into(), addr), &mut dst).unwrap();
            let actual = codec.decode(&mut dst).unwrap().unwrap();
            assert_eq!(String::from_utf8(actual.0.freeze().to_vec()).unwrap(), expect);
            assert_eq!(actual.1, addr);
        }

        CipherKind::VALUES.into_iter().for_each(test_udp);
    }
}
