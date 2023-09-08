use std::net::SocketAddr;
use std::{io, sync::{Arc, Mutex}};

use bytes::{Buf, BufMut, BytesMut};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio_util::codec::{Decoder, Encoder};

use super::{aead::{Authenticator, PayloadDecoder, PayloadEncoder, SupportedCipher}, chunk::AEADChunkSizeParser, EmptyBytesGenerator, EmptyPaddingLengthGenerator, IncreasingNonceGenerator};
use crate::common::{protocol::{network::Network, socks5::{address::Address, message::Socks5CommandRequest, Socks5AddressType}}, util::Dice};

pub struct AddressCodec;

impl AddressCodec {
    pub fn decode(src: &mut BytesMut) -> Result<Option<Socks5CommandRequest>, io::Error> {
        let dst_addr_type = Socks5AddressType(src.get_u8());
        let dst_addr = Address::decode_address(dst_addr_type, src)?;
        let dst_port = src.get_u16();
        Ok(Some(Socks5CommandRequest::connect(dst_addr_type, dst_addr, dst_port)))
    }
}

impl Encoder<Socks5CommandRequest> for AddressCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Socks5CommandRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let temp = dst.split_off(0);
        dst.put_u8(item.dst_addr_type.0);
        Address::encode_address(item.dst_addr_type, &item.dst_addr, dst)?;
        dst.put_u16(item.dst_port);
        dst.unsplit(temp);
        Ok(())
    }
}

impl Decoder for AddressCodec {
    type Item = Socks5CommandRequest;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Self::decode(src)
    }
}

pub struct AEADCipherCodec {
    cipher: SupportedCipher,
    key: Vec<u8>,
    network: Network,
    payload_encoder: Option<PayloadEncoder>,
    payload_decoder: Option<PayloadDecoder>,
}

impl AEADCipherCodec {
    pub fn new(cipher: SupportedCipher, password: &[u8], network: Network) -> Self {
        match cipher {
            SupportedCipher::Aes128Gcm => {
                let key: [u8; 16] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), network, payload_encoder: None, payload_decoder: None }
            }
            SupportedCipher::Aes256Gcm => {
                let key: [u8; 32] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), network, payload_encoder: None, payload_decoder: None }
            }
            SupportedCipher::ChaCha20Poly1305 => {
                let key: [u8; 32] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), network, payload_encoder: None, payload_decoder: None }
            }
        }
    }

    fn generate_key<const N: usize>(password: &[u8]) -> [u8; N] {
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

    fn hkdfsha1(ikm: &[u8], salt: &[u8]) -> Vec<u8> {
        let hk = Hkdf::<Sha1>::new(Some(salt), ikm);
        let okm = &mut vec![0; salt.len()];
        hk.expand(b"ss-subkey", okm).unwrap();
        okm.to_vec()
    }

    fn new_payload_encoder(&mut self, salt: &[u8]) -> PayloadEncoder {
        let key = AEADCipherCodec::hkdfsha1(&self.key, salt);
        let auth = self.new_auth(&key);
        PayloadEncoder::new(0xffff, auth.clone(), Box::new(AEADChunkSizeParser::new(auth)), Box::new(EmptyPaddingLengthGenerator))
    }

    fn new_payload_decoder(&mut self, salt: &[u8]) -> PayloadDecoder {
        let key = AEADCipherCodec::hkdfsha1(&self.key, salt);
        let auth = self.new_auth(&key);
        PayloadDecoder::new(auth.clone(), Box::new(AEADChunkSizeParser::new(auth)), Box::new(EmptyPaddingLengthGenerator))
    }

    fn new_auth(&mut self, key: &Vec<u8>) -> Arc<Mutex<Authenticator>> {
        Arc::new(Mutex::new(Authenticator::new(
            self.cipher.to_aead_cipher(&key),
            Box::new(IncreasingNonceGenerator::generate_initial_aead_nonce()),
            Box::new(EmptyBytesGenerator {}),
        )))
    }
}

impl Encoder<BytesMut> for AEADCipherCodec {
    type Error = io::Error;

    fn encode(&mut self, mut item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self.network {
            Network::TCP => {
                if self.payload_encoder.is_none() {
                    let salt = Dice::roll_bytes(self.key.len());
                    self.payload_encoder = Some(self.new_payload_encoder(&salt));
                    dst.put(&salt[..]);
                }
                self.payload_encoder.as_mut().unwrap().encode_payload(&mut item, dst);
                Ok(())
            }
            Network::UDP => {
                let salt = Dice::roll_bytes(self.key.len());
                let encoder = self.new_payload_encoder(&salt);
                let mut auth = encoder.auth.lock().unwrap();
                dst.put(&salt[..]);
                dst.put(&auth.seal(&item)[..]);
                Ok(())
            }
        }
    }
}

impl Decoder for AEADCipherCodec {
    type Item = BytesMut;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.network {
            Network::TCP => {
                if self.payload_decoder.is_none() {
                    if src.remaining() < self.key.len() {
                        return Ok(None);
                    }
                    let salt = src.split_to(self.key.len());
                    self.payload_decoder = Some(self.new_payload_decoder(&salt));
                }
                self.payload_decoder.as_mut().unwrap().decode_payload(src)
            }
            Network::UDP => {
                if src.remaining() < self.key.len() {
                    return Ok(None);
                }
                let salt = src.split_to(self.key.len());
                let decoder = self.new_payload_decoder(&salt);
                let opened = decoder.auth.lock().unwrap().open(&src.split_off(0));
                Ok(Some(BytesMut::from(&opened[..])))
            }
        }
    }
}

pub struct DatagramPacketCodec {
    cipher: AEADCipherCodec,
}

impl DatagramPacketCodec {
    pub fn new(cipher: AEADCipherCodec) -> Self {
        Self { cipher }
    }
}

impl Encoder<(BytesMut, SocketAddr)> for DatagramPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: (BytesMut, SocketAddr), dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut temp = BytesMut::new();
        Address::encode_socket_address(item.1, &mut temp)?;
        temp.put_slice(&item.0);
        self.cipher.encode(temp, dst)
    }
}

impl Decoder for DatagramPacketCodec {
    type Item = (BytesMut, SocketAddr);

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(mut temp) = self.cipher.decode(src)? {
            let recipient = Address::decode_socket_address(&mut temp)?;
            Ok(Some((temp.split_off(0), recipient)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use base64ct::Encoding;
    use bytes::BytesMut;
    use rand::{distributions::Alphanumeric, random, Rng};
    use tokio_util::codec::{Decoder, Encoder};

    use crate::common::{codec::{aead::SupportedCipher, shadowsocks::{AEADCipherCodec, DatagramPacketCodec}}, protocol::network::Network};

    #[test]
    fn test_generate_key() {
        let password = b"Personal search-enabled assistant for programmers";
        let key: [u8; 16] = AEADCipherCodec::generate_key(password);
        assert_eq!("zsWfM5hwvmTusK6sGOop5w==", base64ct::Base64::encode_string(&key));
        let key: [u8; 32] = AEADCipherCodec::generate_key(password);
        assert_eq!("zsWfM5hwvmTusK6sGOop57hBNhUblVO/PpBKSm34Vu4=", base64ct::Base64::encode_string(&key));
    }

    #[test]
    fn test_tcp() {
        fn test_tcp(cipher: SupportedCipher) {
            let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
            rand::thread_rng().fill(&mut password[..]);
            let mut codec = AEADCipherCodec::new(cipher, &password[..], Network::TCP);
            let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff * 10).map(char::from).collect();
            let src = BytesMut::from(expect.as_str());
            let mut dst = BytesMut::new();
            codec.encode(src, &mut dst).unwrap();
            let actual = codec.decode(&mut dst).unwrap().unwrap();
            let actual = String::from_utf8(actual.freeze().to_vec()).unwrap();
            assert_eq!(expect, actual);
        }

        SupportedCipher::VALUES.into_iter().for_each(test_tcp);
    }

    #[test]
    fn test_udp() {
        fn test_udp(cipher: SupportedCipher) {
            let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
            rand::thread_rng().fill(&mut password[..]);
            let codec = AEADCipherCodec::new(cipher, &password[..], Network::UDP);
            let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff).map(char::from).collect();
            let mut codec = DatagramPacketCodec::new(codec);
            let mut dst = BytesMut::new();
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, random()));
            codec.encode((expect.as_bytes().into(), addr), &mut dst).unwrap();
            let actual = codec.decode(&mut dst).unwrap().unwrap();
            assert_eq!(String::from_utf8(actual.0.freeze().to_vec()).unwrap(), expect);
            assert_eq!(actual.1, addr);
        }

        SupportedCipher::VALUES.into_iter().for_each(test_udp);
    }
}
