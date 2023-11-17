use std::io;
use std::mem::size_of;
use std::net::SocketAddr;

use aead::Buffer;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use hkdf::Hkdf;
use log::trace;
use md5::Digest;
use md5::Md5;
use sha1::Sha1;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::aead::Cipher;
use super::aead::SupportedCipher;
use super::IncreasingNonceGenerator;
use crate::common::network::DatagramPacket;
use crate::common::network::Network;
use crate::common::protocol::socks5::address::Address;
use crate::common::protocol::socks5::message::Socks5CommandRequest;
use crate::common::protocol::socks5::Socks5AddressType;
use crate::common::util::Dice;

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

struct CipherEncoder {
    payload_limit: usize,
    auth: Authenticator,
}

impl CipherEncoder {
    pub fn new(payload_limit: usize, auth: Authenticator) -> Self {
        Self { payload_limit, auth }
    }

    fn seal(&mut self, src: &mut BytesMut, dst: &mut BytesMut) {
        let tag_size = self.auth.cipher.tag_size();
        let encrypted_size = src.remaining().min(self.payload_limit - tag_size - self.auth.size_bytes());
        trace!("Encode payload; payload length={}", encrypted_size);
        let encrypted_size_bytes = self.auth.encode_size(encrypted_size + tag_size);
        dst.put_slice(&encrypted_size_bytes);
        let mut payload_bytes = src.split_to(encrypted_size);
        self.auth.seal(&mut payload_bytes);
        dst.put(payload_bytes);
    }
}

impl CipherEncoder {
    fn encode_payload(&mut self, mut src: BytesMut, dst: &mut BytesMut) {
        while src.has_remaining() {
            self.seal(&mut src, dst);
        }
    }

    fn encode_packet(&mut self, mut src: BytesMut, dst: &mut BytesMut) {
        self.auth.seal(&mut src);
        dst.put(src);
    }
}

struct Authenticator {
    cipher: Box<dyn Cipher>,
    increasing: IncreasingNonceGenerator,
}

impl Authenticator {
    fn new(cipher: Box<dyn Cipher>, increasing: IncreasingNonceGenerator) -> Self {
        Self { cipher, increasing }
    }

    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.cipher.tag_size()
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        let mut bytes = ((size - self.cipher.tag_size()) as u16).to_be_bytes().to_vec();
        self.seal(&mut bytes);
        bytes
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> usize {
        self.open(data);
        let size = data.get_u16();
        size as usize + self.cipher.tag_size()
    }

    fn seal(&mut self, plaintext: &mut dyn Buffer) {
        self.cipher.encrypt_in_place(&self.increasing.generate(), b"", plaintext)
    }

    fn open(&mut self, ciphertext: &mut dyn Buffer) {
        self.cipher.decrypt_in_place(&self.increasing.generate(), b"", ciphertext)
    }
}

struct CipherDecoder {
    payload_length: Option<usize>,
    auth: Authenticator,
}

impl CipherDecoder {
    pub fn new(auth: Authenticator) -> Self {
        Self { payload_length: None, auth }
    }
}

impl CipherDecoder {
    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let mut opened = src.split_off(0);
        self.auth.open(&mut opened);
        Ok(Some(opened))
    }

    fn decode_payload(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let size_bytes = self.auth.size_bytes();
        let mut dst = Vec::new();
        while src.remaining() >= if self.payload_length.is_none() { size_bytes } else { self.payload_length.unwrap() } {
            if let Some(payload_length) = self.payload_length {
                let mut payload_btyes = src.split_to(payload_length);
                self.auth.open(&mut payload_btyes);
                dst.put(payload_btyes);
                self.payload_length = None;
            } else {
                let payload_length = self.auth.decode_size(&mut src.split_to(size_bytes));
                trace!("Decode payload; payload length={:?}", payload_length);
                self.payload_length = Some(payload_length);
            }
        }
        if dst.is_empty() {
            Ok(None)
        } else {
            Ok(Some(BytesMut::from(&dst[..])))
        }
    }
}

pub struct AEADCipherCodec {
    cipher: SupportedCipher,
    key: Vec<u8>,
    network: Network,
    encoder: Option<CipherEncoder>,
    decoder: Option<CipherDecoder>,
}

impl AEADCipherCodec {
    pub fn new(cipher: SupportedCipher, password: &[u8], network: Network) -> Self {
        match cipher {
            SupportedCipher::Aes128Gcm => {
                let key: [u8; 16] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), network, encoder: None, decoder: None }
            }
            SupportedCipher::Aes256Gcm => {
                let key: [u8; 32] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), network, encoder: None, decoder: None }
            }
            SupportedCipher::ChaCha20Poly1305 => {
                let key: [u8; 32] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), network, encoder: None, decoder: None }
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

    fn new_encoder(&mut self, salt: &[u8]) -> CipherEncoder {
        let key = AEADCipherCodec::hkdfsha1(&self.key, salt);
        let auth = self.new_auth(&key);
        CipherEncoder::new(0xffff, auth)
    }

    fn new_decoder(&mut self, salt: &[u8]) -> CipherDecoder {
        let key = AEADCipherCodec::hkdfsha1(&self.key, salt);
        let auth = self.new_auth(&key);
        CipherDecoder::new(auth)
    }

    fn new_auth(&mut self, key: &Vec<u8>) -> Authenticator {
        Authenticator::new(self.cipher.to_aead_cipher(&key), IncreasingNonceGenerator::generate_initial_aead_nonce())
    }
}

impl Encoder<BytesMut> for AEADCipherCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self.network {
            Network::TCP => {
                if self.encoder.is_none() {
                    let salt = Dice::roll_bytes(self.key.len());
                    self.encoder = Some(self.new_encoder(&salt));
                    dst.put(&salt[..]);
                }
                self.encoder.as_mut().unwrap().encode_payload(item, dst);
                Ok(())
            }
            Network::UDP => {
                let salt = Dice::roll_bytes(self.key.len());
                dst.put(&salt[..]);
                self.new_encoder(&salt).encode_packet(item, dst);
                Ok(())
            }
        }
    }
}

impl Decoder for AEADCipherCodec {
    type Item = BytesMut;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        match self.network {
            Network::TCP => {
                if self.decoder.is_none() {
                    if src.remaining() < self.key.len() {
                        return Ok(None);
                    }
                    let salt = src.split_to(self.key.len());
                    self.decoder = Some(self.new_decoder(&salt));
                }
                self.decoder.as_mut().unwrap().decode_payload(src)
            }
            Network::UDP => {
                if src.remaining() < self.key.len() {
                    return Ok(None);
                }
                let salt = src.split_to(self.key.len());
                self.new_decoder(&salt).decode_packet(src)
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

impl Encoder<DatagramPacket> for DatagramPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: (BytesMut, SocketAddr), dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut temp = BytesMut::new();
        Address::encode_socket_address(item.1, &mut temp)?;
        temp.put_slice(&item.0);
        self.cipher.encode(temp, dst)
    }
}

impl Decoder for DatagramPacketCodec {
    type Item = DatagramPacket;

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

    use crate::common::codec::aead::SupportedCipher;
    use crate::common::codec::shadowsocks::AEADCipherCodec;
    use crate::common::codec::shadowsocks::DatagramPacketCodec;
    use crate::common::network::Network;

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
