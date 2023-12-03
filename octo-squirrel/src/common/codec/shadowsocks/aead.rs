use std::mem::size_of;

use aead::Buffer;
use anyhow::Result;
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

use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::CipherMethod;
use crate::common::codec::aead::IncreasingNonceGenerator;
use crate::common::network::DatagramPacket;
use crate::common::network::Network;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::Context;
use crate::common::protocol::shadowsocks::StreamType;
use crate::common::protocol::socks5::address::AddressCodec;
use crate::common::util::Dice;

struct Authenticator {
    method: Box<dyn CipherMethod>,
    increasing: IncreasingNonceGenerator,
}

impl Authenticator {
    fn new(method: Box<dyn CipherMethod>, increasing: IncreasingNonceGenerator) -> Self {
        Self { method, increasing }
    }

    fn size_bytes(&self) -> usize {
        size_of::<u16>() + self.method.tag_size()
    }

    fn encode_size(&mut self, size: usize) -> Vec<u8> {
        let mut bytes = ((size - self.method.tag_size()) as u16).to_be_bytes().to_vec();
        self.seal(&mut bytes);
        bytes
    }

    fn decode_size(&mut self, data: &mut BytesMut) -> usize {
        self.open(data);
        let size = data.get_u16();
        size as usize + self.method.tag_size()
    }

    fn seal(&mut self, plaintext: &mut dyn Buffer) {
        self.method.encrypt_in_place(&self.increasing.generate(), b"", plaintext)
    }

    fn open(&mut self, ciphertext: &mut dyn Buffer) {
        self.method.decrypt_in_place(&self.increasing.generate(), b"", ciphertext)
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
        let tag_size = self.auth.method.tag_size();
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
    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        let mut opened = src.split_off(0);
        self.auth.open(&mut opened);
        Ok(Some(opened))
    }

    fn decode_payload(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>> {
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
    cipher: CipherKind,
    key: Vec<u8>,
    pub(self) encoder: Option<CipherEncoder>,
    pub(self) decoder: Option<CipherDecoder>,
}

impl AEADCipherCodec {
    pub fn new(cipher: CipherKind, password: &[u8]) -> Self {
        match cipher {
            CipherKind::Aes128Gcm => {
                let key: [u8; 16] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), encoder: None, decoder: None }
            }
            CipherKind::Aes256Gcm => {
                let key: [u8; 32] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), encoder: None, decoder: None }
            }
            CipherKind::ChaCha20Poly1305 => {
                let key: [u8; 32] = Self::generate_key(password);
                Self { cipher, key: key.to_vec(), encoder: None, decoder: None }
            }
            CipherKind::Aead2022Blake3Aes128Gcm => todo!(),
            CipherKind::Aead2022Blake3Aes256Gcm => todo!(),
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

    fn encode(&mut self, context: &Context, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        match context.network {
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

    fn decode(&mut self, context: &Context, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.is_empty() {
            return Ok(None);
        }
        match context.network {
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
    type Error = anyhow::Error;

    fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<()> {
        let addr = Address::from(item.1);
        let mut temp = BytesMut::with_capacity(item.0.len() + AddressCodec::length(&addr));
        AddressCodec::encode(&addr, &mut temp)?;
        temp.put(item.0);
        let context = Context::udp(StreamType::Request(addr));
        self.cipher.encode(&context, temp, dst)
    }
}

impl Decoder for DatagramPacketCodec {
    type Item = DatagramPacket;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let context = Context::udp(StreamType::Response);
        if let Some(mut content) = self.cipher.decode(&context, src)? {
            let recipient = AddressCodec::decode(&mut content)?;
            Ok(Some((content.split_off(0), recipient.into())))
        } else {
            Ok(None)
        }
    }
}

pub struct ClientCodec {
    context: Context,
    cipher: AEADCipherCodec,
}

impl ClientCodec {
    pub fn new(context: Context, cipher: AEADCipherCodec) -> Self {
        Self { context, cipher }
    }
}

impl Encoder<BytesMut> for ClientCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, mut item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        if self.cipher.encoder.is_none() {
            if let StreamType::Request(ref addr) = self.context.stream_type {
                let mut addr_bytes = BytesMut::with_capacity(AddressCodec::length(addr));
                AddressCodec::encode(addr, &mut addr_bytes)?;
                addr_bytes.put(item);
                item = addr_bytes;
            }
        }
        self.cipher.encode(&self.context, item, dst)
    }
}

impl Decoder for ClientCodec {
    type Item = BytesMut;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.cipher.decode(&self.context, src)
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

    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::shadowsocks::aead::AEADCipherCodec;
    use crate::common::codec::shadowsocks::aead::DatagramPacketCodec;
    use crate::common::protocol::shadowsocks::Context;
    use crate::common::protocol::shadowsocks::StreamType;

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
        fn test_tcp(cipher: CipherKind) {
            let context = Context::tcp(StreamType::Response);
            let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
            rand::thread_rng().fill(&mut password[..]);
            let mut codec = AEADCipherCodec::new(cipher, &password[..]);
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
            let codec = AEADCipherCodec::new(cipher, &password[..]);
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
