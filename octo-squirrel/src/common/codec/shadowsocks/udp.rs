use std::usize;

use anyhow::bail;
use anyhow::Result;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::ChunkDecoder;
use super::ChunkEncoder;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::shadowsocks::aead_2022::udp;
use crate::common::network::DatagramPacket;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::udp::Context;
use crate::common::protocol::shadowsocks::Mode;
use crate::common::protocol::socks5::address::AddressCodec;
use crate::common::util::Dice;

pub struct AEADCipherCodec<const N: usize> {
    kind: CipherKind,
    key: Box<[u8]>,
}

impl<const N: usize> AEADCipherCodec<N> {
    pub fn new(cipher: CipherKind, password: &[u8]) -> Result<Self> {
        match cipher {
            CipherKind::Aes128Gcm => {
                let key: [u8; 16] = super::aead::openssl_bytes_to_key(password);
                Ok(Self { kind: cipher, key: Box::new(key) })
            }
            CipherKind::Aes256Gcm => {
                let key: [u8; 32] = super::aead::openssl_bytes_to_key(password);
                Ok(Self { kind: cipher, key: Box::new(key) })
            }
            CipherKind::ChaCha20Poly1305 => {
                let key: [u8; 32] = super::aead::openssl_bytes_to_key(password);
                Ok(Self { kind: cipher, key: Box::new(key) })
            }
            CipherKind::Aead2022Blake3Aes128Gcm => {
                let key = super::aead_2022::generate_key(password, 16)?;
                Ok(Self { kind: cipher, key })
            }
            CipherKind::Aead2022Blake3Aes256Gcm => {
                let key = super::aead_2022::generate_key(password, 32)?;
                Ok(Self { kind: cipher, key })
            }
        }
    }

    fn encode(&mut self, context: &mut Context, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        self.encode_packet(context, item, dst)
    }

    fn encode_packet(&self, context: &mut Context, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        if self.kind.is_aead_2022() {
            let padding_length = super::aead_2022::next_padding_length(&item);
            let nonce_length = udp::nonce_length(self.kind)?;
            let tag_size = self.kind.tag_size();
            let mut temp = BytesMut::with_capacity(
                nonce_length
                    + 8
                    + 8
                    + 1
                    + 8
                    + 2
                    + padding_length as usize
                    + AddressCodec::length(context.address.as_ref().unwrap())
                    + item.remaining()
                    + tag_size,
            );
            match context.stream_type {
                Mode::Client => temp.put_u64(context.session.server_session_id),
                Mode::Server => temp.put_u64(context.session.client_session_id),
            }
            context.session.packet_id += 1;
            temp.put_u64(context.session.packet_id);
            temp.put_u8(context.stream_type.to_u8());
            temp.put_u64(super::aead_2022::now());
            temp.put_u16(padding_length);
            temp.put(&Dice::roll_bytes(padding_length as usize)[..]);
            if matches!(context.stream_type, Mode::Server) {
                temp.put_u64(context.session.client_session_id);
            }
            AddressCodec::encode(context.address.as_ref().unwrap(), &mut temp)?;
            temp.put(item);
            let mut nonce: [u8; 12] = [0; 12];
            nonce.copy_from_slice(&temp[4..16]);
            let mut header: [u8; 16] = [0; 16];
            header.copy_from_slice(&temp.split_to(16));
            udp::encrypt_packet_header(self.kind, &self.key, &mut header)?;
            dst.put(&header[..]);
            udp::new_encoder(self.kind, &self.key, 0, nonce).encode_packet(temp, dst);
        } else {
            let salt = Dice::roll_bytes(self.key.len());
            dst.put(&salt[..]);
            let address = context.address.as_ref().unwrap();
            let mut temp = BytesMut::with_capacity(AddressCodec::length(address) + item.remaining());
            AddressCodec::encode(address, &mut temp)?;
            temp.put(item);
            self.new_encoder(&salt).encode_packet(temp, dst);
        }
        Ok(())
    }

    fn new_encoder(&self, salt: &[u8]) -> ChunkEncoder {
        if self.kind.is_aead_2022() {
            super::aead_2022::tcp::new_encoder::<N>(self.kind, &self.key, salt)
        } else {
            super::aead::new_encoder(self.kind, &self.key, salt)
        }
    }

    fn decode(&mut self, context: &mut Context, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.decode_packet(context, src)?))
    }

    fn decode_packet(&self, context: &mut Context, src: &mut BytesMut) -> Result<BytesMut> {
        if self.kind.is_aead_2022() {
            let nonce_length = udp::nonce_length(self.kind)?;
            let tag_size = self.kind.tag_size();
            let header_length = nonce_length + tag_size + 8 + 8 + 1 + 8 + 2;
            if src.remaining() < header_length {
                bail!("Packet too short, at least {} bytes, but found {} bytes", header_length, src.remaining());
            }
            let mut header: [u8; 16] = [0; 16];
            header.copy_from_slice(&src.split_to(16));
            udp::decrypt_packet_header(self.kind, &self.key, &mut header)?;
            let mut nonce: [u8; 12] = [0; 12];
            nonce.copy_from_slice(&header[4..16]);
            let mut header = Bytes::from(header.to_vec());
            let server_session_id = header.get_u64();
            header.get_u64(); // pack id
            let mut packet = udp::new_decoder(self.kind, &self.key, server_session_id, nonce).decode_packet(src)?.unwrap();
            packet.get_u8(); // stream type
            super::aead_2022::validate_timestamp(packet.get_u64())?;
            let padding_length = packet.get_u16();
            if padding_length > 0 {
                packet.advance(padding_length as usize);
            }
            if matches!(context.stream_type, Mode::Client) {
                context.session.client_session_id = packet.get_u64();
            }
            context.address = Some(AddressCodec::decode(&mut packet)?);
            Ok(packet)
        } else {
            if src.remaining() < self.key.len() {
                bail!("Invalid packet length");
            }
            let salt = src.split_to(self.key.len());
            let mut packet = self.new_payload_decoder(&salt).decode_packet(src)?.unwrap();
            context.address = Some(AddressCodec::decode(&mut packet)?);
            Ok(packet)
        }
    }

    fn new_payload_decoder(&self, salt: &BytesMut) -> ChunkDecoder {
        if self.kind.is_aead_2022() {
            super::aead_2022::tcp::new_decoder::<N>(self.kind, &self.key, salt)
        } else {
            super::aead::new_decoder(self.kind, &self.key, salt)
        }
    }
}

pub struct DatagramPacketCodec<const N: usize> {
    context: Context,
    cipher: AEADCipherCodec<N>,
}

impl<const N: usize> DatagramPacketCodec<N> {
    pub fn new(context: Context, cipher: AEADCipherCodec<N>) -> Self {
        Self { context, cipher }
    }
}

impl<const N: usize> Encoder<DatagramPacket> for DatagramPacketCodec<N> {
    type Error = anyhow::Error;

    fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<()> {
        self.context.address = Some(Address::from(item.1));
        self.cipher.encode(&mut self.context, item.0, dst)
    }
}

impl<const N: usize> Decoder for DatagramPacketCodec<N> {
    type Item = DatagramPacket;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if let Some(content) = self.cipher.decode(&mut self.context, src)? {
            Ok(Some((content, self.context.address.take().unwrap().into())))
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

    use bytes::BytesMut;
    use rand::distributions::Alphanumeric;
    use rand::random;
    use rand::Rng;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::shadowsocks::udp::AEADCipherCodec;
    use crate::common::codec::shadowsocks::udp::DatagramPacketCodec;
    use crate::common::protocol::shadowsocks::udp::Context;
    use crate::common::protocol::shadowsocks::Mode;

    const KINDS: [CipherKind; 3] = [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];
    #[test]
    fn test_udp() {
        fn test_udp(cipher: CipherKind) {
            fn test_udp<const N: usize>(cipher: CipherKind) {
                let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
                rand::thread_rng().fill(&mut password[..]);
                let codec: AEADCipherCodec<N> = AEADCipherCodec::new(cipher, &password[..]).unwrap();
                let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff).map(char::from).collect();
                let mut codec = DatagramPacketCodec::new(Context::udp(Mode::Server, None), codec);
                let mut dst = BytesMut::new();
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, random()));
                codec.encode((expect.as_bytes().into(), addr), &mut dst).unwrap();
                let actual = codec.decode(&mut dst).unwrap().unwrap();
                assert_eq!(String::from_utf8(actual.0.freeze().to_vec()).unwrap(), expect);
                assert_eq!(actual.1, addr);
            }

            match cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => test_udp::<16>(cipher),
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => test_udp::<32>(cipher),
            }
        }

        KINDS.into_iter().for_each(test_udp);
    }
}
