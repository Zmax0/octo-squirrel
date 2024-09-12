use std::io::Cursor;
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use byte_string::ByteStr;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::trace;
use rand::random;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::aead_2022;
use super::ChunkDecoder;
use super::ChunkEncoder;
use super::Keys;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::CipherMethod;
use crate::common::codec::aead::KeyInit;
use crate::common::codec::shadowsocks::aead_2022::udp;
use crate::common::manager::shadowsocks::ServerUser;
use crate::common::manager::shadowsocks::ServerUserManager;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::Mode;
use crate::common::protocol::socks5::address::AddressCodec;
use crate::common::util::Dice;

pub struct AEADCipherCodec<const N: usize, CM> {
    kind: CipherKind,
    keys: Keys<N>,
    method: PhantomData<CM>,
}

impl<const N: usize, CM: CipherMethod + KeyInit> AEADCipherCodec<N, CM> {
    pub fn new(kind: CipherKind, password: &str) -> Result<Self, base64ct::Error> {
        Ok(Self { kind, keys: Keys::from(kind, password)?, method: PhantomData })
    }

    pub fn encode(&self, context: &Context<N>, session: &Session<N>, address: &Address, item: BytesMut, dst: &mut BytesMut) -> anyhow::Result<()> {
        match (self.kind.is_aead_2022(), context.stream_type) {
            (true, Mode::Client) => self.encode_client_packet_aead_2022(session, address, item, dst),
            (true, Mode::Server) => self.encode_server_packet_aead_2022(session, address, item, dst),
            (false, _) => {
                let salt = &mut [0; N];
                Dice::fill_bytes(salt);
                dst.put(&salt[..]);
                let mut temp = BytesMut::with_capacity(AddressCodec::length(address) + item.remaining());
                AddressCodec::encode(address, &mut temp)?;
                temp.put(item);
                let mut encoder: ChunkEncoder<CM> = self.new_encoder(salt).map_err(anyhow::Error::msg)?;
                encoder.encode_packet(temp, dst).map_err(|e| anyhow!(e))
            }
        }
    }

    fn encode_client_packet_aead_2022(&self, session: &Session<N>, address: &Address, item: BytesMut, dst: &mut BytesMut) -> anyhow::Result<()> {
        let padding_length = super::aead_2022::next_padding_length(&item);
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let tag_size = self.kind.tag_size();
        let require_eih = self.kind.support_eih() && !self.keys.identity_keys.is_empty();
        let eih_len = if require_eih { 16 } else { 0 };
        let mut temp = BytesMut::with_capacity(
            nonce_length + 8 + 8 + eih_len + 1 + 8 + 2 + padding_length as usize + AddressCodec::length(address) + item.remaining() + tag_size,
        );
        temp.put_u64(session.client_session_id);
        temp.put_u64(session.packet_id);
        if require_eih {
            let mut session_id_packet_id = [0; 16];
            session_id_packet_id.copy_from_slice(&temp[nonce_length..]);
            aead_2022::udp::with_eih(self.kind, &self.keys, &session_id_packet_id, &mut temp)?
        }
        temp.put_u8(Mode::Client.to_u8());
        temp.put_u64(super::aead_2022::now()?);
        temp.put_u16(padding_length);
        temp.put(&Dice::roll_bytes(padding_length as usize)[..]);
        AddressCodec::encode(address, &mut temp)?;
        temp.put(item);
        let mut header = temp.split_to(16);
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&header[4..16]);
        let key: &[u8; N] = if self.keys.identity_keys.is_empty() { &self.keys.enc_key } else { &self.keys.identity_keys[0] };
        udp::aes_encrypt_in_place(self.kind, key, &mut header)?;
        dst.put(header);
        if eih_len > 0 {
            dst.extend_from_slice(&temp.split_to(eih_len))
        }
        udp::new_encoder::<CM>(&self.keys.enc_key, session.client_session_id, nonce)?.encode_packet(temp, dst).map_err(|e| anyhow!(e))
    }

    fn encode_server_packet_aead_2022(&self, session: &Session<N>, address: &Address, item: BytesMut, dst: &mut BytesMut) -> anyhow::Result<()> {
        let padding_length = super::aead_2022::next_padding_length(&item);
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let mut temp = BytesMut::with_capacity(
            nonce_length + 8 + 8 + 1 + 8 + 8 + 2 + padding_length as usize + AddressCodec::length(address) + item.remaining() + self.kind.tag_size(),
        );
        temp.put_u64(session.server_session_id);
        temp.put_u64(session.packet_id);
        temp.put_u8(Mode::Server.to_u8());
        temp.put_u64(super::aead_2022::now()?);
        temp.put_u64(session.client_session_id);
        temp.put_u16(padding_length);
        temp.put(&Dice::roll_bytes(padding_length as usize)[..]);
        AddressCodec::encode(address, &mut temp)?;
        temp.put(item);
        let key = if let Some(user) = &session.user {
            trace!("encrypt with identity {}", user);
            &user.key
        } else {
            &self.keys.enc_key
        };
        let mut header = temp.split_to(16);
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&header[4..16]);
        udp::aes_encrypt_in_place(self.kind, key, &mut header)?;
        dst.put(header);
        udp::new_encoder::<CM>(key, session.server_session_id, nonce)?.encode_packet(temp, dst).map_err(|e| anyhow!(e))
    }

    fn new_encoder(&self, salt: &[u8]) -> Result<ChunkEncoder<CM>, String> {
        if self.kind.is_aead_2022() {
            super::aead_2022::tcp::new_encoder::<N, CM>(&self.keys.enc_key, salt).map_err(|e| e.to_string())
        } else {
            super::aead::new_encoder(&self.keys.enc_key, salt)
        }
    }

    fn decode(&self, context: &Context<N>, src: &mut BytesMut) -> anyhow::Result<SessionPacket<N>> {
        match (self.kind.is_aead_2022(), context.stream_type) {
            (true, Mode::Client) => self.decode_server_packet_aead_2022(src),
            (true, Mode::Server) => self.decode_client_packet_aead_2022(context, src),
            (false, _) => {
                if src.remaining() < self.keys.enc_key.len() {
                    bail!("invalid packet length");
                }
                let salt = src.split_to(self.keys.enc_key.len());
                let mut decoder: ChunkDecoder<CM> = self.new_payload_decoder(&salt).map_err(anyhow::Error::msg)?;
                let mut packet = decoder.decode_packet(src).map_err(|e| anyhow!(e))?.unwrap();
                let address = AddressCodec::decode(&mut packet)?;
                Ok((packet, address, Session::default()))
            }
        }
    }

    // for client mode
    fn decode_server_packet_aead_2022(&self, src: &mut BytesMut) -> Result<SessionPacket<N>, anyhow::Error> {
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let tag_size = self.kind.tag_size();
        let header_length = nonce_length + tag_size + 8 + 8 + 1 + 8 + 2;
        if src.remaining() < header_length {
            bail!("packet too short, at least {} bytes, but found {} bytes", header_length, src.remaining());
        }
        let mut session_id_packet_id = src.split_to(16);
        udp::aes_decrypt_in_place(self.kind, &self.keys.enc_key, &mut session_id_packet_id)?;
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&session_id_packet_id[4..16]);
        let mut header = Cursor::new(&session_id_packet_id);
        let server_session_id = header.get_u64();
        let packet_id = header.get_u64();
        let mut packet = udp::new_decoder::<CM>(&self.keys.enc_key, server_session_id, nonce)?.decode_packet(src).map_err(|e| anyhow!(e))?.unwrap();
        let stream_type = packet.get_u8();
        if stream_type != Mode::Server.to_u8() {
            bail!("invalid socket type, expecting {}, but found {}", Mode::Client.to_u8(), stream_type);
        }
        super::aead_2022::validate_timestamp(packet.get_u64()).map_err(anyhow::Error::msg)?;
        let client_session_id = packet.get_u64();
        let padding_length = packet.get_u16();
        if padding_length > 0 {
            packet.advance(padding_length as usize);
        }
        let session = Session::new(client_session_id, server_session_id, packet_id, None);
        let address = AddressCodec::decode(&mut packet)?;
        Ok((packet, address, session))
    }

    // for server mode
    fn decode_client_packet_aead_2022(&self, context: &Context<N>, src: &mut BytesMut) -> Result<SessionPacket<N>, anyhow::Error> {
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let tag_size = self.kind.tag_size();
        let user_manager = context.user_manager.as_ref();
        let require_eih = self.kind.support_eih() && user_manager.is_some_and(|u| u.user_count() > 0);
        let eih_size = if require_eih { 16 } else { 0 };
        let header_length = nonce_length + tag_size + 8 + 8 + eih_size + 1 + 8 + 2;
        if src.remaining() < header_length {
            bail!("packet too short, at least {} bytes, but found {} bytes", header_length, src.remaining());
        }
        let mut session_id_packet_id: [u8; 16] = [0; 16];
        src.copy_to_slice(&mut session_id_packet_id);
        udp::aes_decrypt_in_place(self.kind, &self.keys.enc_key, &mut session_id_packet_id)?;
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&session_id_packet_id[4..16]);
        let mut header = Cursor::new(&session_id_packet_id);
        let session_id = header.get_u64();
        let packet_id = header.get_u64();
        let mut user = None;
        if require_eih {
            let mut eih = [0; 16];
            src.copy_to_slice(&mut eih);
            trace!("server EIH {:?}, session_id_packet_id: {},{}", ByteStr::new(&eih), session_id, packet_id);
            udp::aes_decrypt_in_place(self.kind, &self.keys.enc_key, &mut eih)?;
            for i in 0..16 {
                eih[i] ^= session_id_packet_id[i];
            }
            if let Some(_user) = user_manager.unwrap().clone_user_by_hash(&eih) {
                trace!("{} chosen by EIH", _user);
                user = Some(_user);
            } else {
                bail!("user with identity {:?} not found", ByteStr::new(&eih));
            }
        }
        let key = if let Some(ref user) = user { &user.key } else { &self.keys.enc_key };
        let mut packet = udp::new_decoder::<CM>(key, session_id, nonce)?.decode_packet(src).map_err(|e| anyhow!(e))?.unwrap();
        let stream_type = packet.get_u8();
        if stream_type != Mode::Client.to_u8() {
            bail!("invalid socket type, expecting {}, but found {}", Mode::Client.to_u8(), stream_type);
        }
        super::aead_2022::validate_timestamp(packet.get_u64()).map_err(anyhow::Error::msg)?;
        let padding_length = packet.get_u16();
        if padding_length > 0 {
            packet.advance(padding_length as usize);
        }
        let session = Session::new(session_id, 0, packet_id, user);
        let address = AddressCodec::decode(&mut packet)?;
        Ok((packet, address, session))
    }

    fn new_payload_decoder(&self, salt: &BytesMut) -> Result<ChunkDecoder<CM>, String> {
        if self.kind.is_aead_2022() {
            super::aead_2022::tcp::new_decoder::<N, CM>(&self.keys.enc_key, salt).map_err(|e| e.to_string())
        } else {
            super::aead::new_decoder(&self.keys.enc_key, salt)
        }
    }
}

pub struct SessionPacketCodec<const N: usize, CM> {
    context: Context<N>,
    cipher: AEADCipherCodec<N, CM>,
    method: PhantomData<CM>,
}

impl<const N: usize, CM: CipherMethod + KeyInit> SessionPacketCodec<N, CM> {
    pub fn new(context: Context<N>, cipher: AEADCipherCodec<N, CM>) -> Self {
        Self { context, cipher, method: PhantomData }
    }

    pub fn encode(&self, (content, address, session): SessionPacket<N>, dst: &mut BytesMut) -> anyhow::Result<()> {
        self.cipher.encode(&self.context, &session, &address, content, dst)
    }

    pub fn decode(&self, src: &mut BytesMut) -> anyhow::Result<Option<SessionPacket<N>>> {
        if src.is_empty() {
            Ok(None)
        } else {
            let len = src.len();
            let mut src = src.split_to(len);
            let (content, address, session) = self.cipher.decode(&self.context, &mut src)?;
            Ok(Some((content, address, session)))
        }
    }
}

impl<const N: usize, CM: CipherMethod + KeyInit> Encoder<SessionPacket<N>> for SessionPacketCodec<N, CM> {
    type Error = anyhow::Error;

    fn encode(&mut self, (content, address, session): SessionPacket<N>, dst: &mut BytesMut) -> anyhow::Result<()> {
        self.cipher.encode(&self.context, &session, &address, content, dst)
    }
}

pub type SessionPacket<const N: usize> = (BytesMut, Address, Session<N>);

impl<const N: usize, CM: CipherMethod + KeyInit> Decoder for SessionPacketCodec<N, CM> {
    type Item = SessionPacket<N>;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> anyhow::Result<Option<Self::Item>> {
        if src.is_empty() {
            Ok(None)
        } else {
            let len = src.len();
            let mut src = src.split_to(len);
            let (content, address, session) = self.cipher.decode(&self.context, &mut src)?;
            Ok(Some((content, address, session)))
        }
    }
}

#[derive(Clone)]
pub struct Context<const N: usize> {
    pub stream_type: Mode,
    pub user_manager: Option<Arc<ServerUserManager<N>>>,
}

impl<const N: usize> Context<N> {
    pub fn new(stream_type: Mode, user_manager: Option<Arc<ServerUserManager<N>>>) -> Self {
        Self { stream_type, user_manager }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Session<const N: usize> {
    pub client_session_id: u64,
    pub server_session_id: u64,
    pub packet_id: u64,
    pub user: Option<Arc<ServerUser<N>>>,
}

impl<const N: usize> Session<N> {
    pub fn new(client_session_id: u64, server_session_id: u64, packet_id: u64, user: Option<Arc<ServerUser<N>>>) -> Self {
        Self { client_session_id, server_session_id, packet_id, user }
    }

    pub fn increase_packet_id(&mut self) {
        self.packet_id = self.packet_id.wrapping_add(1);
    }
}

impl<const N: usize> From<Mode> for Session<N> {
    fn from(value: Mode) -> Self {
        let mut client_session_id = 0;
        let mut server_session_id = 0;
        match value {
            Mode::Client => client_session_id = random(),
            Mode::Server => server_session_id = random(),
        }
        Self { packet_id: 1, client_session_id, server_session_id, user: None }
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use anyhow::anyhow;
    use bytes::BytesMut;
    use rand::distributions::Alphanumeric;
    use rand::random;
    use rand::Rng;

    use crate::common::codec::aead::Aes128GcmCipher;
    use crate::common::codec::aead::Aes256GcmCipher;
    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::aead::CipherMethod;
    use crate::common::codec::aead::KeyInit;
    use crate::common::codec::shadowsocks::udp::AEADCipherCodec;
    use crate::common::codec::shadowsocks::udp::Context;
    use crate::common::codec::shadowsocks::udp::Session;
    use crate::common::codec::shadowsocks::udp::SessionPacketCodec;
    use crate::common::protocol::address::Address;
    use crate::common::protocol::shadowsocks::Mode;

    const KINDS: [CipherKind; 3] = [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];
    #[test]
    fn test_udp() -> anyhow::Result<()> {
        fn test_udp(cipher: CipherKind) -> anyhow::Result<()> {
            fn test_udp<const N: usize, CM: CipherMethod + KeyInit>(cipher: CipherKind) -> anyhow::Result<()> {
                let password_len = rand::thread_rng().gen_range(10..=100);
                let password: String = rand::thread_rng().sample_iter(&Alphanumeric).take(password_len).map(char::from).collect();
                let codec = AEADCipherCodec::new(cipher, &password).map_err(|e| anyhow!(e))?;
                let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff).map(char::from).collect();
                let codec: SessionPacketCodec<N, CM> = SessionPacketCodec::new(Context::new(Mode::Server, None), codec);
                let mut dst = BytesMut::new();
                let addr = Address::Socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, random())));
                codec.encode((expect.as_bytes().into(), addr.clone(), Session::default()), &mut dst)?;
                let actual = codec.decode(&mut dst)?.unwrap();
                assert_eq!(String::from_utf8(actual.0.freeze().to_vec())?, expect);
                assert_eq!(actual.1, addr);
                Ok(())
            }

            match cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => test_udp::<16, Aes128GcmCipher>(cipher),
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => test_udp::<32, Aes256GcmCipher>(cipher),
                _ => unreachable!(),
            }
        }

        for k in KINDS {
            test_udp(k)?
        }
        Ok(())
    }
}
