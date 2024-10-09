use std::cmp::Ordering;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use byte_string::ByteStr;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::debug;
use log::trace;
use lru_time_cache::LruCache;
use rand::random;

use super::aead_2022;
use super::ChunkDecoder;
use super::ChunkEncoder;
use crate::codec::aead::CipherKind;
use crate::codec::aead::CipherMethod;
use crate::codec::shadowsocks::aead_2022::udp;
use crate::manager::shadowsocks::ServerUser;
use crate::manager::shadowsocks::ServerUserManager;
use crate::protocol::address::Address;
use crate::protocol::shadowsocks::Mode;
use crate::protocol::socks5::address;
use crate::util::dice;

pub struct AEADCipherCodec<const N: usize> {
    kind: CipherKind,
}

impl<const N: usize> AEADCipherCodec<N> {
    pub fn new(kind: CipherKind) -> Result<Self, base64ct::Error> {
        Ok(Self { kind })
    }

    pub fn encode(&self, context: &Context<N>, session: &Session<N>, address: &Address, item: BytesMut, dst: &mut BytesMut) -> anyhow::Result<()> {
        match (self.kind.is_aead_2022(), context.stream_type) {
            (true, Mode::Client) => self.encode_client_packet_aead_2022(context, session, address, item, dst),
            (true, Mode::Server) => self.encode_server_packet_aead_2022(context, session, address, item, dst),
            (false, _) => {
                let salt = &mut [0; N];
                dice::fill_bytes(salt);
                dst.extend_from_slice(&salt[..]);
                let mut temp = BytesMut::with_capacity(address::length(address) + item.remaining());
                address::encode(address, &mut temp);
                temp.extend_from_slice(&item);
                let mut encoder = self.new_encoder(context.key, salt)?;
                encoder.encode_packet(temp, dst).map_err(|e| anyhow!(e))
            }
        }
    }

    fn encode_client_packet_aead_2022(
        &self,
        context: &Context<N>,
        session: &Session<N>,
        address: &Address,
        item: BytesMut,
        dst: &mut BytesMut,
    ) -> anyhow::Result<()> {
        let padding_length = aead_2022::next_padding_length(&item);
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let tag_size = self.kind.tag_size();
        let require_eih = self.kind.support_eih() && !context.identity_keys.is_empty();
        let eih_len = if require_eih { 16 } else { 0 };
        let mut temp = BytesMut::with_capacity(
            nonce_length + 8 + 8 + eih_len + 1 + 8 + 2 + padding_length as usize + address::length(address) + item.remaining() + tag_size,
        );
        temp.put_u64(session.client_session_id);
        temp.put_u64(session.packet_id);
        if require_eih {
            let mut session_id_packet_id = [0; 16];
            session_id_packet_id.copy_from_slice(&temp[nonce_length..]);
            udp::with_eih(self.kind, context.key, context.identity_keys, &session_id_packet_id, &mut temp)?
        }
        temp.put_u8(Mode::Client.to_u8());
        temp.put_u64(aead_2022::now()?);
        temp.put_u16(padding_length);
        temp.extend_from_slice(&dice::roll_bytes(padding_length as usize));
        address::encode(address, &mut temp);
        temp.extend_from_slice(&item);
        let mut header = temp.split_to(16);
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&header[4..16]);
        let key = if context.identity_keys.is_empty() { context.key } else { &context.identity_keys[0] };
        udp::aes_encrypt_in_place(self.kind, key, &mut header)?;
        dst.extend_from_slice(&header);
        if eih_len > 0 {
            dst.extend_from_slice(&temp.split_to(eih_len))
        }
        let cipher = unsafe { get_cipher(self.kind, context.key, session.client_session_id) };
        cipher.encrypt_in_place(&nonce, b"", &mut temp).map_err(|e| anyhow!(e))?;
        dst.extend_from_slice(&temp);
        Ok(())
    }

    fn encode_server_packet_aead_2022(
        &self,
        context: &Context<N>,
        session: &Session<N>,
        address: &Address,
        item: BytesMut,
        dst: &mut BytesMut,
    ) -> anyhow::Result<()> {
        let padding_length = aead_2022::next_padding_length(&item);
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let mut temp = BytesMut::with_capacity(
            nonce_length + 8 + 8 + 1 + 8 + 8 + 2 + padding_length as usize + address::length(address) + item.remaining() + self.kind.tag_size(),
        );
        temp.put_u64(session.server_session_id);
        temp.put_u64(session.packet_id);
        temp.put_u8(Mode::Server.to_u8());
        temp.put_u64(aead_2022::now()?);
        temp.put_u64(session.client_session_id);
        temp.put_u16(padding_length);
        temp.extend_from_slice(&dice::roll_bytes(padding_length as usize));
        address::encode(address, &mut temp);
        temp.extend_from_slice(&item);
        let key = if let Some(user) = &session.user {
            trace!("encrypt with identity {}", user);
            &user.key
        } else {
            context.key
        };
        let mut header = temp.split_to(16);
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&header[4..16]);
        udp::aes_encrypt_in_place(self.kind, key, &mut header)?;
        dst.extend_from_slice(&header);
        let cipher = unsafe { get_cipher(self.kind, key, session.server_session_id) };
        cipher.encrypt_in_place(&nonce, b"", &mut temp).map_err(|e| anyhow!(e))?;
        dst.extend_from_slice(&temp);
        Ok(())
    }

    fn new_encoder(&self, key: &[u8], salt: &[u8]) -> anyhow::Result<ChunkEncoder> {
        if self.kind.is_aead_2022() {
            Ok(aead_2022::new_encoder(self.kind, key, salt))
        } else {
            super::aead::new_encoder(self.kind, key, salt).map_err(|e| anyhow!(e))
        }
    }

    fn decode(&self, context: &Context<N>, src: &mut BytesMut) -> anyhow::Result<SessionPacket<N>> {
        match (self.kind.is_aead_2022(), context.stream_type) {
            (true, Mode::Client) => self.decode_server_packet_aead_2022(context, src),
            (true, Mode::Server) => self.decode_client_packet_aead_2022(context, src),
            (false, _) => {
                if src.remaining() < context.key.len() {
                    bail!("invalid packet length");
                }
                let salt = src.split_to(context.key.len());
                let mut decoder = self.new_payload_decoder(context.key, &salt).map_err(anyhow::Error::msg)?;
                let mut packet = decoder.decode_packet(src).map_err(|e| anyhow!(e))?;
                let address = address::decode(&mut packet)?;
                Ok((packet, address, Session::default()))
            }
        }
    }

    // for client mode
    fn decode_server_packet_aead_2022(&self, context: &Context<N>, src: &mut BytesMut) -> Result<SessionPacket<N>, anyhow::Error> {
        let nonce_length = udp::nonce_length(self.kind).map_err(anyhow::Error::msg)?;
        let tag_size = self.kind.tag_size();
        let header_length = nonce_length + tag_size + 8 + 8 + 1 + 8 + 2;
        if src.remaining() < header_length {
            bail!("packet too short, at least {} bytes, but found {} bytes", header_length, src.remaining());
        }
        let mut session_id_packet_id = src.split_to(16);
        udp::aes_decrypt_in_place(self.kind, context.key, &mut session_id_packet_id)?;
        let mut nonce: [u8; 12] = [0; 12];
        nonce.copy_from_slice(&session_id_packet_id[4..16]);
        let mut header = Cursor::new(&session_id_packet_id);
        let server_session_id = header.get_u64();
        let packet_id = header.get_u64();
        let cipher = unsafe { get_cipher(self.kind, context.key, server_session_id) };
        let mut packet = src.split_off(0);
        cipher.decrypt_in_place(&nonce, b"", &mut packet).map_err(|e| anyhow!(e))?;
        let stream_type = packet.get_u8();
        if stream_type != Mode::Server.to_u8() {
            bail!("invalid socket type, expecting {}, but found {}", Mode::Client.to_u8(), stream_type);
        }
        aead_2022::validate_timestamp(packet.get_u64()).map_err(anyhow::Error::msg)?;
        let client_session_id = packet.get_u64();
        let padding_length = packet.get_u16();
        if padding_length > 0 {
            packet.advance(padding_length as usize);
        }
        let session = Session::new(client_session_id, server_session_id, packet_id, None);
        let address = address::decode(&mut packet)?;
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
        udp::aes_decrypt_in_place(self.kind, context.key, &mut session_id_packet_id)?;
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
            udp::aes_decrypt_in_place(self.kind, context.key, &mut eih)?;
            eih.iter_mut().zip(session_id_packet_id).for_each(|(l, r)| *l ^= r);
            if let Some(_user) = user_manager.unwrap().clone_user_by_hash(&eih) {
                trace!("{} chosen by EIH", _user);
                user = Some(_user);
            } else {
                bail!("user with identity {:?} not found", ByteStr::new(&eih));
            }
        }
        let key = if let Some(ref user) = user { &user.key } else { context.key };
        let cipher = unsafe { get_cipher(self.kind, key, session_id) };
        let mut packet = src.split_off(0);
        cipher.decrypt_in_place(&nonce, b"", &mut packet).map_err(|e| anyhow!(e))?;
        let stream_type = packet.get_u8();
        if stream_type != Mode::Client.to_u8() {
            bail!("invalid socket type, expecting {}, but found {}", Mode::Client.to_u8(), stream_type);
        }
        aead_2022::validate_timestamp(packet.get_u64()).map_err(anyhow::Error::msg)?;
        let padding_length = packet.get_u16();
        if padding_length > 0 {
            packet.advance(padding_length as usize);
        }
        let session = Session::new(session_id, 0, packet_id, user);
        let address = address::decode(&mut packet)?;
        Ok((packet, address, session))
    }

    fn new_payload_decoder(&self, key: &[u8], salt: &BytesMut) -> anyhow::Result<ChunkDecoder> {
        if self.kind.is_aead_2022() {
            Ok(aead_2022::new_decoder(self.kind, key, salt))
        } else {
            super::aead::new_decoder(self.kind, key, salt).map_err(|e| anyhow!(e))
        }
    }
}

pub type SessionPacket<const N: usize> = (BytesMut, Address, Session<N>);

pub struct SessionCodec<'a, const N: usize> {
    context: Context<'a, N>,
    cipher: AEADCipherCodec<N>,
}

impl<'a, const N: usize> SessionCodec<'_, N> {
    pub fn new(context: Context<'a, N>, cipher: AEADCipherCodec<N>) -> SessionCodec<'_, N> {
        SessionCodec { context, cipher }
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

#[derive(Clone)]
pub struct Context<'a, const N: usize> {
    stream_type: Mode,
    user_manager: Option<Arc<ServerUserManager<N>>>,
    key: &'a [u8],
    identity_keys: &'a [[u8; N]],
}

impl<const N: usize> Context<'_, N> {
    pub fn new<'a>(
        stream_type: Mode,
        user_manager: Option<Arc<ServerUserManager<N>>>,
        key: &'a [u8],
        identity_keys: &'a [[u8; N]],
    ) -> Context<'a, N> {
        Context { stream_type, user_manager, key, identity_keys }
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

impl<const N: usize> Display for Session<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "C:{}, S:{}, P:{}, U:{}",
            self.client_session_id,
            self.server_session_id,
            self.packet_id,
            self.user.as_ref().map(|u| u.name.as_str()).unwrap_or("")
        )
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
        Self { packet_id: 0, client_session_id, server_session_id, user: None }
    }
}

static mut CACHE: OnceLock<LruCache<CipherKey, CipherMethod>> = OnceLock::new();

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct CipherKey {
    kind: CipherKind,
    key: usize,
    session_id: u64,
}

impl PartialOrd for CipherKey {
    fn partial_cmp(&self, other: &CipherKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CipherKey {
    fn cmp(&self, other: &CipherKey) -> Ordering {
        self.session_id.cmp(&other.session_id).then(self.key.cmp(&other.key)).then(self.kind.cmp(&other.kind))
    }
}

unsafe fn get_cipher(kind: CipherKind, key: &[u8], session_id: u64) -> &CipherMethod {
    CACHE.get_or_init(|| LruCache::with_expiry_duration_and_capacity(Duration::from_secs(30), 102400));
    let cache = CACHE.get_mut().expect("empty cipher cache");
    let key_ptr = key.as_ptr() as usize;
    cache.entry(CipherKey { kind, key: key_ptr, session_id }).or_insert_with(|| {
        debug!("[udp] new cache cipher {}|{}|{}", kind, key_ptr, session_id);
        udp::init_cipher(kind, key, session_id)
    })
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

    use crate::codec::aead::CipherKind;
    use crate::codec::shadowsocks::udp::AEADCipherCodec;
    use crate::codec::shadowsocks::udp::Context;
    use crate::codec::shadowsocks::udp::Session;
    use crate::codec::shadowsocks::udp::SessionCodec;
    use crate::protocol::address::Address;
    use crate::protocol::shadowsocks::aead_2022::password_to_keys;
    use crate::protocol::shadowsocks::Mode;

    const KINDS: [CipherKind; 3] = [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];
    #[test]
    fn test_udp() -> anyhow::Result<()> {
        fn test_udp(cipher: CipherKind) -> anyhow::Result<()> {
            fn test_udp<const N: usize>(cipher: CipherKind) -> anyhow::Result<()> {
                let password: String = rand::thread_rng().sample_iter(&Alphanumeric).take(N).map(char::from).collect();
                let codec = AEADCipherCodec::new(cipher).map_err(|e| anyhow!(e))?;
                let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(0xffff).map(char::from).collect();
                let keys = password_to_keys(&password).map_err(|e| anyhow!(e))?;
                let codec: SessionCodec<N> = SessionCodec::new(Context::new(Mode::Server, None, &keys.0, &keys.1), codec);
                let mut dst = BytesMut::new();
                let addr = Address::Socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, random())));
                codec.encode((expect.as_bytes().into(), addr.clone(), Session::default()), &mut dst)?;
                let actual = codec.decode(&mut dst)?.unwrap();
                assert_eq!(String::from_utf8(actual.0.freeze().to_vec())?, expect);
                assert_eq!(actual.1, addr);
                Ok(())
            }

            match cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => test_udp::<16>(cipher),
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => test_udp::<32>(cipher),
                _ => unreachable!(),
            }
        }

        for k in KINDS {
            test_udp(k)?
        }
        Ok(())
    }
}
