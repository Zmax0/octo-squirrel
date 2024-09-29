use std::io::Cursor;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use base64ct::Base64;
use base64ct::Encoding;
use byte_string::ByteStr;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::trace;
use lru_time_cache::LruCache;
use rand::Rng;

use super::aead_2022;
use super::ChunkDecoder;
use super::ChunkEncoder;
use crate::common::codec::aead::CipherKind;
use crate::common::manager::shadowsocks::ServerUser;
use crate::common::manager::shadowsocks::ServerUserManager;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::Mode;
use crate::common::protocol::socks5::address;
use crate::common::util::dice;

pub struct Context<const N: usize> {
    key: [u8; N],
    identity_keys: Vec<[u8; N]>,
    kind: CipherKind,
    user_manager: Option<Arc<ServerUserManager<N>>>,
    nonce_cache: Mutex<LruCache<Vec<u8>, ()>>,
}

impl<const N: usize> Context<N> {
    pub fn new(key: [u8; N], identity_keys: Vec<[u8; N]>, kind: CipherKind, user_manager: Option<Arc<ServerUserManager<N>>>) -> Self {
        let nonce_cache = Mutex::new(LruCache::with_expiry_duration_and_capacity(Duration::from_secs(30), 102400));
        Self { key, identity_keys, kind, user_manager, nonce_cache }
    }

    pub fn check_nonce_and_set(&self, nonce: &[u8]) -> bool {
        if nonce.is_empty() {
            return false;
        }
        match self.nonce_cache.try_lock() {
            Ok(mut set) => {
                let res = set.get(nonce).is_some();
                if !res {
                    set.insert(nonce.to_vec(), ());
                }
                res
            }
            Err(_) => false,
        }
    }
}

#[derive(Default)]
pub struct AEADCipherCodec<const N: usize> {
    encoder: Option<ChunkEncoder>,
    decoder: Option<ChunkDecoder>,
}

impl<const N: usize> AEADCipherCodec<N> {
    pub fn encode(&mut self, context: &Context<N>, session: &Session<N>, mut item: BytesMut, dst: &mut BytesMut) -> anyhow::Result<()> {
        match self.encoder {
            Some(ref mut encoder) => encoder.encode_payload(item, dst).map_err(|e| anyhow!(e)),
            None => {
                let mut encoder = Self::init_payload_encoder(context, session, dst)?;
                Self::handle_payload_header(&mut encoder, context, session, &mut item, dst)?;
                self.encoder = Some(encoder);
                self.encode(context, session, item, dst)
            }
        }
    }

    fn init_payload_encoder(context: &Context<N>, session: &Session<N>, dst: &mut BytesMut) -> anyhow::Result<ChunkEncoder> {
        Self::with_identity(context, session, &context.key, &context.identity_keys, dst);
        let salt = session.identity.salt;
        trace!("[tcp] new request salt: {:?}", &ByteStr::new(&salt));
        Ok(match (context.kind.is_aead_2022(), session.identity.user.as_ref()) {
            (true, Some(user)) => aead_2022::new_encoder(context.kind, &user.key, &salt),
            (true, None) => aead_2022::new_encoder(context.kind, &context.key, &salt),
            (false, _) => super::aead::new_encoder(context.kind, &context.key, &salt).map_err(anyhow::Error::msg)?,
        })
    }

    fn handle_payload_header(
        encoder: &mut ChunkEncoder,
        context: &Context<N>,
        session: &Session<N>,
        msg: &mut BytesMut,
        dst: &mut BytesMut,
    ) -> anyhow::Result<()> {
        match session.mode {
            Mode::Client => {
                let temp = msg.split_to(msg.len());
                address::encode(session.address.as_ref().unwrap(), msg);
                let is_aead_2022 = context.kind.is_aead_2022();
                if is_aead_2022 {
                    let padding = aead_2022::next_padding_length(&temp);
                    msg.put_u16(padding);
                    msg.extend_from_slice(&dice::roll_bytes(padding as usize))
                }
                msg.extend_from_slice(&temp);
                if is_aead_2022 {
                    let (fix, via) =
                        aead_2022::tcp::new_header(&mut encoder.auth, msg, &session.mode, session.identity.request_salt.as_ref().map(|arr| &arr[..]))
                            .map_err(|e| anyhow!(e))?;
                    dst.extend_from_slice(&fix);
                    dst.extend_from_slice(&via);
                }
                Ok(())
            }
            Mode::Server => {
                if context.kind.is_aead_2022() {
                    let (fix, via) =
                        aead_2022::tcp::new_header(&mut encoder.auth, msg, &session.mode, session.identity.request_salt.as_ref().map(|arr| &arr[..]))
                            .map_err(|e| anyhow!(e))?;
                    dst.extend_from_slice(&fix);
                    dst.extend_from_slice(&via);
                }
                Ok(())
            }
        }
    }

    pub fn decode(&mut self, context: &Context<N>, session: &mut Session<N>, src: &mut BytesMut) -> anyhow::Result<Option<BytesMut>> {
        if src.is_empty() {
            return Ok(None);
        }
        let mut dst = BytesMut::new();
        if self.decoder.is_none() {
            self.init_payload_decoder(context, session, src, &mut dst)?;
        }
        match self.decoder {
            Some(ref mut decoder) => {
                decoder.decode_payload(src, &mut dst).map_err(|e| anyhow!(e))?;
                if dst.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(dst))
                }
            }
            None => Ok(None),
        }
    }

    fn init_payload_decoder(&mut self, context: &Context<N>, session: &mut Session<N>, src: &mut BytesMut, dst: &mut BytesMut) -> anyhow::Result<()> {
        if src.remaining() < session.identity.salt.len() {
            return Ok(());
        }
        let mut cursor = Cursor::new(src);
        if context.kind.is_aead_2022() {
            self.init_aead_2022_payload_decoder(context, session, &mut cursor, dst)?
        } else {
            let salt = cursor.copy_to_bytes(session.identity.salt.len());
            trace!("[tcp] get request salt {}", Base64::encode_string(&salt));
            self.decoder = Some(super::aead::new_decoder(context.kind, &context.key, &salt).map_err(anyhow::Error::msg)?);
        }
        let pos = cursor.position();
        cursor.into_inner().advance(pos as usize);
        Ok(())
    }

    fn init_aead_2022_payload_decoder(
        &mut self,
        context: &Context<N>,
        session: &mut Session<N>,
        src: &mut Cursor<&mut BytesMut>,
        dst: &mut BytesMut,
    ) -> anyhow::Result<()> {
        let tag_size = context.kind.tag_size();
        let request_salt_len = if let Mode::Server = session.mode { 0 } else { N };
        let mut require_eih = false;
        if matches!(session.mode, Mode::Server) {
            require_eih = context.kind.support_eih() && context.user_manager.as_ref().is_some_and(|m| m.user_count() > 0);
        }
        let eih_len = if require_eih { 16 } else { 0 };
        let mut salt = [0; N];
        src.copy_to_slice(&mut salt);
        trace!("[tcp] get request salt {:?}", ByteStr::new(&salt));
        if context.check_nonce_and_set(&salt) {
            bail!("detected repeated nonce salt {:?}", salt);
        }
        session.identity.request_salt = Some(salt);
        let header_len = eih_len + 1 + 8 + request_salt_len + 2 + tag_size;
        if src.remaining() < header_len {
            bail!("header too short, expecting {} bytes, but found {} bytes", header_len + N, src.remaining());
        }
        let mut header = BytesMut::with_capacity(header_len);
        unsafe { header.set_len(header_len) };
        src.copy_to_slice(&mut header);
        let mut decoder = if require_eih {
            let mut eih = [0; 16];
            eih.copy_from_slice(&header.split_to(16));
            aead_2022::tcp::new_decoder_with_eih(
                context.kind,
                &context.key,
                &salt,
                eih,
                &mut session.identity,
                context.user_manager.as_ref().unwrap(),
            )?
        } else {
            aead_2022::new_decoder(context.kind, &context.key, &salt)
        };
        decoder.auth.open(&mut header).map_err(|e| anyhow!(e))?;
        let stream_type_byte = header.get_u8();
        let expect_stream_type_byte = session.mode.expect_u8();
        if stream_type_byte != expect_stream_type_byte {
            bail!("invalid stream type, expecting {}, but found {}", expect_stream_type_byte, stream_type_byte)
        }
        aead_2022::validate_timestamp(header.get_u64()).map_err(anyhow::Error::msg)?;
        if matches!(session.mode, Mode::Client) {
            header.copy_to_slice(session.identity.request_salt.as_mut().unwrap());
            trace!("[tcp] get request header salt {}", Base64::encode_string(session.identity.request_salt.as_ref().unwrap()));
        };
        let length = header.get_u16() as usize;
        if src.remaining() < length + tag_size {
            bail!("Invalid via request header length")
        }
        let mut via = BytesMut::with_capacity(length + tag_size);
        unsafe { via.set_len(length + tag_size) };
        src.copy_to_slice(&mut via);
        decoder.auth.open(&mut via).map_err(|e| anyhow!(e))?;
        self.decoder = Some(decoder);
        if matches!(session.mode, Mode::Server) && session.address.is_none() {
            session.address = Some(address::decode(&mut via)?);
            let padding_len = via.get_u16();
            via.advance(padding_len as usize);
        }
        dst.extend_from_slice(&via);
        Ok(())
    }

    fn with_identity(context: &Context<N>, session: &Session<N>, key: &[u8], identity_keys: &[[u8; N]], dst: &mut BytesMut) {
        let salt = &session.identity.salt;
        dst.extend_from_slice(salt);
        if matches!(session.mode, Mode::Client) && context.kind.support_eih() {
            aead_2022::tcp::with_eih(&context.kind, key, identity_keys, salt, dst);
        }
    }
}

pub struct Session<const N: usize> {
    mode: Mode,
    identity: Identity<N>,
    #[cfg(feature = "server")]
    pub address: Option<Address>,
    #[cfg(not(feature = "server"))]
    address: Option<Address>,
}

impl<const N: usize> Session<N> {
    pub fn new(mode: Mode, identity: Identity<N>, address: Option<Address>) -> Self {
        Self { mode, identity, address }
    }
}

pub struct Identity<const N: usize> {
    pub salt: [u8; N],
    pub request_salt: Option<[u8; N]>,
    pub user: Option<ServerUser<N>>,
}

impl<const N: usize> Default for Identity<N> {
    fn default() -> Self {
        let mut salt: [u8; N] = [0; N];
        rand::thread_rng().fill(&mut salt[..N]);
        Self { salt, request_salt: Default::default(), user: Default::default() }
    }
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use base64ct::Base64;
    use base64ct::Encoding;
    use bytes::BytesMut;
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::shadowsocks::tcp::AEADCipherCodec;
    use crate::common::codec::shadowsocks::tcp::Context;
    use crate::common::codec::shadowsocks::tcp::Identity;
    use crate::common::codec::shadowsocks::tcp::Session;
    use crate::common::protocol::address::Address;
    use crate::common::protocol::shadowsocks::aead_2022::password_to_keys;
    use crate::common::protocol::shadowsocks::Mode;

    const KINDS: [CipherKind; 3] = [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];

    #[test]
    fn test_tcp() -> anyhow::Result<()> {
        fn test_tcp(cipher: CipherKind) -> anyhow::Result<()> {
            fn test_tcp<const N: usize>(cipher: CipherKind) -> anyhow::Result<()> {
                let mut password: [u8; N] = [0; N];
                rand::thread_rng().fill(&mut password[..]);
                let password = Base64::encode_string(&password);
                let (key, identity_keys) = password_to_keys(&password).map_err(|e| anyhow!(e))?;
                let context = Context::new(key, identity_keys, cipher, None);
                let mut session: Session<N> = Session::new(Mode::Server, Identity::default(), Some(Address::Domain("localhost".to_owned(), 0)));
                let mut codec: AEADCipherCodec<N> = AEADCipherCodec::default();
                let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(1).map(char::from).collect();
                let src = BytesMut::from(expect.as_str());
                let mut dst = BytesMut::new();
                codec.encode(&context, &mut session, src, &mut dst)?;
                let actual = codec.decode(&context, &mut session, &mut dst)?.unwrap();
                let actual = String::from_utf8(actual.freeze().to_vec())?;
                assert_eq!(expect, actual);
                Ok(())
            }

            match cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => test_tcp::<16>(cipher),
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => test_tcp::<32>(cipher),
                _ => unreachable!(),
            }
        }

        for kind in KINDS {
            test_tcp(kind)?
        }
        Ok(())
    }
}
