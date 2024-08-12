use std::io::Cursor;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use base64ct::Base64;
use base64ct::Encoding;
use byte_string::ByteStr;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use log::trace;
use lru_time_cache::LruCache;
use rand::Rng;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::aead_2022;
use super::ChunkDecoder;
use super::ChunkEncoder;
use super::Keys;
use crate::common::codec::aead::CipherKind;
use crate::common::codec::aead::CipherMethod;
use crate::common::codec::aead::KeyInit;
use crate::common::manager::shadowsocks::ServerUser;
use crate::common::manager::shadowsocks::ServerUserManager;
use crate::common::protocol::address::Address;
use crate::common::protocol::shadowsocks::Mode;
use crate::common::protocol::socks5::address::AddressCodec;
use crate::common::util::Dice;
use crate::config::ServerConfig;

pub struct Context {
    nonce_cache: Mutex<LruCache<Vec<u8>, ()>>,
}

impl Context {
    pub fn check_nonce_and_set(&self, nonce: &[u8]) -> bool {
        if nonce.is_empty() {
            return false;
        }
        let mut set = self.nonce_cache.lock().unwrap();
        if set.get(nonce).is_some() {
            return true;
        }
        set.insert(nonce.to_vec(), ());
        return false;
    }
}

impl Default for Context {
    fn default() -> Self {
        Self { nonce_cache: Mutex::new(LruCache::with_expiry_duration_and_capacity(Duration::from_secs(30), 102400)) }
    }
}
pub struct PayloadCodec<const N: usize, CM> {
    session: Session<N>,
    cipher: AEADCipherCodec<N, CM>,
}

impl<const N: usize, CM: CipherMethod + KeyInit> PayloadCodec<N, CM> {
    pub fn new(context: Arc<Context>, config: &ServerConfig, address: Address, mode: Mode, user_manager: Option<Arc<ServerUserManager<N>>>) -> Self {
        let session = Session::new(mode, Identity::new(), address, context, user_manager);
        Self { session, cipher: AEADCipherCodec::new(config.cipher, &config.password).unwrap() }
    }
}

impl<const N: usize, CM: CipherMethod + KeyInit> Encoder<BytesMut> for PayloadCodec<N, CM> {
    type Error = anyhow::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        self.cipher.encode(&mut self.session, item, dst)
    }
}

impl<const N: usize, CM: CipherMethod + KeyInit> Decoder for PayloadCodec<N, CM> {
    type Item = BytesMut;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        self.cipher.decode(&mut self.session, src)
    }
}
struct AEADCipherCodec<const N: usize, CM> {
    kind: CipherKind,
    keys: Keys<N>,
    pub(self) encoder: Option<ChunkEncoder<CM>>,
    pub(self) decoder: Option<ChunkDecoder<CM>>,
}

impl<const N: usize, CM> AEADCipherCodec<N, CM>
where
    CM: CipherMethod + KeyInit,
{
    pub fn new(kind: CipherKind, password: &String) -> Result<Self> {
        let keys = Keys::from(kind, password)?;
        Ok(AEADCipherCodec { kind, keys, encoder: None, decoder: None })
    }

    pub fn encode(&mut self, session: &mut Session<N>, mut item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        if let None = self.encoder {
            self.init_payload_encoder(session, self.kind.is_aead_2022(), dst);
            item = self.handle_payload_header(session, item, dst)?;
        }
        self.encoder.as_mut().unwrap().encode_payload(item, dst);
        Ok(())
    }

    fn init_payload_encoder(&mut self, session: &mut Session<N>, is_aead_2022: bool, dst: &mut BytesMut) {
        Self::with_identity(session, &self.kind, &self.keys, dst);
        let salt = session.identity.salt;
        trace!("[tcp] new request salt: {:?}", &ByteStr::new(&salt));
        if is_aead_2022 {
            match session.identity.user.as_ref() {
                Some(user) => self.encoder = Some(aead_2022::tcp::new_encoder::<N, CM>(&user.key, &salt)),
                None => self.encoder = Some(aead_2022::tcp::new_encoder::<N, CM>(&self.keys.enc_key, &salt)),
            };
        } else {
            self.encoder = Some(super::aead::new_encoder(&self.keys.enc_key, &salt));
        }
    }

    fn handle_payload_header(&mut self, session: &Session<N>, mut msg: BytesMut, dst: &mut BytesMut) -> Result<BytesMut> {
        match session.mode {
            Mode::Client => {
                let mut temp = BytesMut::new();
                AddressCodec::encode(&session.address, &mut temp)?;
                let is_aead_2022 = self.kind.is_aead_2022();
                if is_aead_2022 {
                    let padding = super::aead_2022::next_padding_length(&msg);
                    temp.put_u16(padding);
                    temp.put(&Dice::roll_bytes(padding as usize)[..])
                }
                temp.put(msg);
                if is_aead_2022 {
                    let (fix, via) = super::aead_2022::tcp::new_header(
                        &mut self.encoder.as_mut().unwrap().auth,
                        &mut temp,
                        &session.mode,
                        session.identity.request_salt.as_ref().map(|arr| &arr[..]),
                    );
                    dst.put(fix);
                    dst.put(via);
                }
                Ok(temp)
            }
            Mode::Server => {
                if self.kind.is_aead_2022() {
                    super::aead_2022::tcp::new_header(
                        &mut self.encoder.as_mut().unwrap().auth,
                        &mut msg,
                        &session.mode,
                        session.identity.request_salt.as_ref().map(|arr| &arr[..]),
                    );
                }
                Ok(msg)
            }
        }
    }

    fn decode(&mut self, session: &mut Session<N>, src: &mut BytesMut) -> Result<Option<BytesMut>> {
        if src.is_empty() {
            return Ok(None);
        }
        let mut dst = BytesMut::new();
        if let None = self.decoder {
            self.init_payload_decoder(session, src, &mut dst)?;
        }
        if let None = self.decoder {
            return Ok(None);
        }
        self.decoder.as_mut().unwrap().decode_payload(src, &mut dst);
        if dst.has_remaining() {
            Ok(Some(dst))
        } else {
            Ok(None)
        }
    }

    fn init_payload_decoder(&mut self, session: &mut Session<N>, src: &mut BytesMut, dst: &mut BytesMut) -> Result<()> {
        if src.remaining() < session.identity.salt.len() {
            return Ok(());
        }
        let mut cursor = Cursor::new(src);
        if self.kind.is_aead_2022() {
            self.init_aead_2022_payload_decoder(session, &mut cursor, dst)?
        } else {
            let salt = cursor.copy_to_bytes(session.identity.salt.len());
            trace!("[tcp] get request salt {}", Base64::encode_string(&salt));
            self.decoder = Some(super::aead::new_decoder(&self.keys.enc_key, &salt));
        }
        let pos = cursor.position();
        cursor.into_inner().advance(pos as usize);
        Ok(())
    }

    fn init_aead_2022_payload_decoder(&mut self, session: &mut Session<N>, src: &mut Cursor<&mut BytesMut>, dst: &mut BytesMut) -> Result<()> {
        let tag_size = self.kind.tag_size();
        let request_salt_len = if let Mode::Server = session.mode { 0 } else { N };
        let mut require_eih = false;
        if matches!(session.mode, Mode::Server) {
            if let Some(user_manager) = session.user_manager.clone() {
                require_eih = self.kind.support_eih() && user_manager.user_count() > 0
            }
        }
        let eih_len = if require_eih { 16 } else { 0 };
        let mut salt = [0; N];
        src.copy_to_slice(&mut salt);
        trace!("[tcp] get request salt {}", Base64::encode_string(&salt));
        if session.context.check_nonce_and_set(&salt) {
            bail!("detected repeated nonce salt {:?}", salt);
        }
        session.identity.request_salt = Some(salt);
        let header_len = eih_len + 1 + 8 + request_salt_len + 2 + tag_size;
        if src.remaining() < header_len {
            bail!("header too short, expecting {} bytes, but found {} bytes", header_len + N, src.remaining());
        }
        let mut header = vec![0; header_len];
        src.copy_to_slice(&mut header);
        let mut decoder = if require_eih {
            let mut eih = [0; 16];
            eih.copy_from_slice(&header[..16]);
            super::aead_2022::tcp::new_decoder_with_eih(
                &self.keys.enc_key,
                &salt,
                eih,
                &mut session.identity,
                session.user_manager.as_ref().unwrap(),
            )?
        } else {
            super::aead_2022::tcp::new_decoder::<N, CM>(&self.keys.enc_key, &salt)
        };
        decoder.auth.open(&mut header);
        let mut header = Bytes::from(header);
        let stream_type_byte = header.get_u8();
        let expect_stream_type_byte = session.mode.expect_u8();
        if stream_type_byte != expect_stream_type_byte {
            bail!("Invalid stream type, expecting {}, but found {}", expect_stream_type_byte, stream_type_byte)
        }
        super::aead_2022::validate_timestamp(header.get_u64())?;
        if matches!(session.mode, Mode::Client) {
            header.copy_to_slice(session.identity.request_salt.as_mut().unwrap());
            trace!("[tcp] get request header salt {}", Base64::encode_string(session.identity.request_salt.as_ref().unwrap()));
        };
        let length = header.get_u16() as usize;
        if src.remaining() < length + tag_size {
            bail!("Invalid via request header length")
        }
        let mut via = vec![0; length + tag_size];
        src.copy_to_slice(&mut via);
        decoder.auth.open(&mut via);
        self.decoder = Some(decoder);
        dst.put(&via[..]);
        Ok(())
    }

    fn with_identity(session: &mut Session<N>, kind: &CipherKind, keys: &Keys<N>, dst: &mut BytesMut) {
        let salt = &session.identity.salt;
        dst.put_slice(salt);
        if matches!(session.mode, Mode::Client) && kind.support_eih() {
            aead_2022::tcp::with_eih(kind, keys, salt, dst);
        }
    }
}

struct Session<const N: usize> {
    mode: Mode,
    identity: Identity<N>,
    address: Address,
    context: Arc<Context>,
    user_manager: Option<Arc<ServerUserManager<N>>>,
}

impl<const N: usize> Session<N> {
    fn new(mode: Mode, identity: Identity<N>, address: Address, context: Arc<Context>, user_manager: Option<Arc<ServerUserManager<N>>>) -> Self {
        Self { mode, identity, address, context, user_manager }
    }
}

pub struct Identity<const N: usize> {
    pub salt: [u8; N],
    pub request_salt: Option<[u8; N]>,
    pub user: Option<ServerUser<N>>,
}

impl<const N: usize> Identity<N> {
    pub fn new() -> Self {
        let mut salt: [u8; N] = [0; N];
        rand::thread_rng().fill(&mut salt[..N]);
        Self { salt, request_salt: None, user: None }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use bytes::BytesMut;
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    use crate::common::codec::aead::Aes128GcmCipher;
    use crate::common::codec::aead::Aes256GcmCipher;
    use crate::common::codec::aead::CipherKind;
    use crate::common::codec::aead::CipherMethod;
    use crate::common::codec::aead::KeyInit;
    use crate::common::codec::shadowsocks::tcp::AEADCipherCodec;
    use crate::common::codec::shadowsocks::tcp::Context;
    use crate::common::codec::shadowsocks::tcp::Identity;
    use crate::common::codec::shadowsocks::tcp::Session;
    use crate::common::protocol::address::Address;
    use crate::common::protocol::shadowsocks::Mode;

    const KINDS: [CipherKind; 3] = [CipherKind::Aes128Gcm, CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305];

    #[test]
    fn test_tcp() {
        fn test_tcp(cipher: CipherKind) {
            fn test_tcp<const N: usize, CM: CipherMethod + KeyInit>(cipher: CipherKind) {
                let context = Arc::new(Context::default());
                let mut context: Session<N> = Session::new(Mode::Server, Identity::new(), Address::Domain("localhost".to_owned(), 0), context, None);
                let mut password: Vec<u8> = vec![0; rand::thread_rng().gen_range(10..=100)];
                rand::thread_rng().fill(&mut password[..]);
                let mut codec: AEADCipherCodec<N, CM> = AEADCipherCodec::new(cipher, &String::from_utf8(password).unwrap()).unwrap();
                let expect: String = rand::thread_rng().sample_iter(&Alphanumeric).take(1).map(char::from).collect();
                let src = BytesMut::from(expect.as_str());
                let mut dst = BytesMut::new();
                codec.encode(&mut context, src, &mut dst).unwrap();
                let actual = codec.decode(&mut context, &mut dst).unwrap().unwrap();
                let actual = String::from_utf8(actual.freeze().to_vec()).unwrap();
                assert_eq!(expect, actual);
            }

            match cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => test_tcp::<16, Aes128GcmCipher>(cipher),
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => test_tcp::<32, Aes256GcmCipher>(cipher),
            }
        }

        KINDS.into_iter().for_each(test_tcp);
    }
}
