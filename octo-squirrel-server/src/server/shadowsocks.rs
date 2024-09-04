use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use bytes::BytesMut;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::Aes256GcmCipher;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::codec::aead::CipherMethod;
use octo_squirrel::common::codec::aead::KeyInit;
use octo_squirrel::common::codec::shadowsocks::tcp::AEADCipherCodec;
use octo_squirrel::common::codec::shadowsocks::tcp::Context;
use octo_squirrel::common::codec::shadowsocks::tcp::Identity;
use octo_squirrel::common::codec::shadowsocks::tcp::Session;
use octo_squirrel::common::manager::shadowsocks::ServerUser;
use octo_squirrel::common::manager::shadowsocks::ServerUserManager;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::shadowsocks::Mode;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpListener;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::template;
use super::template::Message;

pub async fn startup(config: &ServerConfig) -> anyhow::Result<()>
where
{
    #[inline]
    async fn startup_tcp<const N: usize, CM: CipherMethod + KeyInit + 'static>(
        config: &ServerConfig,
        mut user_manager: ServerUserManager<N>,
    ) -> anyhow::Result<()>
where {
        for user in config.user.iter() {
            user_manager.add_user(ServerUser::from_user(user).map_err(|e| anyhow!(e))?);
        }
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let listener = TcpListener::bind(listen_addr).await?;
        let user_manager = Arc::new(user_manager);
        while let Ok((inbound, _)) = listener.accept().await {
            tokio::spawn(template::relay_tcp(inbound, new_codec::<N, CM>(config, user_manager.clone())?));
        }
        Ok(())
    }

    match config.cipher {
        CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => startup_tcp::<16, Aes128GcmCipher>(config, ServerUserManager::new()).await,
        CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
            startup_tcp::<32, Aes256GcmCipher>(config, ServerUserManager::new()).await
        }
        _ => unreachable!(),
    }
}

fn new_codec<const N: usize, CM: CipherMethod + KeyInit>(
    config: &ServerConfig,
    user_manager: Arc<ServerUserManager<N>>,
) -> Result<PayloadCodec<N, CM>> {
    PayloadCodec::new(Arc::new(Context::default()), config, Mode::Server, None, Some(user_manager))
}

enum State {
    Header,
    Body,
}

struct PayloadCodec<const N: usize, CM> {
    session: Session<N>,
    cipher: AEADCipherCodec<N, CM>,
    state: State,
}

impl<const N: usize, CM: CipherMethod + KeyInit> PayloadCodec<N, CM> {
    pub fn new(
        context: Arc<Context>,
        config: &ServerConfig,
        mode: Mode,
        address: Option<Address>,
        user_manager: Option<Arc<ServerUserManager<N>>>,
    ) -> anyhow::Result<Self> {
        let session = Session::new(mode, Identity::default(), context, address, user_manager);
        Ok(Self { session, cipher: AEADCipherCodec::new(config.cipher, config.password.as_str()).map_err(|e| anyhow!(e))?, state: State::Header })
    }
}

impl<const N: usize, CM: CipherMethod + KeyInit> Encoder<BytesMut> for PayloadCodec<N, CM> {
    type Error = anyhow::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
        self.cipher.encode(&mut self.session, item, dst)
    }
}

impl<const N: usize, CM: CipherMethod + KeyInit> Decoder for PayloadCodec<N, CM> {
    type Item = Message;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        match self.state {
            State::Header => {
                if let (Some(dst), Some(addr)) = (self.cipher.decode(&mut self.session, src)?, self.session.address.as_ref()) {
                    self.state = State::Body;
                    Ok(Some(Message::ConnectTcp(dst, addr.clone())))
                } else {
                    Ok(None)
                }
            }
            State::Body => {
                if let Some(dst) = self.cipher.decode(&mut self.session, src)? {
                    Ok(Some(Message::RelayTcp(dst)))
                } else {
                    Ok(None)
                }
            }
        }
    }
}
