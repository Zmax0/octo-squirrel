use std::fs;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use bytes::BytesMut;
use futures::lock::BiLock;
use futures::SinkExt;
use futures::StreamExt;
use log::error;
use log::info;
use lru_time_cache::Entry;
use lru_time_cache::LruCache;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::Aes256GcmCipher;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::codec::aead::CipherMethod;
use octo_squirrel::common::codec::aead::KeyInit;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::manager::shadowsocks::ServerUser;
use octo_squirrel::common::manager::shadowsocks::ServerUserManager;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::shadowsocks::Mode;
use octo_squirrel::config::ServerConfig;
use template::Message;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio_native_tls::native_tls;
use tokio_native_tls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;

use super::template;

pub async fn startup(config: &ServerConfig) -> anyhow::Result<()> {
    let res = match config.cipher {
        CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
            let mut user_manager: ServerUserManager<16> = ServerUserManager::new();
            for user in config.user.iter() {
                user_manager.add_user(ServerUser::from_user(user).map_err(|e| anyhow!(e))?);
            }
            let user_manager = Arc::new(user_manager);
            tokio::join!(startup_udp::<16, Aes128GcmCipher>(config, &user_manager), startup_tcp::<16, Aes128GcmCipher>(config, &user_manager))
        }
        CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
            let mut user_manager: ServerUserManager<32> = ServerUserManager::new();
            for user in config.user.iter() {
                user_manager.add_user(ServerUser::from_user(user).map_err(|e| anyhow!(e))?);
            }
            let user_manager = Arc::new(user_manager);
            tokio::join!(startup_udp::<32, Aes256GcmCipher>(config, &user_manager), startup_tcp::<32, Aes256GcmCipher>(config, &user_manager))
        }
        _ => unreachable!(),
    };
    match res {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(e)) => bail!("tcp={e}"),
        (Err(e), Ok(_)) => bail!("udp={e}"),
        (Err(e1), Err(e2)) => bail!("tcp={e1}, udp={e2}"),
    }
}

async fn startup_tcp<const N: usize, CM: CipherMethod + KeyInit + Unpin + 'static>(
    config: &ServerConfig,
    user_manager: &Arc<ServerUserManager<N>>,
) -> anyhow::Result<()> {
    info!("Startup tcp server => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    match (&config.ssl, &config.ws) {
        (None, ws_config) => {
            while let Ok((inbound, _)) = listener.accept().await {
                if ws_config.is_some() {
                    tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, tcp::new_codec::<N, CM>(config, user_manager.clone())?));
                } else {
                    tokio::spawn(template::tcp::relay(inbound, tcp::new_codec::<N, CM>(config, user_manager.clone())?));
                }
            }
        }
        (Some(ssl_config), ws_config) => {
            let pem = fs::read(ssl_config.certificate_file.as_str())?;
            let key = fs::read(ssl_config.key_file.as_str())?;
            let identity = native_tls::Identity::from_pkcs8(&pem, &key)?;
            let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
            while let Ok((inbound, _)) = listener.accept().await {
                let tls = tls_acceptor.clone();
                let codec = tcp::new_codec::<N, CM>(config, user_manager.clone())?;
                match tls.accept(inbound).await {
                    Ok(inbound) => {
                        if ws_config.is_some() {
                            tokio::spawn(template::tcp::accept_websocket_then_replay(
                                inbound,
                                tcp::new_codec::<N, CM>(config, user_manager.clone())?,
                            ));
                        } else {
                            tokio::spawn(template::tcp::relay(inbound, codec));
                        }
                    }
                    Err(e) => error!("[tcp] tls handshake failed: {}", e),
                }
            }
        }
    }
    Ok(())
}

async fn startup_udp<const N: usize, CM: CipherMethod + KeyInit + Unpin + 'static>(
    config: &ServerConfig,
    user_manager: &Arc<ServerUserManager<N>>,
) -> anyhow::Result<()> {
    info!("Startup udp server => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    let codec = udp::new_codec::<N, CM>(config, user_manager.clone())?;
    let inbound = UdpSocket::bind(format!("{}:{}", config.host, config.port)).await?;
    let inbound = UdpFramed::new(inbound, codec);
    let (mut inbound_sink, mut inbound_stream) = inbound.split();
    let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let (mut outbound_sink, mut outbound_stream) = UdpFramed::new(outbound, BytesCodec).split::<(BytesMut, SocketAddr)>();
    let (net_map0, net_map1) = BiLock::new(LruCache::with_expiry_duration(Duration::from_secs(600)));
    let c_s_p = async {
        while let Some(Ok(((content, peer_addr), client_addr))) = inbound_stream.next().await {
            let peer_addr = peer_addr.to_socket_addr()?;
            if let Entry::Vacant(entry) = net_map0.lock().await.entry(peer_addr) {
                entry.insert(client_addr);
            }
            outbound_sink.send((content, peer_addr)).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let p_s_c = async {
        while let Some(Ok((content, peer_addr))) = outbound_stream.next().await {
            if let Some(client_addr) = net_map1.lock().await.get(&peer_addr) {
                inbound_sink.send(((content, Address::Socket(peer_addr)), *client_addr)).await?
            }
        }
        Ok::<_, anyhow::Error>(())
    };
    let _ = tokio::join!(p_s_c, c_s_p);
    Ok(())
}

mod udp {
    use octo_squirrel::common::codec::shadowsocks::udp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::udp::Context;
    use octo_squirrel::common::codec::shadowsocks::udp::DatagramPacketCodec;

    use super::*;
    pub fn new_codec<const N: usize, CM: CipherMethod + KeyInit>(
        config: &ServerConfig,
        user_manager: Arc<ServerUserManager<N>>,
    ) -> anyhow::Result<DatagramPacketCodec<N, CM>> {
        let context = Context::new(Mode::Server, None, Some(user_manager));
        let cipher = AEADCipherCodec::new(config.cipher, &config.password).map_err(|e| anyhow!(e))?;
        Ok(DatagramPacketCodec::new(context, cipher))
    }
}

mod tcp {
    use anyhow::Result;
    use octo_squirrel::common::codec::shadowsocks::tcp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::tcp::Context;
    use octo_squirrel::common::codec::shadowsocks::tcp::Identity;
    use octo_squirrel::common::codec::shadowsocks::tcp::Session;

    use super::*;

    pub fn new_codec<const N: usize, CM: CipherMethod + KeyInit>(
        config: &ServerConfig,
        user_manager: Arc<ServerUserManager<N>>,
    ) -> Result<PayloadCodec<N, CM>> {
        PayloadCodec::new(Arc::new(Context::default()), config, Mode::Server, None, Some(user_manager))
    }

    pub struct PayloadCodec<const N: usize, CM> {
        session: Session<N>,
        cipher: AEADCipherCodec<N, CM>,
        state: State,
    }

    enum State {
        Header,
        Body,
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
}
