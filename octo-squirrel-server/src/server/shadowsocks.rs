use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use bytes::BytesMut;
use log::error;
use log::info;
use log::trace;
use log::warn;
use lru_time_cache::LruCache;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::codec::shadowsocks::udp::Context;
use octo_squirrel::common::codec::shadowsocks::udp::Session;
use octo_squirrel::common::codec::shadowsocks::udp::SessionCodec;
use octo_squirrel::common::manager::packet_window::PacketWindowFilter;
use octo_squirrel::common::manager::shadowsocks::ServerUser;
use octo_squirrel::common::manager::shadowsocks::ServerUserManager;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::shadowsocks::aead_2022::password_to_keys;
use octo_squirrel::common::protocol::shadowsocks::Mode;
use octo_squirrel::config::ServerConfig;
use tcp::PayloadCodec;
use tcp::ServerContext;
use template::message::Outbound;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::template;

pub async fn startup(config: &ServerConfig) -> anyhow::Result<()> {
    let res = match config.cipher {
        CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
            let mut user_manager: ServerUserManager<16> = ServerUserManager::new();
            for user in config.user.iter() {
                user_manager.add_user(ServerUser::try_from(user).map_err(|e| anyhow!(e))?);
            }
            let user_manager = Arc::new(user_manager);
            tokio::join!(startup_udp::<16>(config, &user_manager), startup_tcp::<16>(config, &user_manager))
        }
        CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
            let mut user_manager: ServerUserManager<32> = ServerUserManager::new();
            for user in config.user.iter() {
                user_manager.add_user(ServerUser::try_from(user).map_err(|e| anyhow!(e))?);
            }
            let user_manager = Arc::new(user_manager);
            tokio::join!(startup_udp::<32>(config, &user_manager), startup_tcp::<32>(config, &user_manager))
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

async fn startup_tcp<const N: usize>(config: &ServerConfig, user_manager: &Arc<ServerUserManager<N>>) -> anyhow::Result<()> {
    let context = ServerContext::init(config, user_manager.clone())?;
    super::startup_tcp(context, config, |c| Ok(PayloadCodec::from(c))).await
}

async fn startup_udp<const N: usize>(config: &ServerConfig, user_manager: &Arc<ServerUserManager<N>>) -> anyhow::Result<()> {
    let (key, identity_keys) = password_to_keys(&config.password).map_err(|e| anyhow!(e))?;
    let context = Context::new(Mode::Server, Some(user_manager.clone()), &key, &identity_keys);
    let codec = udp::new_codec::<N>(config, context)?;
    let inbound = UdpSocket::bind(format!("{}:{}", config.host, config.port)).await?;
    let (tx, mut rx) = mpsc::channel::<(BytesMut, Address, SocketAddr, Session<N>)>(1024);
    let ttl = Duration::from_secs(300);
    let mut net_map: LruCache<u64, UdpAssociate<N>> = LruCache::with_expiry_duration_and_capacity(ttl, 10240);
    let mut cleanup_timer = time::interval(ttl);
    info!("Udp server running => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    let mut buf = [0; 0x10000];
    loop {
        tokio::select! {
            _ = cleanup_timer.tick() => {
                net_map.iter();
            }
            // p_s_c
            peer_msg = rx.recv() => {
                if let Some((content, peer_addr, client_addr, session)) = peer_msg {
                    net_map.get(&session.client_session_id); // keep alive
                    let mut dst = BytesMut::new();
                    if let Err(e) = SessionCodec::encode(&codec, (content, peer_addr, session), &mut dst) {
                        error!("[udp] encode failed; error={e}")
                    } else {
                        inbound.send_to(&dst, client_addr).await?;
                    }
                } else {
                    trace!("[udp] p_s_c channel closed");
                    break;
                }
            }
            // c_s_p
            client_msg = inbound.recv_from(&mut buf) => {
                match client_msg {
                    Ok((len, client_addr)) => {
                        let mut src = BytesMut::from(&buf[..len]);
                        match SessionCodec::<N>::decode(&codec, &mut src) {
                            Ok(Some((content, peer_addr, session))) => {
                                let key = session.client_session_id;
                                if let Some(assoc) = net_map.get_mut(&key) {
                                    assoc.try_send(content).await?
                                } else {
                                    let assoc = UdpAssociateContext::create(session, client_addr, peer_addr, tx.clone()).await?;
                                    assoc.try_send(content).await?;
                                    net_map.insert(key, assoc);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => error!("[udp] decode failed; error={e}"),
                        }
                    }
                    Err(e) => {
                        error!("[udp] client closed; error={e}");
                        break;
                    }
                }
            }
        }
    }
    info!("Udp server shutdown");
    Ok(())
}

struct UdpAssociate<const N: usize> {
    task: JoinHandle<()>,
    sender: Sender<BytesMut>,
}

impl<const N: usize> UdpAssociate<N> {
    async fn try_send(&self, msg: BytesMut) -> Result<(), mpsc::error::SendError<BytesMut>> {
        self.sender.send(msg).await
    }
}

impl<const N: usize> Drop for UdpAssociate<N> {
    fn drop(&mut self) {
        trace!("abort associate task");
        self.task.abort();
    }
}

struct UdpAssociateContext<const N: usize> {
    session: Session<N>,
    client_addr: SocketAddr,
    peer_addr: Address,
    inbound: Sender<(BytesMut, Address, SocketAddr, Session<N>)>,
    outbound: UdpSocket,
    filter: PacketWindowFilter,
}

impl<const N: usize> UdpAssociateContext<N> {
    async fn create(
        session: Session<N>,
        client_addr: SocketAddr,
        peer_addr: Address,
        inbound: Sender<(BytesMut, Address, SocketAddr, Session<N>)>,
    ) -> anyhow::Result<UdpAssociate<N>> {
        let (sender, receiver) = mpsc::channel(1024);

        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        outbound.connect(&peer_addr.to_socket_addr()?).await?;
        let mut assoc = Self { session, client_addr, peer_addr, inbound, outbound, filter: PacketWindowFilter::new() };
        let task = tokio::spawn(async move { assoc.relay(receiver).await });
        Ok(UdpAssociate { task, sender })
    }

    async fn relay(&mut self, mut receiver: Receiver<BytesMut>) {
        let mut buf = [0; 0x10000];
        loop {
            tokio::select! {
                peer_msg = self.outbound.recv(&mut buf) => {
                    match peer_msg {
                        Ok(len) => {
                            let content = BytesMut::from(&buf[..len]);
                            if let Err(e) = self.inbound.send((content, self.peer_addr.clone(), self.client_addr, self.session.clone())).await {
                                warn!("[udp] p_s_c channel closed; error={e}");
                            }
                        },
                        Err(e) => {
                            error!("[udp] recv peer failed; client={}, peer={}, error={}", self.client_addr, self.peer_addr, e);
                            break;
                        }
                    }
                },
                client_msg = receiver.recv() => {
                    match client_msg {
                        Some(item) => {
                            if !self.validate_packet_id() {
                                error!("[udp] packet_id {} out of window; client={}, peer={}", self.session.packet_id, self.client_addr, self.peer_addr);
                                break;
                            }
                            self.session.increase_packet_id();
                            if let Err(e) = self.outbound.send(&item).await {
                                error!("[udp] send peer failed; client={}, peer={}, error={}", self.client_addr, self.peer_addr, e);
                                break;
                            }
                        }
                        None => {
                            trace!("[udp] c_s_p channel closed; peer={}", self.peer_addr);
                            break;
                        }
                    }
                },
            }
        }
    }

    fn validate_packet_id(&mut self) -> bool {
        self.filter.validate_packet_id(self.session.packet_id, u64::MAX)
    }
}

mod udp {
    use octo_squirrel::common::codec::shadowsocks::udp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::udp::Context;
    use octo_squirrel::common::codec::shadowsocks::udp::SessionCodec;

    use super::*;
    pub fn new_codec<'a, const N: usize>(config: &ServerConfig, context: Context<'a, N>) -> anyhow::Result<SessionCodec<'a, N>> {
        let cipher = AEADCipherCodec::new(config.cipher).map_err(|e| anyhow!(e))?;
        Ok(SessionCodec::<'a, N>::new(context, cipher))
    }
}

mod tcp {
    use anyhow::Result;
    use octo_squirrel::common::codec::shadowsocks::tcp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::tcp::Context;
    use octo_squirrel::common::codec::shadowsocks::tcp::Identity;
    use octo_squirrel::common::codec::shadowsocks::tcp::Session;
    use octo_squirrel::common::protocol::shadowsocks::aead;
    use template::message::Inbound;

    use super::*;

    #[derive(Clone)]
    pub struct ServerContext<const N: usize>(Arc<Context<N>>);

    impl<const N: usize> ServerContext<N> {
        pub fn init(config: &ServerConfig, user_manager: Arc<ServerUserManager<N>>) -> Result<Self> {
            let kind = config.cipher;
            let (key, identity_keys) = if kind.is_aead_2022() {
                password_to_keys(&config.password).map_err(|e| anyhow!(e))?
            } else {
                let key = aead::openssl_bytes_to_key(config.password.as_bytes());
                (key, Vec::with_capacity(0))
            };
            let context = Arc::new(Context::new(key, identity_keys, config.cipher, Some(user_manager)));
            Ok(Self(context))
        }
    }

    pub struct PayloadCodec<const N: usize> {
        context: Arc<Context<N>>,
        session: Session<N>,
        cipher: AEADCipherCodec<N>,
        state: State,
    }

    enum State {
        Header,
        Body,
    }

    impl<const N: usize> PayloadCodec<N> {
        pub fn new(context: Arc<Context<N>>, mode: Mode, address: Option<Address>) -> Self {
            let session = Session::new(mode, Identity::default(), address);
            Self { context, session, cipher: AEADCipherCodec::default(), state: State::Header }
        }
    }

    impl<const N: usize> Encoder<Inbound> for PayloadCodec<N> {
        type Error = anyhow::Error;

        fn encode(&mut self, item: Inbound, dst: &mut BytesMut) -> Result<()> {
            self.cipher.encode(&self.context, &self.session, item.into(), dst)
        }
    }

    impl<const N: usize> Decoder for PayloadCodec<N> {
        type Item = Outbound;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
            match self.state {
                State::Header => {
                    if let (Some(dst), Some(addr)) = (self.cipher.decode(&self.context, &mut self.session, src)?, self.session.address.as_ref()) {
                        self.state = State::Body;
                        Ok(Some(Outbound::ConnectTcp(dst, addr.clone())))
                    } else {
                        Ok(None)
                    }
                }
                State::Body => {
                    if let Some(dst) = self.cipher.decode(&self.context, &mut self.session, src)? {
                        Ok(Some(Outbound::RelayTcp(dst)))
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    impl<const N: usize> From<ServerContext<N>> for PayloadCodec<N> {
        fn from(value: ServerContext<N>) -> Self {
            Self::new(value.0, Mode::Server, None)
        }
    }
}
