use std::net::SocketAddr;

use octo_squirrel::codec::DatagramPacket;
use octo_squirrel::protocol::address::Address;

use crate::client::config::ServerConfig;
use crate::client::template::TcpOutboundContext;
use crate::client::template::UdpOutbound;
use crate::client::template::UdpOutboundContext;

pub struct Shadowsocks<const N: usize>;

impl<const N: usize> TcpOutboundContext for Shadowsocks<N> {
    type Codec = tcp::PayloadCodec<N>;

    type Context = tcp::ClientContext<N>;

    fn new_context(config: &ServerConfig) -> anyhow::Result<Self::Context> {
        config.try_into()
    }

    fn new_codec(target: &Address, context: Self::Context) -> anyhow::Result<Self::Codec> {
        tcp::new_payload_codec(target, context)
    }
}

impl<const N: usize> UdpOutboundContext for Shadowsocks<N> {
    type Key = SocketAddr;

    type Context = udp::Client<N>;

    fn new_key(sender: std::net::SocketAddr, _: &Address) -> Self::Key {
        sender
    }

    fn new_context(config: &ServerConfig) -> anyhow::Result<Self::Context> {
        udp::Client::new(config)
    }
}

impl<const N: usize> UdpOutbound for Shadowsocks<N> {
    type OutboundIn = (DatagramPacket, SocketAddr);

    type OutboundOut = (DatagramPacket, SocketAddr);

    fn to_outbound_out(item: DatagramPacket, proxy: SocketAddr) -> Self::OutboundOut {
        let (content, target) = item;
        ((content, target), proxy)
    }

    fn to_inbound_in(item: Self::OutboundIn, _: &Address, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        let (item, _) = item;
        (item, sender)
    }
}

pub(super) mod tcp {
    use std::sync::Arc;

    use anyhow::Result;
    use anyhow::anyhow;
    use octo_squirrel::codec::shadowsocks::tcp::AEADCipherCodec;
    use octo_squirrel::codec::shadowsocks::tcp::Context;
    use octo_squirrel::codec::shadowsocks::tcp::Identity;
    use octo_squirrel::codec::shadowsocks::tcp::Session;
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::shadowsocks::Mode;
    use octo_squirrel::protocol::shadowsocks::aead;
    use octo_squirrel::protocol::shadowsocks::aead_2022;
    use tokio_util::bytes::BytesMut;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    use crate::client::config::ServerConfig;

    #[derive(Clone)]
    pub struct ClientContext<const N: usize>(Arc<Context<N>>);

    impl<const N: usize> TryFrom<&ServerConfig> for ClientContext<N> {
        type Error = anyhow::Error;

        fn try_from(value: &ServerConfig) -> Result<Self, Self::Error> {
            let kind = value.cipher;
            let (key, identity_keys) = if kind.is_aead_2022() {
                aead_2022::password_to_keys(&value.password).map_err(|e| anyhow!(e))?
            } else {
                let key = aead::openssl_bytes_to_key(value.password.as_bytes());
                (key, Vec::with_capacity(0))
            };
            let context = Arc::new(Context::new(key, identity_keys, value.cipher, None));
            Ok(Self(context))
        }
    }

    pub fn new_payload_codec<const N: usize>(addr: &Address, config: ClientContext<N>) -> Result<PayloadCodec<N>> {
        Ok(PayloadCodec::new(config.0, Mode::Client, Some(addr.clone())))
    }

    pub struct PayloadCodec<const N: usize> {
        context: Arc<Context<N>>,
        session: Session<N>,
        cipher: AEADCipherCodec<N>,
    }

    impl<const N: usize> PayloadCodec<N> {
        pub fn new(context: Arc<Context<N>>, mode: Mode, address: Option<Address>) -> Self {
            let session = Session::new(mode, Identity::default(), address);
            Self { context, session, cipher: AEADCipherCodec::default() }
        }
    }

    impl<const N: usize> Encoder<BytesMut> for PayloadCodec<N> {
        type Error = anyhow::Error;

        fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<()> {
            self.cipher.encode(&self.context, &self.session, item, dst)
        }
    }

    impl<const N: usize> Decoder for PayloadCodec<N> {
        type Item = BytesMut;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
            self.cipher.decode(&self.context, &mut self.session, src)
        }
    }
}

pub(super) mod udp {
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;
    use std::sync::Arc;

    use anyhow::anyhow;
    use anyhow::bail;
    use octo_squirrel::codec::DatagramPacket;
    use octo_squirrel::codec::aead::CipherKind;
    use octo_squirrel::codec::shadowsocks::udp::AEADCipherCodec;
    use octo_squirrel::codec::shadowsocks::udp::Context;
    use octo_squirrel::codec::shadowsocks::udp::Session;
    use octo_squirrel::codec::shadowsocks::udp::SessionCodec;
    use octo_squirrel::manager::packet_window::PacketWindowFilter;
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::shadowsocks::Mode;
    use octo_squirrel::protocol::shadowsocks::aead_2022::password_to_keys;
    use tokio::net::UdpSocket;
    use tokio_util::bytes::BytesMut;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;
    use tokio_util::udp::UdpFramed;

    use crate::client::config::ServerConfig;

    #[derive(Clone)]
    pub struct Client<const N: usize> {
        kind: CipherKind,
        key: Arc<[u8]>,
        identity_keys: Arc<[[u8; N]]>,
    }

    impl<const N: usize> Client<N> {
        pub fn new(config: &ServerConfig) -> anyhow::Result<Client<N>> {
            let (key, identity_keys) = password_to_keys(&config.password).map_err(|e| anyhow!(e))?;
            Ok(Client { kind: config.cipher, key: Arc::new(key), identity_keys: Arc::from(identity_keys) })
        }
    }

    pub async fn new_plain_outbound<const N: usize>(_: &Address, client: &Client<N>) -> anyhow::Result<UdpFramed<DatagramPacketCodec<N>>> {
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
        let outbound_framed = UdpFramed::new(
            outbound,
            DatagramPacketCodec::new(SessionCodec::new(
                Context::new(Mode::Client, None, client.key.clone(), client.identity_keys.clone()),
                AEADCipherCodec::new(client.kind),
            )),
        );
        Ok(outbound_framed)
    }

    pub struct DatagramPacketCodec<const N: usize> {
        codec: SessionCodec<N>,
        session: Session<N>,
        filter: PacketWindowFilter,
    }

    impl<const N: usize> DatagramPacketCodec<N> {
        pub fn new(codec: SessionCodec<N>) -> DatagramPacketCodec<N> {
            DatagramPacketCodec { codec, session: Session::from(Mode::Client), filter: PacketWindowFilter::default() }
        }
    }

    impl<const N: usize> Encoder<DatagramPacket> for DatagramPacketCodec<N> {
        type Error = anyhow::Error;

        fn encode(&mut self, (content, addr): DatagramPacket, dst: &mut BytesMut) -> anyhow::Result<()> {
            self.session.increase_packet_id();
            self.codec.encode((content, addr, self.session.clone()), dst)
        }
    }

    impl<const N: usize> Decoder for DatagramPacketCodec<N> {
        type Item = DatagramPacket;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> anyhow::Result<Option<Self::Item>> {
            if src.is_empty() {
                Ok(None)
            } else {
                match self.codec.decode(src)? {
                    Some((content, addr, session)) => {
                        if !self.filter.validate_packet_id(session.packet_id, u64::MAX) {
                            bail!("[udp] packet_id out of window; session={}", session)
                        }
                        self.session.server_session_id = session.server_session_id;
                        Ok(Some((content, addr)))
                    }
                    None => Ok(None),
                }
            }
        }
    }
}
