pub(super) mod tcp {
    use std::sync::Arc;

    use anyhow::anyhow;
    use anyhow::Result;
    use bytes::BytesMut;
    use octo_squirrel::common::codec::aead::CipherMethod;
    use octo_squirrel::common::codec::aead::KeyInit;
    use octo_squirrel::common::codec::shadowsocks::tcp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::tcp::Context;
    use octo_squirrel::common::codec::shadowsocks::tcp::Identity;
    use octo_squirrel::common::codec::shadowsocks::tcp::Session;
    use octo_squirrel::common::manager::shadowsocks::ServerUserManager;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    pub fn new_payload_codec<const N: usize, CM: CipherMethod + KeyInit>(
        addr: &Address,
        config: &ServerConfig,
    ) -> anyhow::Result<PayloadCodec<N, CM>> {
        PayloadCodec::new(Arc::new(Context::default()), config, Mode::Client, Some(addr.clone()), None)
    }

    pub struct PayloadCodec<const N: usize, CM> {
        session: Session<N>,
        cipher: AEADCipherCodec<N, CM>,
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
            Ok(Self { session, cipher: AEADCipherCodec::new(config.cipher, config.password.as_str()).map_err(|e| anyhow!(e))? })
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
}

pub(super) mod udp {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use anyhow::anyhow;
    use anyhow::Result;
    use bytes::BytesMut;
    use octo_squirrel::common::codec::aead::CipherMethod;
    use octo_squirrel::common::codec::aead::KeyInit;
    use octo_squirrel::common::codec::shadowsocks::udp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::udp::Context;
    use octo_squirrel::common::codec::shadowsocks::udp::Session;
    use octo_squirrel::common::codec::shadowsocks::udp::SessionCodec;
    use octo_squirrel::common::codec::DatagramPacket;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;
    use tokio::net::UdpSocket;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;
    use tokio_util::udp::UdpFramed;

    pub fn new_key(from: SocketAddr, to: &Address) -> (SocketAddr, Address) {
        (from, to.clone())
    }

    pub async fn new_plain_outbound<const N: usize, CM: CipherMethod + KeyInit>(
        _: SocketAddr,
        _: &Address,
        config: &ServerConfig,
    ) -> Result<UdpFramed<DatagramPacketCodec<N, CM>>> {
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let outbound_framed = UdpFramed::new(
            outbound,
            DatagramPacketCodec::new(SessionCodec::new(
                Context::new(Mode::Client, None),
                AEADCipherCodec::new(config.cipher, &config.password).map_err(|e| anyhow!(e))?,
            )),
        );
        Ok(outbound_framed)
    }

    pub fn to_outbound_send(item: (BytesMut, &Address), proxy: SocketAddr) -> (DatagramPacket, SocketAddr) {
        let (content, target) = item;
        ((content, target.clone()), proxy)
    }

    pub fn to_inbound_recv(item: (DatagramPacket, SocketAddr), _: &Address, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        let (item, _) = item;
        (item, sender)
    }

    pub struct DatagramPacketCodec<const N: usize, CM> {
        session: Session<N>,
        codec: SessionCodec<N, CM>,
    }

    impl<const N: usize, CM> DatagramPacketCodec<N, CM> {
        pub fn new(codec: SessionCodec<N, CM>) -> Self {
            Self { session: Session::from(Mode::Client), codec }
        }
    }

    impl<const N: usize, CM: CipherMethod + KeyInit> Encoder<DatagramPacket> for DatagramPacketCodec<N, CM> {
        type Error = anyhow::Error;

        fn encode(&mut self, (content, addr): DatagramPacket, dst: &mut BytesMut) -> anyhow::Result<()> {
            self.codec.encode((content, addr, self.session.clone()), dst)
        }
    }

    impl<const N: usize, CM: CipherMethod + KeyInit> Decoder for DatagramPacketCodec<N, CM> {
        type Item = DatagramPacket;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> anyhow::Result<Option<Self::Item>> {
            if src.is_empty() {
                Ok(None)
            } else {
                match self.codec.decode(src)? {
                    Some((content, addr, session)) => {
                        self.session = session;
                        Ok(Some((content, addr)))
                    }
                    None => Ok(None),
                }
            }
        }
    }
}
