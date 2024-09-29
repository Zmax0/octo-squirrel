pub(super) mod tcp {
    use std::sync::Arc;

    use anyhow::anyhow;
    use anyhow::Result;
    use bytes::BytesMut;
    use octo_squirrel::common::codec::shadowsocks::tcp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::tcp::Context;
    use octo_squirrel::common::codec::shadowsocks::tcp::Identity;
    use octo_squirrel::common::codec::shadowsocks::tcp::Session;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::aead;
    use octo_squirrel::common::protocol::shadowsocks::aead_2022;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

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
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use anyhow::anyhow;
    use bytes::BytesMut;
    use octo_squirrel::common::codec::aead::CipherKind;
    use octo_squirrel::common::codec::shadowsocks::udp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::udp::Context;
    use octo_squirrel::common::codec::shadowsocks::udp::Session;
    use octo_squirrel::common::codec::shadowsocks::udp::SessionCodec;
    use octo_squirrel::common::codec::DatagramPacket;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::aead_2022::password_to_keys;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;
    use tokio::net::UdpSocket;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;
    use tokio_util::udp::UdpFramed;

    #[derive(Clone, Copy)]
    pub struct Client<'a, const N: usize> {
        kind: CipherKind,
        key: &'a [u8],
        identity_keys: &'a [[u8; N]],
    }

    impl<const N: usize> Client<'_, N> {
        pub fn new_static(config: ServerConfig) -> anyhow::Result<Client<'static, N>> {
            let (key, identity_keys) = password_to_keys(&config.password).map_err(|e| anyhow!(e))?;
            let key: &'static [u8; N] = Box::leak::<'static>(Box::new(key));
            let identity_keys: &'static Vec<[u8; N]> = Box::leak::<'static>(Box::new(identity_keys));
            Ok(Client::<'static> { kind: config.cipher, key, identity_keys })
        }
    }

    pub async fn new_plain_outbound<'a, const N: usize>(
        _: SocketAddr,
        _: &Address,
        client: &Client<'a, N>,
    ) -> anyhow::Result<UdpFramed<DatagramPacketCodec<'a, N>>> {
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let outbound_framed = UdpFramed::new(
            outbound,
            DatagramPacketCodec::new(SessionCodec::new(
                Context::new(Mode::Client, None, client.key, client.identity_keys),
                AEADCipherCodec::new(client.kind).map_err(|e| anyhow!(e))?,
            )),
        );
        Ok(outbound_framed)
    }

    pub fn new_key(from: SocketAddr, to: &Address) -> (SocketAddr, Address) {
        (from, to.clone())
    }

    pub fn to_outbound_send(item: (BytesMut, &Address), proxy: SocketAddr) -> (DatagramPacket, SocketAddr) {
        let (content, target) = item;
        ((content, target.clone()), proxy)
    }

    pub fn to_inbound_recv(item: (DatagramPacket, SocketAddr), _: &Address, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        let (item, _) = item;
        (item, sender)
    }

    pub struct DatagramPacketCodec<'a, const N: usize> {
        session: Session<N>,
        codec: SessionCodec<'a, N>,
    }

    impl<const N: usize> DatagramPacketCodec<'_, N> {
        pub fn new(codec: SessionCodec<N>) -> DatagramPacketCodec<'_, N> {
            DatagramPacketCodec { session: Session::from(Mode::Client), codec }
        }
    }

    impl<const N: usize> Encoder<DatagramPacket> for DatagramPacketCodec<'_, N> {
        type Error = anyhow::Error;

        fn encode(&mut self, (content, addr): DatagramPacket, dst: &mut BytesMut) -> anyhow::Result<()> {
            self.codec.encode((content, addr, self.session.clone()), dst)
        }
    }

    impl<const N: usize> Decoder for DatagramPacketCodec<'_, N> {
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
