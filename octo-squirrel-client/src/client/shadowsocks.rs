pub(crate) mod tcp {
    use std::sync::Arc;

    use octo_squirrel::common::codec::shadowsocks::tcp::Context;
    use octo_squirrel::common::codec::shadowsocks::tcp::PayloadCodec;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;

    pub fn new_payload_codec<const N: usize>(addr: Address, config: &ServerConfig) -> PayloadCodec<N> {
        PayloadCodec::new(Arc::new(Context::default()), config, addr, Mode::Client, None)
    }
}

pub(crate) mod udp {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use futures::stream::SplitSink;
    use futures::stream::SplitStream;
    use futures::StreamExt;
    use octo_squirrel::common::codec::shadowsocks::udp::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::udp::DatagramPacketCodec;
    use octo_squirrel::common::network::DatagramPacket;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::udp::Context;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;
    use tokio::net::UdpSocket;
    use tokio_util::udp::UdpFramed;

    pub fn new_key(from: SocketAddr, _: SocketAddr) -> SocketAddr {
        from
    }

    pub async fn new_outbound<const N: usize>(
        _: Address,
        config: &ServerConfig,
    ) -> Result<
        (SplitSink<UdpFramed<DatagramPacketCodec<N>>, (DatagramPacket, SocketAddr)>, SplitStream<UdpFramed<DatagramPacketCodec<N>>>),
        anyhow::Error,
    > {
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let outbound_framed = UdpFramed::new(
            outbound,
            DatagramPacketCodec::new(Context::udp(Mode::Client, None), AEADCipherCodec::new(config.cipher, config.password.as_bytes())?),
        );
        Ok(outbound_framed.split())
    }

    pub fn to_outbound_send(item: (DatagramPacket, SocketAddr), proxy: SocketAddr) -> (DatagramPacket, SocketAddr) {
        (item.0, proxy)
    }

    pub fn to_inbound_recv(item: (DatagramPacket, SocketAddr), _: SocketAddr, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        (item.0, sender)
    }
}
