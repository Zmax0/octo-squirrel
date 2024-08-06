pub(crate) mod tcp {
    use octo_squirrel::common::codec::shadowsocks::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::PayloadCodec;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::Context;
    use octo_squirrel::common::protocol::shadowsocks::StreamType;
    use octo_squirrel::config::ServerConfig;

    pub fn new_payload_codec(addr: Address, config: &ServerConfig) -> PayloadCodec {
        PayloadCodec::new(
            Context::tcp(StreamType::Request, Some(addr)),
            AEADCipherCodec::new(config.cipher, config.password.as_bytes()).expect("create aead cipher codec error"),
        )
    }
}

pub(crate) mod udp {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use futures::stream::SplitSink;
    use futures::stream::SplitStream;
    use futures::StreamExt;
    use octo_squirrel::common::codec::shadowsocks::AEADCipherCodec;
    use octo_squirrel::common::codec::shadowsocks::DatagramPacketCodec;
    use octo_squirrel::common::network::DatagramPacket;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::Context;
    use octo_squirrel::common::protocol::shadowsocks::StreamType;
    use octo_squirrel::config::ServerConfig;
    use tokio::net::UdpSocket;
    use tokio_util::udp::UdpFramed;

    pub fn new_key(from: SocketAddr, _: SocketAddr) -> SocketAddr {
        from
    }

    pub async fn new_outbound(
        _: Address,
        config: &ServerConfig,
    ) -> Result<(SplitSink<UdpFramed<DatagramPacketCodec>, (DatagramPacket, SocketAddr)>, SplitStream<UdpFramed<DatagramPacketCodec>>), anyhow::Error>
    {
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let outbound_framed = UdpFramed::new(
            outbound,
            DatagramPacketCodec::new(Context::udp(StreamType::Request, None), AEADCipherCodec::new(config.cipher, config.password.as_bytes())?),
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
