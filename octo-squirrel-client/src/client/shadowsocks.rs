use std::sync::Arc;

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

pub(super) mod tcp {
    use std::sync::Arc;

    use octo_squirrel::common::codec::aead::CipherMethod;
    use octo_squirrel::common::codec::aead::KeyInit;
    use octo_squirrel::common::codec::shadowsocks::tcp::Context;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::shadowsocks::Mode;
    use octo_squirrel::config::ServerConfig;

    use super::PayloadCodec;

    pub fn new_payload_codec<const N: usize, CM: CipherMethod + KeyInit>(addr: Address, config: &ServerConfig) -> PayloadCodec<N, CM> {
        PayloadCodec::new(Arc::new(Context::default()), config, Mode::Client, Some(addr), None)
    }
}

pub(super) mod udp {
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use anyhow::anyhow;
    use futures::stream::SplitSink;
    use futures::stream::SplitStream;
    use futures::StreamExt;
    use octo_squirrel::common::codec::aead::CipherMethod;
    use octo_squirrel::common::codec::aead::KeyInit;
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

    pub async fn new_outbound<const N: usize, CM: CipherMethod + KeyInit>(
        _: Address,
        config: &ServerConfig,
    ) -> Result<
        (SplitSink<UdpFramed<DatagramPacketCodec<N, CM>>, (DatagramPacket, SocketAddr)>, SplitStream<UdpFramed<DatagramPacketCodec<N, CM>>>),
        anyhow::Error,
    > {
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let outbound_framed = UdpFramed::new(
            outbound,
            DatagramPacketCodec::new(
                Context::udp(Mode::Client, None),
                AEADCipherCodec::new(config.cipher, config.password.as_bytes()).map_err(|e| anyhow!(e))?,
            ),
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
    ) -> Self {
        let session = Session::new(mode, Identity::default(), context, address, user_manager);
        Self { session, cipher: AEADCipherCodec::new(config.cipher, config.password.as_str()).unwrap() }
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
