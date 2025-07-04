use std::net::SocketAddr;

use octo_squirrel::codec::DatagramPacket;
use octo_squirrel::protocol::address::Address;

use crate::client::config::ServerConfig;
use crate::client::template::UdpDnsContext;
use crate::client::template::UdpOutbound;
use crate::client::template::UdpOutboundContext;

enum CodecState {
    Header,
    Body,
}

pub struct Trojan;

impl UdpDnsContext for Trojan {
    type Codec = tcp::ClientCodec;
    type Context = ServerConfig;

    fn new_context(config: &ServerConfig) -> anyhow::Result<ServerConfig> {
        Ok(config.clone())
    }

    fn new_codec(target: &Address, context: Self::Context) -> anyhow::Result<Self::Codec> {
        tcp::new_codec(target, context.password.clone())
    }
}

impl UdpOutboundContext for Trojan {
    type Key = SocketAddr;

    type Context = ServerConfig;

    fn new_key(sender: std::net::SocketAddr, _: &Address) -> Self::Key {
        sender
    }

    fn new_context(config: &ServerConfig) -> anyhow::Result<Self::Context> {
        Ok(config.clone())
    }
}

impl UdpOutbound for Trojan {
    type OutboundIn = DatagramPacket;

    type OutboundOut = DatagramPacket;

    fn to_outbound_out(item: octo_squirrel::codec::DatagramPacket, _: SocketAddr) -> Self::OutboundOut {
        let (content, target) = item;
        (content, target)
    }

    fn to_inbound_in(item: Self::OutboundIn, _: &Address, sender: SocketAddr) -> (octo_squirrel::codec::DatagramPacket, SocketAddr) {
        (item, sender)
    }
}

pub(super) mod tcp {
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::socks5::Socks5CommandType;
    use octo_squirrel::protocol::socks5::address;
    use octo_squirrel::protocol::trojan;
    use octo_squirrel::util::hex;
    use sha2::Digest;
    use sha2::Sha224;
    use tokio_util::bytes::BufMut;
    use tokio_util::bytes::BytesMut;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    use super::CodecState;

    pub fn new_codec(addr: &Address, password: String) -> anyhow::Result<ClientCodec> {
        Ok(ClientCodec::new(password.as_bytes(), Socks5CommandType::Connect as u8, addr.clone()))
    }

    pub struct ClientCodec {
        key: [u8; 56],
        command: u8,
        address: Address,
        status: CodecState,
    }

    impl ClientCodec {
        pub fn new(password: &[u8], command: u8, address: Address) -> Self {
            let mut hasher = Sha224::new();
            hasher.update(password);
            let hash: [u8; 28] = hasher.finalize().into();
            let mut key: [u8; 56] = [0; 56];
            key.copy_from_slice(hex::encode(&hash).as_bytes());
            Self { key, command, address, status: CodecState::Header }
        }
    }

    impl Encoder<BytesMut> for ClientCodec {
        type Error = anyhow::Error;

        fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
            if matches!(self.status, CodecState::Header) {
                dst.extend_from_slice(&self.key);
                dst.extend_from_slice(&trojan::CR_LF);
                dst.put_u8(self.command);
                address::encode(&self.address, dst);
                dst.extend_from_slice(&trojan::CR_LF);
                self.status = CodecState::Body;
            }
            dst.extend_from_slice(&item);
            Ok(())
        }
    }

    impl Decoder for ClientCodec {
        type Item = BytesMut;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            if !src.is_empty() {
                let len = src.len();
                Ok(Some(src.split_to(len)))
            } else {
                Ok(None)
            }
        }
    }
}

pub(super) mod udp {
    use anyhow::Result;
    use anyhow::bail;
    use octo_squirrel::codec::DatagramPacket;
    use octo_squirrel::codec::QuicStream;
    use octo_squirrel::codec::WebSocketStream;
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::socks5::Socks5CommandType;
    use octo_squirrel::protocol::socks5::address;
    use octo_squirrel::protocol::trojan;
    use octo_squirrel::util::hex;
    use sha2::Digest;
    use sha2::Sha224;
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;
    use tokio_util::bytes::Buf;
    use tokio_util::bytes::BufMut;
    use tokio_util::bytes::BytesMut;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;
    use tokio_util::codec::Framed;

    use super::CodecState;
    use crate::client::config::ServerConfig;
    use crate::client::template;

    pub async fn new_quic_outbound(target: &Address, config: &ServerConfig) -> Result<Framed<QuicStream, ClientCodec>> {
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, target.clone());
        if let Some(ssl_config) = &config.quic {
            template::new_quic_outbound(&config.host, config.port, codec, ssl_config).await
        } else {
            bail!("ssl config is required for quic outbound");
        }
    }

    pub async fn new_tls_outbound(target: &Address, config: &ServerConfig) -> Result<Framed<TlsStream<TcpStream>, ClientCodec>> {
        let codec: ClientCodec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, target.clone());
        if let Some(ssl_config) = &config.ssl {
            template::new_tls_outbound(&config.host, config.port, codec, ssl_config).await
        } else {
            bail!("ssl config is required for tls outbound");
        }
    }

    pub async fn new_wss_outbound(target: &Address, config: &ServerConfig) -> Result<Framed<WebSocketStream<TlsStream<TcpStream>>, ClientCodec>> {
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, target.clone());
        if let (Some(ssl_config), Some(ws_config)) = (&config.ssl, &config.ws) {
            template::new_wss_outbound(&config.host, config.port, codec, ssl_config, ws_config).await
        } else {
            bail!("ws config and ssl config are required for wss outbound");
        }
    }
    pub struct ClientCodec {
        key: [u8; 56],
        command: u8,
        address: Address,
        status: CodecState,
    }

    impl ClientCodec {
        pub fn new(password: &[u8], command: u8, address: Address) -> Self {
            let mut hasher = Sha224::new();
            hasher.update(password);
            let hash: [u8; 28] = hasher.finalize().into();
            let mut key: [u8; 56] = [0; 56];
            key.copy_from_slice(hex::encode(&hash).as_bytes());
            Self { key, command, address, status: CodecState::Header }
        }
    }

    impl Encoder<DatagramPacket> for ClientCodec {
        type Error = anyhow::Error;

        fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
            if matches!(self.status, CodecState::Header) {
                dst.extend_from_slice(&self.key);
                dst.extend_from_slice(&trojan::CR_LF);
                dst.put_u8(self.command);
                address::encode(&self.address, dst);
                dst.extend_from_slice(&trojan::CR_LF);
                self.status = CodecState::Body;
            }
            let buffer = &mut BytesMut::new();
            address::encode(&item.1, buffer);
            buffer.put_u16(item.0.len() as u16);
            buffer.extend_from_slice(&trojan::CR_LF);
            buffer.extend_from_slice(&item.0);
            dst.extend_from_slice(buffer);
            Ok(())
        }
    }

    impl Decoder for ClientCodec {
        type Item = DatagramPacket;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            if !src.is_empty() {
                let addr = address::decode(src)?;
                let len = src.get_u16();
                src.advance(trojan::CR_LF.len());
                let content = src.split_to(len as usize);
                Ok(Some((content, addr)))
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use octo_squirrel::util::hex;
    use sha2::Digest;
    use sha2::Sha224;
    use sha2::digest::OutputSizeUser;
    use sha2::digest::typenum::Unsigned;
    #[test]
    fn test() {
        let mut hasher = Sha224::new();
        hasher.update(b"password1");
        let res = hasher.finalize();
        let res: [u8; <Sha224 as OutputSizeUser>::OutputSize::USIZE] = res.into();
        assert_eq!("9440e64e095ff718c1926110fd811e64948984c9dee7ef860feb4d5d", hex::encode(&res))
    }
}
