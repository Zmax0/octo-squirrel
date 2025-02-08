enum CodecState {
    Header,
    Body,
}

pub(super) mod tcp {
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::socks5::address;
    use octo_squirrel::protocol::socks5::Socks5CommandType;
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
    use std::net::SocketAddr;

    use anyhow::anyhow;
    use anyhow::Result;
    use octo_squirrel::codec::DatagramPacket;
    use octo_squirrel::codec::QuicStream;
    use octo_squirrel::codec::WebSocketFramed;
    use octo_squirrel::config::ServerConfig;
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::socks5::address;
    use octo_squirrel::protocol::socks5::Socks5CommandType;
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
    use crate::client::config::SslConfig;
    use crate::client::template;

    pub fn new_key(sender: SocketAddr, _: &Address) -> SocketAddr {
        sender
    }

    pub async fn new_quic_outbound(target: &Address, config: &ServerConfig<SslConfig>) -> Result<Framed<QuicStream, ClientCodec>> {
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, target.clone());
        let quic_config = config.quic.as_ref().ok_or(anyhow!("config.quic is empty"))?;
        template::new_quic_outbound(&config.host, config.port, codec, quic_config).await
    }

    pub async fn new_tls_outbound(target: &Address, config: &ServerConfig<SslConfig>) -> Result<Framed<TlsStream<TcpStream>, ClientCodec>> {
        let ssl_config = config.ssl.as_ref().ok_or(anyhow!("require ssl config"))?;
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, target.clone());
        template::new_tls_outbound(&config.host, config.port, codec, ssl_config).await
    }

    pub async fn new_wss_outbound(
        target: &Address,
        config: &ServerConfig<SslConfig>,
    ) -> Result<WebSocketFramed<TlsStream<TcpStream>, ClientCodec, DatagramPacket, DatagramPacket>> {
        let ssl_config = config.ssl.as_ref().ok_or(anyhow!("require ssl config"))?;
        let ws_config = config.ws.as_ref().ok_or(anyhow!("require ws config"))?;
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, target.clone());
        template::new_wss_outbound(&config.host, config.port, codec, ssl_config, ws_config).await
    }

    pub fn to_outbound_send(item: DatagramPacket, _: SocketAddr) -> DatagramPacket {
        let (content, target) = item;
        (content, target)
    }

    pub fn to_inbound_recv(item: DatagramPacket, _: &Address, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        (item, sender)
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
    use sha2::digest::typenum::Unsigned;
    use sha2::digest::OutputSizeUser;
    use sha2::Digest;
    use sha2::Sha224;
    #[test]
    fn test() {
        let mut hasher = Sha224::new();
        hasher.update(b"password1");
        let res = hasher.finalize();
        let res: [u8; <Sha224 as OutputSizeUser>::OutputSize::USIZE] = res.into();
        assert_eq!("9440e64e095ff718c1926110fd811e64948984c9dee7ef860feb4d5d", hex::encode(&res))
    }
}
