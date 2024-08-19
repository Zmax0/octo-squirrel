pub(crate) mod tcp {
    use bytes::BufMut;
    use bytes::BytesMut;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::socks5::address::AddressCodec;
    use octo_squirrel::common::protocol::socks5::Socks5CommandType;
    use octo_squirrel::common::protocol::trojan;
    use octo_squirrel::common::protocol::trojan::CodecStatus;
    use octo_squirrel::common::util::hex;
    use octo_squirrel::config::ServerConfig;
    use sha2::Digest;
    use sha2::Sha224;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;

    pub fn new_codec(addr: Address, config: &ServerConfig) -> ClientCodec {
        ClientCodec::new(config.password.as_bytes(), Socks5CommandType::Connect as u8, addr)
    }

    pub struct ClientCodec {
        key: [u8; 56],
        command: u8,
        address: Address,
        status: CodecStatus,
    }

    impl ClientCodec {
        pub(super) fn new(password: &[u8], command: u8, address: Address) -> Self {
            let mut hasher = Sha224::new();
            hasher.update(password);
            let hash: [u8; 28] = hasher.finalize().into();
            let mut key: [u8; 56] = [0; 56];
            key.copy_from_slice(hex::encode(&hash).as_bytes());
            Self { key, command, address, status: CodecStatus::Header }
        }
    }

    impl Encoder<BytesMut> for ClientCodec {
        type Error = anyhow::Error;

        fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
            if matches!(self.status, CodecStatus::Header) {
                dst.put_slice(&self.key);
                dst.put_slice(&trojan::CR_LF);
                dst.put_u8(self.command);
                AddressCodec::encode(&self.address, dst)?;
                dst.put_slice(&trojan::CR_LF);
                self.status = CodecStatus::Body;
            }
            dst.put(item);
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

pub(crate) mod udp {
    use std::fs;
    use std::net::SocketAddr;
    use std::net::ToSocketAddrs;

    use anyhow::bail;
    use anyhow::Result;
    use bytes::Buf;
    use bytes::BufMut;
    use bytes::BytesMut;
    use futures::stream::SplitSink;
    use futures::stream::SplitStream;
    use futures::StreamExt;
    use octo_squirrel::common::network::DatagramPacket;
    use octo_squirrel::common::protocol::address::Address;
    use octo_squirrel::common::protocol::socks5::address::AddressCodec;
    use octo_squirrel::common::protocol::socks5::Socks5CommandType;
    use octo_squirrel::common::protocol::trojan;
    use octo_squirrel::common::protocol::trojan::CodecStatus;
    use octo_squirrel::common::util::hex;
    use octo_squirrel::config::ServerConfig;
    use sha2::Digest;
    use sha2::Sha224;
    use tokio::net::TcpStream;
    use tokio_native_tls::native_tls;
    use tokio_native_tls::native_tls::Certificate;
    use tokio_native_tls::TlsConnector;
    use tokio_native_tls::TlsStream;
    use tokio_util::codec::Decoder;
    use tokio_util::codec::Encoder;
    use tokio_util::codec::Framed;

    pub fn new_key(sender: SocketAddr, _: SocketAddr) -> SocketAddr {
        sender
    }

    pub async fn new_tls_outbound(
        recipient: Address,
        config: &ServerConfig,
    ) -> Result<(SplitSink<Framed<TlsStream<TcpStream>, ClientCodec>, DatagramPacket>, SplitStream<Framed<TlsStream<TcpStream>, ClientCodec>>)> {
        let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, recipient);
        let outbound = TcpStream::connect(proxy).await?;
        if let Some(ssl_config) = &config.ssl {
            let pem = fs::read(ssl_config.certificate_file.as_str())?;
            let cert = Certificate::from_pem(&pem)?;
            let tls_connector = TlsConnector::from(native_tls::TlsConnector::builder().add_root_certificate(cert).use_sni(true).build()?);
            match tls_connector.connect(ssl_config.server_name.as_str(), outbound).await {
                Ok(outbound) => Ok(Framed::new(outbound, codec).split()),
                Err(e) => bail!("tls handshake failed: {}", e),
            }
        } else {
            bail!("require ssl config")
        }
    }

    pub async fn new_outbound(
        recipient: Address,
        config: &ServerConfig,
    ) -> Result<(SplitSink<Framed<TcpStream, ClientCodec>, DatagramPacket>, SplitStream<Framed<TcpStream, ClientCodec>>)> {
        let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
        let codec = ClientCodec::new(config.password.as_bytes(), Socks5CommandType::UdpAssociate as u8, recipient);
        let outbound = TcpStream::connect(proxy).await?;
        Ok(Framed::new(outbound, codec).split())
    }

    pub(crate) fn to_outbound_send(item: (DatagramPacket, SocketAddr), _: SocketAddr) -> DatagramPacket {
        item.0
    }

    pub(crate) fn to_inbound_recv(item: DatagramPacket, _: SocketAddr, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        (item, sender)
    }

    pub struct ClientCodec {
        key: [u8; 56],
        command: u8,
        address: Address,
        status: CodecStatus,
    }

    impl ClientCodec {
        pub(super) fn new(password: &[u8], command: u8, address: Address) -> Self {
            let mut hasher = Sha224::new();
            hasher.update(password);
            let hash: [u8; 28] = hasher.finalize().into();
            let mut key: [u8; 56] = [0; 56];
            key.copy_from_slice(hex::encode(&hash).as_bytes());
            Self { key, command, address, status: CodecStatus::Header }
        }
    }

    impl Encoder<DatagramPacket> for ClientCodec {
        type Error = anyhow::Error;

        fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
            if matches!(self.status, CodecStatus::Header) {
                dst.put_slice(&self.key);
                dst.put_slice(&trojan::CR_LF);
                dst.put_u8(self.command);
                AddressCodec::encode(&self.address, dst)?;
                dst.put_slice(&trojan::CR_LF);
                self.status = CodecStatus::Body;
            }
            let buffer = &mut BytesMut::new();
            AddressCodec::encode(&item.1.into(), buffer)?;
            buffer.put_u16(item.0.len() as u16);
            buffer.put_slice(&trojan::CR_LF);
            buffer.put(item.0);
            dst.put(buffer);
            Ok(())
        }
    }

    impl Decoder for ClientCodec {
        type Item = DatagramPacket;

        type Error = anyhow::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            if !src.is_empty() {
                let addr = AddressCodec::decode(src)?;
                let len = src.get_u16();
                src.advance(trojan::CR_LF.len());
                let content = src.split_to(len as usize);
                Ok(Some((content, addr.into())))
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use octo_squirrel::common::util::hex;
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
