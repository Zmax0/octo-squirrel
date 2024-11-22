use std::io::Cursor;
use std::mem::size_of;
use std::net::SocketAddr;

use aes_gcm::aes::cipher::Unsigned;
use aes_gcm::AeadCore;
use aes_gcm::AeadInPlace;
use aes_gcm::Aes128Gcm;
use aes_gcm::KeyInit;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use log::debug;
use log::info;
use octo_squirrel::codec::vmess::aead::AEADBodyCodec;
use octo_squirrel::protocol::vmess::address;
use octo_squirrel::protocol::vmess::aead::*;
use octo_squirrel::protocol::vmess::header::RequestCommand;
use octo_squirrel::protocol::vmess::header::RequestHeader;
use octo_squirrel::protocol::vmess::header::RequestOption;
use octo_squirrel::protocol::vmess::session::ClientSession;
use octo_squirrel::protocol::vmess::VERSION;
use octo_squirrel::util::dice;
use octo_squirrel::util::fnv;
use rand::Rng;
use tokio::net::TcpStream;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;

pub struct ClientAEADCodec {
    header: RequestHeader,
    session: ClientSession,
    body_encoder: Option<AEADBodyCodec>,
    body_decoder: Option<AEADBodyCodec>,
}

impl ClientAEADCodec {
    pub fn new(header: RequestHeader) -> Self {
        let session = ClientSession::new();
        debug!("New session; {}", session);
        Self { header, session, body_encoder: None, body_decoder: None }
    }
}

impl Encoder<BytesMut> for ClientAEADCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self.body_encoder {
            None => {
                let mut header = BytesMut::new();
                header.put_u8(VERSION);
                header.extend_from_slice(&self.session.request_body_iv);
                header.extend_from_slice(&self.session.request_body_key);
                header.put_u8(self.session.response_header);
                header.put_u8(RequestOption::get_mask(&self.header.option)); // option mask
                let padding_len = rand::thread_rng().gen_range(0..16); // dice roll 16
                let security = self.header.security;
                header.put_u8((padding_len << 4) | security as u8);
                header.put_u8(0);
                header.put_u8(self.header.command as u8);
                address::write_address_port(&self.header.address, &mut header)?; // address
                header.extend_from_slice(&dice::roll_bytes(padding_len as usize)); // padding
                header.put_u32(fnv::fnv1a32(&header));
                dst.extend_from_slice(&encrypt::seal_header(&self.header.id, header.freeze())?);
                self.body_encoder = Some(AEADBodyCodec::new_encoder(&self.header, &mut self.session)?);
                self.encode(item, dst)
            }
            Some(ref mut encoder) => match self.header.command {
                RequestCommand::TCP => encoder.encode_payload(item, dst, &mut self.session).map_err(|e| anyhow!(e)),
                RequestCommand::UDP => encoder.encode_packet(item, dst, &mut self.session).map_err(|e| anyhow!(e)),
            },
        }
    }
}

impl Decoder for ClientAEADCodec {
    type Item = BytesMut;

    type Error = anyhow::Error;

    fn decode(&mut self, mut src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        match self.body_decoder {
            None => {
                const NONCE_SIZE: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;
                const TAG_SIZE: usize = <Aes128Gcm as AeadCore>::TagSize::USIZE;
                let header_length_cipher =
                    Aes128Gcm::new_from_slice(&kdf::kdf16(&self.session.response_body_key, vec![kdf::SALT_AEAD_RESP_HEADER_LEN_KEY]))?;
                if src.remaining() < size_of::<u16>() + TAG_SIZE {
                    return Ok(None);
                }
                let header_length_iv: [u8; NONCE_SIZE] = kdf::kdfn(&self.session.response_body_iv, vec![kdf::SALT_AEAD_RESP_HEADER_LEN_IV]);
                let mut cursor = Cursor::new(src);
                let header_length_bytes = cursor.copy_to_bytes(size_of::<u16>() + TAG_SIZE);
                let mut header_length_bytes = BytesMut::from(&header_length_bytes[..]);
                header_length_cipher.decrypt_in_place(&header_length_iv.into(), &[], &mut header_length_bytes).map_err(|e| anyhow!(e))?;
                let header_length = header_length_bytes.get_u16() as usize;
                if cursor.remaining() < header_length + TAG_SIZE {
                    info!(
                        "Unexpected readable bytes for decoding client header: expecting {} but actually {}",
                        header_length + TAG_SIZE,
                        cursor.remaining()
                    );
                    return Ok(None);
                }
                let position = cursor.position();
                src = cursor.into_inner();
                src.advance(position as usize);
                let header_cipher =
                    Aes128Gcm::new_from_slice(&kdf::kdf16(&self.session.response_body_key, vec![kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]))?;
                let header_iv: [u8; NONCE_SIZE] = kdf::kdfn(&self.session.response_body_iv, vec![kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);
                let mut header_bytes = src.split_to(header_length + TAG_SIZE);
                header_cipher.decrypt_in_place(&header_iv.into(), &[], &mut header_bytes).map_err(|e| anyhow!(e))?;
                if self.session.response_header != header_bytes[0] {
                    bail!("Unexpected response header: expecting {} but actually {}", self.session.response_header, header_bytes[0]);
                }
                self.body_decoder = Some(AEADBodyCodec::new_decoder(&self.header, &mut self.session)?);
                self.decode(src)
            }
            Some(ref mut decoder) => match self.header.command {
                RequestCommand::TCP => decoder.decode_payload(src, &mut self.session).map_err(|e| anyhow!(e)),
                RequestCommand::UDP => decoder.decode_packet(src, &mut self.session).map_err(|e| anyhow!(e)),
            },
        }
    }
}

pub(super) mod tcp {
    use std::sync::Arc;

    use octo_squirrel::codec::aead::CipherKind;
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::vmess::header::RequestCommand;
    use octo_squirrel::protocol::vmess::header::RequestHeader;
    use octo_squirrel::protocol::vmess::header::SecurityType;

    use super::ClientAEADCodec;

    pub fn new_codec(addr: &Address, (kind, password): (CipherKind, Arc<String>)) -> anyhow::Result<ClientAEADCodec> {
        let security = if kind == CipherKind::ChaCha20Poly1305 { SecurityType::Chacha20Poly1305 } else { SecurityType::Aes128Gcm };
        let header = RequestHeader::default(RequestCommand::TCP, security, addr.clone(), &password)?;
        Ok(ClientAEADCodec::new(header))
    }
}

pub(super) mod udp {
    use std::net::SocketAddr;

    use anyhow::anyhow;
    use anyhow::Result;
    use bytes::BytesMut;
    use octo_squirrel::codec::aead::CipherKind;
    use octo_squirrel::codec::DatagramPacket;
    use octo_squirrel::codec::WebSocketFramed;
    use octo_squirrel::config::ServerConfig;
    use octo_squirrel::protocol::address::Address;
    use octo_squirrel::protocol::vmess::header::RequestCommand;
    use octo_squirrel::protocol::vmess::header::RequestHeader;
    use octo_squirrel::protocol::vmess::header::SecurityType;
    use tokio::net::TcpStream;
    use tokio_native_tls::TlsStream;
    use tokio_util::codec::Framed;

    use super::ClientAEADCodec;
    use crate::client::template;

    pub fn new_key(sender: SocketAddr, target: &Address) -> (SocketAddr, Address) {
        (sender, target.clone())
    }

    pub fn new_codec(addr: &Address, config: &ServerConfig) -> Result<ClientAEADCodec> {
        let security = if config.cipher == CipherKind::ChaCha20Poly1305 { SecurityType::Chacha20Poly1305 } else { SecurityType::Aes128Gcm };
        let header = RequestHeader::default(RequestCommand::UDP, security, addr.clone(), &config.password)?;
        Ok(ClientAEADCodec::new(header))
    }

    pub async fn new_plain_outbound(server_addr: SocketAddr, target: &Address, config: &ServerConfig) -> Result<Framed<TcpStream, ClientAEADCodec>> {
        let codec = new_codec(target, config)?;
        super::new_plain_outbound(server_addr, codec).await
    }

    pub async fn new_ws_outbound(
        server_addr: SocketAddr,
        target: &Address,
        config: &ServerConfig,
    ) -> Result<WebSocketFramed<TcpStream, ClientAEADCodec, BytesMut, BytesMut>> {
        let codec = new_codec(target, config)?;
        let ws_config = config.ws.as_ref().ok_or(anyhow!("require ws config"))?;
        template::new_ws_outbound(server_addr, codec, ws_config).await
    }

    pub async fn new_tls_outbound(
        server_addr: SocketAddr,
        target: &Address,
        config: &ServerConfig,
    ) -> Result<Framed<TlsStream<TcpStream>, ClientAEADCodec>> {
        let ssl_config = config.ssl.as_ref().ok_or(anyhow!("require ssl config"))?;
        let codec = new_codec(target, config)?;
        template::new_tls_outbound(server_addr, codec, ssl_config).await
    }

    pub async fn new_wss_outbound(
        server_addr: SocketAddr,
        target: &Address,
        config: &ServerConfig,
    ) -> Result<WebSocketFramed<TlsStream<TcpStream>, ClientAEADCodec, BytesMut, BytesMut>> {
        let ssl_config = config.ssl.as_ref().ok_or(anyhow!("require ssl config"))?;
        let ws_config = config.ws.as_ref().ok_or(anyhow!("require ws config"))?;
        let codec = new_codec(target, config)?;
        template::new_wss_outbound(server_addr, codec, ssl_config, ws_config).await
    }

    pub fn to_outbound_send(item: DatagramPacket, _: SocketAddr) -> BytesMut {
        item.0
    }

    pub fn to_inbound_recv(item: BytesMut, recipient: &Address, sender: SocketAddr) -> (DatagramPacket, SocketAddr) {
        ((item, recipient.clone()), sender)
    }
}

pub async fn new_plain_outbound(server_addr: SocketAddr, codec: ClientAEADCodec) -> Result<Framed<TcpStream, ClientAEADCodec>> {
    let outbound = TcpStream::connect(server_addr).await?;
    Ok(Framed::new(outbound, codec))
}
