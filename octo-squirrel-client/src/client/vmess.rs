use std::io::Cursor;
use std::mem::size_of;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use anyhow::bail;
use anyhow::Result;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use futures::SinkExt;
use futures::StreamExt;
use log::debug;
use log::info;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::codec::aead::CipherMethod;
use octo_squirrel::common::codec::vmess::aead::AEADBodyCodec;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::network::DatagramPacket;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::vmess::aead::*;
use octo_squirrel::common::protocol::vmess::header::RequestCommand;
use octo_squirrel::common::protocol::vmess::header::RequestHeader;
use octo_squirrel::common::protocol::vmess::header::RequestOption;
use octo_squirrel::common::protocol::vmess::header::SecurityType;
use octo_squirrel::common::protocol::vmess::session::ClientSession;
use octo_squirrel::common::protocol::vmess::AddressCodec;
use octo_squirrel::common::protocol::vmess::VERSION;
use octo_squirrel::common::util::Dice;
use octo_squirrel::common::util::FNV;
use octo_squirrel::config::ServerConfig;
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
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
        if let None = self.body_encoder {
            let mut header = BytesMut::new();
            header.put_u8(VERSION);
            header.put_slice(&self.session.request_body_iv);
            header.put_slice(&self.session.request_body_key);
            header.put_u8(self.session.response_header);
            header.put_u8(RequestOption::get_mask(&self.header.option)); // option mask
            let padding_len = rand::thread_rng().gen_range(0..16); // dice roll 16
            let security = self.header.security;
            header.put_u8((padding_len << 4) | security as u8);
            header.put_u8(0);
            header.put_u8(self.header.command as u8);
            AddressCodec::write_address_port(&self.header.address, &mut header)?; // address
            header.put_slice(&Dice::roll_bytes(padding_len as usize)); // padding
            header.put_u32(FNV::fnv1a32(&header));
            dst.put(&Encrypt::seal_header(&self.header.id, header.freeze())[..]);
            self.body_encoder = Some(AEADBodyCodec::encoder(&self.header, &mut self.session));
        }
        if self.header.command == RequestCommand::UDP {
            self.body_encoder.as_mut().unwrap().encode_packet(item, dst, &mut self.session);
        } else {
            self.body_encoder.as_mut().unwrap().encode_payload(item, dst, &mut self.session);
        }
        Ok(())
    }
}

impl Decoder for ClientAEADCodec {
    type Item = BytesMut;

    type Error = anyhow::Error;

    fn decode(&mut self, mut src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        if let None = self.body_decoder {
            let header_length_cipher = Aes128GcmCipher::new(&KDF::kdf16(&self.session.response_body_key, vec![KDF::SALT_AEAD_RESP_HEADER_LEN_KEY]));
            if src.remaining() < size_of::<u16>() + header_length_cipher.tag_size() {
                return Ok(None);
            }
            let header_length_iv: [u8; Aes128GcmCipher::NONCE_SIZE] =
                KDF::kdfn(&self.session.response_body_iv, vec![KDF::SALT_AEAD_RESP_HEADER_LEN_IV]);
            let mut cursor = Cursor::new(src);
            let header_length_bytes = cursor.copy_to_bytes(size_of::<u16>() + header_length_cipher.tag_size());
            let mut header_length_bytes = BytesMut::from(&header_length_bytes[..]);
            header_length_cipher.decrypt_in_place(&header_length_iv, b"", &mut header_length_bytes);
            let header_length = header_length_bytes.get_u16() as usize;
            if cursor.remaining() < header_length + header_length_cipher.tag_size() {
                info!(
                    "Unexpected readable bytes for decoding client header: expecting {} but actually {}",
                    header_length + header_length_cipher.tag_size(),
                    cursor.remaining()
                );
                return Ok(None);
            }
            let position = cursor.position();
            src = cursor.into_inner();
            src.advance(position as usize);
            let header_cipher = Aes128GcmCipher::new(&KDF::kdf16(&self.session.response_body_key, vec![KDF::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]));
            let header_iv: [u8; Aes128GcmCipher::NONCE_SIZE] = KDF::kdfn(&self.session.response_body_iv, vec![KDF::SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);
            let mut header_bytes = src.split_to(header_length + header_length_cipher.tag_size());
            header_cipher.decrypt_in_place(&header_iv, b"", &mut header_bytes);
            if self.session.response_header != header_bytes[0] {
                bail!("Unexpected response header: expecting {} but actually {}", self.session.response_header, header_bytes[0]);
            }
            self.body_decoder = Some(AEADBodyCodec::decoder(&self.header, &mut self.session));
        }
        return if self.header.command == RequestCommand::UDP {
            self.body_decoder.as_mut().unwrap().decode_packet(src, &mut self.session)
        } else {
            self.body_decoder.as_mut().unwrap().decode_payload(src, &mut self.session)
        };
    }
}

pub async fn transfer_tcp(inbound: TcpStream, addr: Address, config: ServerConfig) -> Result<()> {
    let security = if config.cipher == CipherKind::ChaCha20Poly1305 { SecurityType::Chacha20Poly1305 } else { SecurityType::Aes128Gcm };
    let header = RequestHeader::default(RequestCommand::TCP, security, addr, config.password);
    let outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
    let (mut inbound_sink, mut inbound_stream) = Framed::new(inbound, BytesCodec).split();
    let (mut outbound_sink, mut outbound_stream) = Framed::new(outbound, ClientAEADCodec::new(header)).split();

    let client_to_server = async { outbound_sink.send_all(&mut inbound_stream).await };
    let server_to_client = async { inbound_sink.send_all(&mut outbound_stream).await };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

pub fn get_udp_key(sender: SocketAddr, recipient: SocketAddr) -> (SocketAddr, SocketAddr) {
    (sender, recipient)
}

pub async fn transfer_udp_outbound(
    config: &ServerConfig,
    sender: SocketAddr,
    recipient: SocketAddr,
    callback: Sender<(DatagramPacket, SocketAddr)>,
) -> Result<Sender<(DatagramPacket, SocketAddr)>> {
    let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
    let outbound = TcpStream::connect(proxy.clone()).await?;
    let outbound_local_addr = outbound.local_addr()?;
    debug!("New udp binding; sender={}, outbound={}", sender, outbound_local_addr);
    let security = if config.cipher == CipherKind::ChaCha20Poly1305 { SecurityType::Chacha20Poly1305 } else { SecurityType::Aes128Gcm };
    let header = RequestHeader::default(RequestCommand::UDP, security, recipient.into(), config.password.clone());
    let outbound = Framed::new(outbound, ClientAEADCodec::new(header));
    let (mut outbound_sink, mut outbound_stream) = outbound.split();
    let (tx, mut rx) = mpsc::channel::<(DatagramPacket, SocketAddr)>(32);
    tokio::spawn(async move {
        while let Some(((content, _), _)) = rx.recv().await {
            outbound_sink.send(content).await.expect("Failed to send");
        }
    });
    tokio::spawn(async move {
        while let Some(Ok(content)) = outbound_stream.next().await {
            callback.send(((content, recipient), sender)).await.expect("Failed to send");
        }
        debug!("No item in outbound stream; sender={}, outbound={}", sender, outbound_local_addr);
        Ok::<(), anyhow::Error>(())
    });
    Ok(tx.clone())
}
