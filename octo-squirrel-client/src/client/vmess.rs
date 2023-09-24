use std::error;
use std::io;
use std::io::Cursor;
use std::io::ErrorKind;
use std::mem::size_of;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use dashmap::mapref::entry::Entry::Vacant;
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::SinkExt;
use futures::StreamExt;
use log::debug;
use log::info;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::Cipher;
use octo_squirrel::common::codec::aead::CipherDecoder;
use octo_squirrel::common::codec::aead::CipherEncoder;
use octo_squirrel::common::codec::aead::SupportedCipher;
use octo_squirrel::common::codec::vmess::AEADBodyCodec;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandRequest;
use octo_squirrel::common::protocol::socks5::Socks5CommandType;
use octo_squirrel::common::protocol::vmess::aead::*;
use octo_squirrel::common::protocol::vmess::header::RequestCommand;
use octo_squirrel::common::protocol::vmess::header::RequestHeader;
use octo_squirrel::common::protocol::vmess::header::RequestOption;
use octo_squirrel::common::protocol::vmess::header::SecurityType;
use octo_squirrel::common::protocol::vmess::session::ClientSession;
use octo_squirrel::common::protocol::vmess::session::Session;
use octo_squirrel::common::protocol::vmess::Address;
use octo_squirrel::common::protocol::vmess::VERSION;
use octo_squirrel::common::util::Dice;
use octo_squirrel::common::util::FNV;
use octo_squirrel::config::ServerConfig;
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::BytesCodec;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

use crate::client::transfer;

struct ClientAEADCodec {
    header: RequestHeader,
    session: ClientSession,
    body_encoder: Option<Box<dyn CipherEncoder>>,
    body_decoder: Option<Box<dyn CipherDecoder>>,
}

impl ClientAEADCodec {
    pub fn new(header: RequestHeader) -> Self {
        let session = ClientSession::new();
        debug!("New session; {}", session);
        Self { header, session, body_encoder: None, body_decoder: None }
    }
}

impl Encoder<BytesMut> for ClientAEADCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if let None = self.body_encoder {
            let mut buffer = BytesMut::new();
            buffer.put_u8(VERSION);
            buffer.put_slice(&self.session.request_body_iv().lock().unwrap());
            buffer.put_slice(self.session.request_body_key());
            buffer.put_u8(self.session.response_header());
            buffer.put_u8(RequestOption::get_mask(&self.header.option)); // option mask
            let padding_len = rand::thread_rng().gen_range(0..16); // dice roll 16
            let security = self.header.security;
            buffer.put_u8((padding_len << 4) | security.0);
            buffer.put_u8(0);
            buffer.put_u8(self.header.command.0);
            Address::write_address_port(&self.header.address, &mut buffer)?; // address
            buffer.put_slice(&Dice::roll_bytes(padding_len as usize)); // padding
            buffer.put_u32(FNV::fnv1a32(&buffer));
            let header_bytes = Encrypt::seal_header(&self.header.id, &buffer);
            dst.put_slice(&header_bytes);
            self.body_encoder = Some(AEADBodyCodec::encoder(&self.header, &self.session));
        }
        if self.header.command == RequestCommand::UDP {
            self.body_encoder.as_mut().unwrap().encode_packet(item, dst);
        } else {
            self.body_encoder.as_mut().unwrap().encode_payload(item, dst);
        }
        Ok(())
    }
}

impl Decoder for ClientAEADCodec {
    type Item = BytesMut;

    type Error = io::Error;

    fn decode(&mut self, mut src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        if let None = self.body_decoder {
            let header_length_cipher = Aes128GcmCipher::new(&KDF::kdf16(self.session.response_body_key(), vec![KDF::SALT_AEAD_RESP_HEADER_LEN_KEY]));
            if src.remaining() < size_of::<u16>() + header_length_cipher.tag_size() {
                return Ok(None);
            }
            let header_length_iv: [u8; Aes128GcmCipher::NONCE_SIZE] =
                KDF::kdfn(&self.session.response_body_iv().lock().unwrap(), vec![KDF::SALT_AEAD_RESP_HEADER_LEN_IV]);
            let mut cursor = Cursor::new(src);
            let header_length_encrypt_bytes = cursor.copy_to_bytes(size_of::<u16>() + header_length_cipher.tag_size());
            let mut header_length_bytes = [0; size_of::<u16>()];
            header_length_bytes
                .copy_from_slice(&header_length_cipher.decrypt(&header_length_iv, &header_length_encrypt_bytes[..], b"")[..size_of::<u16>()]);
            let header_length = u16::from_be_bytes(header_length_bytes) as usize;
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
            let header_cipher = Aes128GcmCipher::new(&KDF::kdf16(self.session.response_body_key(), vec![KDF::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]));
            let header_iv: [u8; Aes128GcmCipher::NONCE_SIZE] =
                KDF::kdfn(&self.session.response_body_iv().lock().unwrap(), vec![KDF::SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);
            let header_encrypt_bytes = src.split_to(header_length + header_length_cipher.tag_size());
            let header_bytes = header_cipher.decrypt(&header_iv, &header_encrypt_bytes, b"");
            if self.session.response_header() != header_bytes[0] {
                let error = format!("Unexpected response header: expecting {} but actually {}", self.session.response_header(), header_bytes[0]);
                return Err(io::Error::new(ErrorKind::InvalidData, error));
            }
            self.body_decoder = Some(AEADBodyCodec::decoder(&self.header, &self.session));
        }
        return if self.header.command == RequestCommand::UDP {
            self.body_decoder.as_mut().unwrap().decode_packet(src)
        } else {
            self.body_decoder.as_mut().unwrap().decode_payload(src)
        };
    }
}

pub async fn transfer_tcp(inbound: TcpStream, request: Socks5CommandRequest, config: ServerConfig) -> Result<(), Box<dyn error::Error>> {
    let security = if config.cipher == SupportedCipher::ChaCha20Poly1305 { SecurityType::CHACHA20_POLY1305 } else { SecurityType::AES128_GCM };
    let header = RequestHeader::default(RequestCommand::TCP, security, request, config.password);
    let outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
    let (mut inbound_sink, mut inbound_stream) = Framed::new(inbound, BytesCodec::new()).split();
    let (mut outbound_sink, mut outbound_stream) = Framed::new(outbound, ClientAEADCodec::new(header)).split();

    let client_to_server = async { outbound_sink.send_all(&mut inbound_stream).await };
    let server_to_client = async { inbound_sink.send_all(&mut outbound_stream).await };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

pub async fn transfer_udp(
    mut inbound_stream: SplitStream<UdpFramed<Socks5UdpCodec>>,
    inbound_sender: Sender<((BytesMut, SocketAddr), SocketAddr)>,
    config: ServerConfig,
) -> Result<(), io::Error> {
    let binding: Arc<DashMap<(SocketAddr, SocketAddr), SplitSink<Framed<TcpStream, ClientAEADCodec>, BytesMut>>> = Arc::new(DashMap::new());
    let proxy = format!("{}:{}", config.host, config.port);
    while let Some(Ok(((content, recipient), sender))) = inbound_stream.next().await {
        if let Vacant(entry) = binding.entry((sender, recipient)) {
            let outbound = TcpStream::connect(proxy.clone()).await?;
            let outbound_local_addr = outbound.local_addr()?;
            debug!("New udp binding; sender={}, outbound={}", sender, outbound_local_addr);
            let security =
                if config.cipher == SupportedCipher::ChaCha20Poly1305 { SecurityType::CHACHA20_POLY1305 } else { SecurityType::AES128_GCM };
            let request = Socks5CommandRequest::from(Socks5CommandType::CONNECT, recipient);
            let header = RequestHeader::default(RequestCommand::UDP, security, request, config.password.clone());
            let outbound = Framed::new(outbound, ClientAEADCodec::new(header));
            let (outbound_sink, mut outbound_stream) = outbound.split();
            entry.insert(outbound_sink);
            tokio::spawn(transfer::remove_binding((sender, recipient), binding.clone()));
            let _writer = inbound_sender.clone();
            tokio::spawn(async move {
                while let Some(Ok(item)) = outbound_stream.next().await {
                    _writer.send(((item, recipient), sender)).await.unwrap();
                }
                debug!("No item in outbound stream; sender={}, outbound={}", sender, outbound_local_addr);
                Ok::<(), io::Error>(())
            });
        };
        info!("Accept udp packet; sender={}, recipient={}, server={}", sender, recipient, proxy);
        binding.get_mut(&(sender, recipient)).unwrap().send(content).await?
    }
    Ok(())
}
