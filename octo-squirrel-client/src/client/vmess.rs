use std::io::Cursor;
use std::io::ErrorKind;
use std::mem::size_of;
use std::{error, io};

use bytes::{Buf, BufMut, BytesMut};
use futures::SinkExt;
use log::{info, trace};
use octo_squirrel::common::codec::aead::{AEADCipher, Aes128GcmCipher, PayloadDecoder, PayloadEncoder, SupportedCipher};
use octo_squirrel::common::codec::vmess::AEADBodyCodec;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandRequest;
use octo_squirrel::common::protocol::vmess::aead::*;
use octo_squirrel::common::protocol::vmess::header::{RequestCommand, RequestHeader, RequestOption, SecurityType};
use octo_squirrel::common::protocol::vmess::session::{ClientSession, Session};
use octo_squirrel::common::protocol::vmess::{Address, VERSION};
use octo_squirrel::common::util::{Dice, FNV};
use octo_squirrel::config::ServerConfig;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Decoder, Encoder, FramedRead, FramedWrite};

pub async fn transfer_tcp(mut inbound: TcpStream, request: Socks5CommandRequest, config: ServerConfig) -> Result<(), Box<dyn error::Error>> {
    let security = if config.cipher == SupportedCipher::ChaCha20Poly1305 { SecurityType::CHACHA20_POLY1305 } else { SecurityType::AES128_GCM };
    let header = RequestHeader::default(RequestCommand::TCP, security, request, config.password);
    let session = ClientSession::new();
    trace!("New session; {}", session);
    let mut outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
    let (ri, wi) = inbound.split();
    let (ro, wo) = outbound.split();

    let client_to_server = async {
        let mut rif = FramedRead::new(ri, BytesCodec::new());
        let mut wof = FramedWrite::new(wo, ClientAEADCodec::new(&header, &session));
        while let Some(Ok(item)) = rif.next().await {
            wof.send(item).await?
        }
        wof.into_inner().shutdown().await
    };

    let server_to_client = async {
        let mut rof = FramedRead::new(ro, ClientAEADCodec::new(&header, &session));
        let mut wif = FramedWrite::new(wi, BytesCodec::new());
        while let Some(Ok(item)) = rof.next().await {
            wif.send(item).await?
        }
        wif.into_inner().shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

struct ClientAEADCodec<'a> {
    header: &'a RequestHeader,
    session: &'a ClientSession,
    body_encoder: Option<PayloadEncoder>,
    body_decoder: Option<PayloadDecoder>,
}

impl ClientAEADCodec<'_> {
    pub fn new<'a>(header: &'a RequestHeader, session: &'a ClientSession) -> ClientAEADCodec<'a> {
        ClientAEADCodec { header, session, body_encoder: None, body_decoder: None }
    }
}

impl Encoder<BytesMut> for ClientAEADCodec<'_> {
    type Error = io::Error;

    fn encode(&mut self, mut item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
            self.body_encoder = Some(AEADBodyCodec::encoder(self.header, self.session));
        }
        if self.header.command == RequestCommand::UDP {
            self.body_encoder.as_mut().unwrap().encode_packet(&mut item, dst);
        } else {
            self.body_encoder.as_mut().unwrap().encode_payload(&mut item, dst);
        }
        Ok(())
    }
}

impl Decoder for ClientAEADCodec<'_> {
    type Item = BytesMut;

    type Error = io::Error;

    fn decode(&mut self, mut src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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
            self.body_decoder = Some(AEADBodyCodec::decoder(self.header, self.session));
        }
        return if self.header.command == RequestCommand::UDP {
            self.body_decoder.as_mut().unwrap().decode_packet(src)
        } else {
            self.body_decoder.as_mut().unwrap().decode_payload(src)
        };
    }
}
