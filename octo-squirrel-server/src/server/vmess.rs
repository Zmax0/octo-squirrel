use aes_gcm::AeadCore;
use aes_gcm::Aes128Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use aes_gcm::aes::cipher::Unsigned;
use anyhow::anyhow;
use anyhow::bail;
use log::debug;
use octo_squirrel::codec::vmess::aead::AEADBodyCodec;
use octo_squirrel::protocol::vmess::address;
use octo_squirrel::protocol::vmess::aead::auth_id;
use octo_squirrel::protocol::vmess::aead::encrypt;
use octo_squirrel::protocol::vmess::aead::kdf;
use octo_squirrel::protocol::vmess::header::RequestCommand;
use octo_squirrel::protocol::vmess::header::RequestHeader;
use octo_squirrel::protocol::vmess::header::RequestOption;
use octo_squirrel::protocol::vmess::header::SecurityType;
use octo_squirrel::protocol::vmess::id;
use octo_squirrel::protocol::vmess::session::ServerSession;
use octo_squirrel::util::fnv;
use tokio_util::bytes::Buf;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::config::ServerConfig;
use super::template::message::InboundIn;
use super::template::message::OutboundIn;

pub fn new_codec(config: &ServerConfig) -> anyhow::Result<ServerAeadCodec> {
    ServerAeadCodec::try_from(config)
}

enum DecodeState {
    Init,
    Ready(RequestHeader, ServerSession, Box<AEADBodyCodec>),
}

enum EncodeState {
    Init,
    Ready(Box<AEADBodyCodec>),
}

pub struct ServerAeadCodec {
    keys: Vec<[u8; 16]>,
    decode_state: DecodeState,
    encode_state: EncodeState,
}

impl ServerAeadCodec {
    fn encode(
        item: BytesMut,
        dst: &mut BytesMut,
        request_header: &RequestHeader,
        session: &mut ServerSession,
        encoder: &mut AEADBodyCodec,
    ) -> anyhow::Result<()> {
        match request_header.command {
            RequestCommand::TCP => encoder.encode_payload(item, dst, session).map_err(|e| anyhow!(e)),
            RequestCommand::UDP => encoder.encode_packet(item, dst, session).map_err(|e| anyhow!(e)),
        }
    }

    fn decode_header(
        src: &mut BytesMut,
        header: &mut RequestHeader,
        session: &mut ServerSession,
        decoder: &mut AEADBodyCodec,
    ) -> anyhow::Result<Option<InboundIn>> {
        match header.command {
            RequestCommand::TCP => {
                if let Some(msg) = decoder.decode_payload(src, session).map_err(|e| anyhow!(e))? {
                    Ok(Some(InboundIn::ConnectTcp(msg, header.address.clone())))
                } else {
                    Ok(None)
                }
            }
            RequestCommand::UDP => {
                if let Some(msg) = decoder.decode_packet(src, session).map_err(|e| anyhow!(e))? {
                    Ok(Some(InboundIn::RelayUdp(msg, header.address.clone())))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn decode_body(
        src: &mut BytesMut,
        header: &mut RequestHeader,
        session: &mut ServerSession,
        decoder: &mut AEADBodyCodec,
    ) -> anyhow::Result<Option<InboundIn>> {
        match header.command {
            RequestCommand::TCP => {
                if let Some(msg) = decoder.decode_payload(src, session).map_err(|e| anyhow!(e))? {
                    Ok(Some(InboundIn::RelayTcp(msg)))
                } else {
                    Ok(None)
                }
            }
            RequestCommand::UDP => {
                if let Some(msg) = decoder.decode_packet(src, session).map_err(|e| anyhow!(e))? {
                    Ok(Some(InboundIn::RelayUdp(msg, header.address.clone())))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

impl Encoder<OutboundIn> for ServerAeadCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: OutboundIn, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if let DecodeState::Ready(ref request_header, ref mut session, _) = self.decode_state {
            match self.encode_state {
                EncodeState::Init => {
                    const NONCE_SIZE: usize = <Aes128Gcm as AeadCore>::NonceSize::USIZE;
                    let header_len_key = kdf::kdf16(&session.response_body_key, vec![kdf::SALT_AEAD_RESP_HEADER_LEN_KEY]);
                    let cipher = Aes128Gcm::new_from_slice(&header_len_key)?;
                    let header_len_iv: [u8; NONCE_SIZE] = kdf::kdfn(&session.response_body_iv, vec![kdf::SALT_AEAD_RESP_HEADER_LEN_IV]);
                    let option = RequestOption::get_mask(&request_header.option);
                    let header: [u8; 4] = [session.response_header, option, 0, 0];
                    dst.extend_from_slice(
                        &cipher
                            .encrypt(&header_len_iv.into(), Payload { msg: &(header.len() as u16).to_be_bytes(), aad: &[] })
                            .map_err(|e| anyhow!(e))?,
                    );
                    let payload_len_key = kdf::kdf16(&session.response_body_key, vec![kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
                    let cipher = Aes128Gcm::new_from_slice(&payload_len_key)?;
                    let payload_len_iv: [u8; NONCE_SIZE] = kdf::kdfn(&session.response_body_iv, vec![kdf::SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);
                    dst.extend_from_slice(&cipher.encrypt(&payload_len_iv.into(), Payload { msg: &header, aad: &[] }).map_err(|e| anyhow!(e))?);
                    let mut encoder = AEADBodyCodec::new_encoder(request_header, session)?;
                    let res = Self::encode(item.into(), dst, request_header, session, &mut encoder);
                    self.encode_state = EncodeState::Ready(Box::new(encoder));
                    res
                }
                EncodeState::Ready(ref mut encoder) => Self::encode(item.into(), dst, request_header, session, encoder),
            }
        } else {
            bail!("decode state is not ready")
        }
    }
}

impl Decoder for ServerAeadCodec {
    type Item = InboundIn;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode_state {
            DecodeState::Init => {
                let auth_id = &src[0..16];
                if let Some(key) = auth_id::matching(auth_id, &self.keys)? {
                    if let Some(header) = encrypt::open_header(&key, src)? {
                        let data = header[..header.len() - 4].to_vec();
                        let mut header = Bytes::from(header);
                        let version = header.get_u8();
                        let mut request_body_iv = [0; 16];
                        header.copy_to_slice(&mut request_body_iv);
                        let mut request_body_key = [0; 16];
                        header.copy_to_slice(&mut request_body_key);
                        let response_header = header.get_u8();
                        let option = header.get_u8();
                        let security = header.get_u8();
                        let padding_len = security >> 4;
                        let security = SecurityType::from(security & 0xF);
                        header.advance(1); // fixed 0
                        let command = header.get_u8();
                        if command != RequestCommand::TCP as u8 && command != RequestCommand::UDP as u8 {
                            bail!("unknown request command: {command}")
                        }
                        let command = if command == RequestCommand::TCP as u8 { RequestCommand::TCP } else { RequestCommand::UDP };
                        let address = address::read_address_port(&mut header)?;
                        header.advance(padding_len as usize);
                        let actual = header.get_u32();
                        if fnv::fnv1a32(&data) != actual {
                            bail!("invalid auth, but this is a AEAD request")
                        }
                        let mut header = RequestHeader::new(version, command, RequestOption::from_mask(option), security, address, key);
                        let mut session = ServerSession::new(request_body_iv, request_body_key, response_header);
                        debug!("New session; {}", session);
                        let mut decoder = AEADBodyCodec::new_decoder(&header, &mut session)?;
                        let res = Self::decode_header(src, &mut header, &mut session, &mut decoder);
                        self.decode_state = DecodeState::Ready(header, session, Box::new(decoder));
                        res
                    } else {
                        Ok(None)
                    }
                } else {
                    bail!("no matched authID")
                }
            }
            DecodeState::Ready(ref mut header, ref mut session, ref mut decoder) => {
                if src.is_empty() {
                    Ok(None)
                } else {
                    Self::decode_body(src, header, session, decoder)
                }
            }
        }
    }
}

impl TryFrom<&ServerConfig> for ServerAeadCodec {
    type Error = anyhow::Error;

    fn try_from(config: &ServerConfig) -> Result<Self, Self::Error> {
        let uuid = config.user.iter().map(|u| &u.password).collect();
        let keys = id::from_passwords(uuid)?;
        Ok(Self { keys, decode_state: DecodeState::Init, encode_state: EncodeState::Init })
    }
}
