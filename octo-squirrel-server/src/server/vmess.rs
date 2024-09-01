use anyhow::anyhow;
use anyhow::bail;
use bytes::Buf;
use bytes::Bytes;
use bytes::BytesMut;
use log::debug;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::CipherMethod;
use octo_squirrel::common::codec::vmess::aead::AEADBodyCodec;
use octo_squirrel::common::protocol::vmess::aead::AuthID;
use octo_squirrel::common::protocol::vmess::aead::Encrypt;
use octo_squirrel::common::protocol::vmess::aead::KDF;
use octo_squirrel::common::protocol::vmess::header::RequestCommand;
use octo_squirrel::common::protocol::vmess::header::RequestHeader;
use octo_squirrel::common::protocol::vmess::header::RequestOption;
use octo_squirrel::common::protocol::vmess::header::SecurityType;
use octo_squirrel::common::protocol::vmess::session::ServerSession;
use octo_squirrel::common::protocol::vmess::AddressCodec;
use octo_squirrel::common::protocol::vmess::ID;
use octo_squirrel::common::util::FNV;
use octo_squirrel::config::ServerConfig;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::template::Message;

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
    ) -> anyhow::Result<Option<Message>> {
        match header.command {
            RequestCommand::TCP => {
                Ok(Some(Message::Connect(decoder.decode_payload(src, session).map_err(|e| anyhow!(e))?.unwrap_or_default(), header.address.clone())))
            }
            RequestCommand::UDP => todo!(),
        }
    }

    fn decode_body(
        src: &mut BytesMut,
        header: &mut RequestHeader,
        session: &mut ServerSession,
        decoder: &mut AEADBodyCodec,
    ) -> anyhow::Result<Option<Message>> {
        match header.command {
            RequestCommand::TCP => Ok(Some(Message::RelayTcp(decoder.decode_payload(src, session).map_err(|e| anyhow!(e))?.unwrap_or_default()))),
            RequestCommand::UDP => todo!(),
        }
    }
}

impl Encoder<BytesMut> for ServerAeadCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if let DecodeState::Ready(ref request_header, ref mut session, _) = self.decode_state {
            match self.encode_state {
                EncodeState::Init => {
                    let header_len_key = KDF::kdf16(&session.response_body_key, vec![KDF::SALT_AEAD_RESP_HEADER_LEN_KEY]);
                    let cipher = Aes128GcmCipher::new_from_slice(&header_len_key)?;
                    let header_len_iv: [u8; Aes128GcmCipher::NONCE_SIZE] =
                        KDF::kdfn(&session.response_body_iv, vec![KDF::SALT_AEAD_RESP_HEADER_LEN_IV]);
                    let option = RequestOption::get_mask(&request_header.option);
                    let header: [u8; 4] = [session.response_header, option, 0, 0];
                    dst.extend_from_slice(&cipher.encrypt(&header_len_iv, &(header.len() as u16).to_be_bytes(), b"").map_err(|e| anyhow!(e))?);
                    let payload_len_key = KDF::kdf16(&session.response_body_key, vec![KDF::SALT_AEAD_RESP_HEADER_PAYLOAD_KEY]);
                    let cipher = Aes128GcmCipher::new_from_slice(&payload_len_key)?;
                    let payload_len_iv: [u8; Aes128GcmCipher::NONCE_SIZE] =
                        KDF::kdfn(&session.response_body_iv, vec![KDF::SALT_AEAD_RESP_HEADER_PAYLOAD_IV]);
                    dst.extend_from_slice(&cipher.encrypt(&payload_len_iv, &header, b"").map_err(|e| anyhow!(e))?);
                    let mut encoder = AEADBodyCodec::encoder(request_header, session)?;
                    let res = Self::encode(item, dst, request_header, session, &mut encoder);
                    self.encode_state = EncodeState::Ready(Box::new(encoder));
                    res
                }
                EncodeState::Ready(ref mut encoder) => Self::encode(item, dst, request_header, session, encoder),
            }
        } else {
            bail!("decode state is not ready")
        }
    }
}

impl Decoder for ServerAeadCodec {
    type Item = Message;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode_state {
            DecodeState::Init => {
                let auth_id = &src[0..16];
                match AuthID::matching(auth_id, &self.keys)? {
                    Some(key) => {
                        if let Some(header) = Encrypt::open_header(&key, src)? {
                            let data = header[..header.len() - 4].to_vec();
                            let mut header = Bytes::from(header);
                            let version = header.get_u8();
                            let mut request_body_iv = [0; 16];
                            header.copy_to_slice(&mut request_body_iv);
                            let mut request_body_key = [0; 16];
                            header.copy_to_slice(&mut request_body_key);
                            let response_header = header.get_u8();
                            let option = header.get_u8();
                            let b35 = header.get_u8();
                            let padding_len = b35 >> 4;
                            let security = SecurityType::from(b35);
                            header.advance(1); // fixed 0
                            let command = header.get_u8();
                            if command == RequestCommand::TCP as u8 || command == RequestCommand::UDP as u8 {
                                let command = if command == RequestCommand::TCP as u8 { RequestCommand::TCP } else { RequestCommand::UDP };
                                let address = AddressCodec::read_address_port(&mut header)?;
                                header.advance(padding_len as usize);
                                let actual = header.get_u32();
                                if FNV::fnv1a32(&data) != actual {
                                    bail!("invalid auth, but this is a AEAD request")
                                }
                                let mut header = RequestHeader::new(version, command, RequestOption::from_mask(option), security, address, key);
                                let mut session = ServerSession::new(request_body_iv, request_body_key, response_header);
                                debug!("New session; {}", session);
                                let mut decoder = AEADBodyCodec::decoder(&header, &mut session)?;
                                let res = Self::decode_header(src, &mut header, &mut session, &mut decoder);
                                self.decode_state = DecodeState::Ready(header, session, Box::new(decoder));
                                return res;
                            } else {
                                bail!("unknown request command: {command}")
                            }
                        }
                    }
                    None => bail!("no matched authID"),
                }
                Ok(None)
            }
            DecodeState::Ready(ref mut header, ref mut session, ref mut decoder) => Self::decode_body(src, header, session, decoder),
        }
    }
}

impl TryFrom<&ServerConfig> for ServerAeadCodec {
    type Error = anyhow::Error;

    fn try_from(config: &ServerConfig) -> Result<Self, Self::Error> {
        let uuid = config.user.iter().map(|u| &u.password).collect();
        let keys = ID::from_passwords(uuid)?;
        Ok(Self { keys, decode_state: DecodeState::Init, encode_state: EncodeState::Init })
    }
}
