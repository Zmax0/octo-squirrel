use core::str;

use anyhow::bail;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use octo_squirrel::common::protocol::socks5::address::AddressCodec;
use octo_squirrel::common::protocol::socks5::Socks5CommandType;
use octo_squirrel::common::protocol::trojan;
use octo_squirrel::common::util::hex;
use octo_squirrel::config::ServerConfig;
use sha2::Digest;
use sha2::Sha224;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::template::Message;

enum CodecState {
    Header,
    Tcp,
    // Udp(Address),
}

pub fn new_codec(config: &ServerConfig) -> ServerCodec {
    let mut hasher = Sha224::new();
    hasher.update(config.password.as_bytes());
    let key = hasher.finalize().into();
    ServerCodec { key, state: CodecState::Header }
}

pub struct ServerCodec {
    key: [u8; 28],
    state: CodecState,
}

impl Decoder for ServerCodec {
    type Item = Message;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            CodecState::Header => {
                if src.remaining() < 60 || src.remaining() < 59 + AddressCodec::try_decode_at(src, 59)? {
                    return Ok(None);
                }
                if src[56] != b'\r' {
                    bail!("not trojan protocol");
                }
                let key = src.split_to(56);
                let key = hex::decode(unsafe { str::from_utf8_unchecked(&key) })?;
                if self.key != key[..self.key.len()] {
                    bail!("not a valid password")
                }
                src.advance(trojan::CR_LF.len());
                let command = Socks5CommandType::new(src.get_u8())?;
                let peer_addr = AddressCodec::decode(src)?;
                src.advance(trojan::CR_LF.len());
                if matches!(command, Socks5CommandType::Connect) {
                    self.state = CodecState::Tcp;
                    let remaining = src.remaining();
                    Ok(Some(Message::Connect(src.split_off(remaining), peer_addr)))
                } else {
                    bail!("unsupported command type: {:?}", command)
                }
            }
            CodecState::Tcp => {
                if src.is_empty() {
                    Ok(None)
                } else {
                    let len = src.len();
                    Ok(Some(Message::Relay(src.split_to(len))))
                }
            } // _ => unreachable!(),
        }
    }
}

impl Encoder<BytesMut> for ServerCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len());
        dst.put(item);
        Ok(())
    }
}
