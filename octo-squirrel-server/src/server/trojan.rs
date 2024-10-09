use core::str;

use anyhow::bail;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::protocol::socks5::address;
use octo_squirrel::protocol::socks5::Socks5CommandType;
use octo_squirrel::protocol::trojan;
use octo_squirrel::util::hex;
use sha2::Digest;
use sha2::Sha224;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::template::message::InboundIn;
use super::template::message::OutboundIn;

enum CodecState {
    Header,
    Tcp,
    Udp,
}

pub fn new_codec(config: &ServerConfig) -> anyhow::Result<ServerCodec> {
    let mut hasher = Sha224::new();
    hasher.update(config.password.as_bytes());
    let key = hasher.finalize().into();
    Ok(ServerCodec { key, state: CodecState::Header })
}

pub struct ServerCodec {
    key: [u8; 28],
    state: CodecState,
}

impl ServerCodec {
    fn decode_packet(&mut self, src: &mut BytesMut) -> Result<Option<InboundIn>, anyhow::Error> {
        let peer_addr = address::decode(src)?;
        let len = src.get_u16();
        src.advance(trojan::CR_LF.len());
        Ok(Some(InboundIn::RelayUdp(src.split_to(len as usize), peer_addr)))
    }
}

impl Decoder for ServerCodec {
    type Item = InboundIn;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            CodecState::Header => {
                if src.remaining() < 60 || src.remaining() < 59 + address::try_decode_at(src, 59)? {
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
                let address = address::decode(src)?;
                src.advance(trojan::CR_LF.len());
                match command {
                    Socks5CommandType::Connect => {
                        self.state = CodecState::Tcp;
                        let remaining = src.remaining();
                        Ok(Some(InboundIn::ConnectTcp(src.split_to(remaining), address)))
                    }
                    Socks5CommandType::UdpAssociate => {
                        self.state = CodecState::Udp;
                        self.decode_packet(src)
                    }
                    _ => bail!("unsupported command type: {:?}", command),
                }
            }
            CodecState::Tcp => {
                if src.is_empty() {
                    Ok(None)
                } else {
                    let len = src.len();
                    Ok(Some(InboundIn::RelayTcp(src.split_to(len))))
                }
            }
            CodecState::Udp => self.decode_packet(src),
        }
    }
}

impl Encoder<OutboundIn> for ServerCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: OutboundIn, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            OutboundIn::Tcp(item) => {
                dst.extend_from_slice(&item);
                Ok(())
            }
            OutboundIn::Udp((content, addr)) => {
                address::encode(&addr.into(), dst);
                dst.put_u16(content.len() as u16);
                dst.extend_from_slice(&trojan::CR_LF);
                dst.extend_from_slice(&content);
                Ok(())
            }
        }
    }
}
