use anyhow::bail;
use anyhow::Result;
use tokio_util::bytes::Buf;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

use super::address;
use super::message::Socks5CommandRequest;
use super::message::Socks5CommandResponse;
use super::message::Socks5InitialRequest;
use super::message::Socks5InitialResponse;
use super::message::Socks5Message;
use super::Socks5AuthMethod;
use super::Socks5CommandStatus;
use super::Socks5CommandType;
use super::VERSION;
use crate::codec::DatagramPacket;

pub struct Socks5ClientEncoder;

impl Encoder<Box<dyn Socks5Message>> for Socks5ClientEncoder {
    type Error = anyhow::Error;

    fn encode(&mut self, mut item: Box<dyn Socks5Message>, dst: &mut BytesMut) -> Result<()> {
        item.encode(dst);
        Ok(())
    }
}

pub struct Socks5ServerEncoder;

impl Encoder<Box<dyn Socks5Message>> for Socks5ServerEncoder {
    type Error = anyhow::Error;

    fn encode(&mut self, mut item: Box<dyn Socks5Message>, dst: &mut BytesMut) -> Result<()> {
        item.encode(dst);
        Ok(())
    }
}

pub struct Socks5InitialRequestDecoder;

impl Decoder for Socks5InitialRequestDecoder {
    type Item = Socks5InitialRequest;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let version = src.get_u8();
        if VERSION != version {
            bail!("unsupported version: {}", version);
        }
        let count = src.get_u8() as usize;
        let mut auth_methods = Vec::with_capacity(count);
        for _ in 0..count {
            auth_methods.push(Socks5AuthMethod::new(src.get_u8())?);
        }
        Ok(Some(Socks5InitialRequest::new(auth_methods)))
    }
}

pub struct Socks5CommandRequestDecoder;

impl Decoder for Socks5CommandRequestDecoder {
    type Item = Socks5CommandRequest;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let version = src.get_u8();
        if VERSION != version {
            bail!("unsupported version: {}", version);
        }
        let command_type = Socks5CommandType::new(src.get_u8())?;
        src.advance(1); // Reserved
        let addr = address::decode(src)?;
        Ok(Some(Socks5CommandRequest::new(command_type, addr)))
    }
}

pub struct Socks5InitialResponseDecoder;

impl Decoder for Socks5InitialResponseDecoder {
    type Item = Socks5InitialResponse;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = src.get_u8();
        if VERSION != version {
            bail!("unsupported version: {}", version);
        }
        Ok(Some(Socks5InitialResponse::new(Socks5AuthMethod::new(src.get_u8())?)))
    }
}

pub struct Socks5CommandResponseDecoder;

impl Decoder for Socks5CommandResponseDecoder {
    type Item = Socks5CommandResponse;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let version = src.get_u8();
        if VERSION != version {
            bail!("unsupported version: {}", version);
        }
        let command_status = Socks5CommandStatus::try_from(src.get_u8())?;
        src.advance(1); // Reserved
        let addr = address::decode(src)?;
        Ok(Some(Socks5CommandResponse::new(command_status, addr)))
    }
}

pub struct Socks5UdpCodec;

impl Decoder for Socks5UdpCodec {
    type Item = DatagramPacket;

    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        if src.remaining() < 5 {
            bail!("Insufficient length of packet");
        }
        if src[2] != 0 {
            bail!("Discarding fragmented payload");
        }
        src.advance(3);
        let recipient = address::decode(src)?;
        Ok(Some((src.split_off(0), recipient)))
    }
}

impl Encoder<DatagramPacket> for Socks5UdpCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: DatagramPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&[0, 0, 0]); // Fragment
        address::encode(&item.1, dst);
        dst.extend_from_slice(&item.0);
        Ok(())
    }
}
