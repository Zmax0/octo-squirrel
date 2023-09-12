use std::{io, net::SocketAddr};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::{address::Address, message::{Socks5CommandRequest, Socks5CommandResponse, Socks5InitialRequest, Socks5InitialResponse, Socks5Message}, Socks5AddressType, Socks5AuthMethod, Socks5CommandStatus, Socks5CommandType, VERSION};

pub struct Socks5ClientEncoder;

impl Encoder<Box<dyn Socks5Message>> for Socks5ClientEncoder {
    type Error = io::Error;

    fn encode(&mut self, mut item: Box<dyn Socks5Message>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        item.encode(dst)
    }
}

pub struct Socks5ServerEncoder;

impl Encoder<Box<dyn Socks5Message>> for Socks5ServerEncoder {
    type Error = io::Error;

    fn encode(&mut self, mut item: Box<dyn Socks5Message>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        item.encode(dst)
    }
}

pub struct Socks5InitialRequestDecoder;

impl Decoder for Socks5InitialRequestDecoder {
    type Item = Socks5InitialRequest;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = src.get_u8();
        if VERSION != version {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported version: {}", version)));
        }
        let count = src.get_u8() as usize;
        let mut auth_methods = Vec::with_capacity(count);
        for _ in 0..count {
            auth_methods.push(Socks5AuthMethod(src.get_u8()));
        }
        Ok(Some(Socks5InitialRequest::new(auth_methods)))
    }
}

pub struct Socks5CommandRequestDecoder;

impl Decoder for Socks5CommandRequestDecoder {
    type Item = Socks5CommandRequest;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = src.get_u8();
        if VERSION != version {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported version: {}", version)));
        }
        let command_type = Socks5CommandType(src.get_u8());
        src.advance(1); // Reserved
        let dst_addr_type = Socks5AddressType(src.get_u8());
        let dst_addr = Address::decode_address(dst_addr_type, src)?;
        let dst_port = src.get_u16();
        Ok(Some(Socks5CommandRequest::new(command_type, dst_addr_type, dst_addr, dst_port)))
    }
}

pub struct Socks5InitialResponseDecoder;

impl Decoder for Socks5InitialResponseDecoder {
    type Item = Socks5InitialResponse;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = src.get_u8();
        if VERSION != version {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported version: {}", version)));
        }
        Ok(Some(Socks5InitialResponse::new(Socks5AuthMethod(src.get_u8()))))
    }
}

pub struct Socks5CommandResponseDecoder;

impl Decoder for Socks5CommandResponseDecoder {
    type Item = Socks5CommandResponse;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = src.get_u8();
        if VERSION != version {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported version: {}", version)));
        }
        let command_status = Socks5CommandStatus(src.get_u8());
        src.advance(1); // Reserved
        let bnd_addr_type = Socks5AddressType(src.get_u8());
        let decode_addr = Address::decode_address(bnd_addr_type, src);
        let bnd_port = src.get_u16();
        match decode_addr {
            Ok(bnd_addr) => Ok(Some(Socks5CommandResponse::new(command_status, bnd_addr_type, bnd_addr, bnd_port))),
            Err(err) => Err(err),
        }
    }
}

pub struct Socks5UdpCodec;

impl Decoder for Socks5UdpCodec {
    type Item = (BytesMut, SocketAddr);

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        if src.remaining() < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Insufficient length of packet"));
        }
        if src[2] != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Discarding fragmented payload"));
        }
        src.advance(3);
        let recipient = Address::decode_socket_address(src)?;
        Ok(Some((src.split_off(0), recipient)))
    }
}

impl Encoder<(BytesMut, SocketAddr)> for Socks5UdpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: (BytesMut, SocketAddr), dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_slice(&[0, 0, 0]); // Fragment
        Address::encode_socket_address(item.1, dst)?;
        dst.put_slice(&item.0);
        Ok(())
    }
}
