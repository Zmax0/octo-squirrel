use std::{fmt::Display, io::Error, net::SocketAddr};

use bytes::BufMut;

use super::{address::Address, Socks5AddressType, Socks5AuthMethod, Socks5CommandStatus, Socks5CommandType, VERSION};

pub trait Socks5Message: Send + Sync {
    fn encode(&mut self, dst: &mut bytes::BytesMut) -> Result<(), Error>;
}

pub struct Socks5InitialRequest {
    auth_methods: Vec<Socks5AuthMethod>,
}

impl Socks5InitialRequest {
    pub fn new(auth_methods: Vec<Socks5AuthMethod>) -> Self {
        Socks5InitialRequest { auth_methods }
    }
}
impl Socks5Message for Socks5InitialRequest {
    fn encode(&mut self, dst: &mut bytes::BytesMut) -> Result<(), Error> {
        dst.put_u8(VERSION);
        dst.put_u8(self.auth_methods.len() as u8);
        for auth_method in self.auth_methods.iter() {
            dst.put_u8((*auth_method).0);
        }
        Ok(())
    }
}

pub struct Socks5InitialResponse {
    pub auth_method: Socks5AuthMethod,
}

impl Socks5InitialResponse {
    pub fn new(auth_method: Socks5AuthMethod) -> Self {
        Self { auth_method }
    }
}

impl Socks5Message for Socks5InitialResponse {
    fn encode(&mut self, dst: &mut bytes::BytesMut) -> Result<(), Error> {
        dst.put_u8(VERSION);
        dst.put_u8(self.auth_method.0);
        Ok(())
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Socks5CommandRequest {
    pub command_type: Socks5CommandType,
    pub dst_addr_type: Socks5AddressType,
    pub dst_addr: String,
    pub dst_port: u16,
}

impl Socks5CommandRequest {
    pub fn new(command_type: Socks5CommandType, dst_addr_type: Socks5AddressType, dst_addr: String, dst_port: u16) -> Self {
        Self { command_type, dst_addr_type, dst_addr, dst_port }
    }

    pub fn connect(dst_addr_type: Socks5AddressType, dst_addr: String, dst_port: u16) -> Self {
        Self { command_type: Socks5CommandType::CONNECT, dst_addr_type, dst_addr, dst_port }
    }

    pub fn from(command_type: Socks5CommandType, addr: SocketAddr) -> Socks5CommandRequest {
        match addr {
            SocketAddr::V4(v4) => Socks5CommandRequest::new(command_type, Socks5AddressType::IPV4, v4.ip().to_string(), v4.port()),
            SocketAddr::V6(v6) => Socks5CommandRequest::new(command_type, Socks5AddressType::IPV6, v6.ip().to_string(), v6.port()),
        }
    }
}

impl Display for Socks5CommandRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.dst_addr, self.dst_port)
    }
}

impl Socks5Message for Socks5CommandRequest {
    fn encode(&mut self, dst: &mut bytes::BytesMut) -> Result<(), Error> {
        dst.put_u8(VERSION);
        dst.put_u8(self.command_type.0);
        dst.put_u8(0x00);
        dst.put_u8(self.dst_addr_type.0);
        Address::encode_address(self.dst_addr_type, &self.dst_addr, dst)?;
        dst.put_u16(self.dst_port);
        Ok(())
    }
}

pub struct Socks5CommandResponse {
    pub command_status: Socks5CommandStatus,
    pub bnd_addr_type: Socks5AddressType,
    pub bnd_addr: String,
    pub bnd_port: u16,
}

impl Socks5Message for Socks5CommandResponse {
    fn encode(&mut self, dst: &mut bytes::BytesMut) -> Result<(), Error> {
        dst.put_u8(VERSION);
        dst.put_u8(self.command_status.0);
        dst.put_u8(0x00);
        dst.put_u8(self.bnd_addr_type.0);
        Address::encode_address(self.bnd_addr_type, &self.bnd_addr, dst)?;
        dst.put_u16(self.bnd_port);
        Ok(())
    }
}

impl Socks5CommandResponse {
    pub fn new(command_status: Socks5CommandStatus, bnd_addr_type: Socks5AddressType, bnd_addr: String, bnd_port: u16) -> Self {
        Self { command_status, bnd_addr_type, bnd_addr, bnd_port }
    }
}
