use std::fmt::Display;
use std::io::Error;
use std::net::SocketAddr;

use bytes::BufMut;

use super::address::AddressCodec;
use super::Socks5AddressType;
use super::Socks5AuthMethod;
use super::Socks5CommandStatus;
use super::Socks5CommandType;
use super::VERSION;
use crate::common::protocol::address::Address;

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
            dst.put_u8(*auth_method as u8);
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
        dst.put_u8(self.auth_method as u8);
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
    pub fn new(command_type: Socks5CommandType, addr: Address) -> Self {
        match addr {
            Address::Domain(dst_addr, dst_port) => Self { command_type, dst_addr_type: Socks5AddressType::Domain, dst_addr, dst_port },
            Address::Socket(addr) => match addr {
                SocketAddr::V4(v4) => {
                    Self { command_type, dst_addr_type: Socks5AddressType::Ipv4, dst_addr: v4.ip().to_string(), dst_port: v4.port() }
                }
                SocketAddr::V6(v6) => {
                    Self { command_type, dst_addr_type: Socks5AddressType::Ipv6, dst_addr: v6.ip().to_string(), dst_port: v6.port() }
                }
            },
        }
    }

    pub fn connect(dst_addr_type: Socks5AddressType, dst_addr: String, dst_port: u16) -> Self {
        Self { command_type: Socks5CommandType::Connet, dst_addr_type, dst_addr, dst_port }
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
        dst.put_u8(self.command_type as u8);
        dst.put_u8(0x00);
        AddressCodec::encode(&self.into(), dst)?;
        dst.put_u16(self.dst_port);
        Ok(())
    }
}

impl From<Socks5CommandRequest> for Address {
    fn from(value: Socks5CommandRequest) -> Self {
        match value.dst_addr_type {
            Socks5AddressType::Ipv4 | Socks5AddressType::Ipv6 => Address::Socket(format!("{}:{}", value.dst_addr, value.dst_port).parse().unwrap()),
            Socks5AddressType::Domain => Address::Domain(value.dst_addr, value.dst_port),
        }
    }
}

impl From<&Socks5CommandRequest> for Address {
    fn from(value: &Socks5CommandRequest) -> Self {
        match value.dst_addr_type {
            Socks5AddressType::Ipv4 | Socks5AddressType::Ipv6 => Address::Socket(format!("{}:{}", value.dst_addr, value.dst_port).parse().unwrap()),
            Socks5AddressType::Domain => Address::Domain(value.dst_addr.clone(), value.dst_port),
        }
    }
}

impl From<&mut Socks5CommandRequest> for Address {
    fn from(value: &mut Socks5CommandRequest) -> Self {
        match value.dst_addr_type {
            Socks5AddressType::Ipv4 | Socks5AddressType::Ipv6 => Address::Socket(format!("{}:{}", value.dst_addr, value.dst_port).parse().unwrap()),
            Socks5AddressType::Domain => Address::Domain(value.dst_addr.clone(), value.dst_port),
        }
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
        dst.put_u8(self.command_status as u8);
        dst.put_u8(0x00);
        AddressCodec::encode(&self.into(), dst)?;
        Ok(())
    }
}

impl From<&mut Socks5CommandResponse> for Address {
    fn from(value: &mut Socks5CommandResponse) -> Self {
        match value.bnd_addr_type {
            Socks5AddressType::Ipv4 | Socks5AddressType::Ipv6 => Address::Socket(format!("{}:{}", value.bnd_addr, value.bnd_port).parse().unwrap()),
            Socks5AddressType::Domain => Address::Domain(value.bnd_addr.clone(), value.bnd_port),
        }
    }
}

impl Socks5CommandResponse {
    pub fn new(command_status: Socks5CommandStatus, addr: Address) -> Self {
        match addr {
            Address::Domain(bnd_addr, bnd_port) => Self { command_status, bnd_addr_type: Socks5AddressType::Domain, bnd_addr, bnd_port },
            Address::Socket(addr) => match addr {
                SocketAddr::V4(v4) => {
                    Self { command_status, bnd_addr_type: Socks5AddressType::Ipv4, bnd_addr: v4.ip().to_string(), bnd_port: v4.port() }
                }
                SocketAddr::V6(v6) => {
                    Self { command_status, bnd_addr_type: Socks5AddressType::Ipv6, bnd_addr: v6.ip().to_string(), bnd_port: v6.port() }
                }
            },
        }
    }
}
