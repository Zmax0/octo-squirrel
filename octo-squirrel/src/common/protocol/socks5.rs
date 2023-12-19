use anyhow::bail;
use anyhow::Result;

pub mod address;
pub mod codec;
pub mod handshake;
pub mod message;

pub const VERSION: u8 = 5;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Socks5CommandStatus {
    Success,
    Failure,
}

impl Socks5CommandStatus {
    pub fn new(byte: u8) -> Result<Self> {
        if Self::Success as u8 == byte {
            Ok(Self::Success)
        } else if Self::Failure as u8 == byte {
            Ok(Self::Failure)
        } else {
            bail!("unsupported command status: {}", byte as u8 & 0xff);
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Socks5AddressType {
    Ipv4 = 1,
    Domain = 3,
    Ipv6 = 4,
}

impl Socks5AddressType {
    pub fn new(byte: u8) -> Result<Self> {
        if Self::Ipv4 as u8 == byte {
            Ok(Self::Ipv4)
        } else if Self::Domain as u8 == byte {
            Ok(Self::Domain)
        } else if Self::Ipv6 as u8 == byte {
            Ok(Self::Ipv6)
        } else {
            bail!("unsupported address type: {}", byte as u8 & 0xff);
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Socks5CommandType {
    Connet = 1,
    Bind = 2,
    UdpAssociate = 3,
}

impl Socks5CommandType {
    pub fn new(byte: u8) -> Result<Self> {
        if Self::Connet as u8 == byte {
            Ok(Self::Connet)
        } else if Self::Bind as u8 == byte {
            Ok(Self::Bind)
        } else if Self::UdpAssociate as u8 == byte {
            Ok(Self::UdpAssociate)
        } else {
            bail!("unsupported command type: {}", byte as u8 & 0xff);
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Socks5AuthMethod {
    NoAuth,
    Gssapi,
    Password,
    Unaccepted = 255,
}

impl Socks5AuthMethod {
    pub fn new(byte: u8) -> Result<Self> {
        if Self::NoAuth as u8 == byte {
            Ok(Self::NoAuth)
        } else if Self::Gssapi as u8 == byte {
            Ok(Self::Gssapi)
        } else if Self::Password as u8 == byte {
            Ok(Self::Password)
        } else if Self::Unaccepted as u8 == byte {
            Ok(Self::Unaccepted)
        } else {
            bail!("unsupported auth method: {}", byte as u8 & 0xff)
        }
    }
}
