use anyhow::Result;
use anyhow::bail;

pub mod address;
pub mod codec;
pub mod handshake;
pub mod message;

const VERSION: u8 = 5;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Socks5CommandStatus {
    Success,
    Failure,
}

impl TryFrom<u8> for Socks5CommandStatus {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if Self::Success as u8 == value {
            Ok(Self::Success)
        } else if Self::Failure as u8 == value {
            Ok(Self::Failure)
        } else {
            bail!("unsupported command status: {}", value);
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Socks5AddressType {
    Ipv4 = 1,
    Domain = 3,
    Ipv6 = 4,
}

impl TryFrom<u8> for Socks5AddressType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if Self::Ipv4 as u8 == value {
            Ok(Self::Ipv4)
        } else if Self::Domain as u8 == value {
            Ok(Self::Domain)
        } else if Self::Ipv6 as u8 == value {
            Ok(Self::Ipv6)
        } else {
            bail!("unsupported address type: {}", value);
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Socks5CommandType {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

impl Socks5CommandType {
    pub fn new(byte: u8) -> Result<Self> {
        if Self::Connect as u8 == byte {
            Ok(Self::Connect)
        } else if Self::Bind as u8 == byte {
            Ok(Self::Bind)
        } else if Self::UdpAssociate as u8 == byte {
            Ok(Self::UdpAssociate)
        } else {
            bail!("unsupported command type: {}", byte);
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
            bail!("unsupported auth method: {}", byte)
        }
    }
}
