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
    pub fn new(byte: u8) -> Self {
        if Self::Success as u8 == byte {
            Self::Success
        } else if Self::Failure as u8 == byte {
            Self::Failure
        } else {
            panic!("unsupported command status: {}", byte as u8 & 0xff);
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
    pub fn new(byte: u8) -> Self {
        if Self::Ipv4 as u8 == byte {
            Self::Ipv4
        } else if Self::Domain as u8 == byte {
            Self::Domain
        } else if Self::Ipv6 as u8 == byte {
            Self::Ipv6
        } else {
            panic!("unsupported address type: {}", byte as u8 & 0xff);
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
    pub fn new(byte: u8) -> Self {
        if Self::Connet as u8 == byte {
            Self::Connet
        } else if Self::Bind as u8 == byte {
            Self::Bind
        } else if Self::UdpAssociate as u8 == byte {
            Self::UdpAssociate
        } else {
            panic!("unsupported command type: {}", byte as u8 & 0xff);
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
    pub fn new(byte: u8) -> Self {
        if Self::NoAuth as u8 == byte {
            Self::NoAuth
        } else if Self::Gssapi as u8 == byte {
            Self::Gssapi
        } else if Self::Password as u8 == byte {
            Self::Password
        } else if Self::Unaccepted as u8 == byte {
            Self::Unaccepted
        } else {
            panic!("unsupported auth method: {}", byte as u8 & 0xff)
        }
    }
}
