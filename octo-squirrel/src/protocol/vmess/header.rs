use super::id;
use super::VERSION;
use crate::codec::aead::CipherKind;
use crate::protocol::address::Address;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum AddressType {
    Ipv4 = 1,
    Domain = 2,
    Ipv6 = 3,
}

impl AddressType {
    pub fn new(byte: u8) -> Self {
        if Self::Ipv4 as u8 == byte {
            Self::Ipv4
        } else if Self::Domain as u8 == byte {
            Self::Domain
        } else if Self::Ipv6 as u8 == byte {
            Self::Ipv6
        } else {
            panic!("unsupported address type: {}", byte);
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum RequestCommand {
    TCP = 1,
    UDP = 2,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum RequestOption {
    ChunkStream = 1,
    ConnectionReuse = 2,
    ChunkMasking = 4,
    GlobalPadding = 8,
    AuthenticatedLength = 16,
}

impl RequestOption {
    pub fn values() -> Vec<Self> {
        vec![Self::ChunkStream, Self::ConnectionReuse, Self::ChunkMasking, Self::GlobalPadding, Self::AuthenticatedLength]
    }

    pub fn from_mask(mask: u8) -> Vec<Self> {
        Self::values().into_iter().filter(|op| *op as u8 & mask != 0).collect()
    }

    pub fn get_mask(options: &[Self]) -> u8 {
        options.iter().map(|x| *x as u8).reduce(|a, b| a | b).unwrap()
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]

pub enum SecurityType {
    Unknown,
    Legacy,
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl From<CipherKind> for SecurityType {
    fn from(value: CipherKind) -> Self {
        match value {
            CipherKind::ChaCha20Poly1305 => SecurityType::Chacha20Poly1305,
            _ => SecurityType::Aes128Gcm,
        }
    }
}

impl From<u8> for SecurityType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Legacy,
            2 => Self::Auto,
            3 => Self::Aes128Gcm,
            4 => Self::Chacha20Poly1305,
            5 => Self::None,
            6 => Self::Zero,
            _ => Self::Unknown,
        }
    }
}

pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub option: Vec<RequestOption>,
    pub security: SecurityType,
    pub address: Address,
    pub id: [u8; 16],
}

impl RequestHeader {
    pub fn new(version: u8, command: RequestCommand, option: Vec<RequestOption>, security: SecurityType, address: Address, id: [u8; 16]) -> Self {
        Self { version, command, option, security, address, id }
    }

    pub fn default(command: RequestCommand, security: SecurityType, address: Address, uuid: &str) -> Result<Self, uuid::Error> {
        Ok(Self {
            version: VERSION,
            command,
            option: vec![RequestOption::ChunkStream, RequestOption::ChunkMasking, RequestOption::GlobalPadding, RequestOption::AuthenticatedLength],
            security,
            address,
            id: id::from_password(uuid)?,
        })
    }
}
