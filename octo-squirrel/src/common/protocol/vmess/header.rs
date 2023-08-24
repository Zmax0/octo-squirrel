use super::{ID, VERSION};
use crate::common::codec::aead::SupportedCipher;
use crate::common::protocol::socks5::message::Socks5CommandRequest;

#[derive(PartialEq)]
pub struct AddressType(pub u8);
pub const IPV4: AddressType = AddressType(1);
pub const DOMAIN: AddressType = AddressType(2);
pub const IPV6: AddressType = AddressType(3);

#[derive(PartialEq, Eq)]
pub struct RequestCommand(pub u8);

impl RequestCommand {
    pub const TCP: RequestCommand = RequestCommand(1);
    pub const UDP: RequestCommand = RequestCommand(2);
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct RequestOption(pub u8);

impl RequestOption {
    pub const CHUNK_STREAM: RequestOption = RequestOption(1);
    pub const CONNECTION_REUSE: RequestOption = RequestOption(2);
    pub const CHUNK_MASKING: RequestOption = RequestOption(4);
    pub const GLOBAL_PADDING: RequestOption = RequestOption(8);
    pub const AUTHENTICATED_LENGTH: RequestOption = RequestOption(16);
}

impl RequestOption {
    pub fn values() -> Vec<RequestOption> {
        vec![
            RequestOption::CHUNK_STREAM,
            RequestOption::CONNECTION_REUSE,
            RequestOption::CHUNK_MASKING,
            RequestOption::GLOBAL_PADDING,
            RequestOption::AUTHENTICATED_LENGTH,
        ]
    }

    pub fn from_mask(mask: u8) -> Vec<RequestOption> {
        Self::values().into_iter().filter(|op| op.0 & mask != 0).collect()
    }

    pub fn get_mask(options: &Vec<RequestOption>) -> u8 {
        options.iter().map(|x| x.0).reduce(|a, b| a | b).unwrap()
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct SecurityType(pub u8);

impl SecurityType {
    pub const UNKNOWN: SecurityType = SecurityType(0);
    pub const LEGACY: SecurityType = SecurityType(1);
    pub const AUTO: SecurityType = SecurityType(2);
    pub const AES128_GCM: SecurityType = SecurityType(3);
    pub const CHACHA20_POLY1305: SecurityType = SecurityType(4);
    pub const NONE: SecurityType = SecurityType(5);
    pub const ZERO: SecurityType = SecurityType(6);
}

impl From<SupportedCipher> for SecurityType {
    fn from(value: SupportedCipher) -> Self {
        match value {
            SupportedCipher::ChaCha20Poly1305 => SecurityType::CHACHA20_POLY1305,
            _ => SecurityType::AES128_GCM,
        }
    }
}

pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub option: Vec<RequestOption>,
    pub security: SecurityType,
    pub address: Socks5CommandRequest,
    pub id: [u8; 16],
}

impl RequestHeader {
    pub fn default(command: RequestCommand, security: SecurityType, address: Socks5CommandRequest, uuid: String) -> Self {
        Self {
            version: VERSION,
            command,
            option: vec![
                RequestOption::CHUNK_STREAM,
                RequestOption::CHUNK_MASKING,
                RequestOption::GLOBAL_PADDING,
                RequestOption::AUTHENTICATED_LENGTH,
            ],
            security,
            address,
            id: ID::new_id(uuid),
        }
    }
}
