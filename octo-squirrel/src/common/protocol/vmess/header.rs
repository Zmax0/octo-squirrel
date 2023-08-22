use super::{ID, VERSION};
use crate::common::protocol::socks5::message::Socks5CommandRequest;

#[derive(PartialEq)]
pub struct AddressType(pub u8);
pub const IPV4: AddressType = AddressType(1);
pub const DOMAIN: AddressType = AddressType(2);
pub const IPV6: AddressType = AddressType(3);

pub struct RequestCommand(pub u8);
pub const TCP: RequestCommand = RequestCommand(1);
pub const UDP: RequestCommand = RequestCommand(2);

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct RequestOption(pub u8);
pub const CHUNK_STREAM: RequestOption = RequestOption(1);
pub const CONNECTION_REUSE: RequestOption = RequestOption(2);
pub const CHUNK_MASKING: RequestOption = RequestOption(4);
pub const GLOBAL_PADDING: RequestOption = RequestOption(8);
pub const AUTHENTICATED_LENGTH: RequestOption = RequestOption(16);

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct SecurityType(pub u8);
pub const UNKNOWN: SecurityType = SecurityType(0);
pub const LEGACY: SecurityType = SecurityType(1);
pub const AUTO: SecurityType = SecurityType(2);
pub const AES128_GCM: SecurityType = SecurityType(3);
pub const CHACHA20_POLY1305: SecurityType = SecurityType(4);
pub const NONE: SecurityType = SecurityType(5);
pub const ZERO: SecurityType = SecurityType(6);

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
            option: vec![CHUNK_STREAM, CHUNK_MASKING, GLOBAL_PADDING, AUTHENTICATED_LENGTH],
            security,
            address,
            id: ID::new_id(uuid),
        }
    }
}
