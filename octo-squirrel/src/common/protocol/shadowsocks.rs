use super::address::Address;
use crate::common::network::Network;

#[derive(Clone)]
pub enum StreamType {
    Request,
    Response,
}

impl StreamType {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Response => 1,
        }
    }

    pub fn expect_u8(&self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 0,
        }
    }
}

#[derive(Clone)]
pub struct Context {
    pub stream_type: StreamType,
    pub network: Network,
    pub address: Option<Address>,
    pub session: Session,
}

impl Context {
    pub fn tcp(stream_type: StreamType, address: Option<Address>) -> Self {
        Self { stream_type, network: Network::TCP, address, session: Session::default() }
    }
    pub fn udp(stream_type: StreamType, address: Option<Address>) -> Self {
        Self { stream_type, network: Network::UDP, address, session: Session::default() }
    }
}

#[derive(Copy, Clone, Default)]
pub struct Session {
    pub packet_id: u64,
    pub client_session_id: u64,
}
