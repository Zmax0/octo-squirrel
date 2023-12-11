use super::address::Address;
use crate::common::network::Network;

#[derive(Clone)]
pub enum StreamType {
    Request(Address),
    Response,
}

impl StreamType {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Request(_) => 0,
            Self::Response => 1,
        }
    }

    pub fn expect_u8(&self) -> u8 {
        match self {
            Self::Request(_) => 1,
            Self::Response => 0,
        }
    }
}

#[derive(Clone)]
pub struct Context {
    pub stream_type: StreamType,
    pub network: Network,
}

impl Context {
    pub fn tcp(stream_type: StreamType) -> Self {
        Self { stream_type, network: Network::TCP }
    }
    pub fn udp(stream_type: StreamType) -> Self {
        Self { stream_type, network: Network::UDP }
    }
}
