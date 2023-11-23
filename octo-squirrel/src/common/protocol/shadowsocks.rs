use super::address::Address;
use crate::common::network::Network;

#[derive(Clone)]
pub enum StreamType {
    Request(Address),
    Response,
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
