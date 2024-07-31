use rand::random;

use super::address::Address;
use crate::common::network::Transport;

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
    pub network: Transport,
    pub address: Option<Address>,
    pub session: Session,
}

impl Context {
    pub fn tcp(stream_type: StreamType, address: Option<Address>) -> Self {
        let session = Session::from(&stream_type);
        Self { stream_type, network: Transport::TCP, address, session }
    }
    pub fn udp(stream_type: StreamType, address: Option<Address>) -> Self {
        let session = Session::from(&stream_type);
        Self { stream_type, network: Transport::UDP, address, session }
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct Session {
    pub packet_id: u64,
    pub client_session_id: u64,
    pub server_session_id: u64,
}

impl From<&StreamType> for Session {
    fn from(value: &StreamType) -> Self {
        let mut client_session_id = 0;
        let mut server_session_id = 0;
        match value {
            StreamType::Request => client_session_id = random(),
            StreamType::Response => server_session_id = random(),
        }
        Self { packet_id: 1, client_session_id, server_session_id }
    }
}
