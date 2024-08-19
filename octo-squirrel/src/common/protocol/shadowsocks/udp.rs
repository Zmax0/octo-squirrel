use rand::random;

use super::Mode;
use crate::common::network::Transport;
use crate::common::protocol::address::Address;

#[derive(Clone)]
pub struct Context {
    pub stream_type: Mode,
    pub network: Transport,
    pub address: Option<Address>,
    pub session: Session,
}

impl Context {
    pub fn tcp(stream_type: Mode, address: Option<Address>) -> Self {
        let session = Session::from(&stream_type);
        Self { stream_type, network: Transport::TCP, address, session }
    }
    pub fn udp(stream_type: Mode, address: Option<Address>) -> Self {
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

impl From<&Mode> for Session {
    fn from(value: &Mode) -> Self {
        let mut client_session_id = 0;
        let mut server_session_id = 0;
        match value {
            Mode::Client => client_session_id = random(),
            Mode::Server => server_session_id = random(),
        }
        Self { packet_id: 1, client_session_id, server_session_id }
    }
}
