use std::net::SocketAddr;

use bytes::BytesMut;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    TCP,
    UDP,
    WS,
}

#[derive(Debug, PartialEq, Clone, Copy, Default, Serialize, Deserialize)]
pub enum PacketEncoding {
    #[default]
    None,
    Packet,
}

pub type DatagramPacket = (BytesMut, SocketAddr);
