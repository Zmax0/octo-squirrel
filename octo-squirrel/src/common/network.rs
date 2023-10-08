use std::net::SocketAddr;

use bytes::BytesMut;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug)]
pub struct Direction(&'static str);
pub const INBOUND: Direction = Direction("←");
pub const OUTBOUND: Direction = Direction("→");

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Network {
    TCP,
    UDP,
}

#[derive(Debug, PartialEq, Clone, Copy, Default, Serialize, Deserialize)]
pub enum PacketEncoding {
    #[default]
    None,
    Packet,
}

pub type DatagramPacket = (BytesMut, SocketAddr);
