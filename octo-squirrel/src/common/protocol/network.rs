use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Direction(&'static str);
pub const INBOUND: Direction = Direction("←");
pub const OUTBOUND: Direction = Direction("→");

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Network {
    TCP,
    UDP,
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum PacketEncoding {
    None,
    Packet,
}

impl Default for PacketEncoding {
    fn default() -> Self {
        PacketEncoding::None
    }
}
