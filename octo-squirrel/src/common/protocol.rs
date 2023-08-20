use serde::{Deserialize, Serialize};

pub mod network;
pub mod socks5;
pub mod vmess;

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocols {
    Shadowsocks,
    Vmess,
}
