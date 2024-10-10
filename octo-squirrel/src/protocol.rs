use std::fmt::Display;
use std::fmt::Formatter;

use serde::Deserialize;
use serde::Serialize;

pub mod address;
pub mod shadowsocks;
pub mod socks;
pub mod socks5;
pub mod trojan;
pub mod vmess;

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Shadowsocks,
    VMess,
    Trojan,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Shadowsocks => write!(f, "shadowsocks"),
            Protocol::VMess => write!(f, "vmess"),
            Protocol::Trojan => write!(f, "trojan"),
        }
    }
}
