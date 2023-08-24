use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

pub mod network;
pub mod socks5;
pub mod vmess;

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocols {
    Shadowsocks,
    VMess,
}

impl Display for Protocols {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocols::Shadowsocks => write!(f, "shadowsocks"),
            Protocols::VMess => write!(f, "vmess"),
        }
    }
}
