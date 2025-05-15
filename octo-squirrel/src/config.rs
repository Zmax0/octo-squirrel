use std::collections::HashMap;
use std::fmt::Display;

use serde::Deserialize;
use serde::Serialize;

pub fn default_path() -> String {
    let mut path = std::env::current_exe().expect("Can't get the current exe path");
    path.pop();
    path.push("config.json");
    path.to_str().expect("Can't convert the path to string").to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Mode {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "tcp_and_udp")]
    TcpAndUdp,
    #[serde(rename = "quic")]
    Quic,
    #[serde(rename = "tcp_and_quic")]
    TcpAndQuic,
}

impl Mode {
    pub fn enable_tcp(&self) -> bool {
        matches!(self, Self::Tcp | Self::TcpAndUdp)
    }

    pub fn enable_udp(&self) -> bool {
        matches!(self, Self::Udp | Self::TcpAndUdp)
    }

    pub fn enable_quic(&self) -> bool {
        matches!(self, Self::Quic | Self::TcpAndQuic)
    }
}

impl Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Tcp => write!(f, "tcp"),
            Mode::Udp => write!(f, "udp"),
            Mode::TcpAndUdp => write!(f, "tcp_and_udp"),
            Mode::Quic => write!(f, "quic"),
            Mode::TcpAndQuic => write!(f, "tcp_and_quic"),
        }
    }
}

impl Default for Mode {
    fn default() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub header: HashMap<String, String>,
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub password: String,
}
