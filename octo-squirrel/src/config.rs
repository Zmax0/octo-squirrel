use std::collections::HashMap;
use std::fmt::Display;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::Serialize;

use crate::codec::aead::CipherKind;
use crate::protocol::Protocol;

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
pub struct ServerConfig<S: Clone + Default> {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub mode: Mode,
    pub password: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub cipher: CipherKind,
    #[serde(default)]
    pub ssl: Option<S>,
    #[serde(default)]
    pub ws: Option<WebSocketConfig>,
    #[serde(default)]
    pub quic: Option<S>,
    #[serde(default)]
    pub user: Vec<User>,
    #[serde(skip)]
    marker: PhantomData<S>,
}

impl<S: Clone + Default> AsRef<ServerConfig<S>> for ServerConfig<S> {
    fn as_ref(&self) -> &ServerConfig<S> {
        self
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
