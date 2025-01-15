use std::collections::HashMap;
use std::env::args;
use std::fmt::Display;
use std::fs::File;
use std::io;

use serde::Deserialize;
use serde::Serialize;

use crate::codec::aead::CipherKind;
use crate::log::Logger;
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
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub mode: Mode,
    pub password: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub cipher: CipherKind,
    #[serde(default)]
    pub ssl: Option<SslConfig>,
    #[serde(default)]
    pub ws: Option<WebSocketConfig>,
    #[serde(default)]
    pub quic: Option<SslConfig>,
    #[serde(default)]
    pub user: Vec<User>,
}

impl AsRef<ServerConfig> for ServerConfig {
    fn as_ref(&self) -> &ServerConfig {
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default)]
    pub host: Option<String>,
    pub port: u16,
    #[serde(default)]
    pub mode: Mode,
    pub index: usize,
    #[serde(default)]
    pub logger: Logger,
    pub servers: Vec<ServerConfig>,
}

impl ClientConfig {
    pub fn get_current(&mut self) -> ServerConfig {
        self.servers.remove(self.index)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    #[serde(rename = "certificateFile")]
    pub certificate_file: String,
    #[serde(rename = "keyFile", default)]
    pub key_file: String,
    #[serde(rename = "serverName")]
    pub server_name: String,
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

pub fn init_client() -> Result<ClientConfig, io::Error> {
    use std::io::Read;
    let path = args().nth(1).unwrap_or("config.json".to_owned());
    let mut json = String::new();
    File::open(&path).unwrap_or_else(|_| panic!("Can't find the config (by path {}). Please ensure the file path is the 1st start command arg (named 'config.json') and put the file into the same folder", &path)).read_to_string(&mut json)?;
    let config: ClientConfig = serde_json::from_str(&json)?;
    Ok(config)
}

pub fn init_server() -> Result<Vec<ServerConfig>, io::Error> {
    use std::io::Read;
    let path = args().nth(1).unwrap_or("config.json".to_owned());
    let mut json = String::new();
    File::open(&path).unwrap_or_else(|_| panic!("Can't find the config (by path {}). Please ensure the file path is the 1st start command arg (named 'config.json') and put the file into the same folder", &path)).read_to_string(&mut json)?;
    let config: Vec<ServerConfig> = serde_json::from_str(&json)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use rand::distributions::Alphanumeric;
    use rand::random;
    use rand::Rng;
    use serde_json::json;

    use crate::codec::aead::CipherKind;
    use crate::config::ClientConfig;
    use crate::protocol::Protocol;

    #[test]
    fn test_config_serialize() {
        let client_port: u16 = random();
        let server_port: u16 = random();
        let server_name: String = rand::thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        let server_host = format!("www.{}.com", server_name);
        let json = json!({
          "port": client_port,
          "index": 0,
          "mode" : "tcp_and_udp",
          "servers": [
            {
              "host": server_host,
              "port": server_port,
              "password": "{password}",
              "cipher": "chacha20-ietf-poly1305",
              "protocol": "vmess",
              "ssl": {
                "certificateFile": "/path/to/certificate.crt",
                "keyFile": "/path/to/private.key",
                "serverName": server_name
              },
              "mode": "tcp"
            }
          ]
        });
        let mut client_config: ClientConfig = serde_json::from_value(json).unwrap();
        assert_eq!(client_port, client_config.port);
        let current = client_config.get_current();
        assert_eq!(server_host, current.host);
        assert_eq!(server_port, current.port);
        assert_eq!(CipherKind::ChaCha20Poly1305, current.cipher);
        assert_eq!(Protocol::VMess, current.protocol);
        assert!(current.ssl.is_some());
        assert_eq!(current.ssl.as_ref().unwrap().server_name, server_name)
    }
}
