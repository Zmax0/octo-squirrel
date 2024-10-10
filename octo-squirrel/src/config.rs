use std::collections::HashMap;
#[cfg(any(feature = "client", feature = "server"))]
use std::env::args;
#[cfg(any(feature = "client", feature = "server"))]
use std::fs::File;
#[cfg(any(feature = "client", feature = "server"))]
use std::io;
#[cfg(any(feature = "client", feature = "server"))]
use std::io::BufReader;

use serde::Deserialize;
use serde::Serialize;

use crate::codec::aead::CipherKind;
use crate::log::Logger;
use crate::network::PacketEncoding;
use crate::network::Transport;
use crate::protocol::Protocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub cipher: CipherKind,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub transport: Vec<Transport>,
    #[serde(rename = "packetEncoding")]
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
    #[serde(default)]
    pub ssl: Option<SslConfig>,
    #[serde(default)]
    pub ws: Option<WebSocketConfig>,
    #[cfg(feature = "server")]
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
    pub port: u16,
    pub index: usize,
    #[serde(default)]
    pub logger: Logger,
    pub servers: Vec<ServerConfig>,
}

impl ClientConfig {
    pub fn get_current(&self) -> Option<&ServerConfig> {
        self.servers.get(self.index)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    #[serde(rename = "certificateFile")]
    pub certificate_file: String,
    #[cfg(feature = "server")]
    #[serde(rename = "keyFile")]
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

#[cfg(feature = "client")]
pub fn init_client() -> Result<ClientConfig, io::Error> {
    let path = args().nth(1).unwrap_or("config.json".to_owned());
    let file = File::open(&path).unwrap_or_else(|_| panic!("Can't find the config (by path {}). Please ensure the file path is the 1st start command arg (named 'config.json') and put the file into the same folder", &path));
    let config: ClientConfig = serde_json::from_reader(BufReader::new(file))?;
    Ok(config)
}

#[cfg(feature = "server")]
pub fn init_server() -> Result<Vec<ServerConfig>, io::Error> {
    let path = args().nth(1).unwrap_or("config.json".to_owned());
    let file = File::open(&path).unwrap_or_else(|_| panic!("Can't find the config (by path {}). Please ensure the file path is the 1st start command arg (named 'config.json') and put the file into the same folder", &path));
    let config: Vec<ServerConfig> = serde_json::from_reader(BufReader::new(file))?;
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
    use crate::network::PacketEncoding;
    use crate::network::Transport;
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
          "servers": [
            {
              "host": server_host,
              "port": server_port,
              "password": "{password}",
              "cipher": "chacha20-poly1305",
              "protocol": "vmess",
              "remark": "",
              "transport": [
                "tcp",
                "udp"
              ],
              "ssl": {
                "certificateFile": "/path/to/certificate.crt",
                "keyFile": "/path/to/private.key",
                "serverName": server_name
              }
            }
          ]
        });
        let client_config: ClientConfig = serde_json::from_value(json).unwrap();
        assert_eq!(client_port, client_config.port);
        let current = client_config.get_current().unwrap();
        assert_eq!(server_host, current.host);
        assert_eq!(server_port, current.port);
        assert_eq!(CipherKind::ChaCha20Poly1305, current.cipher);
        assert_eq!(Protocol::VMess, current.protocol);
        assert_eq!(vec![Transport::TCP, Transport::UDP], current.transport);
        assert_eq!(PacketEncoding::None, current.packet_encoding);
        assert!(current.ssl.is_some());
        assert_eq!(current.ssl.as_ref().unwrap().server_name, server_name)
    }
}
