use std::env::args;
use std::fs::File;
use std::io;
use std::io::BufReader;

use serde::{Deserialize, Serialize};

use crate::common::codec::aead::SupportedCipher;
use crate::common::protocol::network::{Network, PacketEncoding};
use crate::common::protocol::Protocols;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub cipher: SupportedCipher,
    pub protocol: Protocols,
    pub remark: String,
    #[serde(default = "Vec::new")]
    pub networks: Vec<Network>,
    #[serde(rename = "packetEncoding")]
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub port: u16,
    pub index: usize,
    pub servers: Vec<ServerConfig>,
}

impl ClientConfig {
    pub fn get_current(&self) -> Option<&ServerConfig> {
        self.servers.get(self.index)
    }
}

pub fn init() -> Result<ClientConfig, io::Error> {
    let path = args().nth(1).expect("Please set config path in start command args.");
    let file = File::open(path)?;
    let config: ClientConfig = serde_json::from_reader(BufReader::new(file))?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::common::codec::aead::SupportedCipher;
    use crate::common::protocol::network::{Network, PacketEncoding};
    use crate::common::protocol::Protocols;
    use crate::config::ClientConfig;

    #[test]
    fn test_config_serialize() {
        let json = json!({
          "port": 1081,
          "index": 0,
          "servers": [
            {
              "host": "localhost",
              "port": 1090,
              "password": "{password}",
              "cipher": "chacha20-poly1305",
              "protocol": "vmess",
              "remark": "",
              "networks": [
                "TCP",
                "UDP"
              ],
              "packetEncoding": "Packet"
            }
          ]
        });
        let client_config: ClientConfig = serde_json::from_value(json).unwrap();
        assert_eq!(1089, client_config.port);
        let current = client_config.get_current().unwrap();
        assert_eq!("localhost", current.host);
        assert_eq!(1090, current.port);
        assert_eq!(SupportedCipher::ChaCha20Poly1305, current.cipher);
        assert_eq!(Protocols::Vmess, current.protocol);
        assert_eq!(vec![Network::TCP, Network::UDP], current.networks);
        assert_eq!(PacketEncoding::Packet, current.packet_encoding);
    }
}
