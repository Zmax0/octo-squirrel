use std::env::args;
use std::fs::File;
use std::io::Read;

use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::config::Mode;
use octo_squirrel::config::WebSocketConfig;
use octo_squirrel::log::Logger;
use octo_squirrel::protocol::Protocol;
use serde::Deserialize;
use serde::Serialize;

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
    pub dns: Option<DnsConfig>,
}

impl AsRef<ServerConfig> for ServerConfig {
    fn as_ref(&self) -> &ServerConfig {
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsConfig {
    pub url: String,
    pub ssl: Option<SslConfig>,
    pub cache_size: usize,
    #[serde(skip_serializing)]
    pub cache: super::dns::Cache,
}

impl<'de> Deserialize<'de> for DnsConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = serde_json::Map::deserialize(deserializer)?;
        let url = map.get("url").ok_or(serde::de::Error::missing_field("url"))?;
        let url = String::deserialize(url).map_err(serde::de::Error::custom)?;
        let ssl = if let Some(ssl) = map.get("ssl") { Some(SslConfig::deserialize(ssl).map_err(serde::de::Error::custom)?) } else { None };
        let cache_size =
            if let Some(cache_size) = map.get("cache_size") { usize::deserialize(cache_size).map_err(serde::de::Error::custom)? } else { 100 };
        let cache = super::dns::Cache::new(cache_size);
        Ok(DnsConfig { url, ssl, cache_size, cache })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    #[serde(default, rename = "certificateFile")]
    pub certificate_file: Option<String>,
    #[serde(default, rename = "keyFile")]
    pub key_file: Option<String>,
    #[serde(default, rename = "serverName")]
    pub server_name: Option<String>,
}

pub fn init() -> Result<ClientConfig, std::io::Error> {
    let path = args().nth(1).unwrap_or(octo_squirrel::config::default_path());
    let mut json = String::new();
    File::open(&path).unwrap_or_else(|_| panic!("Can't find the config (by path {}). Please ensure the file path is the 1st start command arg (named 'config.json') and put the file into the same folder", &path)).read_to_string(&mut json)?;
    let config: ClientConfig = serde_json::from_str(&json)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use octo_squirrel::codec::aead::CipherKind;
    use octo_squirrel::protocol::Protocol;
    use rand::random;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_config_serialize() {
        let client_port: u16 = random();
        let server_port: u16 = random();
        let server_host = "www.example.com";
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
                      "serverName": server_host
                  },
                  "mode": "tcp",
                  "dns": {
                      "url": "https://8.8.8.8/dns-query",
                      "ssl": {
                        "certificateFile": "/path/to/certificate.crt",
                        "keyFile": "/path/to/private.key",
                        "serverName": server_host
                    }
                  }
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
        assert_eq!(current.ssl.as_ref().unwrap().server_name.as_ref().unwrap(), &server_host);
        assert!(current.dns.is_some());
        assert_eq!(current.dns.as_ref().unwrap().url, "https://8.8.8.8/dns-query");
        assert!(current.dns.as_ref().unwrap().ssl.is_some());
        assert_eq!(current.dns.as_ref().unwrap().ssl.as_ref().unwrap().server_name.as_ref().unwrap(), &server_host);
    }
}
