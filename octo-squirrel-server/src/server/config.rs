use std::env::args;
use std::fs::File;
use std::io::Read;

use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::config::Mode;
use octo_squirrel::config::User;
use octo_squirrel::config::WebSocketConfig;
use octo_squirrel::protocol::Protocol;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    #[serde(rename = "certificateFile")]
    pub certificate_file: String,
    #[serde(rename = "keyFile")]
    pub key_file: String,
    #[serde(rename = "serverName")]
    pub server_name: String,
}

pub fn init() -> Result<Vec<ServerConfig>, std::io::Error> {
    let path = args().nth(1).unwrap_or(octo_squirrel::config::default_path());
    let mut json = String::new();
    File::open(&path).unwrap_or_else(|_| panic!("Can't find the config (by path {}). Please ensure the file path is the 1st start command arg (named 'config.json') and put the file into the same folder", &path)).read_to_string(&mut json)?;
    let config: Vec<ServerConfig> = serde_json::from_str(&json)?;
    Ok(config)
}

#[cfg(test)]
mod test {
    use octo_squirrel::codec::aead::CipherKind;
    use octo_squirrel::protocol::Protocol;
    use rand::Rng;
    use rand::distr::Alphanumeric;
    use rand::random;
    use serde_json::json;

    use super::ServerConfig;

    #[test]
    fn test_config_serialize() {
        let server_port: u16 = random();
        let server_name: String = rand::rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect();
        let server_host = format!("www.{}.com", server_name);
        let json = json!({
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
        });
        let current: ServerConfig = serde_json::from_value(json).unwrap();
        assert_eq!(server_host, current.host);
        assert_eq!(server_port, current.port);
        assert_eq!(CipherKind::ChaCha20Poly1305, current.cipher);
        assert_eq!(Protocol::VMess, current.protocol);
        assert!(current.ssl.is_some());
        assert_eq!(current.ssl.as_ref().unwrap().server_name, server_name)
    }
}
