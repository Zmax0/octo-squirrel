use std::fmt::Display;
use std::net::SocketAddr;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Address {
    Domain(String, u16),
    Socket(SocketAddr),
}

impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        Address::Socket(value)
    }
}

impl From<Address> for SocketAddr {
    fn from(value: Address) -> Self {
        match value {
            Address::Domain(host, port) => format!("{}:{}", host, port).parse().unwrap(),
            Address::Socket(addr) => addr,
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Domain(host, port) => write!(f, "{}:{}", host, port),
            Address::Socket(addr) => addr.fmt(f),
        }
    }
}
