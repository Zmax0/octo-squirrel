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
