use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::vec;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Address {
    Domain(String, u16),
    Socket(SocketAddr),
}

impl Address {
    pub fn to_socket_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Address::Domain(host, port) => {
                format!("{host}:{port}").to_socket_addrs()?.next().ok_or(io::Error::new(io::ErrorKind::AddrNotAvailable, ""))
            }
            Address::Socket(addr) => Ok(*addr),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(value: SocketAddr) -> Self {
        Address::Socket(value)
    }
}

impl ToSocketAddrs for Address {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        match self {
            Address::Domain(host, port) => format!("{host}:{port}").to_socket_addrs(),
            Address::Socket(addr) => Ok(vec![*addr].into_iter()),
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
