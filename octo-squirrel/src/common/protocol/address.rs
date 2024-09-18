use std::fmt::Display;
use std::io;
use std::net::IpAddr;
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

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn cmp_ip_addr(this: &[u8], other: IpAddr) -> std::cmp::Ordering {
            match other {
                IpAddr::V4(ref ipv4_addr) => this.cmp(&ipv4_addr.octets()),
                IpAddr::V6(ref ipv6_addr) => this.cmp(&ipv6_addr.octets()),
            }
        }

        match (self, other) {
            (Address::Domain(this_host, this_port), Address::Domain(other_host, other_port)) => {
                this_port.cmp(other_port).then_with(|| this_host.cmp(other_host))
            }
            (Address::Domain(this_host, this_port), Address::Socket(other_addr)) => {
                this_port.cmp(&other_addr.port()).then_with(|| cmp_ip_addr(this_host.as_bytes(), other_addr.ip()))
            }
            (Address::Socket(this_addr), Address::Domain(other_host, other_port)) => {
                this_addr.port().cmp(other_port).then_with(|| cmp_ip_addr(other_host.as_bytes(), this_addr.ip()).reverse())
            }
            (Address::Socket(this), Address::Socket(other)) => this.cmp(other),
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
