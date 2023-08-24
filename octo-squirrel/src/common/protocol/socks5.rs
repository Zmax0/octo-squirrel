pub mod address;
pub mod codec;
pub mod handshake;
pub mod message;

pub const VERSION: u8 = 5;

pub struct Socks5CommandStatus(pub u8);

impl Socks5CommandStatus {
    pub const SUCCESS: Socks5CommandStatus = Socks5CommandStatus(0);
    pub const FAILURE: Socks5CommandStatus = Socks5CommandStatus(1);
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Socks5AddressType(pub u8);

impl Socks5AddressType {
    pub const IPV4: Socks5AddressType = Socks5AddressType(1);
    pub const DOMAIN: Socks5AddressType = Socks5AddressType(3);
    pub const IPV6: Socks5AddressType = Socks5AddressType(4);
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Socks5CommandType(pub u8);

impl Socks5CommandType {
    pub const CONNECT: Socks5CommandType = Socks5CommandType(1);
    pub const BIND: Socks5CommandType = Socks5CommandType(2);
    pub const UDP_ASSOCIATE: Socks5CommandType = Socks5CommandType(3);
}

#[derive(PartialEq)]
pub struct Socks5AuthMethod(pub u8);

impl Socks5AuthMethod {
    pub const NO_AUTH: Socks5AuthMethod = Socks5AuthMethod(0);
    pub const GSSAPI: Socks5AuthMethod = Socks5AuthMethod(1);
    pub const PASSWORD: Socks5AuthMethod = Socks5AuthMethod(2);
    pub const UNACCEPTED: Socks5AuthMethod = Socks5AuthMethod(255);
}
