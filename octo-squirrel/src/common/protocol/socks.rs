pub enum SocksVersion {
    Socks4a = 4,
    Socks5 = 5,
    Unknown = 0xff,
}

impl From<u8> for SocksVersion {
    fn from(value: u8) -> Self {
        if value == Self::Socks4a as u8 {
            return Self::Socks4a;
        }
        if value == Self::Socks5 as u8 {
            return Self::Socks5;
        }
        Self::Unknown
    }
}
