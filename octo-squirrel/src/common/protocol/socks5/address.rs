use std::io::Error;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;

use super::Socks5AddressType;

pub struct Address;

impl Address {
    pub fn encode_address(addr_type: Socks5AddressType, addr_value: &String, dst: &mut BytesMut) -> Result<(), Error> {
        if addr_type == Socks5AddressType::IPV4 {
            let v4: Ipv4Addr = addr_value.parse().unwrap();
            dst.put_slice(&v4.octets());
            return Ok(());
        } else if addr_type == Socks5AddressType::IPV6 {
            let v6: Ipv6Addr = addr_value.parse().unwrap();
            dst.put_slice(&v6.octets());
            return Ok(());
        } else if addr_type == Socks5AddressType::DOMAIN {
            dst.put_u8(addr_value.len() as u8);
            if addr_value.is_ascii() {
                dst.put_slice(addr_value.as_bytes());
            } else {
                for b in addr_value.as_bytes() {
                    if b.is_ascii() {
                        dst.put_u8(*b);
                    } else {
                        dst.put_u8(b'?');
                    }
                }
            }
            return Ok(());
        }
        let msg = format!("unsupported address type: {}", addr_type.0 & 0xff);
        Err(Error::new(ErrorKind::InvalidData, msg))
    }

    pub fn encode_socket_address(addr: SocketAddr, dst: &mut BytesMut) -> Result<(), Error> {
        return match addr {
            SocketAddr::V4(v4) => {
                dst.put_u8(Socks5AddressType::IPV4.0);
                dst.put_slice(&v4.ip().octets());
                dst.put_u16(v4.port());
                Ok(())
            }
            SocketAddr::V6(v6) => {
                dst.put_u8(Socks5AddressType::IPV6.0);
                dst.put_slice(&v6.ip().octets());
                dst.put_u16(v6.port());
                Ok(())
            }
        };
    }

    pub fn decode_address(addr_type: Socks5AddressType, src: &mut BytesMut) -> Result<String, Error> {
        if addr_type == Socks5AddressType::IPV4 {
            let ip_v4 = Ipv4Addr::from(src.get_u32());
            return Ok(ip_v4.to_string());
        } else if addr_type == Socks5AddressType::IPV6 {
            let ip_v6 = Ipv6Addr::from(src.get_u128());
            return Ok(ip_v6.to_string());
        } else if addr_type == Socks5AddressType::DOMAIN {
            let len = src.get_u8();
            let bytes = src.copy_to_bytes(len as usize);
            return Ok(String::from_utf8(bytes.to_vec()).unwrap());
        }
        let msg = format!("unsupported address type: {}", addr_type.0 & 0xff);
        Err(Error::new(ErrorKind::InvalidData, msg))
    }

    pub fn decode_socket_address(src: &mut BytesMut) -> Result<SocketAddr, Error> {
        let addr_type = Socks5AddressType(src.get_u8());
        if addr_type == Socks5AddressType::IPV4 {
            let ip_v4 = Ipv4Addr::from(src.get_u32());
            return Ok(SocketAddr::V4(SocketAddrV4::new(ip_v4, src.get_u16())));
        } else if addr_type == Socks5AddressType::IPV6 {
            let ip_v6 = Ipv6Addr::from(src.get_u128());
            return Ok(SocketAddr::V6(SocketAddrV6::new(ip_v6, src.get_u16(), 0, 0)));
        } else if addr_type == Socks5AddressType::DOMAIN {
            let len = src.get_u8();
            let bytes = src.copy_to_bytes(len as usize);
            return Ok(String::from_utf8(bytes.to_vec()).unwrap().parse().unwrap());
        }
        let msg = format!("unsupported address type: {}", addr_type.0 & 0xff);
        Err(Error::new(ErrorKind::InvalidData, msg))
    }
}

#[test]
fn test_codec() {
    fn test_codec(address: String, addr_type: Socks5AddressType) {
        let buf = &mut BytesMut::new();
        let res = Address::encode_address(addr_type, &address, buf);
        let mut actual_address = String::new();
        if let Ok(()) = res {
            let res = Address::decode_address(addr_type, buf);
            if let Ok(address) = res {
                actual_address = address;
            }
        }
        assert!(!buf.has_remaining());
        assert_eq!(address, actual_address);
    }

    test_codec("192.168.1.1".to_string(), Socks5AddressType::IPV4);
    test_codec("abcd:ef01:2345:6789:abcd:ef01:2345:6789".to_string(), Socks5AddressType::IPV6);
    test_codec("www.w3.org".to_string(), Socks5AddressType::DOMAIN);
}
