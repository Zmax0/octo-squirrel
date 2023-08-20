use std::{io::{Error, ErrorKind}, net::{Ipv4Addr, Ipv6Addr}};

use bytes::{Buf, BufMut, BytesMut};

use super::{Socks5AddressType, DOMAIN, IPV4, IPV6};

pub struct Socks5AddressEncoder;

impl Socks5AddressEncoder {
    pub fn encode_address(addr_type: Socks5AddressType, addr_value: &String, dst: &mut BytesMut) -> Result<(), Error> {
        if addr_type == IPV4 {
            let ip_v4: Ipv4Addr = addr_value.parse().unwrap();
            dst.extend_from_slice(&ip_v4.octets());
            return Ok(());
        } else if addr_type == IPV6 {
            let ip_v6: Ipv6Addr = addr_value.parse().unwrap();
            dst.extend_from_slice(&ip_v6.octets());
            return Ok(());
        } else if addr_type == DOMAIN {
            dst.put_u8(addr_value.len() as u8);
            if addr_value.is_ascii() {
                dst.extend_from_slice(addr_value.as_bytes());
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
}

pub struct Socks5AddressDecoder;

impl Socks5AddressDecoder {
    pub fn decode_address(addr_type: Socks5AddressType, src: &mut BytesMut) -> Result<String, Error> {
        if addr_type == IPV4 {
            let ip_v4 = Ipv4Addr::from(src.get_u32());
            return Ok(ip_v4.to_string());
        } else if addr_type == IPV6 {
            let ip_v6 = Ipv6Addr::from(src.get_u128());
            return Ok(ip_v6.to_string());
        } else if addr_type == DOMAIN {
            let len = src.get_u8();
            let bytes = src.copy_to_bytes(len as usize);
            return Ok(String::from_utf8(bytes.to_vec()).unwrap());
        }
        let msg = format!("unsupported address type: {}", addr_type.0 & 0xff);
        Err(Error::new(ErrorKind::InvalidData, msg))
    }
}

#[test]
fn test_codec() {
    fn test_codec(address: String, addr_type: Socks5AddressType) {
        let buf = &mut BytesMut::new();
        let res = Socks5AddressEncoder::encode_address(addr_type, &address, buf);
        let mut actual_address = String::new();
        if let Ok(()) = res {
            let res = Socks5AddressDecoder::decode_address(addr_type, buf);
            if let Ok(address) = res {
                actual_address = address;
            }
        }
        assert!(!buf.has_remaining());
        assert_eq!(address, actual_address);
    }

    test_codec("192.168.1.1".to_string(), IPV4);
    test_codec("abcd:ef01:2345:6789:abcd:ef01:2345:6789".to_string(), IPV6);
    test_codec("www.w3.org".to_string(), DOMAIN);
}
