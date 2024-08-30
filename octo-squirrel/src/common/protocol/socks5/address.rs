use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use anyhow::Result;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;

use super::Socks5AddressType;
use crate::common::protocol::address::Address;

pub struct AddressCodec;

impl AddressCodec {
    pub fn encode(addr: &Address, dst: &mut BytesMut) -> Result<()> {
        match addr {
            Address::Domain(host, port) => {
                dst.put_u8(Socks5AddressType::Domain as u8);
                dst.put_u8(host.len() as u8);
                if host.is_ascii() {
                    dst.put_slice(host.as_bytes());
                } else {
                    for b in host.as_bytes() {
                        if b.is_ascii() {
                            dst.put_u8(*b);
                        } else {
                            dst.put_u8(b'?');
                        }
                    }
                }
                dst.put_u16(*port);
            }
            Address::Socket(socket_addr) => match socket_addr {
                SocketAddr::V4(v4) => {
                    dst.put_u8(Socks5AddressType::Ipv4 as u8);
                    dst.put_slice(&v4.ip().octets());
                    dst.put_u16(v4.port());
                }
                SocketAddr::V6(v6) => {
                    dst.put_u8(Socks5AddressType::Ipv6 as u8);
                    dst.put_slice(&v6.ip().octets());
                    dst.put_u16(v6.port())
                }
            },
        }
        Ok(())
    }

    pub fn decode(src: &mut BytesMut) -> Result<Address> {
        let addr_type = Socks5AddressType::new(src.get_u8())?;
        match addr_type {
            Socks5AddressType::Ipv4 => {
                let ip_v4 = Ipv4Addr::from(src.get_u32());
                Ok(Address::Socket(SocketAddr::V4(SocketAddrV4::new(ip_v4, src.get_u16()))))
            }
            Socks5AddressType::Domain => {
                let len = src.get_u8();
                let host_bytes = src.copy_to_bytes(len as usize);
                let port = src.get_u16();
                Ok(Address::Domain(String::from_utf8(host_bytes.to_vec())?.parse()?, port))
            }
            Socks5AddressType::Ipv6 => {
                let ip_v6 = Ipv6Addr::from(src.get_u128());
                Ok(Address::Socket(SocketAddr::V6(SocketAddrV6::new(ip_v6, src.get_u16(), 0, 0))))
            }
        }
    }

    pub fn length(addr: &Address) -> usize {
        match addr {
            Address::Domain(host, _) => 1 + 1 + host.len() + 2,
            Address::Socket(socket_addr) => match socket_addr {
                SocketAddr::V4(_) => 1 + 4 + 2,
                SocketAddr::V6(_) => 1 + 8 * 2 + 2,
            },
        }
    }

    pub fn try_decode_at(src: &BytesMut, at: usize) -> Result<usize> {
        match Socks5AddressType::new(src[at])? {
            Socks5AddressType::Ipv4 => Ok(1 + 4 + 2),
            Socks5AddressType::Domain => Ok(1 + 1 + src[at + 1] as usize + 2),
            Socks5AddressType::Ipv6 => Ok(1 + 8 * 2 + 2),
        }
    }
}

#[test]
fn test_codec() {
    fn test_codec(src: Address) {
        let buf = &mut BytesMut::new();
        let res = AddressCodec::encode(&src, buf);
        if let Ok(()) = res {
            let res = AddressCodec::decode(buf);
            if let Ok(actual) = res {
                assert_eq!(src, actual);
            }
        }
        assert!(!buf.has_remaining());
    }

    test_codec(Address::Socket("192.168.1.1:8080".parse().unwrap()));
    test_codec(Address::Socket("[abcd:ef01:2345:6789:abcd:ef01:2345:6789]:443".parse().unwrap()));
    test_codec(Address::Domain("www.w3.org".to_owned(), 80));
}
