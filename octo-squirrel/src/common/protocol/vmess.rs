pub mod aead;
pub mod encoding;
pub mod header;
use std::{io::{Error, ErrorKind}, net::{Ipv4Addr, Ipv6Addr}, time::{SystemTime, UNIX_EPOCH}};

use aes::cipher::generic_array::GenericArray;
use bytes::{Buf, BufMut, BytesMut};
use crc::{Crc, CRC_32_MPEG_2};
use hmac::digest::OutputSizeUser;
use md5::{Digest, Md5};
use rand::Rng;
use uuid::Uuid;

use super::socks5::{self, message::Socks5CommandRequest};
use crate::common::protocol::vmess::header::AddressType;

pub const VERSION: u8 = 1;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub fn crc32(bytes: &[u8]) -> u32 {
    Crc::<u32>::new(&CRC_32_MPEG_2).checksum(bytes)
}

pub fn timestamp(delta: i32) -> i64 {
    let range_in_delta = rand::thread_rng().gen_range(0..delta * 2) - delta;
    return now() - range_in_delta as i64;
}

pub struct Address;

impl Address {
    pub fn write_address_port(address: Socks5CommandRequest, buf: &mut BytesMut) -> Result<(), Error> {
        let dst_addr = address.dst_addr;
        if dst_addr.is_empty() {
            panic!("Empty destination address")
        }
        let dst_addr_type = address.dst_addr_type;
        buf.put_u16(address.dst_port);
        if dst_addr_type == socks5::IPV4 {
            buf.put_u8(header::IPV4.0);
            let ip_v4: Ipv4Addr = dst_addr.parse().unwrap();
            buf.extend_from_slice(&ip_v4.octets());
        } else if dst_addr_type == socks5::IPV6 {
            buf.put_u8(header::IPV6.0);
            let ip_v6: Ipv6Addr = dst_addr.parse().unwrap();
            buf.extend_from_slice(&ip_v6.octets());
        } else if dst_addr_type == socks5::DOMAIN {
            let bytes = dst_addr.as_bytes();
            buf.put_u8(header::DOMAIN.0);
            buf.put_u8(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        } else {
            let msg = format!("unsupported address type: {}", dst_addr_type.0 & 0xff);
            return Err(Error::new(ErrorKind::InvalidData, msg));
        }
        Ok(())
    }

    pub fn read_address_port(buf: &mut BytesMut) -> Result<Socks5CommandRequest, Error> {
        let dst_port = buf.get_u16();
        let dst_addr;
        let dst_addr_type;
        let addr_type = AddressType(buf.get_u8());
        if addr_type == header::IPV4 {
            dst_addr_type = socks5::IPV4;
            dst_addr = Ipv4Addr::from(buf.get_u32()).to_string();
        } else if addr_type == header::IPV6 {
            dst_addr_type = socks5::IPV6;
            dst_addr = Ipv6Addr::from(buf.get_u128()).to_string();
        } else {
            dst_addr_type = socks5::DOMAIN;
            let length = buf.get_u8() as usize;
            dst_addr = String::from_utf8(buf.copy_to_bytes(length).to_vec()).unwrap();
        }
        Ok(Socks5CommandRequest::connect(dst_addr_type, dst_addr, dst_port))
    }
}

pub struct ID;
impl ID {
    pub fn new_ids(uuid: Vec<String>) -> Vec<[u8; 16]> {
        let mut res = Vec::with_capacity(uuid.len());
        for uuid in uuid {
            res.push(Self::new_id(uuid));
        }
        res
    }

    pub fn new_id(uuid: String) -> [u8; 16] {
        fn new_id(uuid: &[u8; 16]) -> [u8; 16] {
            let salt = "c48619fe-8f02-49e0-b9e9-edf763e17e21".as_bytes();
            let mut hasher = Md5::new();
            hasher.update(uuid);
            hasher.update(salt);
            let mut id = GenericArray::<u8, <Md5 as OutputSizeUser>::OutputSize>::default();
            hasher.finalize_into(&mut id);
            id.into()
        }
        let uuid = Uuid::parse_str(uuid.as_str()).unwrap();
        let uuid = uuid.as_bytes();
        new_id(uuid)
    }
}

#[cfg(test)]
mod test {
    use base64ct::{Base64, Encoding};
    use bytes::{Buf, BytesMut};

    use super::{Address, ID};
    use crate::common::protocol::socks5::{self, message::Socks5CommandRequest};

    #[test]
    fn test_address_codec() {
        fn test_address_codec(address: Socks5CommandRequest) {
            let buf = &mut BytesMut::new();
            let res = Address::write_address_port(address.clone(), buf);
            let mut actual = None;
            if let Ok(()) = res {
                let res = Address::read_address_port(buf);
                if let Ok(request) = res {
                    actual = Some(request);
                }
            }
            assert!(!buf.has_remaining());
            let actual = actual.unwrap();
            assert_eq!(address, actual);
        }

        test_address_codec(Socks5CommandRequest::connect(socks5::IPV4, "192.168.1.1".to_string(), 443));
        test_address_codec(Socks5CommandRequest::connect(socks5::IPV6, "abcd:ef01:2345:6789:abcd:ef01:2345:6789".to_string(), 80));
        test_address_codec(Socks5CommandRequest::connect(socks5::DOMAIN, "www.w3.org".to_string(), 0xFFF));
    }

    #[test]
    fn test_new_id() {
        let id = ID::new_id("b831381d-6324-4d53-ad4f-8cda48b30811".to_string());
        assert_eq!("tQ2RasDOwGeYGvjl84p1jw==", Base64::encode_string(&id));
    }
}
