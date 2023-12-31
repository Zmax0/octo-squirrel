pub mod aead;
pub mod encoding;
pub mod header;
pub mod session;
use std::io::Error;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use aes::cipher::generic_array::GenericArray;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use crc::Crc;
use crc::CRC_32_ISO_HDLC;
use hmac::digest::OutputSizeUser;
use md5::Digest;
use md5::Md5;
use rand::Rng;
use uuid::Uuid;

use super::address::Address;
use crate::common::protocol::vmess::header::AddressType;

pub const VERSION: u8 = 1;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub fn crc32(bytes: &[u8]) -> u32 {
    Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(bytes)
}

pub fn timestamp(delta: i32) -> i64 {
    let range_in_delta = rand::thread_rng().gen_range(0..delta * 2) - delta;
    return now() - range_in_delta as i64;
}

pub struct AddressCodec;

impl AddressCodec {
    pub fn write_address_port(address: &Address, buf: &mut BytesMut) -> Result<(), Error> {
        match address {
            Address::Domain(host, port) => {
                if host.is_empty() {
                    panic!("Empty destination address")
                }
                buf.put_u16(*port);
                let bytes = host.as_bytes();
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
            }
            Address::Socket(addr) => match addr {
                SocketAddr::V4(v4) => {
                    buf.put_u16(v4.port());
                    buf.put_u8(AddressType::Ipv4 as u8);
                    buf.put_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    buf.put_u16(v6.port());
                    buf.put_u8(AddressType::Ipv6 as u8);
                    buf.put_slice(&v6.ip().octets());
                }
            },
        }
        Ok(())
    }

    pub fn read_address_port(buf: &mut BytesMut) -> Result<Address, Error> {
        let port = buf.get_u16();
        let addr_type = AddressType::new(buf.get_u8());
        match addr_type {
            AddressType::Ipv4 => Ok(Address::Socket(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(buf.get_u32()), port)))),
            AddressType::Domain => {
                let length = buf.get_u8() as usize;
                Ok(Address::Domain(String::from_utf8(buf.copy_to_bytes(length).to_vec()).unwrap(), port))
            }
            AddressType::Ipv6 => Ok(Address::Socket(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(buf.get_u128()), port, 0, 0)))),
        }
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
    use base64ct::Base64;
    use base64ct::Encoding;
    use bytes::Buf;
    use bytes::BytesMut;

    use super::AddressCodec;
    use super::ID;
    use crate::common::protocol::address::Address;

    #[test]
    fn test_address_codec() {
        fn test_address_codec(address: Address) {
            let buf = &mut BytesMut::new();
            let res = AddressCodec::write_address_port(&address, buf);
            if let Ok(()) = res {
                let res = AddressCodec::read_address_port(buf);
                if let Ok(actual) = res {
                    assert_eq!(address, actual);
                }
            }
            assert!(!buf.has_remaining());
        }

        test_address_codec(Address::Socket("192.168.1.1:443".parse().unwrap()));
        test_address_codec(Address::Socket("[abcd:ef01:2345:6789:abcd:ef01:2345:6789]:443".parse().unwrap()));
        test_address_codec(Address::Domain("www.w3.org".to_owned(), 0xFFF));
    }

    #[test]
    fn test_new_id() {
        let id = ID::new_id("b831381d-6324-4d53-ad4f-8cda48b30811".to_string());
        assert_eq!("tQ2RasDOwGeYGvjl84p1jw==", Base64::encode_string(&id));
    }
}
