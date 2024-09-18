use bytes::BufMut;

use super::address;
use super::Socks5AuthMethod;
use super::Socks5CommandStatus;
use super::Socks5CommandType;
use super::VERSION;
use crate::common::protocol::address::Address;

pub trait Socks5Message: Send + Sync {
    fn encode(&mut self, dst: &mut bytes::BytesMut);
}

pub struct Socks5InitialRequest {
    auth_methods: Vec<Socks5AuthMethod>,
}

impl Socks5InitialRequest {
    pub fn new(auth_methods: Vec<Socks5AuthMethod>) -> Self {
        Socks5InitialRequest { auth_methods }
    }
}
impl Socks5Message for Socks5InitialRequest {
    fn encode(&mut self, dst: &mut bytes::BytesMut) {
        dst.put_u8(VERSION);
        dst.put_u8(self.auth_methods.len() as u8);
        for auth_method in self.auth_methods.iter() {
            dst.put_u8(*auth_method as u8);
        }
    }
}

pub struct Socks5InitialResponse {
    pub auth_method: Socks5AuthMethod,
}

impl Socks5InitialResponse {
    pub fn new(auth_method: Socks5AuthMethod) -> Self {
        Self { auth_method }
    }
}

impl Socks5Message for Socks5InitialResponse {
    fn encode(&mut self, dst: &mut bytes::BytesMut) {
        dst.put_u8(VERSION);
        dst.put_u8(self.auth_method as u8);
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Socks5CommandRequest {
    pub command_type: Socks5CommandType,
    pub dst_addr: Address,
}

impl Socks5CommandRequest {
    pub fn new(command_type: Socks5CommandType, dst_addr: Address) -> Self {
        Self { command_type, dst_addr }
    }
}

impl Socks5Message for Socks5CommandRequest {
    fn encode(&mut self, dst: &mut bytes::BytesMut) {
        dst.put_u8(VERSION);
        dst.put_u8(self.command_type as u8);
        dst.put_u8(0);
        address::encode(&self.dst_addr, dst);
    }
}

pub struct Socks5CommandResponse {
    pub command_status: Socks5CommandStatus,
    pub bnd_addr: Address,
}

impl Socks5Message for Socks5CommandResponse {
    fn encode(&mut self, dst: &mut bytes::BytesMut) {
        dst.put_u8(VERSION);
        dst.put_u8(self.command_status as u8);
        dst.put_u8(0x00);
        address::encode(&self.bnd_addr, dst);
    }
}

impl Socks5CommandResponse {
    pub fn new(command_status: Socks5CommandStatus, bnd_addr: Address) -> Self {
        Self { command_status, bnd_addr }
    }
}
