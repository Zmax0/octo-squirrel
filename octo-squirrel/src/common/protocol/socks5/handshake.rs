use std::net::SocketAddr;

use futures::FutureExt;
use futures::SinkExt;
use futures::StreamExt;
use tokio::io;
use tokio::net::TcpStream;
use tokio_util::codec::FramedRead;
use tokio_util::codec::FramedWrite;

use super::codec::Socks5ClientEncoder;
use super::codec::Socks5CommandRequestDecoder;
use super::codec::Socks5CommandResponseDecoder;
use super::codec::Socks5InitialRequestDecoder;
use super::codec::Socks5InitialResponseDecoder;
use super::codec::Socks5ServerEncoder;
use super::message::Socks5CommandRequest;
use super::message::Socks5CommandResponse;
use super::message::Socks5InitialRequest;
use super::message::Socks5InitialResponse;
use super::Socks5CommandType;
use crate::common::protocol::socks5::Socks5AuthMethod;

pub struct ClientHandShake;

impl ClientHandShake {
    pub async fn no_auth(command_type: Socks5CommandType, proxy_addr: SocketAddr, dst_add: SocketAddr) -> Result<Socks5CommandResponse, io::Error> {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let (rh, wh) = stream.split();
        let mut writer = FramedWrite::new(wh, Socks5ClientEncoder);
        writer.send(Box::new(Socks5InitialRequest::new(vec![Socks5AuthMethod::NO_AUTH]))).await?;
        let mut reader = FramedRead::new(rh, Socks5InitialResponseDecoder);
        let initial_response = reader.next().map(Option::unwrap).await?;
        if initial_response.auth_method != Socks5AuthMethod::NO_AUTH {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "proxy's auth method is not NO_AUTH"));
        }
        writer.send(Box::new(Socks5CommandRequest::from(command_type, dst_add))).await?;
        let mut reader = FramedRead::new(reader.into_inner(), Socks5CommandResponseDecoder);
        let command_response = reader.next().map(Option::unwrap).await?;
        Ok(command_response)
    }
}

pub struct ServerHandShake;

impl ServerHandShake {
    pub async fn no_auth(stream: &mut TcpStream, response: Socks5CommandResponse) -> Result<Socks5CommandRequest, io::Error> {
        let (rh, wh) = stream.split();
        let mut reader = FramedRead::new(rh, Socks5InitialRequestDecoder);
        reader.next().map(Option::unwrap).await?;
        let mut reader = FramedRead::new(reader.into_inner(), Socks5CommandRequestDecoder);
        let mut writer = FramedWrite::new(wh, Socks5ServerEncoder);
        writer.send(Box::new(Socks5InitialResponse::new(Socks5AuthMethod::NO_AUTH))).await?;
        let command_request = reader.next().map(Option::unwrap).await?;
        writer.send(Box::new(response)).await?;
        Ok(command_request)
    }
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod test {
    use std::error::Error;

    use crate::common::protocol::socks5::handshake::ClientHandShake;
    use crate::common::protocol::socks5::Socks5CommandType;
    #[tokio::test]
    async fn no_auth() -> Result<(), Box<dyn Error>> {
        let proxy_addr = "127.0.0.1:7890".parse().unwrap();
        let dst_addr = "127.0.0.1:9090".parse().unwrap();
        let response = ClientHandShake::no_auth(Socks5CommandType::CONNECT, proxy_addr, dst_addr).await?;
        assert_eq!(response.bnd_addr, "127.0.0.1");
        assert_eq!(response.bnd_port, 7890);
        Ok(())
    }
}
