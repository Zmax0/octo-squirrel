use std::net::SocketAddr;

use futures::{FutureExt, SinkExt, StreamExt};
use tokio::{io, net::TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::{codec::{Socks5ClientEncoder, Socks5CommandRequestDecoder, Socks5CommandResponseDecoder, Socks5InitialRequestDecoder, Socks5InitialResponseDecoder, Socks5ServerEncoder}, message::{Socks5CommandRequest, Socks5CommandResponse, Socks5InitialRequest, Socks5InitialResponse}, Socks5CommandType, NO_AUTH};

pub struct ClientHandShake;

impl ClientHandShake {
    pub async fn no_auth(command_type: Socks5CommandType, proxy_addr: SocketAddr, dst_add: SocketAddr) -> Result<Socks5CommandResponse, io::Error> {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let (rh, wh) = stream.split();
        let mut writer = FramedWrite::new(wh, Socks5ClientEncoder);
        writer.send(Box::new(Socks5InitialRequest::new(vec![NO_AUTH]))).await?;
        let mut reader = FramedRead::new(rh, Socks5InitialResponseDecoder);
        let initial_response = reader.next().map(Option::unwrap).await?;
        if initial_response.auth_method != NO_AUTH {
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
        writer.send(Box::new(Socks5InitialResponse::new(NO_AUTH))).await?;
        let command_request = reader.next().map(Option::unwrap).await?;
        writer.send(Box::new(response)).await?;
        Ok(command_request)
    }
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod test {
    use std::error::Error;

    use crate::common::protocol::socks5::{handshake::ClientHandShake, CONNECT};
    #[tokio::test]
    async fn no_auth() -> Result<(), Box<dyn Error>> {
        let proxy_addr = "127.0.0.1:7890".parse().unwrap();
        let dst_addr = "127.0.0.1:9090".parse().unwrap();
        let response = ClientHandShake::no_auth(CONNECT, proxy_addr, dst_addr).await?;
        assert_eq!(response.bnd_addr, "127.0.0.1");
        assert_eq!(response.bnd_port, 7890);
        Ok(())
    }
}
