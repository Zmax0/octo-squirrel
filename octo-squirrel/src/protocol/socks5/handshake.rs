pub mod client {
    use std::net::SocketAddr;

    use anyhow::Result;
    use anyhow::bail;
    use futures::FutureExt;
    use futures::SinkExt;
    use futures::StreamExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::FramedRead;
    use tokio_util::codec::FramedWrite;

    use crate::protocol::socks5::Socks5AuthMethod;
    use crate::protocol::socks5::Socks5CommandType;
    use crate::protocol::socks5::codec::Socks5ClientEncoder;
    use crate::protocol::socks5::codec::Socks5CommandResponseDecoder;
    use crate::protocol::socks5::codec::Socks5InitialResponseDecoder;
    use crate::protocol::socks5::message::Socks5CommandRequest;
    use crate::protocol::socks5::message::Socks5CommandResponse;
    use crate::protocol::socks5::message::Socks5InitialRequest;

    pub async fn no_auth(command_type: Socks5CommandType, proxy_addr: SocketAddr, dst_addr: SocketAddr) -> Result<Socks5CommandResponse> {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let (rh, wh) = stream.split();
        let mut writer = FramedWrite::new(wh, Socks5ClientEncoder);
        writer.send(Box::new(Socks5InitialRequest::new(vec![Socks5AuthMethod::NoAuth]))).await?;
        let mut reader = FramedRead::new(rh, Socks5InitialResponseDecoder);
        let initial_response = reader.next().map(Option::unwrap).await?;
        if initial_response.auth_method != Socks5AuthMethod::NoAuth {
            bail!("proxy's auth method is not NO_AUTH");
        }
        writer.send(Box::new(Socks5CommandRequest::new(command_type, dst_addr.into()))).await?;
        let mut reader = FramedRead::new(reader.into_inner(), Socks5CommandResponseDecoder);
        let command_response = reader.next().map(Option::unwrap).await?;
        Ok(command_response)
    }
}

pub mod server {
    use anyhow::Result;
    use futures::FutureExt;
    use futures::SinkExt;
    use futures::StreamExt;
    use tokio::net::TcpStream;
    use tokio_util::codec::FramedRead;
    use tokio_util::codec::FramedWrite;

    use crate::protocol::socks5::Socks5AuthMethod;
    use crate::protocol::socks5::codec::Socks5CommandRequestDecoder;
    use crate::protocol::socks5::codec::Socks5InitialRequestDecoder;
    use crate::protocol::socks5::codec::Socks5ServerEncoder;
    use crate::protocol::socks5::message::Socks5CommandRequest;
    use crate::protocol::socks5::message::Socks5CommandResponse;
    use crate::protocol::socks5::message::Socks5InitialResponse;

    pub async fn no_auth(stream: &mut TcpStream, response: Socks5CommandResponse) -> Result<Socks5CommandRequest> {
        let (rh, wh) = stream.split();
        let mut reader = FramedRead::new(rh, Socks5InitialRequestDecoder);
        reader.next().map(Option::unwrap).await?;
        let mut reader = FramedRead::new(reader.into_inner(), Socks5CommandRequestDecoder);
        let mut writer = FramedWrite::new(wh, Socks5ServerEncoder);
        writer.send(Box::new(Socks5InitialResponse::new(Socks5AuthMethod::NoAuth))).await?;
        let command_request = reader.next().map(Option::unwrap).await?;
        writer.send(Box::new(response)).await?;
        Ok(command_request)
    }
}
