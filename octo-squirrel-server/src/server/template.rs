use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use log::error;
use log::info;
use octo_squirrel::codec::BytesCodec;
use octo_squirrel::codec::WebSocketFramed;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;
use tokio_websockets::ServerBuilder;

pub(super) mod message {
    use std::net::SocketAddr;

    use anyhow::bail;
    use bytes::BytesMut;
    use octo_squirrel::protocol::address::Address;

    pub enum Outbound {
        ConnectTcp(BytesMut, Address),
        RelayTcp(BytesMut),
        RelayUdp(BytesMut, Address),
    }

    impl TryFrom<Outbound> for BytesMut {
        type Error = anyhow::Error;

        fn try_from(value: Outbound) -> Result<Self, Self::Error> {
            if let Outbound::RelayTcp(value) = value {
                Ok(value)
            } else {
                bail!("expect relay tcp message")
            }
        }
    }

    impl TryFrom<Outbound> for (BytesMut, SocketAddr) {
        type Error = anyhow::Error;

        fn try_from(value: Outbound) -> Result<Self, Self::Error> {
            if let Outbound::RelayUdp(c, a) = value {
                Ok((c, a.to_socket_addr()?))
            } else {
                bail!("expect relay tcp message")
            }
        }
    }

    pub enum Inbound {
        RelayTcp(BytesMut),
        RelayUdp((BytesMut, SocketAddr)),
    }

    impl From<Inbound> for BytesMut {
        fn from(value: Inbound) -> Self {
            match value {
                Inbound::RelayTcp(bytes) => bytes,
                Inbound::RelayUdp((bytes, _)) => bytes,
            }
        }
    }

    impl From<BytesMut> for Inbound {
        fn from(value: BytesMut) -> Self {
            Self::RelayTcp(value)
        }
    }

    impl From<(BytesMut, SocketAddr)> for Inbound {
        fn from(value: (BytesMut, SocketAddr)) -> Self {
            Self::RelayUdp(value)
        }
    }
}

pub(super) mod tcp {
    use futures::future;
    use message::Inbound;
    use message::Outbound;
    use octo_squirrel::relay;
    use octo_squirrel::relay::End;

    use super::*;

    pub async fn accept_websocket_then_replay<I, C>(inbound: I, codec: C)
    where
        I: AsyncRead + AsyncWrite + Unpin,
        C: Encoder<Inbound, Error = anyhow::Error> + Decoder<Item = Outbound, Error = anyhow::Error> + Unpin + Send + 'static,
    {
        match ServerBuilder::new().accept(inbound).await {
            Ok(inbound) => {
                let (inbound_sink, inbound_stream) = WebSocketFramed::new(inbound, codec).split();
                relay_to(inbound_sink, inbound_stream).await;
            }
            Err(e) => error!("[tcp] websocket handshake failed; error={}", e),
        }
    }

    pub async fn relay<I, C>(inbound: I, codec: C)
    where
        I: AsyncRead + AsyncWrite,
        C: Encoder<Inbound, Error = anyhow::Error> + Decoder<Item = Outbound, Error = anyhow::Error> + Send + 'static,
    {
        let (inbound_sink, inbound_stream) = codec.framed(inbound).split();
        relay_to(inbound_sink, inbound_stream).await;
    }

    async fn relay_to<Si, St>(mut inbound_sink: Si, mut inbound_stream: St)
    where
        Si: Sink<Inbound, Error = anyhow::Error> + Unpin,
        St: Stream<Item = Result<Outbound, anyhow::Error>> + Unpin,
    {
        match inbound_stream.next().await {
            Some(Ok(Outbound::ConnectTcp(msg, addr))) => {
                if let Ok(resolved_addr) = addr.to_socket_addr() {
                    match TcpStream::connect(resolved_addr).await {
                        Err(e) => error!("[*-tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                        Ok(outbound) => {
                            let res = relay_tcp_bidirectional(&mut inbound_sink, &mut inbound_stream, outbound, Outbound::RelayTcp(msg)).await;
                            info!("[*-tcp] relay completed: peer={}/{}: {:?}", addr, resolved_addr, res);
                        }
                    }
                } else {
                    error!("[*-tcp] DNS resolve failed: peer={addr}");
                }
            }
            Some(Ok(Outbound::RelayUdp(msg, addr))) => match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await {
                Err(e) => error!("[*-udp] socket bind failed; error={}", e),
                Ok(outbound) => {
                    let res = relay_udp_bidirectional(&mut inbound_sink, &mut inbound_stream, outbound, Outbound::RelayUdp(msg, addr)).await;
                    info!("[*-udp] relay completed: {:?}", res);
                }
            },
            Some(Ok(Outbound::RelayTcp(_))) => error!("[*-tcp] expect a connect message for the first time"),
            Some(Err(e)) => error!("[tcp] decode failed; error={e}"),
            None => (),
        }
    }

    async fn relay_tcp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: TcpStream, first: Outbound) -> relay::Result
    where
        Si: Sink<Inbound, Error = anyhow::Error> + Unpin,
        St: Stream<Item = Result<Outbound, anyhow::Error>> + Unpin,
    {
        let (outbound_sink, outbound_stream) = BytesCodec.framed(outbound).split();
        relay_bidirectional(inbound_sink, inbound_stream, outbound_sink, outbound_stream, first).await
    }

    async fn relay_udp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: UdpSocket, first: Outbound) -> relay::Result
    where
        Si: Sink<Inbound, Error = anyhow::Error> + Unpin,
        St: Stream<Item = Result<Outbound, anyhow::Error>> + Unpin,
    {
        let (outbound_sink, outbound_stream) = UdpFramed::new(outbound, BytesCodec).split();
        relay_bidirectional(inbound_sink, inbound_stream, outbound_sink, outbound_stream, first).await
    }

    pub async fn relay_bidirectional<ISink, IStream, O, OSink, OStream>(
        mut inbound_sink: ISink,
        inbound_stream: IStream,
        mut outbound_sink: OSink,
        outbound_stream: OStream,
        first: Outbound,
    ) -> relay::Result
    where
        ISink: Sink<Inbound, Error = anyhow::Error> + Unpin,
        IStream: Stream<Item = Result<Outbound, anyhow::Error>> + Unpin,
        O: Into<Inbound> + TryFrom<Outbound, Error = anyhow::Error>,
        OSink: Sink<O, Error = anyhow::Error> + Unpin,
        OStream: Stream<Item = Result<O, anyhow::Error>> + Unpin,
    {
        let mut outbound_stream = outbound_stream.filter_map(|r| future::ready(r.ok())).map(O::into).map(Ok);
        let c_s_p = async {
            outbound_sink.send(first.try_into()?).await?;
            let mut inbound_stream = inbound_stream.filter_map(|r| future::ready(r.ok())).map(Outbound::try_into);
            outbound_sink.send_all(&mut inbound_stream).await
        };
        tokio::select! {
            res = inbound_sink.send_all(&mut outbound_stream) => {
                match res {
                    Ok(_) => relay::Result::Close(End::Peer, End::Server),
                    Err(e) => relay::Result::Err(End::Peer, End::Server, e),
                }
            },
            res = c_s_p => {
                match res {
                    Ok(_) => relay::Result::Close(End::Client, End::Server),
                    Err(e) => relay::Result::Err(End::Client, End::Server, e),
                }
            }
        }
    }
}
