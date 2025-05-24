use std::future;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;

use anyhow::anyhow;
use anyhow::bail;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use log::error;
use log::info;
use message::InboundIn;
use message::OutboundIn;
use octo_squirrel::codec::BytesCodec;
use octo_squirrel::codec::QuicStream;
use octo_squirrel::protocol::address::Address;
use octo_squirrel::relay;
use octo_squirrel::relay::Side;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;
use tokio_websockets::ServerBuilder;

pub(super) mod message {
    use std::fmt::Debug;

    use byte_string::ByteStr;

    use super::*;

    pub enum InboundIn {
        ConnectTcp(BytesMut, Address),
        RelayTcp(BytesMut),
        RelayUdp(BytesMut, Address),
    }

    impl TryFrom<InboundIn> for BytesMut {
        type Error = anyhow::Error;

        fn try_from(value: InboundIn) -> Result<Self, Self::Error> {
            if let InboundIn::RelayTcp(value) = value { Ok(value) } else { bail!("expect relay tcp message") }
        }
    }

    impl TryFrom<InboundIn> for (BytesMut, SocketAddr) {
        type Error = anyhow::Error;

        fn try_from(value: InboundIn) -> Result<Self, Self::Error> {
            if let InboundIn::RelayUdp(c, a) = value { Ok((c, a.to_socket_addr()?)) } else { bail!("expect relay tcp message") }
        }
    }

    impl Debug for InboundIn {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                InboundIn::ConnectTcp(item, addr) => write!(f, "ConnectTcp({:?}, {})", ByteStr::new(item), addr),
                InboundIn::RelayTcp(item) => write!(f, "RelayTcp({:?})", ByteStr::new(item)),
                InboundIn::RelayUdp(item, addr) => write!(f, "RelayUdp({:?}, {})", ByteStr::new(item), addr),
            }
        }
    }

    pub enum OutboundIn {
        Tcp(BytesMut),
        Udp((BytesMut, SocketAddr)),
    }

    impl From<OutboundIn> for BytesMut {
        fn from(value: OutboundIn) -> Self {
            match value {
                OutboundIn::Tcp(bytes) => bytes,
                OutboundIn::Udp((bytes, _)) => bytes,
            }
        }
    }

    impl From<BytesMut> for OutboundIn {
        fn from(value: BytesMut) -> Self {
            Self::Tcp(value)
        }
    }

    impl From<(BytesMut, SocketAddr)> for OutboundIn {
        fn from(value: (BytesMut, SocketAddr)) -> Self {
            Self::Udp(value)
        }
    }
}

pub(super) mod tcp {
    use message::InboundIn;
    use message::OutboundIn;
    use octo_squirrel::codec::WebSocketStream;
    use tokio_util::codec::Framed;

    use super::*;

    pub async fn accept_websocket_then_replay<I, C>(inbound: I, codec: C)
    where
        I: AsyncRead + AsyncWrite + Unpin,
        C: Encoder<OutboundIn, Error = anyhow::Error> + Decoder<Item = InboundIn, Error = anyhow::Error> + Unpin + Send + 'static,
    {
        match ServerBuilder::new().accept(inbound).await {
            Ok((_, inbound)) => {
                let (mut inbound_sink, mut inbound_stream) = Framed::new(WebSocketStream::new(inbound), codec).split();
                relay_to(&mut inbound_sink, &mut inbound_stream).await;
            }
            Err(e) => error!("[tcp] websocket handshake failed; error={}", e),
        }
    }

    pub async fn relay<I, C>(inbound: I, codec: C)
    where
        I: AsyncRead + AsyncWrite + Unpin,
        C: Encoder<OutboundIn, Error = anyhow::Error> + Decoder<Item = InboundIn, Error = anyhow::Error> + Send + 'static,
    {
        let (mut inbound_sink, mut inbound_stream) = codec.framed(inbound).split();
        relay_to(&mut inbound_sink, &mut inbound_stream).await;
        let _ = inbound_sink.close().await;
    }
}

pub(super) mod quic {
    use tokio_util::codec::Framed;

    use super::*;
    pub async fn relay<C>(inbound: QuicStream, codec: C) -> anyhow::Result<()>
    where
        C: Encoder<OutboundIn, Error = anyhow::Error> + Decoder<Item = InboundIn, Error = anyhow::Error> + Send + 'static,
    {
        let (mut inbound_sink, mut inbound_stream) = codec.framed(inbound).split();
        relay_to(&mut inbound_sink, &mut inbound_stream).await;
        let inbound = inbound_sink.reunite(inbound_stream).map(Framed::into_inner).map_err(|e| anyhow!(e))?;
        inbound.close().await
    }
}

async fn relay_to<Si, St>(inbound_sink: &mut Si, inbound_stream: &mut St)
where
    Si: Sink<OutboundIn, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<InboundIn, anyhow::Error>> + Unpin,
{
    match inbound_stream.next().await {
        Some(Ok(InboundIn::ConnectTcp(msg, addr))) => {
            if let Ok(resolved_addr) = addr.to_socket_addr() {
                match TcpStream::connect(resolved_addr).await {
                    Err(e) => error!("[*-tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                    Ok(outbound) => {
                        let res = relay_tcp_bidirectional(inbound_sink, inbound_stream, outbound, InboundIn::RelayTcp(msg)).await;
                        info!("[*-tcp] relay completed: peer={}/{}: {:?}", addr, resolved_addr, res);
                    }
                }
            } else {
                error!("[*-tcp] DNS resolve failed: peer={addr}");
            }
        }
        Some(Ok(InboundIn::RelayUdp(msg, addr))) => match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await {
            Err(e) => error!("[*-udp] socket bind failed; error={}", e),
            Ok(outbound) => {
                let res = relay_udp_bidirectional(inbound_sink, inbound_stream, outbound, InboundIn::RelayUdp(msg, addr)).await;
                info!("[*-udp] relay completed: {:?}", res);
            }
        },
        Some(Ok(InboundIn::RelayTcp(_))) => error!("[*-tcp] expect a connect message for the first time"),
        Some(Err(e)) => error!("[tcp] decode failed; error={e}"),
        None => (),
    }
}

async fn relay_tcp_bidirectional<Si, St>(inbound_sink: &mut Si, inbound_stream: &mut St, outbound: TcpStream, first: InboundIn) -> relay::Result
where
    Si: Sink<OutboundIn, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<InboundIn, anyhow::Error>> + Unpin,
{
    let (outbound_sink, outbound_stream) = BytesCodec.framed(outbound).split();
    relay_bidirectional(inbound_sink, inbound_stream, outbound_sink, outbound_stream, first).await
}

async fn relay_udp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: UdpSocket, first: InboundIn) -> relay::Result
where
    Si: Sink<OutboundIn, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<InboundIn, anyhow::Error>> + Unpin,
{
    let (outbound_sink, outbound_stream) = UdpFramed::new(outbound, BytesCodec).split();
    relay_bidirectional(inbound_sink, inbound_stream, outbound_sink, outbound_stream, first).await
}

async fn relay_bidirectional<ISink, IStream, O, OSink, OStream>(
    mut inbound_sink: ISink,
    inbound_stream: IStream,
    mut outbound_sink: OSink,
    outbound_stream: OStream,
    first: InboundIn,
) -> relay::Result
where
    ISink: Sink<OutboundIn, Error = anyhow::Error> + Unpin,
    IStream: Stream<Item = Result<InboundIn, anyhow::Error>> + Unpin,
    O: Into<OutboundIn> + TryFrom<InboundIn, Error = anyhow::Error>,
    OSink: Sink<O, Error = anyhow::Error> + Unpin,
    OStream: Stream<Item = Result<O, anyhow::Error>> + Unpin,
{
    match first.try_into() {
        Ok(first) => match outbound_sink.send(first).await {
            Ok(_) => (),
            Err(e) => return relay::Result::Err(Side::Server, Side::Peer, e),
        },
        Err(e) => return relay::Result::Err(Side::Client, Side::Server, e),
    };
    let outbound_stream = outbound_stream.filter_map(|r| future::ready(r.ok())).map(O::into).map(Ok);
    let inbound_stream = inbound_stream.filter_map(|r| future::ready(r.ok())).map(InboundIn::try_into);

    let p_s_c = async {
        match outbound_stream.forward(&mut inbound_sink).await {
            Ok(_) => Err::<(), _>(relay::Result::Close(Side::Peer, Side::Server)),
            Err(e) => Err(relay::Result::Err(Side::Peer, Side::Server, e)),
        }
    };

    let c_s_p = async {
        match inbound_stream.forward(outbound_sink).await {
            Ok(_) => Err::<(), _>(relay::Result::Close(Side::Client, Side::Server)),
            Err(e) => Err(relay::Result::Err(Side::Client, Side::Server, e)),
        }
    };

    match tokio::try_join!(p_s_c, c_s_p) {
        Ok(_) => unreachable!("should never reach here"),
        Err(e) => e,
    }
}
