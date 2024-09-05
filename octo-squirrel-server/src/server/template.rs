use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use anyhow::anyhow;
use anyhow::bail;
use bytes::BytesMut;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use log::error;
use log::info;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::codec::WebSocketFramed;
use octo_squirrel::common::protocol::address::Address;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;
use tokio_websockets::ServerBuilder;

pub enum Message {
    ConnectTcp(BytesMut, Address),
    RelayTcp(BytesMut),
    RelayUdp(BytesMut, Address),
}

pub async fn relay_tcp<I, C>(inbound: I, codec: C)
where
    I: AsyncRead + AsyncWrite,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    let (inbound_sink, inbound_stream) = codec.framed(inbound).split();
    relay_to(inbound_sink, inbound_stream).await;
}

async fn relay_to<Si, St>(mut inbound_sink: Si, mut inbound_stream: St)
where
    Si: Sink<BytesMut, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
{
    match inbound_stream.next().await {
        Some(Ok(Message::ConnectTcp(msg, addr))) => {
            if let Ok(resolved_addr) = addr.to_socket_addr() {
                match TcpStream::connect(resolved_addr).await {
                    Err(e) => error!("[tcp-tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                    Ok(outbound) => {
                        if let Err(e) = relay_tcp_bidirectional(&mut inbound_sink, &mut inbound_stream, outbound, Message::RelayTcp(msg)).await {
                            info!("[tcp-tcp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                        }
                    }
                }
            } else {
                error!("[tcp-tcp] DNS resolve failed: peer={addr}");
            }
        }
        Some(Ok(Message::RelayUdp(msg, addr))) => match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await {
            Err(e) => error!("[tcp-udp] socket bind failed; error={}", e),
            Ok(outbound) => {
                if let Err(e) = relay_udp_bidirectional(&mut inbound_sink, &mut inbound_stream, outbound, Message::RelayUdp(msg, addr)).await {
                    info!("[tcp-udp] relay completed: {}", e);
                }
            }
        },
        Some(Ok(Message::RelayTcp(_))) => error!("[tcp-tcp] expect a connect message for the first time"),
        Some(Err(e)) => error!("[tcp] decode failed; error={e}"),
        None => (),
    }
}

async fn relay_tcp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: TcpStream, first: Message) -> Result<((), ()), anyhow::Error>
where
    Si: Sink<BytesMut, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
{
    let (outbound_sink, outbound_stream) = BytesCodec.framed(outbound).split();
    relay_bidirectional(
        inbound_sink,
        inbound_stream,
        outbound_sink,
        outbound_stream,
        |m| {
            if let Message::RelayTcp(m) = m {
                Ok(m)
            } else {
                bail!("expect relay tcp message")
            }
        },
        |b| b,
        first,
    )
    .await
}

async fn relay_udp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: UdpSocket, first: Message) -> Result<((), ()), anyhow::Error>
where
    Si: Sink<BytesMut, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
{
    let (outbound_sink, outbound_stream) = UdpFramed::new(outbound, BytesCodec).split();
    relay_bidirectional(
        inbound_sink,
        inbound_stream,
        outbound_sink,
        outbound_stream,
        |m| {
            if let Message::RelayUdp(c, a) = m {
                Ok((c, a.to_socket_addr()?))
            } else {
                bail!("expect relay udp message")
            }
        },
        |(c, _)| c,
        first,
    )
    .await
}

async fn relay_bidirectional<ISink, IStream, OSink, OStream, Item, MtoI, ItoB>(
    mut inbound_sink: ISink,
    mut inbound_stream: IStream,
    mut outbound_sink: OSink,
    mut outbound_stream: OStream,
    mut m_to_o: MtoI,
    mut o_to_b: ItoB,
    first: Message,
) -> Result<((), ()), anyhow::Error>
where
    ISink: Sink<BytesMut, Error = anyhow::Error> + Unpin,
    IStream: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
    OSink: Sink<Item, Error = anyhow::Error> + Unpin,
    OStream: Stream<Item = Result<Item, anyhow::Error>> + Unpin,
    MtoI: FnMut(Message) -> Result<Item, anyhow::Error>,
    ItoB: FnMut(Item) -> BytesMut,
{
    let p_s_c = async {
        while let Some(Ok(next)) = outbound_stream.next().await {
            inbound_sink.send(o_to_b(next)).await?;
        }
        Err::<(), _>(anyhow!("peer is closed"))
    };
    let c_s_p = async {
        outbound_sink.send(m_to_o(first)?).await?;
        while let Some(Ok(next)) = inbound_stream.next().await {
            outbound_sink.send(m_to_o(next)?).await?
        }
        Err::<(), _>(anyhow!("client is closed"))
    };
    tokio::try_join!(p_s_c, c_s_p)
}

pub async fn accept_websocket<I, C>(inbound: I, codec: C)
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Unpin + Send + 'static,
{
    match ServerBuilder::new().accept(inbound).await {
        Ok(inbound) => {
            let (inbound_sink, inbound_stream) = WebSocketFramed::new(inbound, codec).split();
            relay_to(inbound_sink, inbound_stream).await;
        }
        Err(e) => error!("[tcp] websocket handshake failed; error={}", e),
    }
}
