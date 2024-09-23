use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

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

pub mod tcp {
    use futures::future;
    use octo_squirrel::common::relay;
    use octo_squirrel::common::relay::End;

    use super::*;

    pub async fn accept_websocket_then_replay<I, C>(inbound: I, codec: C)
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

    pub async fn relay<I, C>(inbound: I, codec: C)
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
                        Err(e) => error!("[*-tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                        Ok(outbound) => {
                            let res = relay_tcp_bidirectional(&mut inbound_sink, &mut inbound_stream, outbound, Message::RelayTcp(msg)).await;
                            info!("[*-tcp] relay completed: peer={}/{}: {:?}", addr, resolved_addr, res);
                        }
                    }
                } else {
                    error!("[*-tcp] DNS resolve failed: peer={addr}");
                }
            }
            Some(Ok(Message::RelayUdp(msg, addr))) => match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await {
                Err(e) => error!("[*-udp] socket bind failed; error={}", e),
                Ok(outbound) => {
                    let res = relay_udp_bidirectional(&mut inbound_sink, &mut inbound_stream, outbound, Message::RelayUdp(msg, addr)).await;
                    info!("[*-udp] relay completed: {:?}", res);
                }
            },
            Some(Ok(Message::RelayTcp(_))) => error!("[*-tcp] expect a connect message for the first time"),
            Some(Err(e)) => error!("[tcp] decode failed; error={e}"),
            None => (),
        }
    }

    async fn relay_tcp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: TcpStream, first: Message) -> relay::Result
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

    async fn relay_udp_bidirectional<Si, St>(inbound_sink: Si, inbound_stream: St, outbound: UdpSocket, first: Message) -> relay::Result
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

    pub async fn relay_bidirectional<ISink, IStream, OSink, OStream, MtoO, O, OtoI, I>(
        mut inbound_sink: ISink,
        inbound_stream: IStream,
        mut outbound_sink: OSink,
        outbound_stream: OStream,
        mut m_to_o: MtoO,
        mut o_to_i: OtoI,
        first: Message,
    ) -> relay::Result
    where
        ISink: Sink<I, Error = anyhow::Error> + Unpin,
        IStream: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
        OSink: Sink<O, Error = anyhow::Error> + Unpin,
        OStream: Stream<Item = Result<O, anyhow::Error>> + Unpin,
        MtoO: FnMut(Message) -> Result<O, anyhow::Error>,
        OtoI: FnMut(O) -> I,
    {
        let mut outbound_stream = outbound_stream.filter_map(|r| future::ready(r.ok())).map(|o| Ok(o_to_i(o)));
        let c_s_p = async {
            outbound_sink.send(m_to_o(first)?).await?;
            let mut inbound_stream = inbound_stream.filter_map(|r| future::ready(r.ok())).map(m_to_o);
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
