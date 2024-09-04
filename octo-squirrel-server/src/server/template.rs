use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use anyhow::anyhow;
use bytes::BytesMut;
use futures::lock::BiLock;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use log::error;
use log::info;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::protocol::address::Address;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;
use tokio_websockets::WebSocketStream;

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
    let (mut inbound_sink, mut inbound_stream) = codec.framed(inbound).split();
    match inbound_stream.next().await {
        Some(Ok(Message::ConnectTcp(msg, addr))) => {
            if let Ok(resolved_addr) = addr.to_socket_addr() {
                match TcpStream::connect(resolved_addr).await {
                    Err(e) => error!("[tcp-tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                    Ok(outbound) => {
                        if let Err(e) = relay_plain(&mut inbound_sink, &mut inbound_stream, outbound, msg).await {
                            info!("[tcp-tcp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                        }
                    }
                }
            } else {
                error!("[tcp-tcp] DNS resolve failed: peer={addr}");
            }
        }
        Some(Ok(Message::RelayUdp(msg, addr))) => {
            if let Ok(resolved_addr) = addr.to_socket_addr() {
                match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await {
                    Err(e) => error!("[tcp-udp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                    Ok(outbound) => {
                        outbound.send_to(&msg, resolved_addr).await.unwrap_or_else(|e| {
                            error!("[tcp-udp] send to peer failed; error={e}");
                            0
                        });
                        if let Err(e) = relay_udp(&mut inbound_sink, &mut inbound_stream, outbound).await {
                            info!("[tcp-udp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                        }
                    }
                }
            } else {
                error!("[tcp-udp] DNS resolve failed: peer={addr}");
            }
        }
        Some(Ok(Message::RelayTcp(_))) => error!("[tcp-tcp] expect a connect message for the first time"),
        Some(Err(e)) => error!("[tcp] decode failed; error={e}"),
        None => (),
    }
}

async fn relay_plain<Si, St>(inbound_sink: &mut Si, inbound_stream: &mut St, outbound: TcpStream, msg: BytesMut) -> Result<((), ()), anyhow::Error>
where
    Si: Sink<BytesMut, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
{
    let (mut outbound_sink, mut outbound_stream) = BytesCodec.framed(outbound).split();
    let p_s_c = async {
        while let Some(Ok(next)) = outbound_stream.next().await {
            inbound_sink.send(next).await?
        }
        Err::<(), _>(anyhow!("peer is closed"))
    };
    let c_s_p = async {
        outbound_sink.send(msg).await?;
        while let Some(Ok(Message::RelayTcp(next))) = inbound_stream.next().await {
            outbound_sink.send(next).await?
        }
        Err::<(), _>(anyhow!("client is closed"))
    };
    tokio::try_join!(p_s_c, c_s_p)
}

async fn relay_udp<Si, St>(inbound_sink: &mut Si, inbound_stream: &mut St, outbound: UdpSocket) -> Result<((), ()), anyhow::Error>
where
    Si: Sink<BytesMut, Error = anyhow::Error> + Unpin,
    St: Stream<Item = Result<Message, anyhow::Error>> + Unpin,
{
    let (mut outbound_sink, mut outbound_stream) = UdpFramed::new(outbound, BytesCodec).split();
    let p_s_c = async {
        while let Some(Ok((next, _))) = outbound_stream.next().await {
            inbound_sink.send(next).await?;
        }
        Err::<(), _>(anyhow!("peer is closed"))
    };
    let c_s_p = async {
        while let Some(Ok(Message::RelayUdp(content, addr))) = inbound_stream.next().await {
            outbound_sink.send((content, addr.to_socket_addr()?)).await?
        }
        Err::<(), _>(anyhow!("client is closed"))
    };
    tokio::try_join!(p_s_c, c_s_p)
}

pub async fn relay_websocket<I, C>(mut inbound: WebSocketStream<I>, mut codec: C)
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    if let Some(Ok(websocket_msg)) = inbound.next().await {
        match codec.decode(&mut websocket_msg.into_payload().into()) {
            Ok(Some(Message::ConnectTcp(head, addr))) => {
                if let Ok(resolved_addr) = addr.to_socket_addr() {
                    match TcpStream::connect(resolved_addr).await {
                        Err(e) => error!("[ws-tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                        Ok(outbound) => {
                            if let Err(e) = replay_websocket_tcp(inbound, outbound, codec, head).await {
                                info!("[ws-tcp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                            }
                        }
                    }
                } else {
                    error!("[ws-tcp] DNS resolve failed: peer={addr}");
                }
            }
            Ok(Some(Message::RelayUdp(msg, addr))) => {
                if let Ok(resolved_addr) = addr.to_socket_addr() {
                    match UdpSocket::bind(resolved_addr).await {
                        Err(e) => error!("[ws-udp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                        Ok(outbound) => {
                            outbound.send(&msg).await.unwrap_or_else(|e| {
                                error!("[ws-udp] send to peer failed; error={e}");
                                0
                            });
                            if let Err(e) = replay_websocket_udp(inbound, outbound, codec).await {
                                info!("[ws-udp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                            }
                        }
                    }
                } else {
                    error!("[ws-udp] DNS resolve failed: peer={addr}");
                }
            }
            Ok(Some(Message::RelayTcp(_))) => error!("[ws-tcp] expect a connect message for the first time"),
            Ok(None) => (),
            Err(e) => error!("[ws] decode failed; error={e}"),
        }
    }
}

async fn replay_websocket_tcp<I, C>(inbound: WebSocketStream<I>, outbound: TcpStream, mut codec: C, head: BytesMut) -> Result<((), ()), anyhow::Error>
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    let (codec0, codec1) = BiLock::new(&mut codec);
    let (mut server_client, mut client_server) = inbound.split();
    let (mut server_peer, mut peer_server) = BytesCodec.framed(outbound).split();
    let c_s_p = async {
        server_peer.send(head).await?;
        while let Some(Ok(websocket_msg)) = client_server.next().await {
            if let Some(Message::RelayTcp(msg)) = codec0.lock().await.decode(&mut websocket_msg.into_payload().into())? {
                server_peer.send(msg).await?
            }
        }
        Err::<(), _>(anyhow!("client is closed"))
    };
    let p_s_c = async {
        while let Some(Ok(mut msg)) = peer_server.next().await {
            let mut dst = msg.split_off(msg.len());
            codec1.lock().await.encode(msg, &mut dst)?;
            let item = tokio_websockets::Message::binary::<BytesMut>(dst);
            server_client.send(item).await?
        }
        Err::<(), _>(anyhow!("peer is closed"))
    };
    tokio::try_join!(c_s_p, p_s_c)
}

async fn replay_websocket_udp<I, C>(inbound: WebSocketStream<I>, outbound: UdpSocket, mut codec: C) -> Result<((), ()), anyhow::Error>
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    let (codec0, codec1) = BiLock::new(&mut codec);
    let (mut server_client, mut client_server) = inbound.split();
    let (mut server_peer, mut peer_server) = UdpFramed::new(outbound, BytesCodec).split();
    let c_s_p = async {
        while let Some(Ok(websocket_msg)) = client_server.next().await {
            if let Some(Message::RelayUdp(content, addr)) = codec0.lock().await.decode(&mut websocket_msg.into_payload().into())? {
                server_peer.send((content, addr.to_socket_addr()?)).await?
            }
        }
        Err::<(), _>(anyhow!("client is closed"))
    };
    let p_s_c = async {
        while let Some(Ok((mut msg, _))) = peer_server.next().await {
            let mut dst = msg.split_off(msg.len());
            codec1.lock().await.encode(msg, &mut dst)?;
            let item = tokio_websockets::Message::binary::<BytesMut>(dst);
            server_client.send(item).await?
        }
        Err::<(), _>(anyhow!("peer is closed"))
    };
    tokio::try_join!(c_s_p, p_s_c)
}
