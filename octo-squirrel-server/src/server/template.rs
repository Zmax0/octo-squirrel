use anyhow::anyhow;
use bytes::BytesMut;
use futures::lock::BiLock;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::SinkExt;
use futures::StreamExt;
use log::error;
use log::info;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::protocol::address::Address;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_websockets::WebSocketStream;

pub enum Message {
    Connect(BytesMut, Address),
    RelayTcp(BytesMut),
    // ReplayUdp(BytesMut),
}

pub async fn relay_tcp<Codec, I>(inbound: I, codec: Codec)
where
    I: AsyncRead + AsyncWrite,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    let (mut inbound_sink, mut inbound_stream) = codec.framed(inbound).split();
    match inbound_stream.next().await {
        Some(Ok(Message::Connect(msg, addr))) => {
            if let Ok(resolved_addr) = addr.to_socket_addr() {
                match TcpStream::connect(resolved_addr).await {
                    Err(e) => error!("[tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                    Ok(outbound) => {
                        if let Err(e) = relay_tcp0(&mut inbound_sink, &mut inbound_stream, outbound, msg).await {
                            info!("[tcp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                        }
                    }
                }
            } else {
                error!("[tcp] DNS resolve failed: peer={}", addr);
            }
        }
        Some(Ok(Message::RelayTcp(_))) => error!("[tcp] expect a connect message for the first time"),
        Some(Err(e)) => error!("[tcp] decode failed; error={e}"),
        None => (),
    }
}

async fn relay_tcp0<Codec, I>(
    inbound_sink: &mut SplitSink<Framed<I, Codec>, BytesMut>,
    inbound_stream: &mut SplitStream<Framed<I, Codec>>,
    outbound: TcpStream,
    msg: BytesMut,
) -> Result<((), ()), anyhow::Error>
where
    I: AsyncRead + AsyncWrite,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    let (mut outbound_sink, mut outbound_stream) = BytesCodec.framed(outbound).split::<BytesMut>();
    let p_s_c = async {
        while let Some(Ok(next)) = outbound_stream.next().await {
            inbound_sink.send(next).await?;
        }
        Err::<(), _>(anyhow!("peer is closed"))
    };
    let c_s_p = async {
        outbound_sink.send(msg).await?;
        while let Some(Ok(next)) = inbound_stream.next().await {
            match next {
                Message::Connect(next, _) => outbound_sink.send(next).await?,
                Message::RelayTcp(next) => outbound_sink.send(next).await?,
                // Message::ReplayUdp(_) => error!("[tcp] should not relay udp"),
            }
        }
        Err::<(), _>(anyhow!("client is closed"))
    };
    tokio::try_join!(p_s_c, c_s_p)
}

pub async fn relay_websocket<I, C>(inbound: WebSocketStream<I>, mut codec: C)
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error>,
{
    let (mut server_client, mut client_server) = inbound.split();
    // server_client.with(|a: BytesMut| async move { Ok::<_, anyhow::Error>(tokio_websockets::Message::binary(BytesMut::new())) });
    if let Some(Ok(websocket_msg)) = client_server.next().await {
        match codec.decode(&mut websocket_msg.into_payload().into()) {
            Ok(Some(Message::Connect(head, addr))) => {
                if let Ok(resolved_addr) = addr.to_socket_addr() {
                    match TcpStream::connect(resolved_addr).await {
                        Err(e) => error!("[tcp] connect failed: peer={}/{}; error={}", addr, resolved_addr, e),
                        Ok(outbound) => {
                            let (codec0, codec1) = BiLock::new(&mut codec);
                            let (mut server_peer, mut peer_server) = BytesCodec.framed(outbound).split::<BytesMut>();
                            let c_s_p = async {
                                server_peer.send(head).await?;
                                while let Some(Ok(websocket_msg)) = client_server.next().await {
                                    if let Some(msg) = codec0.lock().await.decode(&mut websocket_msg.into_payload().into())? {
                                        match msg {
                                            Message::Connect(msg, _) => server_peer.send(msg).await?,
                                            Message::RelayTcp(msg) => server_peer.send(msg).await?,
                                        }
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
                            if let Err(e) = tokio::try_join!(c_s_p, p_s_c) {
                                info!("[tcp] relay completed: peer={}/{}: {}", addr, resolved_addr, e);
                            }
                        }
                    }
                } else {
                    error!("[tcp] DNS resolve failed: peer={}", addr);
                }
            }
            Ok(Some(Message::RelayTcp(_))) => error!("[tcp] expect a connect message for the first time"),
            Ok(None) => (),
            Err(e) => error!("[tcp] decode failed; error={e}"),
        }
    }
}
