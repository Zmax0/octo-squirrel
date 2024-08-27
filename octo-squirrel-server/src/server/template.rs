use anyhow::anyhow;
use bytes::BytesMut;
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

pub enum Message {
    Connect(BytesMut, Address),
    Relay(BytesMut),
}

pub async fn relay_tcp<Codec, I>(inbound: I, codec: Codec)
where
    I: AsyncRead + AsyncWrite,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = Message, Error = anyhow::Error> + Send + 'static,
{
    let (mut inbound_sink, mut inbound_stream) = codec.framed(inbound).split();
    if let Some(Ok(Message::Connect(msg, addr))) = inbound_stream.next().await {
        if let Ok(peer_addr) = addr.to_socket_addr() {
            if let Ok(outbound) = TcpStream::connect(peer_addr).await {
                let (mut outbound_sink, mut outbound_stream) = BytesCodec.framed(outbound).split::<BytesMut>();
                let peer_server = async {
                    while let Some(Ok(next)) = outbound_stream.next().await {
                        inbound_sink.send(next).await?;
                    }
                    Err::<(), _>(anyhow!("peer is closed"))
                };
                let client_server = async {
                    outbound_sink.send(msg).await?;
                    while let Some(Ok(next)) = inbound_stream.next().await {
                        match next {
                            Message::Connect(next, _) => outbound_sink.send(next).await?,
                            Message::Relay(next) => outbound_sink.send(next).await?,
                        }
                    }
                    Err::<(), _>(anyhow!("client is closed"))
                };
                if let Err(e) = tokio::try_join!(peer_server, client_server) {
                    info!("[tcp] relay completed: peer={}/{}: {}", addr, peer_addr, e);
                }
            } else {
                error!("[tcp] connect failed: peer={}/{}", addr, peer_addr);
            }
        } else {
            error!("[tcp] DNS resolve failed: peer={}", addr);
        }
    } else {
        error!("[tcp] expect a connect message for the first time")
    }
}
