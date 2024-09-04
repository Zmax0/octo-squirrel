use std::fmt::Debug;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use bytes::BytesMut;
use futures::lock::BiLock;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use http::HeaderName;
use http::HeaderValue;
use log::debug;
use log::error;
use log::info;
use lru_time_cache::Entry;
use lru_time_cache::LruCache;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Certificate;
use tokio_native_tls::TlsConnector;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;
use tokio_websockets::ClientBuilder;
use tokio_websockets::Message;

use super::handshake;

pub async fn transfer_tcp<NewCodec, Codec>(listener: TcpListener, config: &ServerConfig, new_codec: NewCodec)
where
    NewCodec: FnOnce(Address, &ServerConfig) -> Result<Codec> + Copy + Send + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static,
{
    while let Ok((mut inbound, src)) = listener.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            let handshake = handshake::get_request_addr(&mut inbound).await;
            if let Ok(request) = handshake {
                if let Err(e) = try_transfer_tcp(inbound, src, request, &config, new_codec).await {
                    error!("[tcp] transfer failed; error={}", e);
                }
            } else {
                error!("[tcp] local handshake failed; error={}", handshake.unwrap_err());
            }
            Ok::<(), anyhow::Error>(())
        });
    }
}

#[inline]
async fn try_transfer_tcp<NewCodec, Codec>(
    inbound: TcpStream,
    src: SocketAddr,
    request: Address,
    config: &ServerConfig,
    new_codec: NewCodec,
) -> Result<()>
where
    NewCodec: FnOnce(Address, &ServerConfig) -> Result<Codec> + Copy,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static,
{
    let outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
    info!("[tcp] connect {}, peer={}, local={}", &config.protocol, &request, &src);
    match (&config.ssl, &config.ws) {
        (None, None) => relay_plain(inbound, outbound, new_codec(request, config)?).await,
        (None, Some(ws_config)) => {
            let mut builder = ClientBuilder::new().uri(&format!("ws://{}:{}{}", config.host, config.port, &ws_config.path))?;
            for (k, v) in ws_config.header.iter() {
                builder = builder.add_header(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
            }
            match builder.connect_on(outbound).await {
                Ok((outbound, _)) => relay_websocket(inbound, outbound, new_codec(request, config)?).await,
                Err(e) => bail!("[tcp] websocket handshake failed: {}", e),
            }
        }
        (Some(ssl_config), ws_config) => {
            let pem = fs::read(ssl_config.certificate_file.as_str())?;
            let cert = Certificate::from_pem(&pem)?;
            let connector = TlsConnector::from(native_tls::TlsConnector::builder().add_root_certificate(cert).use_sni(true).build()?);
            match ws_config {
                None => match connector.connect(ssl_config.server_name.as_str(), outbound).await {
                    Ok(outbound) => relay_plain(inbound, outbound, new_codec(request, config)?).await,
                    Err(e) => bail!("[tcp] tls handshake failed: {}", e),
                },
                Some(ws_config) => {
                    let mut builder = ClientBuilder::new().uri(&format!("ws://{}:{}{}", config.host, config.port, &ws_config.path))?;
                    for (k, v) in ws_config.header.iter() {
                        builder = builder.add_header(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
                    }
                    match tokio_websockets::Connector::NativeTls(connector).wrap(ssl_config.server_name.as_str(), outbound).await {
                        Ok(outbound) => match builder.connect_on(outbound).await {
                            Ok((outbound, _)) => relay_websocket(inbound, outbound, new_codec(request, config)?).await,
                            Err(e) => bail!("[tcp] websocket handshake failed: {}", e),
                        },
                        Err(e) => bail!("[tcp] tls handshake failed: {}", e),
                    }
                }
            }
        }
    }
}

async fn relay_websocket<I, O, C>(inbound: I, outbound: O, mut codec: C) -> Result<(), anyhow::Error>
where
    I: AsyncRead + AsyncWrite,
    O: Sink<Message, Error = tokio_websockets::Error> + Stream<Item = Result<Message, tokio_websockets::Error>>,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error>,
{
    use octo_squirrel::common::codec::BytesCodec;
    let (mut inbound_sink, mut inbound_stream) = Framed::new(inbound, BytesCodec).split::<BytesMut>();
    let (mut outbound_sink, mut outbound_stream) = outbound.split();
    let (codec0, codec1) = BiLock::new(&mut codec);
    let server_to_client = async {
        while let Some(Ok(msg)) = outbound_stream.next().await {
            if let Some(msg) = codec0.lock().await.decode(&mut msg.into_payload().into())? {
                inbound_sink.send(msg).await?;
            }
        }
        Err::<(), _>(anyhow!("server is closed"))
    };

    let local_to_client = async {
        while let Some(Ok(mut item)) = inbound_stream.next().await {
            let mut dst = item.split_off(item.len());
            codec1.lock().await.encode(item, &mut dst)?;
            outbound_sink.send(Message::binary::<BytesMut>(dst)).await?;
        }
        Err::<(), _>(anyhow!("local is closed"))
    };
    if let Err(e) = tokio::try_join!(local_to_client, server_to_client) {
        info!("[tcp] relay completed: {}", e)
    }
    Ok(())
}

async fn relay_plain<I, O, C>(inbound: I, outbound: O, codec: C) -> Result<(), anyhow::Error>
where
    I: AsyncRead + AsyncWrite,
    O: AsyncRead + AsyncWrite,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error>,
{
    use octo_squirrel::common::codec::BytesCodec;
    let (mut inbound_sink, mut inbound_stream) = Framed::new(inbound, BytesCodec).split::<BytesMut>();
    let (mut outbound_sink, mut outbound_stream) = codec.framed(outbound).split();
    let server_to_client = async {
        while let Some(Ok(next)) = outbound_stream.next().await {
            inbound_sink.send(next).await?;
        }
        Err::<(), _>(anyhow!("server-client is interrupted"))
    };
    let client_to_server = async {
        while let Some(Ok(next)) = inbound_stream.next().await {
            outbound_sink.send(next).await?;
        }
        Err::<(), _>(anyhow!("client-server is interrupted"))
    };
    let _ = tokio::try_join!(client_to_server, server_to_client);
    Ok(())
}

pub trait Async3<P1, P2, P3, G1, G2, G3>: FnOnce(P1, P2, P3) -> <Self as Async3<P1, P2, P3, G1, G2, G3>>::Future {
    type Future: Future<Output = <Self as Async3<P1, P2, P3, G1, G2, G3>>::Output>;
    type Output;
}

impl<P1, P2, P3, G1, G2, G3, Fn, Res> Async3<P1, P2, P3, G1, G2, G3> for Fn
where
    Fn: FnOnce(P1, P2, P3) -> Res,
    Res: Future,
{
    type Future = Res;
    type Output = Res::Output;
}

pub async fn transfer_udp<Item, OutboundSink, OutboundStream, Key, NewKey, NewOutbound, ToOutboundSend, ToInboundRecv>(
    inbound: UdpSocket,
    config: &ServerConfig,
    new_key: NewKey,
    new_outbound: NewOutbound,
    to_inbound_recv: ToInboundRecv,
    to_outbound_send: ToOutboundSend,
) -> Result<()>
where
    Item: Send + Sync + 'static,
    OutboundSink: Sink<Item, Error = anyhow::Error> + Send + 'static,
    OutboundStream: Stream<Item = Result<Item, anyhow::Error>> + Unpin + Send + 'static,
    NewKey: FnOnce(SocketAddr, &Address) -> Key + Copy,
    Key: Ord + Debug + Clone + Send + Sync + 'static,
    NewOutbound: for<'a, 'b> Async3<
            SocketAddr,
            &'a Address,
            &'b ServerConfig,
            OutboundSink,
            OutboundStream,
            Item,
            Output = Result<(SplitSink<OutboundSink, Item>, SplitStream<OutboundStream>), anyhow::Error>,
        > + Copy,
    ToOutboundSend: FnOnce((BytesMut, &Address), SocketAddr) -> Item + Copy,
    ToInboundRecv: FnOnce(Item, &Address, SocketAddr) -> ((BytesMut, Address), SocketAddr) + Send + Copy + 'static,
{
    let server_addr = Address::Domain(config.host.clone(), config.port).to_socket_addr()?;
    // client->local|inbound, local->client|inbound
    let (mut client_local, mut local_client) = UdpFramed::new(inbound, Socks5UdpCodec).split();
    let mut client_server_cache = LruCache::with_expiry_duration_and_capacity(Duration::from_secs(600), 64);
    let (client_local_tx, mut client_local_rx) = mpsc::channel::<((BytesMut, Address), SocketAddr)>(32);
    // client->local|mpsc
    tokio::spawn(async move {
        while let Some(item) = client_local_rx.recv().await {
            client_local.send(item).await.unwrap_or_else(|e| error!("[udp] failed to send inbound msg; error={}", e));
        }
    });
    // local->client|inbound
    while let Some(Ok(((content, target), sender))) = local_client.next().await {
        let key = new_key(sender, &target);
        if let Entry::Vacant(entry) = client_server_cache.entry(key.clone()) {
            let target = target.clone();
            debug!("[udp] new binding; key={:?}", key);
            // client->server|outbound, server->client|outbound
            let (client_server, mut server_client) = new_outbound(server_addr, &target, config).await?;
            entry.insert(client_server);
            let _client_local_tx = client_local_tx.clone();
            let _key = key.clone();
            tokio::spawn(async move {
                // server->client|outbound
                while let Some(Ok(outbound_recv)) = server_client.next().await {
                    // client->local|mpsc
                    _client_local_tx
                        .send(to_inbound_recv(outbound_recv, &target, sender))
                        .await
                        .unwrap_or_else(|e| error!("[udp] failed to send inbound mpsc msg; {}", e));
                }
            });
        }
        // client->server|outbound
        client_server_cache.get_mut(&key).unwrap().send(to_outbound_send((content, &target), server_addr)).await?;
    }
    Ok(())
}
