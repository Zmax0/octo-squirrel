use core::fmt::Debug;
use std::fs;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use bytes::BytesMut;
use futures::stream::SplitSink;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use http::HeaderName;
use http::HeaderValue;
use log::debug;
use log::error;
use log::info;
use log::trace;
use lru_time_cache::Entry;
use lru_time_cache::LruCache;
use octo_squirrel::codec::BytesCodec;
use octo_squirrel::codec::DatagramPacket;
use octo_squirrel::codec::WebSocketFramed;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::config::SslConfig;
use octo_squirrel::config::WebSocketConfig;
use octo_squirrel::protocol::address::Address;
use octo_squirrel::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::relay;
use octo_squirrel::relay::End;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Certificate;
use tokio_native_tls::TlsConnector;
use tokio_native_tls::TlsStream;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;
use tokio_websockets::ClientBuilder;

use super::handshake;

pub async fn transfer_tcp<NewContext, Context, NewCodec, Codec>(
    listener: TcpListener,
    config: &ServerConfig,
    new_context: NewContext,
    new_codec: NewCodec,
) where
    NewContext: FnOnce(&ServerConfig) -> Result<Context> + 'static,
    Context: Clone + Send + 'static,
    NewCodec: FnOnce(&Address, Context) -> Result<Codec> + Copy + Send + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    let server_addr: &'static str = Box::leak::<'static>(format!("{}:{}", config.host, config.port).into_boxed_str());
    let context = new_context(config);
    let config = Arc::new(config.clone());
    match context {
        Ok(context) => {
            while let Ok((mut inbound, src)) = listener.accept().await {
                let context = context.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let handshake = handshake::get_request_addr(&mut inbound).await;
                    if let Ok(request) = handshake {
                        info!("[tcp] accept {}, peer={}, local={}", config.protocol, request, &src);
                        match try_transfer_tcp(inbound, server_addr, &request, config.ssl.as_ref(), config.ws.as_ref(), context, new_codec).await {
                            Ok(res) => info!("[tcp] relay complete, local={}, server={}, peer={}, {:?}", &src, &server_addr, request, res),
                            Err(e) => error!("[tcp] transfer failed; error={}", e),
                        }
                    } else {
                        error!("[tcp] local handshake failed; error={}", handshake.unwrap_err());
                    }
                });
            }
        }
        Err(e) => error!("create client context failed; error={e}"),
    }
}

#[inline]
pub async fn try_transfer_tcp<Context, NewCodec, Codec>(
    inbound: TcpStream,
    server_addr: &'static str,
    peer_addr: &Address,
    ssl: Option<&SslConfig>,
    ws: Option<&WebSocketConfig>,
    context: Context,
    new_codec: NewCodec,
) -> Result<relay::Result>
where
    NewCodec: FnOnce(&Address, Context) -> Result<Codec>,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    let local_client = Framed::new(inbound, BytesCodec);
    let codec = new_codec(peer_addr, context)?;
    // let server_addr: String = format!("{}:{}", config.host, config.port);
    Ok(match (ssl, ws) {
        (None, None) => {
            let outbound = TcpStream::connect(&server_addr).await?;
            let client_server = codec.framed(outbound);
            relay_tcp(local_client, client_server).await
        }
        (None, Some(ws_config)) => {
            let client_server = new_ws_outbound(&server_addr, codec, ws_config).await?;
            relay_tcp(local_client, client_server).await
        }
        (Some(ssl_config), None) => {
            let client_server = new_tls_outbound(&server_addr, codec, ssl_config).await?;
            relay_tcp(local_client, client_server).await
        }
        (Some(ssl_config), Some(ws_config)) => {
            let client_server = new_wss_outbound(&server_addr, codec, ssl_config, ws_config).await?;
            relay_tcp(local_client, client_server).await
        }
    })
}

async fn relay_tcp<I, O>(local_client: I, client_server: O) -> relay::Result
where
    I: Sink<BytesMut, Error = anyhow::Error> + Stream<Item = Result<BytesMut>>,
    O: Sink<BytesMut, Error = anyhow::Error> + Stream<Item = Result<BytesMut>>,
{
    let (mut c_l, mut l_c) = local_client.split();
    let (mut c_s, mut s_c) = client_server.split();
    tokio::select! {
        res = c_s.send_all(&mut l_c) => {
            match res {
                Ok(_) => relay::Result::Close(End::Local, End::Client),
                Err(e) => relay::Result::Err(End::Local, End::Client,e),
            }
        },
        res = c_l.send_all(&mut s_c) => {
            match res {
                Ok(_) => relay::Result::Close(End::Server, End::Client),
                Err(e) => relay::Result::Err(End::Server, End::Client, e),
            }
        }
    }
}

pub trait AsyncP3G2<P1, P2, P3, G1, G2>: FnOnce(P1, P2, P3) -> <Self as AsyncP3G2<P1, P2, P3, G1, G2>>::Future {
    type Future: Future<Output = <Self as AsyncP3G2<P1, P2, P3, G1, G2>>::Output>;
    type Output;
}

impl<P1, P2, P3, G1, G2, Fn, Future> AsyncP3G2<P1, P2, P3, G1, G2> for Fn
where
    Fn: FnOnce(P1, P2, P3) -> Future,
    Future: core::future::Future,
{
    type Future = Future;
    type Output = Future::Output;
}

pub async fn transfer_udp<Context, NewContext, Key, NewKey, Out, NewOut, ToOutSend, ToInRecv, OutRecv, OutSend>(
    inbound: UdpSocket,
    config: ServerConfig,
    new_context: NewContext,
    new_key: NewKey,
    new_out: NewOut,
    to_inbound_recv: ToInRecv,
    to_outbound_send: ToOutSend,
) -> Result<()>
where
    NewContext: FnOnce(ServerConfig) -> Result<Context>,
    NewKey: FnOnce(SocketAddr, &Address) -> Key + Copy,
    Key: Ord + Clone + Debug + Send + Sync + 'static,
    NewOut: for<'a> AsyncP3G2<SocketAddr, &'a Address, &'a Context, Out, OutRecv, Output = Result<Out, anyhow::Error>> + Copy,
    Out: Sink<OutSend, Error = anyhow::Error> + Stream<Item = Result<OutRecv, anyhow::Error>> + Unpin + Send + 'static,
    ToOutSend: FnOnce((BytesMut, &Address), SocketAddr) -> OutSend + Copy,
    ToInRecv: FnOnce(OutRecv, &Address, SocketAddr) -> (DatagramPacket, SocketAddr) + Send + Copy + 'static,
    OutRecv: Send + Sync + 'static,
{
    use std::net::ToSocketAddrs;

    let server_addr = format!("{}:{}", config.host, config.port).to_socket_addrs()?.next().ok_or(anyhow!("server address is not available"))?;
    let context = new_context(config)?;
    // client->local|inbound, local->client|inbound
    let (mut client_local, mut local_client) = UdpFramed::new(inbound, Socks5UdpCodec).split();
    let ttl = Duration::from_secs(600);
    let mut client_server_cache = LruCache::with_expiry_duration_and_capacity(ttl, 64);
    let (client_local_tx, mut client_local_rx) = mpsc::channel(1024);
    let mut cleanup_timer = time::interval(ttl);
    loop {
        tokio::select! {
            // clean up
            _ = cleanup_timer.tick() => {
                client_server_cache.iter();
            }
            // client->local|mpsc
            Some((item, key)) = client_local_rx.recv() => {
                client_server_cache.get(&key);
                client_local.send(item).await.unwrap_or_else(|e| error!("[udp] failed to send inbound msg; error={}", e));
            }
            // local->client|inbound
            Some(Ok(((content, target), sender))) = local_client.next() => {
                let key = new_key(sender, &target);
                if let Entry::Vacant(entry) = client_server_cache.entry(key.clone()) {
                    let target = target.clone();
                    debug!("[udp] new binding; key={:?}", &key);
                    // client->server|outbound, server->client|outbound
                    let (client_server, mut server_client) = new_out(server_addr, &target, &context).await?.split();
                    let _client_local_tx = client_local_tx.clone();
                    let _key = key.clone();
                    let relay_task = tokio::spawn(async move {
                        // server->client|outbound
                        while let Some(next) = server_client.next().await {
                            match next {
                                Ok(outbound_recv) => {
                                    // client->local|mpsc
                                    _client_local_tx
                                    .send((to_inbound_recv(outbound_recv, &target, sender), _key.clone()))
                                    .await
                                    .unwrap_or_else(|e| error!("[udp] client*-local send mpsc failed; error={}", e));
                                }
                                Err(e) => error!("[udp] server*-client decode failed; error={}", e),
                            }
                        }
                    });
                    entry.insert(Binding { sink: client_server, relay_task });
                }
                // client->server|outbound
                client_server_cache.get_mut(&key).unwrap().sink.send(to_outbound_send((content, &target), server_addr)).await?;
            }
            else => break,
        }
    }
    Ok(())
}

struct Binding<Out, OutSend> {
    sink: SplitSink<Out, OutSend>,
    relay_task: JoinHandle<()>,
}

impl<Out, OutSend> Drop for Binding<Out, OutSend> {
    fn drop(&mut self) {
        trace!("remove binding");
        self.relay_task.abort();
    }
}

pub async fn new_tls_outbound<A, C, E, D>(addr: A, codec: C, ssl_config: &SslConfig) -> Result<Framed<TlsStream<TcpStream>, C>>
where
    A: ToSocketAddrs,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = TcpStream::connect(addr).await?;
    let pem = fs::read(ssl_config.certificate_file.as_str())?;
    let cert = Certificate::from_pem(&pem)?;
    let connector = TlsConnector::from(native_tls::TlsConnector::builder().add_root_certificate(cert).use_sni(true).build()?);
    let outbound = connector.connect(&ssl_config.server_name, outbound).await?;
    Ok(codec.framed(outbound))
}

pub async fn new_ws_outbound<A, C, E, D>(addr: A, codec: C, ws_config: &WebSocketConfig) -> Result<WebSocketFramed<TcpStream, C, E, D>>
where
    A: ToSocketAddrs,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = TcpStream::connect(addr).await?;
    let addr = outbound.peer_addr()?;
    let (outbound, _) = new_ws_builder(addr.ip(), addr.port(), ws_config)?.connect_on(outbound).await.map_err(|e| anyhow!(e))?;
    Ok(WebSocketFramed::new(outbound, codec))
}

pub async fn new_wss_outbound<A, C, E, D>(
    addr: A,
    codec: C,
    ssl_config: &SslConfig,
    ws_config: &WebSocketConfig,
) -> Result<WebSocketFramed<TlsStream<TcpStream>, C, E, D>>
where
    A: ToSocketAddrs,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = TcpStream::connect(addr).await?;
    let addr = outbound.peer_addr()?;
    let pem = fs::read(ssl_config.certificate_file.as_str())?;
    let cert = Certificate::from_pem(&pem)?;
    let connector = TlsConnector::from(native_tls::TlsConnector::builder().add_root_certificate(cert).use_sni(true).build()?);
    let outbound = connector.connect(&ssl_config.server_name, outbound).await?;
    let (outbound, _) = new_ws_builder(addr.ip(), addr.port(), ws_config)?.connect_on(outbound).await.map_err(|e| anyhow!(e))?;
    Ok(WebSocketFramed::new(outbound, codec))
}

#[inline]
fn new_ws_builder<'a>(ip: IpAddr, port: u16, ws_config: &WebSocketConfig) -> Result<ClientBuilder<'a>> {
    let mut host = None;
    let mut builder = ClientBuilder::new();
    for (k, v) in ws_config.header.iter() {
        if k == "host" || k == "Host" {
            host = Some(v);
        } else {
            builder = builder.add_header(HeaderName::from_str(k)?, HeaderValue::from_str(v)?);
        }
    }
    if let Some(host) = host {
        builder = builder.uri(&format!("ws://{}:{}{}", host, port, &ws_config.path))?;
    } else {
        builder = builder.uri(&format!("ws://{}:{}{}", ip, port, &ws_config.path))?;
    }
    Ok(builder)
}
