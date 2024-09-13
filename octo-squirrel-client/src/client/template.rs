use std::fmt::Debug;
use std::fs;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use bytes::BytesMut;
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
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::codec::WebSocketFramed;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::common::relay;
use octo_squirrel::common::relay::End;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::config::SslConfig;
use octo_squirrel::config::WebSocketConfig;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
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

pub async fn transfer_tcp<NewCodec, Codec>(listener: TcpListener, config: &ServerConfig, new_codec: NewCodec)
where
    NewCodec: FnOnce(&Address, &ServerConfig) -> Result<Codec> + Copy + Send + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
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
    NewCodec: FnOnce(&Address, &ServerConfig) -> Result<Codec> + Copy,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    info!("[tcp] connect {}, peer={}, local={}", &config.protocol, request, &src);
    let local_client = Framed::new(inbound, BytesCodec);
    let codec = new_codec(&request, config)?;
    let server_addr = format!("{}:{}", config.host, config.port);
    let res = match (&config.ssl, &config.ws) {
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
    };
    info!("[tcp] relay complete, local={}, server={}, peer={}, {:?}", &src, &server_addr, request, res);
    Ok(())
}

async fn relay_tcp<I, O>(local_client: I, client_server: O) -> relay::Result
where
    I: Sink<BytesMut, Error = anyhow::Error> + Stream<Item = anyhow::Result<BytesMut>>,
    O: Sink<BytesMut, Error = anyhow::Error> + Stream<Item = anyhow::Result<BytesMut>>,
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

pub trait AsyncP3G2<P1, P2, P3, G1, G2>: std::ops::FnOnce(P1, P2, P3) -> <Self as AsyncP3G2<P1, P2, P3, G1, G2>>::Future {
    type Future: Future<Output = <Self as AsyncP3G2<P1, P2, P3, G1, G2>>::Output>;
    type Output;
}

impl<P1, P2, P3, G1, G2, Fn, Future> AsyncP3G2<P1, P2, P3, G1, G2> for Fn
where
    Fn: std::ops::FnOnce(P1, P2, P3) -> Future,
    Future: core::future::Future,
{
    type Future = Future;
    type Output = Future::Output;
}

pub async fn transfer_udp<OutRecv, OutSend, Key, NewKey, Out, NewOut, ToOutSend, ToInRecv>(
    inbound: UdpSocket,
    config: &ServerConfig,
    new_key: NewKey,
    new_out: NewOut,
    to_inbound_recv: ToInRecv,
    to_outbound_send: ToOutSend,
) -> Result<()>
where
    OutRecv: Send + Sync + 'static,
    Out: Sink<OutSend, Error = anyhow::Error> + Stream<Item = Result<OutRecv, anyhow::Error>> + Unpin + Send + 'static,
    NewKey: FnOnce(SocketAddr, &Address) -> Key + Copy,
    Key: Ord + Debug + Clone + Send + Sync + 'static,
    NewOut: for<'a, 'b> AsyncP3G2<SocketAddr, &'a Address, &'b ServerConfig, Out, OutRecv, Output = Result<Out, anyhow::Error>> + Copy,
    ToOutSend: FnOnce((BytesMut, &Address), SocketAddr) -> OutSend + Copy,
    ToInRecv: FnOnce(OutRecv, &Address, SocketAddr) -> ((BytesMut, Address), SocketAddr) + Send + Copy + 'static,
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
            let (client_server, mut server_client) = new_out(server_addr, &target, config).await?.split();
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
