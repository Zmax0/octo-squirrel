use core::fmt::Debug;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::ops::AsyncFn;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use bytes::BytesMut;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use futures::stream::SplitSink;
use http::HeaderName;
use http::HeaderValue;
use log::debug;
use log::error;
use log::info;
use lru_time_cache::Entry;
use lru_time_cache::LruCache;
use octo_squirrel::codec::BytesCodec;
use octo_squirrel::codec::DatagramPacket;
use octo_squirrel::codec::QuicStream;
use octo_squirrel::codec::WebSocketFramed;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::config::WebSocketConfig;
use octo_squirrel::protocol::address::Address;
use octo_squirrel::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::relay;
use octo_squirrel::relay::End;
use quinn::crypto::rustls::QuicClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;
use tokio_websockets::ClientBuilder;

use super::config::SslConfig;
use super::handshake;

pub async fn transfer_tcp<NewContext, Context, NewCodec, Codec>(
    listener: TcpListener,
    config: ServerConfig<SslConfig>,
    new_context: NewContext,
    new_codec: NewCodec,
) where
    NewContext: FnOnce(&ServerConfig<SslConfig>) -> Result<Context> + 'static,
    Context: Clone + Send + 'static,
    NewCodec: FnOnce(&Address, Context) -> Result<Codec> + Copy + Send + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    let context = new_context(&config);
    let config = Arc::new(config);
    match context {
        Ok(context) => {
            while let Ok((mut inbound, local_addr)) = listener.accept().await {
                let context = context.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let handshake = handshake::get_request_addr(&mut inbound).await;
                    if let Ok(peer_addr) = handshake {
                        info!("[tcp] accept {}, peer={}, local={}", config.protocol, peer_addr, &local_addr);
                        match try_transfer_tcp(inbound, &peer_addr, &config, context, new_codec).await {
                            Ok(res) => info!(
                                "[tcp] relay complete, local={}, server={}:{}, peer={}, {:?}",
                                &local_addr, &config.host, config.port, peer_addr, res
                            ),
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

pub async fn try_transfer_tcp<Context, NewCodec, Codec>(
    inbound: TcpStream,
    peer_addr: &Address,
    config: &ServerConfig<SslConfig>,
    context: Context,
    new_codec: NewCodec,
) -> Result<relay::Result>
where
    NewCodec: FnOnce(&Address, Context) -> Result<Codec>,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    let local_client = Framed::new(inbound, BytesCodec);
    let codec = new_codec(peer_addr, context)?;
    Ok(match (&config.ssl, &config.ws, &config.quic) {
        (None, None, None) => {
            let client_server = new_plain_outbound(&config.host, config.port, codec).await?;
            relay_tcp(local_client, client_server).await
        }
        (_, _, Some(quic_config)) => {
            let client_server = new_quic_outbound(&config.host, config.port, codec, quic_config).await?;
            relay_tcp(local_client, client_server).await
        }
        (None, Some(ws_config), None) => {
            let client_server = new_ws_outbound(&config.host, config.port, codec, ws_config).await?;
            relay_tcp(local_client, client_server).await
        }
        (Some(ssl_config), None, None) => {
            let client_server = new_tls_outbound(&config.host, config.port, codec, ssl_config).await?;
            relay_tcp(local_client, client_server).await
        }
        (Some(ssl_config), Some(ws_config), None) => {
            let client_server = new_wss_outbound(&config.host, config.port, codec, ssl_config, ws_config).await?;
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
    loop {
        tokio::select! {
            res = l_c.next() => match res {
                Some(Ok(item)) => match c_s.send(item).await {
                    Ok(_) => (),
                    Err(e) => return relay::Result::Err(End::Client, End::Server, e),
                },
                Some(Err(e)) => return relay::Result::Err(End::Local, End::Client, e),
                None => return relay::Result::Close(End::Local, End::Client),
            },
            res = s_c.next() => match res {
                Some(Ok(item)) => match c_l.send(item).await {
                    Ok(_) => (),
                    Err(e) => return relay::Result::Err(End::Client, End::Local, e),
                },
                Some(Err(e)) => return relay::Result::Err(End::Server, End::Client, e),
                None => return relay::Result::Close(End::Server, End::Client),
            }
        }
    }
}

pub async fn transfer_udp<Context, NewContext, Key, NewKey, Out, NewOut, ToOutSend, ToInRecv, OutRecv, OutSend>(
    inbound: UdpSocket,
    config: ServerConfig<SslConfig>,
    new_context: NewContext,
    new_key: NewKey,
    new_out: NewOut,
    to_inbound_recv: ToInRecv,
    to_outbound_send: ToOutSend,
) -> Result<()>
where
    NewContext: FnOnce(ServerConfig<SslConfig>) -> Result<Context>,
    NewKey: FnOnce(SocketAddr, &Address) -> Key + Copy,
    Key: Ord + Clone + Debug + Send + Sync + 'static,
    NewOut: AsyncFn(&Address, &Context) -> Result<Out, anyhow::Error> + Copy,
    Out: Sink<OutSend, Error = anyhow::Error> + Stream<Item = Result<OutRecv, anyhow::Error>> + Unpin + Send + 'static,
    ToOutSend: FnOnce(DatagramPacket, SocketAddr) -> OutSend + Copy,
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
                client_server_cache.iter(); // removes expired items before creating the iterator
            }
            // client->local|mpsc
            Some((item, key)) = client_local_rx.recv() => {
                client_server_cache.get(&key);
                client_local.send(item).await.unwrap_or_else(|e| error!("[udp] failed to send inbound msg; error={}", e));
            }
            // local->client|inbound
            Some(Ok(((content, target), sender))) = local_client.next() => {
                let key = new_key(sender, &target);
                let _key = key.clone();
                match client_server_cache.entry(key) {
                    Entry::Vacant(entry) => {
                        debug!("[udp] new binding; key={:?}", &_key);
                        let out = new_out(&target, &context).await?;
                        let (sink, relay_task) = new_binding(server_addr, client_local_tx.clone(), ((content, target), sender), _key, out, to_inbound_recv, to_outbound_send).await?;
                        entry.insert(Binding {sink, relay_task});
                    }
                    Entry::Occupied(entry) => {
                        // client->server|outbound
                        let value = entry.into_mut();
                        if value.relay_task.is_finished() {
                            debug!("[udp] retry binding; key={:?}", &_key);
                            let out = new_out(&target, &context).await?;
                            let (sink, relay_task) = new_binding(server_addr, client_local_tx.clone(), ((content, target), sender), _key, out, to_inbound_recv, to_outbound_send).await?;
                            value.sink = sink;
                            value.relay_task = relay_task;
                        } else {
                            value.sink.send(to_outbound_send((content, target), server_addr)).await?;
                        }
                    }
                }
            }
            else => break,
        }
    }
    Ok(())
}

type ClientLocalSender<T> = Sender<((DatagramPacket, SocketAddr), T)>;

async fn new_binding<Key, Out, OutSend, ToOutSend, OutRecv, ToInRecv>(
    server_addr: SocketAddr,
    client_local: ClientLocalSender<Key>,
    msg: (DatagramPacket, SocketAddr),
    key: Key,
    out: Out,
    to_inbound_recv: ToInRecv,
    to_outbound_send: ToOutSend,
) -> Result<(SplitSink<Out, OutSend>, JoinHandle<()>)>
where
    Key: Ord + Clone + Debug + Send + Sync + 'static,
    Out: Sink<OutSend, Error = anyhow::Error> + Stream<Item = Result<OutRecv, anyhow::Error>> + Unpin + Send + 'static,
    OutRecv: Send + Sync + 'static,
    ToInRecv: FnOnce(OutRecv, &Address, SocketAddr) -> (DatagramPacket, SocketAddr) + Send + Copy + 'static,
    ToOutSend: FnOnce(DatagramPacket, SocketAddr) -> OutSend + Copy,
{
    let ((content, target), sender) = msg;
    // client->server|outbound, server->client|outbound
    let (mut client_server, mut server_client) = out.split();
    let _target = target.clone();
    let relay_task = tokio::spawn(async move {
        // server->client|outbound
        while let Some(next) = server_client.next().await {
            match next {
                Ok(outbound_recv) => {
                    // client->local|mpsc
                    client_local
                        .send((to_inbound_recv(outbound_recv, &_target, sender), key.clone()))
                        .await
                        .unwrap_or_else(|e| error!("[udp] client*-local send mpsc failed; error={}", e));
                }
                Err(e) => {
                    error!("[udp] server*-client decode failed; error={}", e);
                    break;
                }
            }
        }
        debug!("[udp] server-client relay task done");
    });
    // client->server|outbound
    client_server.send(to_outbound_send((content, target), server_addr)).await?;
    Ok((client_server, relay_task))
}

struct Binding<Out, OutSend> {
    sink: SplitSink<Out, OutSend>,
    relay_task: JoinHandle<()>,
}

impl<Out, OutSend> Drop for Binding<Out, OutSend> {
    fn drop(&mut self) {
        debug!("[udp] remove binding");
        self.relay_task.abort();
    }
}

pub async fn new_plain_outbound<C, E, D>(host: &str, port: u16, codec: C) -> Result<Framed<TcpStream, C>, anyhow::Error>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = TcpStream::connect((host, port)).await?;
    let client_server = codec.framed(outbound);
    Ok(client_server)
}

pub async fn new_quic_outbound<C, E, D>(host: &str, port: u16, codec: C, config: &SslConfig) -> Result<Framed<QuicStream, C>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let mut tls_config = rustls_client_config(config)?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut endpoint = quinn::Endpoint::client(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    let quic_client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    endpoint.set_default_client_config(quic_client_config);
    let server_name = if let Some(server_name) = &config.server_name { server_name } else { &host.to_owned() };
    let conn = endpoint.connect(format!("{host}:{port}").parse()?, server_name)?.await?;
    let (send, recv) = conn.open_bi().await?;
    Ok(codec.framed(QuicStream::new(send, recv)))
}

pub async fn new_tls_outbound<C, E, D>(host: &str, port: u16, codec: C, ssl_config: &SslConfig) -> Result<Framed<TlsStream<TcpStream>, C>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = rustls_stream(host, port, ssl_config).await?;
    Ok(codec.framed(outbound))
}

pub async fn new_ws_outbound<C, E, D>(host: &str, port: u16, codec: C, ws_config: &WebSocketConfig) -> Result<WebSocketFramed<TcpStream, C, E, D>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = TcpStream::connect((host, port)).await?;
    let (outbound, _) = new_ws_builder(host, port, ws_config)?.connect_on(outbound).await.map_err(|e| anyhow!(e))?;
    Ok(WebSocketFramed::new(outbound, codec))
}

pub async fn new_wss_outbound<C, E, D>(
    host: &str,
    port: u16,
    codec: C,
    ssl_config: &SslConfig,
    ws_config: &WebSocketConfig,
) -> Result<WebSocketFramed<TlsStream<TcpStream>, C, E, D>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = rustls_stream(host, port, ssl_config).await?;
    let (outbound, _) = new_ws_builder(host, port, ws_config)?.connect_on(outbound).await.map_err(|e| anyhow!(e))?;
    Ok(WebSocketFramed::new(outbound, codec))
}

fn new_ws_builder<'a>(host: &str, port: u16, ws_config: &WebSocketConfig) -> Result<ClientBuilder<'a>> {
    let mut ws_host = None;
    let mut builder = ClientBuilder::new();
    for (k, v) in ws_config.header.iter() {
        if k == "host" || k == "Host" {
            ws_host = Some(v);
        } else {
            builder = builder.add_header(HeaderName::from_str(k)?, HeaderValue::from_str(v)?)?;
        }
    }
    if let Some(ws_host) = ws_host {
        builder = builder.uri(&format!("ws://{}:{}{}", ws_host, port, &ws_config.path))?;
    } else {
        builder = builder.uri(&format!("ws://{}:{}{}", host, port, &ws_config.path))?;
    }
    Ok(builder)
}

pub async fn rustls_stream(host: &str, port: u16, ssl_config: &SslConfig) -> Result<TlsStream<TcpStream>> {
    let stream = TcpStream::connect((host, port)).await?;
    let config = rustls_client_config(ssl_config)?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = if let Some(server_name) = &ssl_config.server_name {
        ServerName::try_from(server_name.to_owned())?
    } else {
        ServerName::try_from(host.to_owned())?
    };
    connector.connect(server_name, stream).await.map_err(|e| anyhow!(e))
}

fn rustls_client_config(ssl_config: &SslConfig) -> Result<ClientConfig> {
    let config = if let Some(certificate_file) = &ssl_config.certificate_file {
        let mut roots = RootCertStore::empty();
        let cert = CertificateDer::from_pem_file(certificate_file)?;
        roots.add(cert)?;
        ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
    } else {
        ClientConfig::with_platform_verifier()
    };
    Ok(config)
}
