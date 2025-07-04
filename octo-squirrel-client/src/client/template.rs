use core::fmt::Debug;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::ops::AsyncFn;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use anyhow::anyhow;
use bytes::BytesMut;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use futures::stream::SplitSink;
use hickory_resolver::Name;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::rr::RecordType;
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
use octo_squirrel::codec::WebSocketStream;
use octo_squirrel::config::WebSocketConfig;
use octo_squirrel::protocol::address::Address;
use octo_squirrel::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::relay;
use octo_squirrel::relay::Side;
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
use crate::client::config::DnsConfig;
use crate::client::config::ServerConfig;

pub async fn transfer_tcp<NewContext, Context, NewCodec, Codec>(
    listener: TcpListener,
    config: ServerConfig,
    new_context: NewContext,
    new_codec: NewCodec,
) where
    NewContext: FnOnce(&ServerConfig) -> Result<Context> + 'static,
    Context: Clone + Send + 'static,
    NewCodec: FnMut(&Address, Context) -> Result<Codec> + Copy + Send + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    match new_context(&config) {
        Ok(context) => {
            let config = Arc::new(config);
            while let Ok((inbound, local_addr)) = listener.accept().await {
                let context = context.clone();
                let config = config.clone();
                tokio::spawn(transfer_tcp(new_codec, context, config, inbound, local_addr));
            }
        }
        Err(e) => error!("create context failed; error={e}"),
    }

    async fn transfer_tcp<Context, NewCodec, Codec>(
        new_codec: NewCodec,
        context: Context,
        config: Arc<ServerConfig>,
        mut inbound: TcpStream,
        local_addr: SocketAddr,
    ) where
        Context: Clone + Send + 'static,
        NewCodec: FnMut(&Address, Context) -> Result<Codec> + Copy + Send + 'static,
        Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
    {
        match tokio::time::timeout(Duration::from_secs(30), handshake::get_request_addr(&mut inbound)).await {
            Ok(Ok(peer_addr)) => {
                info!("[tcp] accept {}, peer={}, local={}", config.protocol, peer_addr, &local_addr);
                match TcpOutbound::new(&config).relay_tcp(inbound, &peer_addr, &config, context, new_codec).await {
                    Ok(res) => {
                        info!("[tcp] relay complete, local={}, server={}:{}, peer={}, {:?}", &local_addr, &config.host, config.port, peer_addr, res)
                    }
                    Err(e) => error!("[tcp] transfer failed; error={}", e),
                }
            }
            Ok(Err(e)) => error!("[tcp] local handshake failed; error={}", e),
            Err(_) => info!("[tcp] local handshake timeout, local={}", &local_addr),
        }
    }
}

enum TcpOutbound<'a> {
    Plain,
    Tls(&'a SslConfig),
    Ws(&'a WebSocketConfig),
    Wss(&'a SslConfig, &'a WebSocketConfig),
    Quic(&'a SslConfig),
}

impl TcpOutbound<'_> {
    pub fn new(config: &ServerConfig) -> TcpOutbound<'_> {
        match (&config.ssl, &config.ws, &config.quic) {
            (None, None, None) => TcpOutbound::Plain,
            (_, _, Some(quic_config)) => TcpOutbound::Quic(quic_config),
            (None, Some(ws_config), None) => TcpOutbound::Ws(ws_config),
            (Some(ssl_config), None, None) => TcpOutbound::Tls(ssl_config),
            (Some(ssl_config), Some(ws_config), None) => TcpOutbound::Wss(ssl_config, ws_config),
        }
    }

    pub async fn relay_tcp<Context, NewCodec, Codec>(
        self,
        inbound: TcpStream,
        peer_addr: &Address,
        config: &ServerConfig,
        context: Context,
        mut new_codec: NewCodec,
    ) -> Result<relay::Result>
    where
        Context: Clone,
        NewCodec: FnMut(&Address, Context) -> Result<Codec>,
        Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
    {
        let codec = if let (Some(dns_config), Err(_)) = (&config.dns, IpAddr::from_str(&peer_addr.get_host())) {
            let resolved_peer_ip = self.lookup(&config.host, config.port, peer_addr, context.clone(), &mut new_codec, dns_config).await?;
            let resolved_peer_addr = Address::Socket(SocketAddr::new(resolved_peer_ip, peer_addr.get_port()));
            new_codec(&resolved_peer_addr, context)?
        } else {
            new_codec(peer_addr, context)?
        };
        let local_client = Framed::new(inbound, BytesCodec);
        match self {
            TcpOutbound::Plain => {
                let client_server = new_plain_outbound(&config.host, config.port, codec).await?;
                Ok(relay_tcp(local_client, client_server).await)
            }
            TcpOutbound::Tls(ssl_config) => {
                let client_server = new_tls_outbound(&config.host, config.port, codec, ssl_config).await?;
                Ok(relay_tcp(local_client, client_server).await)
            }
            TcpOutbound::Ws(ws_config) => {
                let client_server = new_ws_outbound(&config.host, config.port, codec, ws_config).await?;
                Ok(relay_tcp(local_client, client_server).await)
            }
            TcpOutbound::Wss(ssl_config, ws_config) => {
                let client_server = new_wss_outbound(&config.host, config.port, codec, ssl_config, ws_config).await?;
                Ok(relay_tcp(local_client, client_server).await)
            }
            TcpOutbound::Quic(ssl_config) => {
                let client_server = new_quic_outbound(&config.host, config.port, codec, ssl_config).await?;
                Ok(relay_tcp(local_client, client_server).await)
            }
        }
    }

    async fn lookup<Context, NewCodec, Codec>(
        &self,
        host: &str,
        port: u16,
        peer_addr: &Address,
        context: Context,
        new_codec: &mut NewCodec,
        dns_config: &DnsConfig,
    ) -> Result<IpAddr>
    where
        NewCodec: FnMut(&Address, Context) -> Result<Codec>,
        Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
    {
        let query = Query::query(Name::from_str(&format!("{}.", peer_addr.get_host()))?, RecordType::A);
        if let Some(ip) = dns_config.cache.get(&query, Instant::now()) {
            debug!("[dns] dns cached; {} => {:?}", peer_addr.get_host(), ip);
            Ok(ip)
        } else {
            let dns_request_context = super::dns::DnsRequestContext::new(dns_config)?;
            let codec = new_codec(&Address::Domain(dns_request_context.host.clone(), dns_request_context.port), context)?;
            let lookup = match *self {
                TcpOutbound::Plain => {
                    let outbound = new_plain_outbound(host, port, codec).await?;
                    super::dns::a_query(outbound, dns_request_context, query.clone()).await?
                }
                TcpOutbound::Tls(ssl_config) => {
                    let outbound = new_tls_outbound(host, port, codec, ssl_config).await?;
                    super::dns::a_query(outbound, dns_request_context, query.clone()).await?
                }
                TcpOutbound::Ws(ws_config) => {
                    let outbound = new_ws_outbound(host, port, codec, ws_config).await?;
                    super::dns::a_query(outbound, dns_request_context, query.clone()).await?
                }
                TcpOutbound::Wss(ssl_config, ws_config) => {
                    let outbound = new_wss_outbound(host, port, codec, ssl_config, ws_config).await?;
                    super::dns::a_query(outbound, dns_request_context, query.clone()).await?
                }
                TcpOutbound::Quic(ssl_config) => {
                    let outbound = new_quic_outbound(host, port, codec, ssl_config).await?;
                    super::dns::a_query(outbound, dns_request_context, query.clone()).await?
                }
            };
            let ttl = lookup.records().iter().next().map(|r| r.ttl()).ok_or(anyhow!("[dns] no ttl found"))?;
            let ip = LookupIp::from(lookup).iter().next().ok_or(anyhow!("[dns] no ip found"))?;
            dns_config.cache.insert(query, ip, ttl, Instant::now());
            debug!("[dns] new query; {} => {:?}", &peer_addr.get_host(), ip);
            Ok(ip)
        }
    }
}

async fn relay_tcp<I, O>(local_client: I, client_server: O) -> relay::Result
where
    I: Sink<BytesMut, Error = anyhow::Error> + Stream<Item = Result<BytesMut>>,
    O: Sink<BytesMut, Error = anyhow::Error> + Stream<Item = Result<BytesMut>>,
{
    let (mut c_l, l_c) = local_client.split();
    let (mut c_s, s_c) = client_server.split();

    let l_c_s = async {
        match l_c.forward(&mut c_s).await {
            Ok(_) => Err::<(), _>(relay::Result::Close(Side::Local, Side::Client)),
            Err(e) => Err(relay::Result::Err(Side::Local, Side::Client, e)),
        }
    };

    let s_c_l = async {
        match s_c.forward(&mut c_l).await {
            Ok(_) => Err::<(), _>(relay::Result::Close(Side::Server, Side::Client)),
            Err(e) => Err(relay::Result::Err(Side::Server, Side::Client, e)),
        }
    };

    match tokio::try_join!(l_c_s, s_c_l) {
        Ok(_) => unreachable!("should never reach here"),
        Err(res) => {
            match tokio::join!(c_s.close(), c_l.close()) {
                (Ok(_), Ok(_)) => (),
                (Ok(_), Err(e)) => error!("[tcp] close client*-local failed; error={}", e),
                (Err(e), Ok(_)) => error!("[tcp] close client*-server failed; error={}", e),
                (Err(e1), Err(e2)) => error!("[tcp] close error; client*-server={} client*-local={}", e1, e2),
            }
            res
        }
    }
}

pub(crate) trait UdpOutboundContext {
    type Key: Ord + Clone + Debug + Send + Sync + 'static;
    type Context;

    fn new_key(sender: SocketAddr, target: &Address) -> Self::Key;

    fn new_context(config: &ServerConfig) -> anyhow::Result<Self::Context>;
}

pub(crate) trait UdpOutbound: UdpDnsContext + UdpOutboundContext {
    type OutboundIn: Send;
    type OutboundOut;

    fn to_outbound_out(item: DatagramPacket, target: SocketAddr) -> Self::OutboundOut;

    fn to_inbound_in(item: Self::OutboundIn, target: &Address, sender: SocketAddr) -> (DatagramPacket, SocketAddr);

    async fn new_binding<Out>(
        server_addr: SocketAddr,
        client_local: ClientLocalSender<Self::Key>,
        msg: (DatagramPacket, SocketAddr),
        key: Self::Key,
        out: Out,
    ) -> Result<(SplitSink<Out, Self::OutboundOut>, JoinHandle<()>)>
    where
        Out: Sink<Self::OutboundOut, Error = anyhow::Error> + Stream<Item = Result<Self::OutboundIn, anyhow::Error>> + Send + 'static,
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
                            .send((Self::to_inbound_in(outbound_recv, &_target, sender), key.clone()))
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
        client_server.send(Self::to_outbound_out((content, target), server_addr)).await?;
        Ok((client_server, relay_task))
    }

    async fn transfer_udp<NewOutbound, Outbound>(inbound: UdpSocket, config: ServerConfig, new_outbound: NewOutbound) -> Result<()>
    where
        NewOutbound: AsyncFn(&Address, &<Self as UdpOutboundContext>::Context) -> Result<Outbound, anyhow::Error> + Copy,
        Outbound: Sink<Self::OutboundOut, Error = anyhow::Error> + Stream<Item = Result<Self::OutboundIn, anyhow::Error>> + Unpin + Send + 'static,
    {
        use std::net::ToSocketAddrs;

        let server_addr = format!("{}:{}", config.host, config.port).to_socket_addrs()?.next().ok_or(anyhow!("server address is not available"))?;
        let context = <Self as UdpOutboundContext>::new_context(&config)?;
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
                Some(Ok(((content, mut target), sender))) = local_client.next() => {
                    if let Some(ip) = Self::lookup(&target, &config).await {
                        target = Address::Socket(SocketAddr::new(ip, target.get_port()));
                    }
                    let key = Self::new_key(sender, &target);
                    let _key = key.clone();
                    match client_server_cache.entry(key) {
                        Entry::Vacant(entry) => {
                            debug!("[udp] new binding; key={:?}", &_key);
                            let out = new_outbound(&target, &context).await?;
                            let (sink, relay_task) = <Self as UdpOutbound>::new_binding(server_addr, client_local_tx.clone(), ((content, target), sender), _key, out,).await?;
                            entry.insert(Binding {sink, relay_task});
                        }
                        Entry::Occupied(entry) => {
                            // client->server|outbound
                            let value = entry.into_mut();
                            if value.relay_task.is_finished() {
                                debug!("[udp] retry binding; key={:?}", &_key);
                                let out = new_outbound(&target, &context).await?;
                                let (sink, relay_task) = <Self as UdpOutbound>::new_binding(server_addr, client_local_tx.clone(), ((content, target), sender), _key, out).await?;
                                value.sink = sink;
                                value.relay_task = relay_task;
                            } else {
                                value.sink.send(<Self as UdpOutbound>::to_outbound_out((content, target), server_addr)).await?;
                            }
                        }
                    }
                }
                else => break,
            }
        }
        Ok(())
    }
}

pub(crate) trait UdpDnsContext {
    type Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Unpin + Send + 'static;
    type Context;

    fn new_context(config: &ServerConfig) -> Result<Self::Context>;

    fn new_codec(target: &Address, context: Self::Context) -> Result<Self::Codec>;

    async fn lookup(target: &Address, config: &ServerConfig) -> Option<IpAddr> {
        if let (Some(dns_config), Err(_)) = (&config.dns, IpAddr::from_str(&target.get_host())) {
            let context = Self::new_context(config).expect("[dns] new context failed");
            TcpOutbound::new(config)
                .lookup(&config.host, config.port, target, context, &mut Self::new_codec, dns_config)
                .await
                .map(Some)
                .unwrap_or_else(|e| {
                    error!("[dns] lookup failed for target={:?}; error={}", target, e);
                    None
                })
        } else {
            None
        }
    }
}

type ClientLocalSender<T> = Sender<((DatagramPacket, SocketAddr), T)>;

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

pub async fn new_quic_outbound<C, E, D>(host: &str, port: u16, codec: C, ssl_config: &SslConfig) -> Result<Framed<QuicStream, C>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let mut tls_config = rustls_client_config(ssl_config)?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut endpoint = quinn::Endpoint::client(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    let quic_client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    endpoint.set_default_client_config(quic_client_config);
    let server_name = if let Some(server_name) = &ssl_config.server_name { server_name } else { &host.to_owned() };
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

pub async fn new_ws_outbound<C, E, D>(host: &str, port: u16, codec: C, ws_config: &WebSocketConfig) -> Result<Framed<WebSocketStream<TcpStream>, C>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = TcpStream::connect((host, port)).await?;
    let (outbound, _) = new_ws_builder(host, port, ws_config)?.connect_on(outbound).await.map_err(|e| anyhow!(e))?;
    let outbound = WebSocketStream::new(outbound);
    Ok(Framed::new(outbound, codec))
}

pub async fn new_wss_outbound<C, D, E>(
    host: &str,
    port: u16,
    codec: C,
    ssl_config: &SslConfig,
    ws_config: &WebSocketConfig,
) -> Result<Framed<WebSocketStream<TlsStream<TcpStream>>, C>>
where
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    let outbound = rustls_stream(host, port, ssl_config).await?;
    let (outbound, _) = new_ws_builder(host, port, ws_config)?.connect_on(outbound).await.map_err(|e| anyhow!(e))?;
    let outbound = WebSocketStream::new(outbound);
    Ok(Framed::new(outbound, codec))
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

pub fn rustls_client_config(ssl_config: &SslConfig) -> Result<ClientConfig> {
    let config = if let Some(certificate_file) = &ssl_config.certificate_file {
        let mut roots = RootCertStore::empty();
        let cert = CertificateDer::from_pem_file(certificate_file)?;
        roots.add(cert)?;
        ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
    } else {
        ClientConfig::with_platform_verifier()?
    };
    #[cfg(debug_assertions)]
    {
        use quinn::rustls::KeyLogFile;
        let mut config = config;
        config.key_log = Arc::new(KeyLogFile::new());
        Ok(config)
    }
    #[cfg(not(debug_assertions))]
    Ok(config)
}
