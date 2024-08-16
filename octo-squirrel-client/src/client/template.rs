use std::fmt::Debug;
use std::fs;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::BytesMut;
use dashmap::mapref::entry::Entry::Vacant;
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use log::debug;
use log::error;
use log::info;
use octo_squirrel::common::network::DatagramPacket;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::common::protocol::socks5::handshake::ServerHandShake;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandResponse;
use octo_squirrel::common::protocol::socks5::Socks5CommandStatus;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Certificate;
use tokio_native_tls::TlsConnector;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

pub(super) async fn transfer_tcp<NewCodec, Codec>(listener: TcpListener, config: &ServerConfig, new_codec: NewCodec) -> Result<()>
where
    NewCodec: FnOnce(Address, &ServerConfig) -> Codec + Copy,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static,
{
    while let Ok((mut inbound, src)) = listener.accept().await {
        let local_addr = inbound.local_addr().unwrap();
        let response = Socks5CommandResponse::new(Socks5CommandStatus::Success, local_addr.into());
        let handshake = ServerHandShake::no_auth(&mut inbound, response).await;
        if let Ok(request) = handshake {
            let request_str = request.to_string();
            let outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
            info!("[tcp] accept {}, dest={}; {}={}", &config.protocol, &request_str, &src, outbound.peer_addr()?);
            if let Some(ssl_config) = &config.ssl {
                let pem = fs::read(ssl_config.certificate_file.as_str())?;
                let cert = Certificate::from_pem(&pem)?;
                let tls_connector = TlsConnector::from(native_tls::TlsConnector::builder().add_root_certificate(cert).use_sni(true).build()?);
                match tls_connector.connect(ssl_config.server_name.as_str(), outbound).await {
                    Ok(outbound) => {
                        tokio::spawn(relay_tcp(inbound, outbound, new_codec(request.into(), config)));
                    }
                    Err(e) => error!("tls handshake failed: {}", e),
                }
            } else {
                tokio::spawn(relay_tcp(inbound, outbound, new_codec(request.into(), config)));
            }
        } else {
            error!("[tcp] failed to handshake; error={}", handshake.unwrap_err());
        }
    }
    Ok(())
}

async fn relay_tcp<I, O, C>(inbound: I, outbound: O, codec: C) -> Result<(), anyhow::Error>
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
        inbound_sink.close().await
    };
    let client_to_server = async {
        while let Some(Ok(next)) = inbound_stream.next().await {
            outbound_sink.send(next).await?;
        }
        outbound_sink.close().await
    };
    tokio::try_join!(client_to_server, server_to_client)?;
    info!("[tcp] relay complete");
    Ok(())
}

pub(super) trait AsyncOutbound<Config, Sink, Stream, Item>:
    FnOnce(Address, Config) -> <Self as AsyncOutbound<Config, Sink, Stream, Item>>::Future
{
    type Future: Future<Output = <Self as AsyncOutbound<Config, Sink, Stream, Item>>::Output>;
    type Output;
}

impl<Config, Sink, Stream, Item, Fn, Res> AsyncOutbound<Config, Sink, Stream, Item> for Fn
where
    Fn: FnOnce(Address, Config) -> Res,
    Res: Future,
{
    type Future = Res;
    type Output = Res::Output;
}

pub(super) async fn transfer_udp<OutboundSink, OutboundStream, Key, NewKey, NewOutbound, ToOutboundSend, OutboundSend, OutboundRecv, ToInboundRecv>(
    inbound: UdpSocket,
    config: &ServerConfig,
    new_key: NewKey,
    new_outbound: NewOutbound,
    to_inbound_recv: ToInboundRecv,
    to_outbound_send: ToOutboundSend,
) -> Result<()>
where
    OutboundSink: Sink<OutboundSend, Error = anyhow::Error> + Sized + Send + 'static,
    OutboundStream: Stream<Item = Result<OutboundRecv, anyhow::Error>> + Send + 'static,
    NewKey: FnOnce(SocketAddr, SocketAddr) -> Key + Copy,
    Key: Hash + Eq + Debug + Copy + Send + Sync + 'static,
    NewOutbound: for<'a> AsyncOutbound<
            &'a ServerConfig,
            OutboundSink,
            OutboundStream,
            OutboundRecv,
            Output = Result<(SplitSink<OutboundSink, OutboundSend>, SplitStream<OutboundStream>), anyhow::Error>,
        > + Copy,
    ToOutboundSend: FnOnce((DatagramPacket, SocketAddr), SocketAddr) -> OutboundSend + Copy,
    OutboundSend: Send + Sync + 'static,
    OutboundRecv: Send + Sync + 'static,
    ToInboundRecv: FnOnce(OutboundRecv, SocketAddr, SocketAddr) -> (DatagramPacket, SocketAddr) + Send + Copy + 'static,
{
    let (mut inbound_sink, mut inbound_stream) = UdpFramed::new(inbound, Socks5UdpCodec).split();
    let outbound_map: Arc<DashMap<Key, SplitSink<OutboundSink, OutboundSend>>> = Arc::new(DashMap::new());
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<(DatagramPacket, SocketAddr)>(32);
    tokio::spawn(async move {
        while let Some(item) = inbound_rx.recv().await {
            inbound_sink.send(item).await.unwrap_or_else(|e| error!("[udp] failed to send inbound msg; {}", e));
        }
    });
    while let Some(Ok((inbound_recv, sender))) = inbound_stream.next().await {
        let key = new_key(sender, inbound_recv.1);
        if let Vacant(entry) = outbound_map.entry(key) {
            debug!("[udp] new binding; key={:?}", key);
            let (outbound_sink, mut outbound_stream) = new_outbound(inbound_recv.1.into(), config).await?;
            entry.insert(outbound_sink);
            let _outbound_map = outbound_map.clone();
            tokio::spawn(async move {
                time::sleep(Duration::from_secs(10)).await;
                if let Some((_, mut outbound_sink)) = _outbound_map.remove(&key) {
                    debug!("[udp] remove binding; key={:?}", key);
                    outbound_sink.close().await.unwrap_or_else(|e| error!("[udp] failed to close outbound; {}", e))
                }
            });
            let _inbound_tx = inbound_tx.clone();
            tokio::spawn(async move {
                while let Some(Ok(outbound_recv)) = outbound_stream.next().await {
                    _inbound_tx
                        .send(to_inbound_recv(outbound_recv, inbound_recv.1, sender))
                        .await
                        .unwrap_or_else(|e| error!("[udp] failed to send inbound mpsc msg; {}", e));
                }
            });
        }
        let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
        outbound_map.get_mut(&key).unwrap().send(to_outbound_send((inbound_recv, sender), proxy)).await?;
    }
    Ok(())
}
