use std::fmt::Debug;
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
use futures::lock::Mutex;
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
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::time;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

pub async fn transfer_tcp<NewCodec, Codec>(listener: TcpListener, config: &ServerConfig, new_codec: NewCodec) -> Result<()>
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
            info!("[tcp] accept inbound: src={}, dest={}, protocol={}", src, request_str, config.protocol);
            let outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
            tokio::spawn(relay_tcp(inbound, outbound, new_codec(request.into(), config)));
        } else {
            error!("[tcp] failed to handshake; error={}", handshake.unwrap_err());
            inbound.shutdown().await?;
        }
    }
    Ok(())
}

async fn relay_tcp<Codec>(inbound: TcpStream, outbound: TcpStream, codec: Codec) -> Result<(), anyhow::Error>
where
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error>,
{
    use octo_squirrel::common::codec::BytesCodec;
    let (mut inbound_sink, mut inbound_stream) = Framed::new(inbound, BytesCodec).split::<BytesMut>();
    let (mut outbound_sink, mut outbound_stream) = codec.framed(outbound).split();
    let client_to_server = async { inbound_sink.send_all(&mut outbound_stream).await };
    let server_to_client = async { outbound_sink.send_all(&mut inbound_stream).await };
    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

pub trait AsyncOutbound<Config, Sink, Stream, Item>: FnOnce(Address, Config) -> <Self as AsyncOutbound<Config, Sink, Stream, Item>>::Future {
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

pub async fn transfer_udp<OutboundSink, OutboundStream, Key, NewKey, NewOutbound, ToOutboundSend, OutboundSend, OutboundRecv, ToInboundRecv>(
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
    let (inbound_sink, mut inbound_stream) = UdpFramed::new(inbound, Socks5UdpCodec).split();
    let outbound_map: Arc<DashMap<Key, SplitSink<OutboundSink, OutboundSend>>> = Arc::new(DashMap::new());
    let inbound_sink: Arc<Mutex<SplitSink<UdpFramed<Socks5UdpCodec>, ((BytesMut, SocketAddr), SocketAddr)>>> = Arc::new(Mutex::new(inbound_sink));
    while let Some(Ok((inbound_recv, sender))) = inbound_stream.next().await {
        let key = new_key(sender, inbound_recv.1);
        if let Vacant(entry) = outbound_map.entry(key) {
            debug!("[udp] new binding; key={:?}", key);
            let (outbound_sink, mut outbound_stream) = new_outbound(inbound_recv.1.into(), &config).await?;
            entry.insert(outbound_sink);
            let _binding = outbound_map.clone();
            tokio::spawn(async move {
                time::sleep(Duration::from_secs(600)).await;
                if let Some(_) = _binding.remove(&key) {
                    debug!("[udp] remove binding; key={:?}", key);
                }
            });
            let _inbound_sink = inbound_sink.clone();
            tokio::spawn(async move {
                while let Some(Ok(outbound_recv)) = outbound_stream.next().await {
                    _inbound_sink.lock().await.send(to_inbound_recv(outbound_recv, inbound_recv.1, sender)).await.unwrap();
                }
            });
        }
        let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
        outbound_map.get_mut(&key).unwrap().send(to_outbound_send((inbound_recv, sender), proxy)).await?;
    }
    Ok(())
}
