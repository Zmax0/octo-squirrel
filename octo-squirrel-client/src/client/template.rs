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
use futures::FutureExt;
use futures::SinkExt;
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
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time;
use tokio_util::udp::UdpFramed;

pub trait AsyncUdpOutbound<T>: FnMut(T, SocketAddr, SocketAddr, Sender<(DatagramPacket, SocketAddr)>) -> <Self as AsyncUdpOutbound<T>>::Fut {
    type Fut: Future<Output = <Self as AsyncUdpOutbound<T>>::Output>;
    type Output;
}

impl<T, F, Fut> AsyncUdpOutbound<T> for F
where
    F: FnMut(T, SocketAddr, SocketAddr, Sender<(DatagramPacket, SocketAddr)>) -> Fut,
    Fut: Future,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

pub async fn transfer_udp<Key, FnKey, FnOutbound>(socket: UdpSocket, config: ServerConfig, f_key: FnKey, mut f_outbound: FnOutbound) -> Result<()>
where
    Key: Copy + Eq + Hash + Send + Sync + 'static,
    FnKey: FnOnce(SocketAddr, SocketAddr) -> Key + Copy,
    FnOutbound: for<'a> AsyncUdpOutbound<&'a ServerConfig, Output = Result<Sender<(DatagramPacket, SocketAddr)>>>,
{
    let inbound = UdpFramed::new(socket, Socks5UdpCodec);
    let (mut sink, mut stream) = inbound.split();
    let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
    let binding: Arc<DashMap<Key, Sender<(DatagramPacket, SocketAddr)>>> = Arc::new(DashMap::new());
    let (inbound_sink_sender, mut inbound_sink_receiver) = mpsc::channel::<((BytesMut, SocketAddr), SocketAddr)>(32);
    tokio::spawn(async move {
        while let Some(msg) = inbound_sink_receiver.recv().await {
            sink.send(msg).await.unwrap();
        }
    });
    while let Some(Ok((msg, sender))) = stream.next().await {
        let key = f_key(sender, msg.1);
        if let Vacant(entry) = binding.entry(key) {
            entry.insert(f_outbound(&config, sender, msg.1, inbound_sink_sender.clone()).await?);
            let _binding = binding.clone();
            tokio::spawn(async move {
                time::sleep(Duration::from_secs(60)).await;
                if let Some(_) = _binding.remove(&key) {
                    debug!("Remove udp binding; sender={:?}", sender);
                }
            });
        }
        binding.get_mut(&key).unwrap().send((msg, proxy)).await.unwrap()
    }
    Ok(())
}

pub async fn transfer_tcp<Fn, Fut>(listener: TcpListener, current: &ServerConfig, mut f: Fn) -> Result<()>
where
    Fn: FnMut(TcpStream, Address, ServerConfig) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    while let Ok((mut inbound, _)) = listener.accept().await {
        let local_addr = inbound.local_addr().unwrap();
        let response = Socks5CommandResponse::new(Socks5CommandStatus::Success, local_addr.into());
        let handshake = ServerHandShake::no_auth(&mut inbound, response).await;
        if let Ok(request) = handshake {
            let request_str = request.to_string();
            info!("Accept tcp inbound; dest={}, protocol={}", request_str, current.protocol);
            let transfer = f(inbound, request.into(), current.clone()).map(move |r| {
                if let Err(e) = r {
                    error!("Failed to transfer tcp; request={}; error={}", request_str, e);
                }
            });
            tokio::spawn(transfer);
        } else {
            error!("Failed to handshake; error={}", handshake.unwrap_err());
            inbound.shutdown().await?;
        }
    }
    Ok(())
}
