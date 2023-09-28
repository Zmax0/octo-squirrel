use std::future::Future;
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use dashmap::mapref::entry::Entry::Vacant;
use dashmap::DashMap;
use futures::SinkExt;
use futures::StreamExt;
use log::debug;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::config::ServerConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time;
use tokio_util::udp::UdpFramed;

pub trait AsyncFnMut<T>: FnMut(T, SocketAddr, SocketAddr, Sender<((BytesMut, SocketAddr), SocketAddr)>) -> <Self as AsyncFnMut<T>>::Fut {
    type Fut: Future<Output = <Self as AsyncFnMut<T>>::Output>;
    type Output;
}

impl<T, F, Fut> AsyncFnMut<T> for F
where
    F: FnMut(T, SocketAddr, SocketAddr, Sender<((BytesMut, SocketAddr), SocketAddr)>) -> Fut,
    Fut: Future,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

pub async fn transfer_udp<Key, FnKey, FnOutbound>(
    socket: UdpSocket,
    config: ServerConfig,
    fn_key: FnKey,
    mut fn_outbound: FnOutbound,
) -> Result<(), io::Error>
where
    Key: Copy + Eq + Hash + Send + Sync + 'static,
    FnKey: FnOnce(SocketAddr, SocketAddr) -> Key + Copy,
    FnOutbound: for<'a> AsyncFnMut<&'a ServerConfig, Output = Result<Sender<((BytesMut, SocketAddr), SocketAddr)>, io::Error>>,
{
    let inbound = UdpFramed::new(socket, Socks5UdpCodec);
    let (mut sink, mut stream) = inbound.split();
    let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
    let binding: Arc<DashMap<Key, Sender<((BytesMut, SocketAddr), SocketAddr)>>> = Arc::new(DashMap::new());
    let (inbound_sink_sender, mut inbound_sink_receiver) = mpsc::channel::<((BytesMut, SocketAddr), SocketAddr)>(32);
    tokio::spawn(async move {
        while let Some(msg) = inbound_sink_receiver.recv().await {
            sink.send(msg).await.unwrap();
        }
    });
    while let Some(Ok((msg, sender))) = stream.next().await {
        let key = fn_key(sender, msg.1);
        if let Vacant(entry) = binding.entry(key) {
            entry.insert(fn_outbound(&config, sender, msg.1, inbound_sink_sender.clone()).await?);
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
