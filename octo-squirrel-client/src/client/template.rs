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
use log::debug;
use octo_squirrel::config::ServerConfig;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::time;

pub trait AsyncFn<T>: FnMut(T, SocketAddr, SocketAddr, Sender<((BytesMut, SocketAddr), SocketAddr)>) -> <Self as AsyncFn<T>>::Fut {
    type Fut: Future<Output = <Self as AsyncFn<T>>::Output>;
    type Output;
}

impl<T, F, Fut> AsyncFn<T> for F
where
    F: FnMut(T, SocketAddr, SocketAddr, Sender<((BytesMut, SocketAddr), SocketAddr)>) -> Fut,
    Fut: Future,
{
    type Fut = Fut;
    type Output = Fut::Output;
}

pub async fn transfer_udp<Key, FnKey, FnOutbound>(
    mut inbound_receiver: Receiver<((BytesMut, SocketAddr), SocketAddr)>, /* client->server */
    inbound_sender: Sender<((BytesMut, SocketAddr), SocketAddr)>,         /* server->client */
    config: ServerConfig,
    fn_key: FnKey,
    mut fn_outbound: FnOutbound,
) -> Result<(), io::Error>
where
    Key: Copy + Eq + Hash + Send + Sync + 'static,
    FnKey: FnOnce(SocketAddr, SocketAddr) -> Key + Copy,
    FnOutbound: for<'a> AsyncFn<&'a ServerConfig, Output = Result<Sender<((BytesMut, SocketAddr), SocketAddr)>, io::Error>>,
{
    let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
    let binding: Arc<DashMap<Key, Sender<((BytesMut, SocketAddr), SocketAddr)>>> = Arc::new(DashMap::new());
    while let Some((msg, sender)) = inbound_receiver.recv().await {
        let key = fn_key(sender, msg.1);
        if let Vacant(entry) = binding.entry(key) {
            entry.insert(fn_outbound(&config, sender, msg.1, inbound_sender.clone()).await?);
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
