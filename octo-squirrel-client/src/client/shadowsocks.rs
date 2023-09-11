use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;

use bytes::BytesMut;
use dashmap::mapref::entry::Entry::Vacant;
use dashmap::DashMap;
use futures::lock::Mutex;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::info;
use octo_squirrel::common::codec::shadowsocks::{AEADCipherCodec, AddressCodec, DatagramPacketCodec};
use octo_squirrel::common::protocol::network::Network;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandRequest;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::codec::{BytesCodec, Encoder, FramedRead, FramedWrite};
use tokio_util::udp::UdpFramed;

pub async fn transfer_tcp(mut inbound: TcpStream, request: Socks5CommandRequest, config: ServerConfig) -> Result<(), Box<dyn Error>> {
    let mut outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;

    let (ri, wi) = inbound.split();
    let (ro, wo) = outbound.split();

    let client_to_server = async {
        let mut rif = FramedRead::new(ri, BytesCodec::new());
        AddressCodec.encode(request, rif.read_buffer_mut())?;
        let mut wof = FramedWrite::new(wo, AEADCipherCodec::new(config.cipher, config.password.as_bytes(), Network::TCP));
        while let Some(Ok(item)) = rif.next().await {
            wof.send(item).await?
        }
        wof.into_inner().shutdown().await
    };

    let server_to_client = async {
        let mut rof = FramedRead::new(ro, AEADCipherCodec::new(config.cipher, config.password.as_bytes(), Network::TCP));
        let mut wif = FramedWrite::new(wi, BytesCodec::new());
        while let Some(Ok(item)) = rof.next().await {
            wif.send(item).await?
        }
        wif.into_inner().shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

pub async fn transfer_udp(inbound: UdpSocket, config: ServerConfig) -> Result<(), Box<dyn Error>> {
    let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
    let binding: Arc<DashMap<SocketAddr, SplitSink<UdpFramed<DatagramPacketCodec>, ((BytesMut, SocketAddr), SocketAddr)>>> = Arc::new(DashMap::new());
    let (inbound_sink, mut inbound_stream) = UdpFramed::new(inbound, Socks5UdpCodec).split();
    let inbound_sink = Arc::new(Mutex::new(inbound_sink));
    while let Some(Ok((msg, sender))) = inbound_stream.next().await {
        if let Vacant(entry) = binding.entry(sender) {
            let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
            info!("New binding; sender={}, outbound={}", sender, outbound.local_addr()?);
            let outbound =
                UdpFramed::new(outbound, DatagramPacketCodec::new(AEADCipherCodec::new(config.cipher, config.password.as_bytes(), Network::UDP)));
            let (outbound_sink, mut outbound_stream) = outbound.split();
            entry.insert(outbound_sink);
            let _binding = binding.clone();
            let _sink = inbound_sink.clone();
            let server_to_client = async move {
                while let Some(Ok(item)) = outbound_stream.next().await {
                    if _binding.contains_key(&sender) {
                        _sink.lock().await.send((item.0, sender)).await?;
                    } else {
                        break;
                    }
                }
                Ok::<(), io::Error>(())
            };
            tokio::spawn(server_to_client);
        };
        info!("Accept udp pocket; sender={}, recipient={}, server={}", sender, msg.1, proxy);
        binding.get_mut(&sender).unwrap().send((msg, proxy)).await?
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;

    use dashmap::DashMap;
    use hierarchical_hash_wheel_timer::thread_timer::TimerWithThread;
    use hierarchical_hash_wheel_timer::ClosureTimer;
    use log::info;
    use tokio::net::UdpSocket;

    #[test]
    fn test_schedule() {
        octo_squirrel::log::init().unwrap();
        let timer_core = TimerWithThread::new().unwrap();
        let mut timer = timer_core.timer_ref();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 16803));
        let binding = Arc::new(DashMap::new());
        let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        binding.insert(addr, outbound);
        info!("start; len={}", binding.len());
        let b = binding.clone();
        timer.schedule_action_once(addr, Duration::from_secs(5), move |id| {
            info!("remove");
            b.remove(&id);
        });
        std::thread::sleep(Duration::from_secs(10));
        info!("end; len={}", binding.len());
        timer_core.shutdown().unwrap();
    }
}
