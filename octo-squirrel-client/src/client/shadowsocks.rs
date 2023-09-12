use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use dashmap::mapref::entry::Entry::Vacant;
use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{debug, info};
use octo_squirrel::common::codec::shadowsocks::{AEADCipherCodec, AddressCodec, DatagramPacketCodec};
use octo_squirrel::common::protocol::network::Network;
use octo_squirrel::common::protocol::socks5::codec::Socks5UdpCodec;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandRequest;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time;
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

type DatagramPacket = (BytesMut, SocketAddr);

pub async fn transfer_udp(inbound: UdpFramed<Socks5UdpCodec>, config: ServerConfig) -> Result<(), Box<dyn Error>> {
    let proxy = format!("{}:{}", config.host, config.port).to_socket_addrs().unwrap().last().unwrap();
    let binding: Arc<DashMap<SocketAddr, SplitSink<UdpFramed<DatagramPacketCodec>, ((BytesMut, SocketAddr), SocketAddr)>>> = Arc::new(DashMap::new());
    let (mut inbound_sink, mut inbound_stream) = inbound.split();
    let (tx, mut rx) = mpsc::channel::<(DatagramPacket, SocketAddr)>(32);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            inbound_sink.send(msg).await.unwrap();
        }
    });
    while let Some(Ok((msg, sender))) = inbound_stream.next().await {
        if let Vacant(entry) = binding.entry(sender) {
            let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
            let outbound_local_addr = outbound.local_addr()?;
            debug!("New udp binding; sender={}, outbound={}", sender, outbound_local_addr);
            let outbound =
                UdpFramed::new(outbound, DatagramPacketCodec::new(AEADCipherCodec::new(config.cipher, config.password.as_bytes(), Network::UDP)));
            let (outbound_sink, mut outbound_stream) = outbound.split();
            entry.insert(outbound_sink);
            let _binding = binding.clone();
            tokio::spawn(async move {
                time::sleep(Duration::from_secs(60)).await;
                if let Some(mut entry) = _binding.remove(&sender) {
                    entry.1.close().await.expect("Close udp outbound sink failed");
                    debug!("Remove udp binding; sender={}", sender);
                }
            });
            let _binding = binding.clone();
            let _tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(Some(Ok(item))) = time::timeout(Duration::from_secs(600), outbound_stream.next()).await {
                    if _binding.contains_key(&sender) {
                        _tx.send((item.0, sender)).await.unwrap();
                    } else {
                        break;
                    }
                }
                debug!("Outbound udp timeout; sender={}, outbound={}", sender, outbound_local_addr);
                Ok::<(), io::Error>(())
            });
        };
        info!("Accept udp pocket; sender={}, recipient={}, server={}", sender, msg.1, proxy);
        binding.get_mut(&sender).unwrap().send((msg, proxy)).await?
    }
    Ok(())
}
