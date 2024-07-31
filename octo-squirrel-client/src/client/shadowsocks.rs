use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;

use anyhow::Result;
use futures::SinkExt;
use futures::StreamExt;
use log::debug;
use octo_squirrel::common::codec::shadowsocks::AEADCipherCodec;
use octo_squirrel::common::codec::shadowsocks::DatagramPacketCodec;
use octo_squirrel::common::codec::shadowsocks::PayloadCodec;
use octo_squirrel::common::network::DatagramPacket;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::shadowsocks::Context;
use octo_squirrel::common::protocol::shadowsocks::StreamType;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time;
use tokio_util::udp::UdpFramed;

use super::template;

pub async fn transfer_tcp(mut inbound: TcpStream, addr: Address, config: ServerConfig) -> Result<()> {
    let mut outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
    let codec = PayloadCodec::new(Context::tcp(StreamType::Request, Some(addr)), AEADCipherCodec::new(config.cipher, config.password.as_bytes())?);
    if let Err(_) = template::relay_tcp(&mut inbound, &mut outbound, codec).await {
        outbound.shutdown().await?
    };
    Ok(())
}

pub fn get_udp_key(sender: SocketAddr, _: SocketAddr) -> SocketAddr {
    sender
}

pub async fn transfer_udp_outbound(
    config: &ServerConfig,
    sender: SocketAddr,
    _: SocketAddr,
    callback: Sender<(DatagramPacket, SocketAddr)>,
) -> Result<Sender<(DatagramPacket, SocketAddr)>> {
    let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let outbound_local_addr = outbound.local_addr()?;
    let outbound = UdpFramed::new(
        outbound,
        DatagramPacketCodec::new(Context::udp(StreamType::Request, None), AEADCipherCodec::new(config.cipher, config.password.as_bytes())?),
    );
    let (tx, mut rx) = mpsc::channel::<(DatagramPacket, SocketAddr)>(32);
    let (mut outbound_sink, mut outbound_stream) = outbound.split();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            outbound_sink.send(msg).await.unwrap()
        }
    });
    tokio::spawn(async move {
        while let Ok(item) = time::timeout(Duration::from_secs(600), outbound_stream.next()).await {
            if let Some(Ok(item)) = item {
                callback.send((item.0, sender)).await.unwrap();
            } else {
                debug!("No item in outbound stream; sender={}, outbound={}", sender, outbound_local_addr);
                break;
            }
        }
        debug!("Outbound stream timeout; sender={}, outbound={}", sender, outbound_local_addr);
        Ok::<(), anyhow::Error>(())
    });
    Ok(tx.clone())
}
