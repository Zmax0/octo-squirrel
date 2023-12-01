use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;

use anyhow::Result;
use futures::SinkExt;
use futures::StreamExt;
use log::debug;
use octo_squirrel::common::codec::shadowsocks::aead::AEADCipherCodec;
use octo_squirrel::common::codec::shadowsocks::aead::ClientCodec;
use octo_squirrel::common::codec::shadowsocks::aead::DatagramPacketCodec;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::network::DatagramPacket;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::shadowsocks::Context;
use octo_squirrel::common::protocol::shadowsocks::StreamType;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time;
use tokio_util::codec::Framed;
use tokio_util::udp::UdpFramed;

pub async fn transfer_tcp(inbound: TcpStream, addr: Address, config: ServerConfig) -> Result<()> {
    let outbound = TcpStream::connect(format!("{}:{}", config.host, config.port)).await?;
    let (mut inbound_sink, mut inbound_stream) = Framed::new(inbound, BytesCodec).split();
    let (mut outbound_sink, mut outbound_stream) = Framed::new(
        outbound,
        ClientCodec::new(Context::tcp(StreamType::Request(addr)), AEADCipherCodec::new(config.cipher, config.password.as_bytes())),
    )
    .split();
    let client_to_server = async { outbound_sink.send_all(&mut inbound_stream).await };
    let server_to_client = async { inbound_sink.send_all(&mut outbound_stream).await };
    tokio::try_join!(client_to_server, server_to_client)?;
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
    let outbound = UdpFramed::new(outbound, DatagramPacketCodec::new(AEADCipherCodec::new(config.cipher, config.password.as_bytes())));
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
