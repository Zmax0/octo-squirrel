use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use anyhow::Result;

use log::info;
use octo_squirrel::common::network::Network;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

use crate::client::shadowsocks;
use crate::client::template;
use crate::client::vmess;

mod client;

#[tokio::main]
async fn main() -> Result<()> {
    let config = octo_squirrel::config::init()?;
    octo_squirrel::log::init(&config.logger)?;
    let current = config.get_current().expect("Empty proxy server.");
    if current.networks.contains(&Network::UDP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Listening UDP on: {}", socket.local_addr().unwrap());
        tokio::spawn(transfer_udp(socket, current.clone()));
    }
    if current.networks.contains(&Network::TCP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening TCP on: {}", listener.local_addr().unwrap());
        transfer_tcp(listener, current).await?;
    }
    Ok(())
}

async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) -> Result<()> {
    match current.protocol {
        Protocols::Shadowsocks => template::transfer_tcp(listener, current, shadowsocks::transfer_tcp).await?,
        Protocols::VMess => template::transfer_tcp(listener, current, vmess::transfer_tcp).await?,
    }
    Ok(())
}

async fn transfer_udp(socket: UdpSocket, current: ServerConfig) -> Result<()> {
    match current.protocol {
        Protocols::Shadowsocks => template::transfer_udp(socket, current, shadowsocks::get_udp_key, shadowsocks::transfer_udp_outbound).await?,
        Protocols::VMess => template::transfer_udp(socket, current, vmess::get_udp_key, vmess::transfer_udp_outbound).await?,
    }
    Ok(())
}
