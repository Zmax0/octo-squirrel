use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use log::info;
use octo_squirrel::common::network::Transport;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

mod client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = octo_squirrel::config::init()?;
    octo_squirrel::log::init(&config.logger)?;
    let current = config.get_current().expect("Empty proxy server.");
    if current.transport.contains(&Transport::UDP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Listening UDP on: {}", socket.local_addr().unwrap());
        tokio::spawn(client::transfer_udp(socket, current.clone()));
    }
    if current.transport.contains(&Transport::TCP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening TCP on: {}", listener.local_addr().unwrap());
        client::transfer_tcp(listener, current).await?;
    }
    Ok(())
}
