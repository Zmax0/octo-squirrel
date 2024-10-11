use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use log::info;
use octo_squirrel::network::Transport;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

mod client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = octo_squirrel::config::init_client()?;
    let current = config.get_current().expect("Empty proxy server.");
    octo_squirrel::log::init(config.logger.level())?;
    let listen_addr: SocketAddrV4 = match config.host.as_ref() {
        Some(host) => format!("{}:{}", host, config.port).parse()?,
        None => SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port),
    };
    if current.transport.contains(&Transport::UDP) {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Listening UDP on: {}", socket.local_addr()?);
        tokio::spawn(client::transfer_udp(socket, current.clone()));
    }
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Listening TCP on: {}", listener.local_addr()?);
    client::transfer_tcp(listener, current).await;
    Ok(())
}
