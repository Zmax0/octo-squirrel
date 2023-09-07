use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4};

use futures::FutureExt;
use log::{error, info};
use octo_squirrel::common::protocol::network::Network;
use octo_squirrel::common::protocol::socks5::{handshake::ServerHandShake, message::Socks5CommandResponse, Socks5AddressType, Socks5CommandStatus};
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};

use crate::client::{shadowsocks, vmess};

mod client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    octo_squirrel::log::init()?;
    let config = octo_squirrel::config::init()?;
    let current = config.get_current().expect("Empty proxy server.");
    if current.networks.contains(&Network::UDP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Listening UDP on: {}", socket.local_addr().unwrap());
        proxy_udp(socket, current).unwrap();
    }
    if current.networks.contains(&Network::TCP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening TCP on: {}", listener.local_addr().unwrap());
        transfer_tcp(listener, current).await?;
    }
    Ok(())
}

async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) -> Result<(), Box<dyn Error>> {
    while let Ok((mut inbound, _)) = listener.accept().await {
        let response = Socks5CommandResponse::new(Socks5CommandStatus::SUCCESS, Socks5AddressType::DOMAIN, "localhost".to_owned(), 1089);
        let handshake = ServerHandShake::no_auth(&mut inbound, response).await;
        if let Ok(request) = handshake {
            info!("Accept inbound; dest={}, protocol={}", request, current.protocol);
            match current.protocol {
                Protocols::Shadowsocks => {
                    let transfer = shadowsocks::transfer_tcp(inbound, request, current.clone()).map(|r| {
                        if let Err(e) = r {
                            error!("Failed to transfer tcp; error={}", e);
                        }
                    });
                    tokio::spawn(transfer);
                }
                Protocols::VMess => {
                    let transfer = vmess::transfer_tcp(inbound, request, current.clone()).map(|r| {
                        if let Err(e) = r {
                            error!("Failed to transfer tcp; error={}", e);
                        }
                    });
                    tokio::spawn(transfer);
                }
            }
        } else {
            error!("Failed to handshake; error={}", handshake.unwrap_err());
            inbound.shutdown().await?;
        }
    }
    Ok(())
}

fn proxy_udp(socket: UdpSocket, current: &ServerConfig) -> Result<(), Box<dyn Error>> {
    match current.protocol {
        Protocols::Shadowsocks => {
            let transfer = shadowsocks::transfer_udp(socket, current.clone()).map(|r| {
                if let Err(e) = r {
                    error!("Failed to transfer udp; error={}", e);
                }
            });
            tokio::spawn(transfer);
        }
        Protocols::VMess => {}
    }
    Ok(())
}
