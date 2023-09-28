use std::error::Error;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use futures::FutureExt;
use log::error;
use log::info;
use octo_squirrel::common::protocol::network::Network;
use octo_squirrel::common::protocol::socks5::handshake::ServerHandShake;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandResponse;
use octo_squirrel::common::protocol::socks5::Socks5AddressType;
use octo_squirrel::common::protocol::socks5::Socks5CommandStatus;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

use crate::client::shadowsocks;
use crate::client::template;
use crate::client::vmess;

mod client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) -> Result<(), Box<dyn Error>> {
    while let Ok((mut inbound, _)) = listener.accept().await {
        let local_addr = inbound.local_addr().unwrap();
        let response = Socks5CommandResponse::new(
            Socks5CommandStatus::SUCCESS,
            if local_addr.is_ipv4() { Socks5AddressType::IPV4 } else { Socks5AddressType::IPV6 },
            local_addr.ip().to_string(),
            local_addr.port(),
        );
        let handshake = ServerHandShake::no_auth(&mut inbound, response).await;
        if let Ok(request) = handshake {
            let request_str = request.to_string();
            info!("Accept tcp inbound; dest={}, protocol={}", request_str, current.protocol);
            match current.protocol {
                Protocols::Shadowsocks => {
                    let transfer = shadowsocks::transfer_tcp(inbound, request, current.clone()).map(move |r| {
                        if let Err(e) = r {
                            error!("Failed to transfer tcp; request={}; error={}", request_str, e);
                        }
                    });
                    tokio::spawn(transfer);
                }
                Protocols::VMess => {
                    let transfer = vmess::transfer_tcp(inbound, request, current.clone()).map(move |r| {
                        if let Err(e) = r {
                            error!("Failed to transfer tcp; request={}, error={}", request_str, e);
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

async fn transfer_udp(socket: UdpSocket, current: ServerConfig) -> Result<(), io::Error> {
    match current.protocol {
        Protocols::Shadowsocks => {
            template::transfer_udp(socket, current, shadowsocks::get_udp_key, shadowsocks::transfer_udp_outbound).await?;
        }
        Protocols::VMess => {
            template::transfer_udp(socket, current, vmess::get_udp_key, vmess::transfer_udp_outbound).await?;
        }
    }
    Ok(())
}
