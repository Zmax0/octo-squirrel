use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use anyhow::Result;
use log::info;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::network::Transport;
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
    if current.transport.contains(&Transport::UDP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Listening UDP on: {}", socket.local_addr().unwrap());
        tokio::spawn(transfer_udp(socket, current.clone()));
    }
    if current.transport.contains(&Transport::TCP) {
        let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port);
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening TCP on: {}", listener.local_addr().unwrap());
        transfer_tcp(listener, current).await?;
    }
    Ok(())
}

async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) -> Result<()> {
    match current.protocol {
        Protocols::Shadowsocks => {
            match current.cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                    template::transfer_tcp(listener, current, shadowsocks::tcp::new_payload_codec::<16>).await?
                }
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
                    template::transfer_tcp(listener, current, shadowsocks::tcp::new_payload_codec::<32>).await?
                }
            };
        }
        Protocols::VMess => template::transfer_tcp(listener, current, vmess::tcp::new_client_aead_codec).await?,
        Protocols::Trojan => todo!(),
    }
    Ok(())
}

async fn transfer_udp(socket: UdpSocket, current: ServerConfig) -> Result<()> {
    match current.protocol {
        Protocols::Shadowsocks => {
            match current.cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                    template::transfer_udp(
                        socket,
                        &current,
                        shadowsocks::udp::new_key,
                        shadowsocks::udp::new_outbound::<16>,
                        shadowsocks::udp::to_inbound_recv,
                        shadowsocks::udp::to_outbound_send,
                    )
                    .await?;
                }
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
                    template::transfer_udp(
                        socket,
                        &current,
                        shadowsocks::udp::new_key,
                        shadowsocks::udp::new_outbound::<32>,
                        shadowsocks::udp::to_inbound_recv,
                        shadowsocks::udp::to_outbound_send,
                    )
                    .await?;
                }
            };
        }
        Protocols::VMess => {
            template::transfer_udp(
                socket,
                &current,
                vmess::udp::new_key,
                vmess::udp::new_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await?
        }
        Protocols::Trojan => todo!(),
    }
    Ok(())
}
