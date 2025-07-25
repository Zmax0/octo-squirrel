use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use config::ServerConfig;
use log::error;
use log::info;
use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::protocol::Protocol::*;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

use crate::client::template::TcpOutboundContext;
use crate::client::template::UdpOutbound;

mod config;
mod dns;
mod handshake;
mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn main() -> anyhow::Result<()> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut config = config::init()?;
    let current = config.get_current();
    octo_squirrel::log::init(config.logger.root_level(), config.logger.level())?;
    let listen_addr: SocketAddrV4 = match config.host.as_ref() {
        Some(host) => format!("{}:{}", host, config.port).parse()?,
        None => SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.port),
    };
    if config.mode.enable_udp() {
        let socket = UdpSocket::bind(listen_addr).await?;
        info!("Listening UDP on: {}", socket.local_addr()?);
        tokio::spawn(transfer_udp(socket, current.clone()));
    }
    if config.mode.enable_tcp() {
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening TCP on: {}", listener.local_addr()?);
        transfer_tcp(listener, current).await;
    }
    Ok(())
}

async fn transfer_tcp(listener: TcpListener, config: ServerConfig) {
    match config.protocol {
        Shadowsocks => match config.cipher {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => shadowsocks::Shadowsocks::<16>::transfer_tcp(listener, config).await,
            CipherKind::Aes256Gcm
            | CipherKind::Aead2022Blake3Aes256Gcm
            | CipherKind::ChaCha20Poly1305
            | CipherKind::Aead2022Blake3ChaCha8Poly1305
            | CipherKind::Aead2022Blake3ChaCha20Poly1305 => shadowsocks::Shadowsocks::<32>::transfer_tcp(listener, config).await,
            CipherKind::Unknown => error!("unknown cipher kind"),
        },
        VMess => vmess::Vmess::transfer_tcp(listener, config).await,
        Trojan => trojan::Trojan::transfer_tcp(listener, config).await,
    }
}

async fn transfer_udp(socket: UdpSocket, current: ServerConfig) {
    match (current.protocol, &current.ssl, &current.ws, &current.quic) {
        (Shadowsocks, _, _, _) => match current.cipher {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                shadowsocks::Shadowsocks::<16>::transfer_udp(socket, current, shadowsocks::udp::new_plain_outbound::<16>).await
            }
            CipherKind::Aes256Gcm
            | CipherKind::Aead2022Blake3Aes256Gcm
            | CipherKind::ChaCha20Poly1305
            | CipherKind::Aead2022Blake3ChaCha8Poly1305
            | CipherKind::Aead2022Blake3ChaCha20Poly1305 => {
                shadowsocks::Shadowsocks::<32>::transfer_udp(socket, current, shadowsocks::udp::new_plain_outbound::<32>).await
            }
            CipherKind::Unknown => {
                error!("unknown cipher kind");
                Ok(())
            }
        },
        (VMess, None, None, None) => vmess::Vmess::transfer_udp(socket, current, vmess::udp::new_plain_outbound).await,
        (VMess, _, _, Some(_)) => vmess::Vmess::transfer_udp(socket, current, vmess::udp::new_quic_outbound).await,
        (VMess, None, Some(_), None) => vmess::Vmess::transfer_udp(socket, current, vmess::udp::new_ws_outbound).await,
        (VMess, Some(_), None, None) => vmess::Vmess::transfer_udp(socket, current, vmess::udp::new_tls_outbound).await,
        (VMess, Some(_), Some(_), None) => vmess::Vmess::transfer_udp(socket, current, vmess::udp::new_wss_outbound).await,
        (Trojan, _, _, Some(_)) => trojan::Trojan::transfer_udp(socket, current, trojan::udp::new_quic_outbound).await,
        (Trojan, _, None, None) => trojan::Trojan::transfer_udp(socket, current, trojan::udp::new_tls_outbound).await,
        (Trojan, _, Some(_), None) => trojan::Trojan::transfer_udp(socket, current, trojan::udp::new_wss_outbound).await,
    }
    .unwrap_or_else(|e| error!("[udp] transfer failed; error={}", e));
}
