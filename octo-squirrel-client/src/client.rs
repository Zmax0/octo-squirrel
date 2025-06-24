use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use config::ServerConfig;
use log::error;
use log::info;
use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::protocol::Protocol::*;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

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

async fn transfer_tcp(listener: TcpListener, current: ServerConfig) {
    match current.protocol {
        Shadowsocks => match current.cipher {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                template::transfer_tcp(
                    listener,
                    current,
                    |c| shadowsocks::tcp::ClientContext::<16>::try_from(c),
                    shadowsocks::tcp::new_payload_codec::<16>,
                )
                .await
            }
            CipherKind::Aes256Gcm
            | CipherKind::Aead2022Blake3Aes256Gcm
            | CipherKind::ChaCha20Poly1305
            | CipherKind::Aead2022Blake3ChaCha8Poly1305
            | CipherKind::Aead2022Blake3ChaCha20Poly1305 => {
                template::transfer_tcp(
                    listener,
                    current,
                    |c| shadowsocks::tcp::ClientContext::<32>::try_from(c),
                    shadowsocks::tcp::new_payload_codec::<32>,
                )
                .await
            }
            CipherKind::Unknown => error!("unknown cipher kind"),
        },
        VMess => {
            let opt_mask = current.ext.as_ref().and_then(|e| e.opt_mask);
            template::transfer_tcp(listener, current, move |c| Ok((c.cipher, c.password.clone(), opt_mask)), vmess::tcp::new_codec).await
        }
        Trojan => template::transfer_tcp(listener, current, |c| Ok(c.password.clone()), trojan::tcp::new_codec).await,
    }
}

async fn transfer_udp(socket: UdpSocket, current: ServerConfig) {
    match (current.protocol, &current.ssl, &current.ws, &current.quic) {
        (Shadowsocks, _, _, _) => match current.cipher {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                template::transfer_udp(
                    socket,
                    current,
                    shadowsocks::udp::Client::new_static,
                    shadowsocks::udp::new_key,
                    shadowsocks::udp::new_plain_outbound::<16>,
                    shadowsocks::udp::to_inbound_recv,
                    shadowsocks::udp::to_outbound_send,
                )
                .await
            }
            CipherKind::Aes256Gcm
            | CipherKind::Aead2022Blake3Aes256Gcm
            | CipherKind::ChaCha20Poly1305
            | CipherKind::Aead2022Blake3ChaCha8Poly1305
            | CipherKind::Aead2022Blake3ChaCha20Poly1305 => {
                template::transfer_udp(
                    socket,
                    current,
                    shadowsocks::udp::Client::new_static,
                    shadowsocks::udp::new_key,
                    shadowsocks::udp::new_plain_outbound::<32>,
                    shadowsocks::udp::to_inbound_recv,
                    shadowsocks::udp::to_outbound_send,
                )
                .await
            }
            CipherKind::Unknown => {
                error!("unknown cipher kind");
                Ok(())
            }
        },
        (VMess, None, None, None) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                vmess::udp::new_key,
                vmess::udp::new_plain_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await
        }
        (VMess, _, _, Some(_)) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                vmess::udp::new_key,
                vmess::udp::new_quic_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await
        }
        (VMess, None, Some(_), None) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                vmess::udp::new_key,
                vmess::udp::new_ws_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await
        }
        (VMess, Some(_), None, None) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                vmess::udp::new_key,
                vmess::udp::new_tls_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await
        }
        (VMess, Some(_), Some(_), None) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                vmess::udp::new_key,
                vmess::udp::new_wss_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await
        }
        (Trojan, _, _, Some(_)) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                trojan::udp::new_key,
                trojan::udp::new_quic_outbound,
                trojan::udp::to_inbound_recv,
                trojan::udp::to_outbound_send,
            )
            .await
        }
        (Trojan, _, None, None) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                trojan::udp::new_key,
                trojan::udp::new_tls_outbound,
                trojan::udp::to_inbound_recv,
                trojan::udp::to_outbound_send,
            )
            .await
        }
        (Trojan, _, Some(_), None) => {
            template::transfer_udp(
                socket,
                current,
                Ok,
                trojan::udp::new_key,
                trojan::udp::new_wss_outbound,
                trojan::udp::to_inbound_recv,
                trojan::udp::to_outbound_send,
            )
            .await
        }
    }
    .unwrap_or_else(|e| error!("[udp] transfer failed; error={}", e));
}
