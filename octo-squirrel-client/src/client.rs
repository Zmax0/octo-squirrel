use std::sync::Arc;

use bytes::Bytes;
use log::error;
use octo_squirrel::codec::aead::CipherKind;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::protocol::Protocol::*;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

mod handshake;
mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) {
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
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
                template::transfer_tcp(
                    listener,
                    current,
                    |c| shadowsocks::tcp::ClientContext::<32>::try_from(c),
                    shadowsocks::tcp::new_payload_codec::<32>,
                )
                .await
            }
            _ => unreachable!(),
        },
        VMess => template::transfer_tcp(listener, current, |c| Ok((c.cipher, Arc::new(c.password.clone()))), vmess::tcp::new_codec).await,
        Trojan => template::transfer_tcp(listener, current, |c| Ok(Bytes::from(c.password.clone())), trojan::tcp::new_codec).await,
    }
}

pub async fn transfer_udp(socket: UdpSocket, current: ServerConfig) {
    match (current.protocol, &current.ssl, &current.ws) {
        (Shadowsocks, _, _) => match current.cipher {
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
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
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
            _ => unreachable!(),
        },
        (VMess, None, None) => {
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
        (VMess, None, Some(_)) => {
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
        (VMess, Some(_), None) => {
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
        (VMess, Some(_), Some(_)) => {
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
        (Trojan, _, None) => {
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
        (Trojan, _, Some(_)) => {
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
