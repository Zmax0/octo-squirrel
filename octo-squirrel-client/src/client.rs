use log::error;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::Aes256GcmCipher;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

mod handshake;
mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) {
    match current.protocol {
        Protocols::Shadowsocks => match current.cipher {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                template::transfer_tcp(listener, current, shadowsocks::tcp::new_payload_codec::<16, Aes128GcmCipher>).await
            }
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
                template::transfer_tcp(listener, current, shadowsocks::tcp::new_payload_codec::<32, Aes256GcmCipher>).await
            }
            _ => unreachable!(),
        },
        Protocols::VMess => template::transfer_tcp(listener, current, vmess::tcp::new_codec).await,
        Protocols::Trojan => template::transfer_tcp(listener, current, trojan::tcp::new_codec).await,
    }
}

pub async fn transfer_udp(socket: UdpSocket, current: ServerConfig) {
    match current.protocol {
        Protocols::Shadowsocks => match current.cipher {
            CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                template::transfer_udp(
                    socket,
                    &current,
                    shadowsocks::udp::new_key,
                    shadowsocks::udp::new_outbound::<16, Aes128GcmCipher>,
                    shadowsocks::udp::to_inbound_recv,
                    shadowsocks::udp::to_outbound_send,
                )
                .await
            }
            CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
                template::transfer_udp(
                    socket,
                    &current,
                    shadowsocks::udp::new_key,
                    shadowsocks::udp::new_outbound::<32, Aes256GcmCipher>,
                    shadowsocks::udp::to_inbound_recv,
                    shadowsocks::udp::to_outbound_send,
                )
                .await
            }
            _ => unreachable!(),
        },
        Protocols::VMess => {
            template::transfer_udp(
                socket,
                &current,
                vmess::udp::new_key,
                vmess::udp::new_outbound,
                vmess::udp::to_inbound_recv,
                vmess::udp::to_outbound_send,
            )
            .await
        }
        Protocols::Trojan => match &current.ssl {
            Some(_) => {
                template::transfer_udp(
                    socket,
                    &current,
                    trojan::udp::new_key,
                    trojan::udp::new_tls_outbound,
                    trojan::udp::to_inbound_recv,
                    trojan::udp::to_outbound_send,
                )
                .await
            }
            None => {
                template::transfer_udp(
                    socket,
                    &current,
                    trojan::udp::new_key,
                    trojan::udp::new_outbound,
                    trojan::udp::to_inbound_recv,
                    trojan::udp::to_outbound_send,
                )
                .await
            }
        },
    }
    .unwrap_or_else(|e| error!("[udp] transfer failed; error={}", e));
}
