use anyhow::Result;
use octo_squirrel::common::codec::aead::Aes128GcmCipher;
use octo_squirrel::common::codec::aead::Aes256GcmCipher;
use octo_squirrel::common::codec::aead::CipherKind;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

pub(super) mod shadowsocks;
pub(super) mod template;
pub(super) mod vmess;

pub(super) async fn transfer_tcp(listener: TcpListener, current: &ServerConfig) -> Result<()> {
    match current.protocol {
        Protocols::Shadowsocks => {
            match current.cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                    template::transfer_tcp(listener, current, shadowsocks::tcp::new_payload_codec::<16, Aes128GcmCipher>).await?
                }
                CipherKind::Aes256Gcm | CipherKind::Aead2022Blake3Aes256Gcm | CipherKind::ChaCha20Poly1305 => {
                    template::transfer_tcp(listener, current, shadowsocks::tcp::new_payload_codec::<32, Aes256GcmCipher>).await?
                }
            };
        }
        Protocols::VMess => template::transfer_tcp(listener, current, vmess::tcp::new_client_aead_codec).await?,
        Protocols::Trojan => todo!(),
    }
    Ok(())
}

pub(super) async fn transfer_udp(socket: UdpSocket, current: ServerConfig) -> Result<()> {
    match current.protocol {
        Protocols::Shadowsocks => {
            match current.cipher {
                CipherKind::Aes128Gcm | CipherKind::Aead2022Blake3Aes128Gcm => {
                    template::transfer_udp(
                        socket,
                        &current,
                        shadowsocks::udp::new_key,
                        shadowsocks::udp::new_outbound::<16, Aes128GcmCipher>,
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
                        shadowsocks::udp::new_outbound::<32, Aes256GcmCipher>,
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
