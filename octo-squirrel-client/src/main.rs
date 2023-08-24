use std::error::Error;

use futures::FutureExt;
use log::{error, info};
use octo_squirrel::common::protocol::socks5::{handshake::ServerHandShake, message::Socks5CommandResponse, Socks5AddressType, Socks5CommandStatus};
use octo_squirrel::common::protocol::Protocols;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

mod shadowsocks;
mod vmess;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    octo_squirrel::log::init()?;
    let config = octo_squirrel::config::init()?;
    let current = config.get_current().expect("Empty proxy server.");

    let listen_addr = format!("localhost:{}", config.port);
    let proxy_addr = format!("{}:{}", current.host, current.port);

    info!("Listening on: {}", listen_addr);
    info!("Proxying to: {}", proxy_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((mut inbound, addr)) = listener.accept().await {
        info!("Accept inbound; addr={}, protocol={}", addr, current.protocol);
        let response = Socks5CommandResponse::new(Socks5CommandStatus::SUCCESS, Socks5AddressType::DOMAIN, "localhost".to_owned(), 1089);
        let handshake = ServerHandShake::no_auth(&mut inbound, response).await;
        if let Ok(request) = handshake {
            match current.protocol {
                Protocols::Shadowsocks => {
                    let transfer = shadowsocks::transfer_tcp(inbound, proxy_addr.to_owned(), request, current.clone()).map(|r| {
                        if let Err(e) = r {
                            error!("Failed to transfer; error={}", e);
                        }
                    });
                    tokio::spawn(transfer);
                }
                Protocols::VMess => {
                    let transfer = vmess::transfer_tcp(inbound, proxy_addr.to_owned(), request, current.clone()).map(|r| {
                        if let Err(e) = r {
                            error!("Failed to transfer; error={}", e);
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
