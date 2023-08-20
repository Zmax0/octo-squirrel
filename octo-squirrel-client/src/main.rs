use std::error::Error;

use futures::{FutureExt, SinkExt};
use log::{error, info};
use octo_squirrel::{common::{codec::shadowsocks::{AEADCipherCodec, AddressCodec}, protocol::socks5::{handshake::ServerHandShake, message::{Socks5CommandRequest, Socks5CommandResponse}, DOMAIN, SUCCESS}}, config::ServerConfig};
use tokio::net::TcpListener;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Encoder, FramedRead, FramedWrite};

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
        info!("Accept inbound; addr={}", addr);
        let response = Socks5CommandResponse::new(SUCCESS, DOMAIN, "localhost".to_owned(), 1089);
        let handshake = ServerHandShake::no_auth(&mut inbound, response).await;
        if let Ok(request) = handshake {
            let transfer = transfer_tcp(inbound, proxy_addr.to_owned(), request, current.clone()).map(|r| {
                if let Err(e) = r {
                    error!("Failed to transfer; error={}", e);
                }
            });
            tokio::spawn(transfer);
        } else {
            error!("Failed to handshake; error={}", handshake.unwrap_err());
            inbound.shutdown().await?;
        }
    }
    Ok(())
}

fn new_cipher_codec(config: &ServerConfig) -> AEADCipherCodec {
    AEADCipherCodec::new(config.cipher, config.password.as_bytes(), config.networks[0])
}

async fn transfer_tcp(mut inbound: TcpStream, proxy_addr: String, request: Socks5CommandRequest, config: ServerConfig) -> Result<(), Box<dyn Error>> {
    let mut outbound = TcpStream::connect(proxy_addr).await?;

    let (ri, wi) = inbound.split();
    let (ro, wo) = outbound.split();

    let client_to_server = async {
        let mut rif = FramedRead::new(ri, BytesCodec::new());
        AddressCodec.encode(request, rif.read_buffer_mut())?;
        let mut wof = FramedWrite::new(wo, new_cipher_codec(&config));
        while let Some(Ok(item)) = rif.next().await {
            wof.send(item).await?
        }
        wof.into_inner().shutdown().await
    };

    let server_to_client = async {
        let mut rof = FramedRead::new(ro, new_cipher_codec(&config));
        let mut wif = FramedWrite::new(wi, BytesCodec::new());
        while let Some(Ok(item)) = rof.next().await {
            wif.send(item).await?
        }
        wif.into_inner().shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}
