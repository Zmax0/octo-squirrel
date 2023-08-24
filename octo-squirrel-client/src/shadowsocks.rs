use std::error::Error;

use futures::SinkExt;
use octo_squirrel::common::codec::shadowsocks::{AEADCipherCodec, AddressCodec};
use octo_squirrel::common::protocol::socks5::message::Socks5CommandRequest;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Encoder, FramedRead, FramedWrite};

pub(crate) async fn transfer_tcp(
    mut inbound: TcpStream,
    proxy_addr: String,
    request: Socks5CommandRequest,
    config: ServerConfig,
) -> Result<(), Box<dyn Error>> {
    let mut outbound = TcpStream::connect(proxy_addr).await?;

    let (ri, wi) = inbound.split();
    let (ro, wo) = outbound.split();

    let client_to_server = async {
        let mut rif = FramedRead::new(ri, BytesCodec::new());
        AddressCodec.encode(request, rif.read_buffer_mut())?;
        let mut wof = FramedWrite::new(wo, AEADCipherCodec::new(config.cipher, config.password.as_bytes(), config.networks[0]));
        while let Some(Ok(item)) = rif.next().await {
            wof.send(item).await?
        }
        wof.into_inner().shutdown().await
    };

    let server_to_client = async {
        let mut rof = FramedRead::new(ro, AEADCipherCodec::new(config.cipher, config.password.as_bytes(), config.networks[0]));
        let mut wif = FramedWrite::new(wi, BytesCodec::new());
        while let Some(Ok(item)) = rof.next().await {
            wif.send(item).await?
        }
        wif.into_inner().shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}
