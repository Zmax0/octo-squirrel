use std::fs;

use bytes::BytesMut;
use log::error;
use log::info;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio_native_tls::native_tls;
use tokio_native_tls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_websockets::ServerBuilder;

mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn startup(config: ServerConfig) {
    info!("Startup tcp server => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    match config.protocol {
        Protocols::Shadowsocks => shadowsocks::startup(&config).await,
        Protocols::VMess => startup_tcp(&config, vmess::new_codec).await,
        Protocols::Trojan => startup_tcp(&config, trojan::new_codec).await,
    }
    .unwrap_or_else(|e| error!("Startup {} failed; error={}", config.protocol, e))
}

async fn startup_tcp<NewCodec, Codec>(config: &ServerConfig, new_codec: NewCodec) -> anyhow::Result<()>
where
    NewCodec: FnOnce(&ServerConfig) -> anyhow::Result<Codec> + Copy + Send + Sync + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = template::Message, Error = anyhow::Error> + Send + 'static,
{
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    match (&config.ssl, &config.ws) {
        (None, ws_config) => {
            while let Ok((inbound, _)) = listener.accept().await {
                if ws_config.is_some() {
                    tokio::spawn(accept_websocket(inbound, new_codec(config)?));
                } else {
                    tokio::spawn(template::relay_tcp(inbound, new_codec(config)?));
                }
            }
        }
        (Some(ssl_config), ws_config) => {
            let pem = fs::read(ssl_config.certificate_file.as_str())?;
            let key = fs::read(ssl_config.key_file.as_str())?;
            let identity = native_tls::Identity::from_pkcs8(&pem, &key)?;
            let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
            while let Ok((inbound, _)) = listener.accept().await {
                let tls = tls_acceptor.clone();
                let codec = new_codec(config)?;
                match tls.accept(inbound).await {
                    Ok(inbound) => {
                        if ws_config.is_some() {
                            tokio::spawn(accept_websocket(inbound, new_codec(config)?));
                        } else {
                            tokio::spawn(template::relay_tcp(inbound, codec));
                        }
                    }
                    Err(e) => error!("[tcp] tls handshake failed: {}", e),
                }
            }
        }
    }
    Ok(())
}

async fn accept_websocket<I, C>(inbound: I, codec: C)
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = template::Message, Error = anyhow::Error> + Send + 'static,
{
    match ServerBuilder::new().accept(inbound).await {
        Ok(inbound) => template::relay_websocket(inbound, codec).await,
        Err(e) => error!("[tcp] websocket handshake failed; error={}", e),
    }
}
