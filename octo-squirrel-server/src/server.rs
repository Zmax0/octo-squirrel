use std::fs;

use log::error;
use log::info;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::protocol::Protocol;
use tokio::net::TcpListener;
use tokio_native_tls::native_tls;
use tokio_native_tls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn startup(config: ServerConfig) {
    match config.protocol {
        Protocol::Shadowsocks => shadowsocks::startup(&config).await,
        Protocol::VMess => startup_tcp(&config, &config, vmess::new_codec).await,
        Protocol::Trojan => startup_tcp(&config, &config, trojan::new_codec).await,
    }
    .unwrap_or_else(|e| error!("Startup {} failed; error={}", config.protocol, e))
}

async fn startup_tcp<Context, NewCodec, Codec>(context: Context, config: &ServerConfig, new_codec: NewCodec) -> anyhow::Result<()>
where
    Context: Clone,
    NewCodec: FnOnce(Context) -> anyhow::Result<Codec> + Copy + Send + Sync + 'static,
    Codec: Encoder<template::message::Inbound, Error = anyhow::Error>
        + Decoder<Item = template::message::Outbound, Error = anyhow::Error>
        + Unpin
        + Send
        + 'static,
{
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    match (&config.ssl, &config.ws) {
        (None, ws_config) => {
            while let Ok((inbound, _)) = listener.accept().await {
                if ws_config.is_some() {
                    tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, new_codec(context.clone())?));
                } else {
                    tokio::spawn(template::tcp::relay(inbound, new_codec(context.clone())?));
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
                let codec = new_codec(context.clone())?;
                match tls.accept(inbound).await {
                    Ok(inbound) => {
                        if ws_config.is_some() {
                            tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, new_codec(context.clone())?));
                        } else {
                            tokio::spawn(template::tcp::relay(inbound, codec));
                        }
                    }
                    Err(e) => error!("[tcp] tls handshake failed: {}", e),
                }
            }
        }
    }
    info!("Tcp server running => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    Ok(())
}
