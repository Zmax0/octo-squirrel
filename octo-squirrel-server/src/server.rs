use std::env;
use std::sync::Arc;

use futures::future::join_all;
use log::error;
use log::info;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::protocol::Protocol;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn main() -> anyhow::Result<()> {
    let servers = octo_squirrel::config::init_server()?;
    if let Some(level) = env::args().nth(2) {
        octo_squirrel::log::init(&level)?;
    } else {
        octo_squirrel::log::init("info")?;
    }
    let tasks: Vec<JoinHandle<()>> = servers.into_iter().map(|server| tokio::spawn(async move { startup(server).await })).collect();
    join_all(tasks).await;
    Ok(())
}

async fn startup(config: ServerConfig) {
    match config.protocol {
        Protocol::Shadowsocks => shadowsocks::startup(&config).await,
        Protocol::VMess => startup_tcp(&config, &config, vmess::new_codec).await,
        Protocol::Trojan => startup_tcp(&config, &config, trojan::new_codec).await,
    }
    .unwrap_or_else(|e| error!("Startup {} failed; error={}", config.protocol, e))
}

async fn startup_tcp<RefContext, Context, NewCodec, Codec>(context: RefContext, config: &ServerConfig, new_codec: NewCodec) -> anyhow::Result<()>
where
    RefContext: AsRef<Context>,
    NewCodec: FnOnce(&Context) -> anyhow::Result<Codec> + Copy + Send + Sync + 'static,
    Codec: Encoder<template::message::OutboundIn, Error = anyhow::Error>
        + Decoder<Item = template::message::InboundIn, Error = anyhow::Error>
        + Unpin
        + Send
        + 'static,
{
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    info!("Tcp server running => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    match (&config.ssl, &config.ws) {
        (None, ws_config) => {
            while let Ok((inbound, _)) = listener.accept().await {
                if ws_config.is_some() {
                    tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, new_codec(context.as_ref())?));
                } else {
                    tokio::spawn(template::tcp::relay(inbound, new_codec(context.as_ref())?));
                }
            }
        }
        (Some(ssl_config), ws_config) => {
            let cert = CertificateDer::from_pem_file(ssl_config.certificate_file.as_str())?;
            let key = PrivateKeyDer::from_pem_file(ssl_config.key_file.as_str())?;
            let tls_config = tokio_rustls::rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key)?;
            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
            while let Ok((inbound, _)) = listener.accept().await {
                let codec = new_codec(context.as_ref())?;
                match tls_acceptor.accept(inbound).await {
                    Ok(inbound) => {
                        if ws_config.is_some() {
                            tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, new_codec(context.as_ref())?));
                        } else {
                            tokio::spawn(template::tcp::relay(inbound, codec));
                        }
                    }
                    Err(e) => error!("[tcp] tls handshake failed: {}", e),
                }
            }
        }
    }
    Ok(())
}
