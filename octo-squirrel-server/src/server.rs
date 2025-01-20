use std::env;
use std::sync::Arc;

use anyhow::anyhow;
use futures::future::join_all;
use log::error;
use log::info;
use octo_squirrel::codec::QuicStream;
use octo_squirrel::config::ServerConfig;
use octo_squirrel::protocol::Protocol;
use quinn::crypto::rustls::QuicServerConfig;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::rustls;
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
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        Protocol::VMess => {
            merge_result(tokio::join!(startup_quic(&config, &config, vmess::new_codec), startup_tcp(&config, &config, vmess::new_codec)))
        }
        Protocol::Trojan => {
            merge_result(tokio::join!(startup_quic(&config, &config, trojan::new_codec), startup_tcp(&config, &config, trojan::new_codec)))
        }
    }
    .unwrap_or_else(|e| error!("Startup {} failed; error={}", config.protocol, e));
}

fn merge_result(res: (anyhow::Result<()>, anyhow::Result<()>)) -> anyhow::Result<()> {
    match res {
        (Ok(_), Ok(_)) => Ok(()),
        (Ok(_), Err(e)) => Err(anyhow!("tcp={e}")),
        (Err(e), Ok(_)) => Err(anyhow!("quic={e}")),
        (Err(e1), Err(e2)) => Err(anyhow!("quic={e1}, tcp={e2}")),
    }
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
            let tls_config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key)?;
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

async fn startup_quic<RefContext, Context, NewCodec, Codec>(context: RefContext, config: &ServerConfig, new_codec: NewCodec) -> anyhow::Result<()>
where
    RefContext: AsRef<Context>,
    NewCodec: FnOnce(&Context) -> anyhow::Result<Codec> + Copy + Send + Sync + 'static,
    Codec: Encoder<template::message::OutboundIn, Error = anyhow::Error>
        + Decoder<Item = template::message::InboundIn, Error = anyhow::Error>
        + Unpin
        + Send
        + 'static,
{
    if let Some(ssl_config) = &config.quic {
        info!("Quic server running => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
        let cert = CertificateDer::from_pem_file(ssl_config.certificate_file.as_str())?;
        let key = PrivateKeyDer::from_pem_file(ssl_config.key_file.as_str())?;
        let mut tls_config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key)?;
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let quic_server_config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
        let addr = format!("{}:{}", config.host, config.port).parse()?;
        let endpoint = quinn::Endpoint::server(quic_server_config, addr)?;
        while let Some(incoming) = endpoint.accept().await {
            let codec = new_codec(context.as_ref())?;
            tokio::spawn(async {
                let connection = incoming.await?;
                let (send, recv) = connection.accept_bi().await?;
                template::quic::relay(QuicStream::new(send, recv), codec).await?;
                Ok::<(), anyhow::Error>(())
            });
        }
        endpoint.wait_idle().await;
    }
    Ok(())
}
