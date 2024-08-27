use std::fs;

use bytes::BytesMut;
use log::error;
use log::info;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpListener;
use tokio_native_tls::native_tls;
use tokio_native_tls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

mod shadowsocks;
mod template;
mod trojan;

pub async fn startup(config: ServerConfig) {
    info!("Startup tcp server => {}|{:?}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    match config.protocol {
        Protocols::Shadowsocks => shadowsocks::startup_tcp(&config).await,
        Protocols::VMess => Ok(()),
        Protocols::Trojan => startup_tcp(&config, trojan::new_codec).await,
    }
    .unwrap_or_else(|e| {
        error!("Startup failed; error={}", e);
    })
}

async fn startup_tcp<NewCodec, Codec>(config: &ServerConfig, new_codec: NewCodec) -> anyhow::Result<()>
where
    NewCodec: FnOnce(&ServerConfig) -> Codec + Copy + Send + Sync + 'static,
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = template::Message, Error = anyhow::Error> + Send + 'static,
{
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    if let Some(ssl_config) = &config.ssl {
        let pem = fs::read(ssl_config.certificate_file.as_str())?;
        let key = fs::read(ssl_config.key_file.as_str())?;
        let identity = native_tls::Identity::from_pkcs8(&pem, &key)?;
        let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);
        while let Ok((inbound, _)) = listener.accept().await {
            let tls = tls_acceptor.clone();
            let codec = new_codec(config);
            tokio::spawn(async move {
                match tls.accept(inbound).await {
                    Ok(inbound) => {
                        template::relay_tcp(inbound, codec).await;
                    }
                    Err(e) => {
                        error!("[tcp] tls handshake failed: {}", e);
                    }
                }
            });
        }
    } else {
        while let Ok((inbound, _)) = listener.accept().await {
            tokio::spawn(template::relay_tcp(inbound, new_codec(config)));
        }
    }
    Ok(())
}
