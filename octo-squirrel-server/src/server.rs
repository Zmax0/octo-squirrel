use std::fs;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::time::Duration;

use bytes::BytesMut;
use futures::SinkExt;
use futures::StreamExt;
use log::error;
use log::info;
use lru_time_cache::Entry;
use lru_time_cache::LruCache;
use octo_squirrel::common::codec::BytesCodec;
use octo_squirrel::common::codec::DatagramPacket;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::Protocols;
use octo_squirrel::config::ServerConfig;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_native_tls::native_tls;
use tokio_native_tls::TlsAcceptor;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::udp::UdpFramed;

mod shadowsocks;
mod template;
mod trojan;
mod vmess;

pub async fn startup(config: ServerConfig) {
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
    Codec: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = template::Message, Error = anyhow::Error> + Unpin + Send + 'static,
{
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    match (&config.ssl, &config.ws) {
        (None, ws_config) => {
            while let Ok((inbound, _)) = listener.accept().await {
                if ws_config.is_some() {
                    tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, new_codec(config)?));
                } else {
                    tokio::spawn(template::tcp::relay(inbound, new_codec(config)?));
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
                            tokio::spawn(template::tcp::accept_websocket_then_replay(inbound, new_codec(config)?));
                        } else {
                            tokio::spawn(template::tcp::relay(inbound, codec));
                        }
                    }
                    Err(e) => error!("[tcp] tls handshake failed: {}", e),
                }
            }
        }
    }
    info!("Startup tcp server => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    Ok(())
}

async fn startup_udp<C>(config: &ServerConfig, codec: C) -> anyhow::Result<()>
where
    C: Decoder<Item = DatagramPacket, Error = anyhow::Error> + Encoder<DatagramPacket, Error = anyhow::Error> + Send + 'static,
{
    info!("Startup udp server => {}|{}|{}:{}", config.protocol, config.cipher, config.host, config.port);
    let inbound = UdpSocket::bind(format!("{}:{}", config.host, config.port)).await?;
    let inbound = UdpFramed::new(inbound, codec);
    let (mut inbound_sink, mut inbound_stream) = inbound.split();
    let (inbound_sink_tx, mut inbound_sink_rx) = mpsc::channel::<((BytesMut, Address), SocketAddr)>(32);
    tokio::spawn(async move {
        while let Some(item) = inbound_sink_rx.recv().await {
            inbound_sink.send(item).await.unwrap_or_else(|e| error!("[udp] failed to send inbound msg; error={}", e));
        }
    });
    let mut outbound_map = LruCache::with_expiry_duration(Duration::from_secs(600));
    while let Some(next) = inbound_stream.next().await {
        match next {
            Ok(((content, addr), key)) => {
                if let Entry::Vacant(entry) = outbound_map.entry(key) {
                    let outbound = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
                    let (outbound_sink, outbound_stream) = UdpFramed::new(outbound, BytesCodec).split::<(BytesMut, SocketAddr)>();
                    entry.insert(outbound_sink);
                    tokio::spawn(template::udp::relay_outbound(inbound_sink_tx.clone(), outbound_stream, |o| (o.0, Address::Socket(o.1)), key));
                }
                outbound_map.get_mut(&key).unwrap().send((content, addr.to_socket_addr()?)).await?;
            }
            Err(e) => {
                error!("[udp] decode failed; error={e}");
            }
        }
    }
    Ok(())
}
