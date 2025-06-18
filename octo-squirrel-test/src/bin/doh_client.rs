use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use hickory_client::proto::op::Query;
use hickory_client::proto::rr::RecordType;
use hickory_client::proto::xfer::DnsRequestOptions;
use hickory_client::proto::xfer::Protocol;
use hickory_resolver::Name;
use hickory_resolver::caching_client::CachingClient;
use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::name_server::NameServer;
use hickory_resolver::name_server::TokioConnectionProvider;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::KeyLogFile;

#[tokio::main]
async fn main() {
    const NAME: &str = "example.com.";
    const IP_ADDR: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut client_config = ClientConfig::with_platform_verifier().unwrap();
    client_config.key_log = Arc::new(KeyLogFile::new());
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let mut config = NameServerConfig::new((IP_ADDR, 443).into(), Protocol::Https);
    config.tls_dns_name = Some(IP_ADDR.to_string());
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.tls_config = client_config;
    let name_server = NameServer::new(config, resolver_opts, TokioConnectionProvider::default());
    let caching_client = CachingClient::new(100, name_server, false);
    let result = caching_client.lookup(Query::query(Name::from_str(NAME).unwrap(), RecordType::A), DnsRequestOptions::default()).await.unwrap();
    println!("{:?}", result);
}
