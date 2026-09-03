use std::future::ready;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use bytes::Bytes;
use bytes::BytesMut;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use h2::client::SendRequest;
use hickory_resolver::caching_client::CachingClient;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::DnsExchange;
use hickory_resolver::net::xfer::DnsRequestSender;
use hickory_resolver::net::xfer::DnsResponseStream;
use hickory_resolver::proto::op::DnsRequest;
use hickory_resolver::proto::op::DnsRequestOptions;
use hickory_resolver::proto::op::DnsResponse;
use hickory_resolver::proto::op::Query;
use http::Method;
use http::Request;
use http::Uri;
use http::Version;
use log::error;
use log::trace;
use quinn::rustls::ClientConfig;
use quinn::rustls::pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;
use tokio_util::io::CopyToBytes;
use tokio_util::io::SinkWriter;
use tokio_util::io::StreamReader;

use super::config::DnsConfig;
use super::config::SslConfig;

fn framed_io<T, C>(framed: Framed<T, C>) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    let (sink, stream) = framed.split();
    let reader = StreamReader::new(stream.map(|result| result.map_err(io::Error::other)));
    let sink = sink.with(|bytes: Bytes| ready(Ok::<BytesMut, anyhow::Error>(bytes.into()))).sink_map_err(io::Error::other);
    let writer = SinkWriter::new(CopyToBytes::new(sink));
    tokio::io::join(reader, writer)
}

pub struct DnsRequestContext<'a> {
    ssl: Option<&'a SslConfig>,
    uri: Uri,
    pub host: String,
    pub port: u16,
}

impl<'a> DnsRequestContext<'a> {
    pub fn new(config: &'a DnsConfig) -> anyhow::Result<DnsRequestContext<'a>> {
        let uri = Uri::from_str(&config.url)?;
        let ssl = config.ssl.as_ref();
        let host = uri.host().ok_or(anyhow!("[dns] url has no host"))?.to_owned();
        let port = uri.port_u16().unwrap_or(443);
        Ok(Self { ssl, uri, host, port })
    }
}

const MIME_APPLICATION_DNS: &str = "application/dns-message";

#[derive(Clone)]
struct DnsHandle {
    uri: Uri,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl DnsHandle {
    async fn new<S>(uri: Uri, stream: TlsStream<S>) -> Result<Self, NetError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (h2, connection) = h2::client::handshake(stream).await.map_err(|e| NetError::from(format!("[dns] h2 handshake error: {e}")))?;
        tokio::spawn(async move {
            connection.await.unwrap_or_else(|e| error!("[dns] http2 connection failed: {}", e));
        });
        Ok(Self { uri, h2, is_shutdown: false })
    }

    async fn send(h2: SendRequest<Bytes>, uri: Uri, message: Bytes) -> Result<DnsResponse, NetError> {
        let mut h2 = match h2.ready().await {
            Ok(h2) => h2,
            Err(err) => {
                return Err(NetError::from(format!("[dns] h2 send_request error: {err}")));
            }
        };

        // build up the http request
        let request = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::POST)
            .header(http::header::ACCEPT, MIME_APPLICATION_DNS)
            .header(http::header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(http::header::CONTENT_LENGTH, message.len())
            .uri(uri)
            .body(())
            .map_err(|e| NetError::from(format!("[dns] http stream errored: {e}")))?;

        trace!("[dns] request: {:#?}", request);

        // Send the request
        let (response_future, mut send_stream) =
            h2.send_request(request, false).map_err(|err| NetError::from(format!("[dns] h2 send_request error: {err}")))?;

        send_stream.send_data(message, true).map_err(|e| NetError::from(format!("[dns] h2 send_data error: {e}")))?;

        let mut response_stream = response_future.await.map_err(|err| NetError::from(format!("received a stream error: {err}")))?;

        trace!("[dns] got response: {:#?}", response_stream);

        // get the length of packet
        let content_length = response_stream
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .map(|v| v.to_str())
            .transpose()
            .map_err(|e| NetError::from(format!("[dns] bad headers received: {e}")))?
            .map(usize::from_str)
            .transpose()
            .map_err(|e| NetError::from(format!("[dns] bad headers received: {e}")))?;

        let mut response_bytes = BytesMut::with_capacity(content_length.unwrap_or(512).clamp(512, 4_096));

        while let Some(partial_bytes) = response_stream.body_mut().data().await {
            let partial_bytes = partial_bytes.map_err(|e| NetError::from(format!("[dns] bad http request: {e}")))?;

            trace!("[dns] got bytes: {}", partial_bytes.len());
            response_bytes.extend(partial_bytes);

            // assert the length
            if let Some(content_length) = content_length {
                if response_bytes.len() >= content_length {
                    break;
                }
            }
        }

        // assert the length
        if let Some(content_length) = content_length {
            if response_bytes.len() != content_length {
                return Err(NetError::from(format!("[dns] expected byte length: {}, got: {}", content_length, response_bytes.len())));
            }
        }

        // Was it a successful request?
        if !response_stream.status().is_success() {
            let error_string = String::from_utf8_lossy(response_bytes.as_ref());
            return Err(NetError::from(format!("[dns] http unsuccessful code: {}, message: {}", response_stream.status(), error_string)));
        } else {
            // verify content type
            {
                // in the case that the ContentType is not specified, we assume it's the standard DNS format
                let content_type = response_stream
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .map(|h| h.to_str().map_err(|err| NetError::from(format!("[dns] ContentType header not a string: {err}"))))
                    .unwrap_or(Ok(MIME_APPLICATION_DNS))?;

                if content_type != MIME_APPLICATION_DNS {
                    return Err(NetError::from(format!("[dns] ContentType unsupported (must be {}): '{}'", MIME_APPLICATION_DNS, content_type)));
                }
            }
        };
        // and finally convert the bytes into a DNS message
        DnsResponse::from_buffer(response_bytes.to_vec()).map_err(NetError::from)
    }
}

impl Stream for DnsHandle {
    type Item = Result<(), NetError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(()))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(NetError::from(format!("h2 stream errored: {e}",))))),
        }
    }
}

impl DnsRequestSender for DnsHandle {
    fn send_message(&mut self, mut request: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // per the RFC, a zero id allows for the HTTP packet to be cached better
        request.metadata.id = 0;

        let bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return NetError::from(err).into(),
        };

        Box::pin(Self::send(self.h2.clone(), self.uri.clone(), Bytes::from(bytes))).into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

pub async fn a_query<T, C>(framed: Framed<T, C>, context: DnsRequestContext<'_>, query: Query) -> anyhow::Result<Lookup>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
{
    let mut client_config;
    let server_name;
    if let Some(ssl) = context.ssl {
        client_config = super::template::rustls_client_config(ssl)?;
        if let Some(name) = ssl.server_name.as_ref() {
            server_name = ServerName::try_from(name.to_owned())?;
        } else {
            server_name = ServerName::try_from(context.host)?;
        }
    } else {
        client_config = ClientConfig::with_platform_verifier()?;
        #[cfg(debug_assertions)]
        {
            use quinn::rustls::KeyLogFile;
            client_config.key_log = Arc::new(KeyLogFile::new());
        }
        server_name = ServerName::try_from(context.host)?;
    }
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_connector = TlsConnector::from(Arc::new(client_config));
    let tls_stream = tls_connector.connect(server_name, framed_io(framed)).await?;
    let stream = DnsHandle::new(context.uri, tls_stream).await?;
    let (dns_exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(stream);
    tokio::spawn(background);
    let client = CachingClient::new(10, dns_exchange, false);
    let lookup = client.lookup(query, DnsRequestOptions::default()).await?;
    Ok(lookup)
}

#[derive(Debug, Clone)]
pub struct Cache(moka::sync::Cache<Query, CacheValue>);

#[derive(Debug, Clone)]
struct CacheValue {
    ip: IpAddr,
    valid_until: Instant,
}

impl CacheValue {
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    /// Returns the ttl as a Duration of time remaining.
    fn ttl(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }

    fn with_updated_ttl(&self, now: Instant) -> Self {
        let ttl: u64 = self.ttl(now).as_secs();
        let valid_until = now + Duration::from_secs(ttl);
        Self { ip: self.ip, valid_until }
    }
}

impl Cache {
    pub fn new(size: usize) -> Self {
        let cache = moka::sync::Cache::builder().max_capacity(size.try_into().unwrap_or(u64::MAX)).expire_after(CacheValueExpiry).build();
        Self(cache)
    }

    pub fn insert(&self, query: Query, ip: IpAddr, ttl: u32, now: Instant) {
        let valid_until = now + Duration::from_secs(ttl.into());
        self.0.insert(query, CacheValue { ip, valid_until });
    }

    pub fn get(&self, query: &Query, now: Instant) -> Option<IpAddr> {
        if let Some(value) = self.0.get(query) {
            if !value.is_current(now) {
                return None;
            }
            Some(value.with_updated_ttl(now).ip)
        } else {
            None
        }
    }
}

struct CacheValueExpiry;

impl moka::Expiry<Query, CacheValue> for CacheValueExpiry {
    fn expire_after_create(&self, _key: &Query, value: &CacheValue, created_at: Instant) -> Option<Duration> {
        Some(value.ttl(created_at))
    }

    fn expire_after_update(
        &self,
        _key: &Query,
        value: &CacheValue,
        updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl(updated_at))
    }
}
