use std::io;
use std::marker::PhantomData;
use std::mem::take;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::ready;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use h2::client::SendRequest;
use hickory_resolver::caching_client::CachingClient;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::proto::ProtoError;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::runtime::TokioTime;
use hickory_resolver::proto::xfer::DnsExchange;
use hickory_resolver::proto::xfer::DnsRequest;
use hickory_resolver::proto::xfer::DnsRequestOptions;
use hickory_resolver::proto::xfer::DnsRequestSender;
use hickory_resolver::proto::xfer::DnsResponse;
use hickory_resolver::proto::xfer::DnsResponseStream;
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
use tokio::io::ReadBuf;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::codec::Framed;

use super::config::DnsConfig;
use super::config::SslConfig;

struct FramedWrapper<T, C, E, D> {
    framed: Framed<T, C>,
    read_buffer: BytesMut,
    marker_e: PhantomData<E>,
    marker_d: PhantomData<D>,
}

impl<T, C, E, D> FramedWrapper<T, C, E, D>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Send + 'static + Unpin,
{
    pub fn new(framed: Framed<T, C>) -> Self {
        Self { framed, read_buffer: BytesMut::new(), marker_e: PhantomData, marker_d: PhantomData }
    }
}

impl<T, C, E, D> AsyncRead for FramedWrapper<T, C, E, D>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Send + 'static + Unpin,
    E: Unpin,
    D: AsRef<[u8]> + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.read_buffer.is_empty() {
            match ready!(self.framed.poll_next_unpin(cx)) {
                Some(Ok(msg)) => {
                    let msg = msg.as_ref();
                    if msg.len() >= buf.remaining() {
                        let (left, right) = msg.split_at(buf.remaining());
                        buf.put_slice(left);
                        self.read_buffer.extend_from_slice(right);
                    } else {
                        buf.put_slice(msg);
                    }
                    Poll::Ready(Ok(()))
                }
                Some(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                None => Poll::Pending,
            }
        } else {
            if self.read_buffer.len() > buf.remaining() {
                buf.put(self.read_buffer.split_to(buf.remaining()));
            } else {
                buf.put_slice(&take(&mut self.read_buffer));
            }
            Poll::Ready(Ok(()))
        }
    }
}

impl<T, C, E, D> AsyncWrite for FramedWrapper<T, C, E, D>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Send + 'static + Unpin,
    E: for<'a> From<&'a [u8]> + Unpin,
    D: Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        match ready!(self.framed.poll_ready_unpin(cx)) {
            Ok(_) => match self.framed.start_send_unpin(buf.into()) {
                Ok(_) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            },
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.framed.poll_flush_unpin(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.framed.poll_close_unpin(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
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
    async fn new<T, C>(uri: Uri, stream: TlsStream<FramedWrapper<T, C, BytesMut, BytesMut>>) -> Result<Self, ProtoError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        C: Encoder<BytesMut, Error = anyhow::Error> + Decoder<Item = BytesMut, Error = anyhow::Error> + Send + 'static + Unpin,
    {
        let (h2, connection) = h2::client::handshake(stream).await.map_err(|e| ProtoError::from(format!("[dns] h2 handshake error: {e}")))?;
        tokio::spawn(async move {
            connection.await.unwrap_or_else(|e| error!("[dns] http2 connection failed: {}", e));
        });
        Ok(Self { uri, h2, is_shutdown: false })
    }

    async fn send(h2: SendRequest<Bytes>, uri: Uri, message: Bytes) -> Result<DnsResponse, ProtoError> {
        let mut h2 = match h2.ready().await {
            Ok(h2) => h2,
            Err(err) => {
                return Err(ProtoError::from(format!("[dns] h2 send_request error: {err}")));
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
            .map_err(|e| ProtoError::from(format!("[dns] http stream errored: {e}")))?;

        trace!("[dns] request: {:#?}", request);

        // Send the request
        let (response_future, mut send_stream) =
            h2.send_request(request, false).map_err(|err| ProtoError::from(format!("[dns] h2 send_request error: {err}")))?;

        send_stream.send_data(message, true).map_err(|e| ProtoError::from(format!("[dns] h2 send_data error: {e}")))?;

        let mut response_stream = response_future.await.map_err(|err| ProtoError::from(format!("received a stream error: {err}")))?;

        trace!("[dns] got response: {:#?}", response_stream);

        // get the length of packet
        let content_length = response_stream
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .map(|v| v.to_str())
            .transpose()
            .map_err(|e| ProtoError::from(format!("[dns] bad headers received: {e}")))?
            .map(usize::from_str)
            .transpose()
            .map_err(|e| ProtoError::from(format!("[dns] bad headers received: {e}")))?;

        let mut response_bytes = BytesMut::with_capacity(content_length.unwrap_or(512).clamp(512, 4_096));

        while let Some(partial_bytes) = response_stream.body_mut().data().await {
            let partial_bytes = partial_bytes.map_err(|e| ProtoError::from(format!("[dns] bad http request: {e}")))?;

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
                return Err(ProtoError::from(format!("[dns] expected byte length: {}, got: {}", content_length, response_bytes.len())));
            }
        }

        // Was it a successful request?
        if !response_stream.status().is_success() {
            let error_string = String::from_utf8_lossy(response_bytes.as_ref());
            return Err(ProtoError::from(format!("[dns] http unsuccessful code: {}, message: {}", response_stream.status(), error_string)));
        } else {
            // verify content type
            {
                // in the case that the ContentType is not specified, we assume it's the standard DNS format
                let content_type = response_stream
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .map(|h| h.to_str().map_err(|err| ProtoError::from(format!("[dns] ContentType header not a string: {err}"))))
                    .unwrap_or(Ok(MIME_APPLICATION_DNS))?;

                if content_type != MIME_APPLICATION_DNS {
                    return Err(ProtoError::from(format!("[dns] ContentType unsupported (must be {}): '{}'", MIME_APPLICATION_DNS, content_type)));
                }
            }
        };
        // and finally convert the bytes into a DNS message
        DnsResponse::from_buffer(response_bytes.to_vec())
    }
}

impl Stream for DnsHandle {
    type Item = Result<(), ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(()))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(ProtoError::from(format!("h2 stream errored: {e}",))))),
        }
    }
}

impl DnsRequestSender for DnsHandle {
    fn send_message(&mut self, mut request: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // per the RFC, a zero id allows for the HTTP packet to be cached better
        request.set_id(0);

        let bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return err.into(),
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
    let tls_stream = tls_connector.connect(server_name, FramedWrapper::new(framed)).await?;
    let stream = DnsHandle::new(context.uri, tls_stream).await?;
    let (dns_exchange, background) = DnsExchange::from_stream::<_, TokioTime>(stream);
    tokio::spawn(async move {
        background.await.unwrap_or_else(|e| error!("[dns] exchange background failed: {}", e));
    });
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
