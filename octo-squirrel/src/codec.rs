pub mod aead;
mod chunk;
pub mod shadowsocks;
pub mod vmess;

use std::future::ready;
use std::io;

use anyhow::Result;
use futures::SinkExt;
use futures::StreamExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_util::io::CopyToBytes;
use tokio_util::io::SinkWriter;
use tokio_util::io::StreamReader;
use tokio_websockets::Message;

use super::protocol::address::Address;

pub struct BytesCodec;

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>> {
        if !buf.is_empty() {
            let len = buf.len();
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<Bytes> for BytesCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<()> {
        buf.extend_from_slice(&data);
        Ok(())
    }
}

impl Encoder<BytesMut> for BytesCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<()> {
        buf.extend_from_slice(&data);
        Ok(())
    }
}

pub type DatagramPacket = (BytesMut, Address);

pub fn websocket_stream<T>(inner: tokio_websockets::WebSocketStream<T>) -> impl AsyncRead + AsyncWrite + Unpin + use<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (sink, stream) = inner.split();
    let reader = StreamReader::new(stream.filter_map(|message: Result<Message, tokio_websockets::Error>| {
        let bytes = match message {
            Ok(message) if message.is_binary() || message.is_text() => Some(Ok(Bytes::from(message.into_payload()))),
            Ok(_) => None,
            Err(error) => Some(Err(io::Error::other(error))),
        };
        ready(bytes)
    }));
    let writer = SinkWriter::new(CopyToBytes::new(
        sink.with(|bytes: Bytes| ready(Ok::<Message, tokio_websockets::Error>(Message::binary(bytes)))).sink_map_err(io::Error::other),
    ));
    tokio::io::join(reader, writer)
}

pub type QuicStream = tokio::io::Join<quinn::RecvStream, quinn::SendStream>;

pub fn quic_stream(send: quinn::SendStream, recv: quinn::RecvStream) -> QuicStream {
    tokio::io::join(recv, send)
}
