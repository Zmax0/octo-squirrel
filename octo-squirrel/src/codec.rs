pub mod aead;
mod chunk;
pub mod shadowsocks;
pub mod vmess;

use std::io;
use std::mem::take;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::task::ready;

use anyhow::Result;
use anyhow::bail;
use futures::SinkExt;
use futures::StreamExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_websockets::Payload;

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
pub struct WebSocketStream<T> {
    inner: tokio_websockets::proto::WebSocketStream<T>,
    read_buffer: BytesMut,
}

impl<T> WebSocketStream<T> {
    pub fn new(inner: tokio_websockets::proto::WebSocketStream<T>) -> Self {
        Self { inner, read_buffer: BytesMut::new() }
    }
}

impl<T> AsyncRead for WebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), std::io::Error>> {
        if !self.read_buffer.is_empty() {
            let cur =
                if self.read_buffer.len() <= buf.remaining() { take(&mut self.read_buffer) } else { self.read_buffer.split_to(buf.remaining()) };
            buf.put_slice(&cur);
            Poll::Ready(Ok(()))
        } else {
            match ready!(self.inner.poll_next_unpin(cx)) {
                Some(Ok(msg)) => {
                    if msg.is_binary() || msg.is_text() {
                        let payload = msg.as_payload();
                        if payload.len() <= buf.remaining() {
                            buf.put_slice(payload);
                        } else {
                            let (left, right) = payload.split_at(buf.remaining());
                            buf.put_slice(left);
                            self.read_buffer.extend_from_slice(right);
                        }
                    }
                    Poll::Ready(Ok(()))
                }
                Some(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                None => Poll::Pending,
            }
        }
    }
}

impl<T> AsyncWrite for WebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::result::Result<usize, io::Error>> {
        match ready!(self.inner.poll_ready_unpin(cx)) {
            Ok(_) => match self.inner.start_send_unpin(tokio_websockets::Message::binary(Payload::from(buf.to_vec()))) {
                Ok(_) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(io::Error::other(e))),
            },
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), io::Error>> {
        self.inner.poll_flush_unpin(cx).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), io::Error>> {
        self.inner.poll_close_unpin(cx).map_err(io::Error::other)
    }
}

pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        QuicStream { send, recv }
    }

    pub async fn close(mut self) -> Result<()> {
        self.send.finish()?;
        match self.send.stopped().await {
            Ok(_) => Ok(()),
            Err(e) => bail!(e),
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), std::io::Error>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
