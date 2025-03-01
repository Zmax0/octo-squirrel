pub mod aead;
mod chunk;
pub mod shadowsocks;
pub mod vmess;

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::task::ready;

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use futures::Sink;
use futures::SinkExt;
use futures::Stream;
use futures::StreamExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio_util::bytes::Bytes;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;
use tokio_websockets::WebSocketStream;

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

pub struct WebSocketFramed<T, C, E, D> {
    stream: WebSocketStream<T>,
    codec: C,
    encode_item: PhantomData<E>,
    decode_item: PhantomData<D>,
}

impl<T, C, E, D> Unpin for WebSocketFramed<T, C, E, D> {}

impl<T, C, E, D> WebSocketFramed<T, C, E, D>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    pub fn new(stream: WebSocketStream<T>, codec: C) -> Self {
        Self { stream, codec, encode_item: PhantomData, decode_item: PhantomData }
    }
}

impl<T, C, E, D> Stream for WebSocketFramed<T, C, E, D>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    type Item = Result<D>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.stream.poll_next_unpin(cx)) {
            Some(Ok(msg)) => match self.codec.decode(&mut msg.into_payload().into()) {
                Ok(Some(item)) => Poll::Ready(Some(Ok(item))),
                Ok(None) => Poll::Pending,
                Err(e) => Poll::Ready(Some(Err(e))),
            },
            Some(Err(e)) => Poll::Ready(Some(Err(anyhow!(e)))),
            None => Poll::Ready(None),
        }
    }
}

impl<T, C, E, D> Sink<E> for WebSocketFramed<T, C, E, D>
where
    T: AsyncRead + AsyncWrite + Unpin,
    C: Encoder<E, Error = anyhow::Error> + Decoder<Item = D, Error = anyhow::Error> + Unpin,
{
    type Error = anyhow::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.stream.poll_ready_unpin(cx).map_err(|e| anyhow!(e))
    }

    fn start_send(mut self: Pin<&mut Self>, item: E) -> Result<(), Self::Error> {
        let mut dst = BytesMut::new();
        self.codec.encode(item, &mut dst)?;
        self.stream.start_send_unpin(tokio_websockets::Message::binary(dst)).map_err(|e| anyhow!(e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.stream.poll_flush_unpin(cx).map_err(|e| anyhow!(e))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.stream.poll_close_unpin(cx).map_err(|e| anyhow!(e))
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
