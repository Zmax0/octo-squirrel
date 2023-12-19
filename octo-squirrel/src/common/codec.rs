pub mod aead;
pub mod chunk;
pub mod shadowsocks;
pub mod vmess;

use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

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
        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}

impl Encoder<BytesMut> for BytesCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, data: BytesMut, buf: &mut BytesMut) -> Result<()> {
        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}
