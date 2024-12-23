use std::mem::size_of;

#[derive(PartialEq, Eq)]
pub struct PlainSizeParser;

impl PlainSizeParser {
    pub const fn size_bytes() -> usize {
        size_of::<u16>()
    }

    pub fn encode_size(size: usize) -> Vec<u8> {
        (size as u16).to_be_bytes().to_vec()
    }

    pub fn decode_size(data: &[u8]) -> usize {
        let mut bytes = [0; Self::size_bytes()];
        bytes.copy_from_slice(&data[..Self::size_bytes()]);
        u16::from_be_bytes(bytes) as usize
    }
}
