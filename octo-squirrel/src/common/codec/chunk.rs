use std::mem::size_of;

#[derive(PartialEq, Eq)]
pub struct PlainSizeParser;

impl PlainSizeParser {
    pub fn size_bytes() -> usize {
        size_of::<u16>()
    }

    pub fn encode_size(&mut self, size: usize) -> Vec<u8> {
        (size as u16).to_be_bytes().to_vec()
    }

    pub fn decode_size(&mut self, data: &[u8]) -> usize {
        let mut bytes = [0; size_of::<u16>()];
        bytes.copy_from_slice(&data[..size_of::<u16>()]);
        u16::from_be_bytes(bytes) as usize
    }
}
