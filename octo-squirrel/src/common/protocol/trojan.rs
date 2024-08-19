pub const CR_LF: [u8; 2] = [b'\r', b'\n'];

pub enum CodecStatus {
    Header,
    Body,
}
