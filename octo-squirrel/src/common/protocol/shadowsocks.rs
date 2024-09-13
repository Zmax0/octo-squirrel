#[derive(Copy, Clone)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }

    pub fn expect_u8(&self) -> u8 {
        match self {
            Self::Client => 1,
            Self::Server => 0,
        }
    }
}
