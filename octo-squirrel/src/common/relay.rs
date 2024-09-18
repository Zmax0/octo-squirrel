use std::fmt::Debug;
use std::fmt::Formatter;

pub enum End {
    Local,
    Client,
    Server,
    Peer,
}

impl Debug for End {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Client => write!(f, "client"),
            Self::Server => write!(f, "server"),
            Self::Peer => write!(f, "peer"),
        }
    }
}

pub enum Result {
    Close(End, End),
    Err(End, End, anyhow::Error),
}

impl Debug for Result {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Close(arg0, arg1) => write!(f, "{:?}*-{:?} closed", arg0, arg1),
            Self::Err(arg0, arg1, arg2) => write!(f, "relay {:?}-{:?} failed; error={}", arg0, arg1, arg2),
        }
    }
}
