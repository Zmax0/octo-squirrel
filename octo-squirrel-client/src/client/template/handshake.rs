use anyhow::anyhow;
use anyhow::bail;
use octo_squirrel::common::protocol::address::Address;
use octo_squirrel::common::protocol::socks::SocksVersion;
use octo_squirrel::common::protocol::socks5::handshake::ServerHandShake;
use octo_squirrel::common::protocol::socks5::message::Socks5CommandResponse;
use octo_squirrel::common::protocol::socks5::Socks5CommandStatus;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub enum Proxy {
    Http(Address),
    Https(Address),
    Socks5,
    Unknown,
}

pub async fn get_request_addr(stream: &mut TcpStream) -> anyhow::Result<Address> {
    let next = recognize(stream).await?;
    match next {
        Proxy::Http(address) => Ok(address),
        Proxy::Https(address) => {
            let _ = stream.read(&mut [0; 1024]).await?;
            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
            Ok(address)
        }
        Proxy::Socks5 => {
            let local_addr = stream.local_addr().unwrap();
            let response = Socks5CommandResponse::new(Socks5CommandStatus::Success, local_addr.into());
            let handshake = ServerHandShake::no_auth(stream, response).await;
            handshake.map(Address::from)
        }
        Proxy::Unknown => bail!("Unknown type of handshake"),
    }
}

async fn recognize(stream: &mut TcpStream) -> Result<Proxy, anyhow::Error> {
    let mut buf = [0; 1024];
    let len = stream.peek(&mut buf).await?;
    let version = SocksVersion::from(buf[0]);
    if matches!(version, SocksVersion::Socks5) {
        Ok(Proxy::Socks5)
    } else {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        if let (Ok(_), Some(path), Some(method)) = (req.parse(&buf[..len]), req.path, req.method) {
            Ok(recognize_http(method, path)?)
        } else {
            Ok(Proxy::Unknown)
        }
    }
}

fn recognize_http(method: &str, mut path: &str) -> Result<Proxy, anyhow::Error> {
    if let Some(i) = path.rfind('?') {
        path = &path[..i];
    }
    if path.ends_with('/') {
        path = &path[..path.len() - 1];
    }
    if let Some(i) = path.find("://").map(|i| i + 3) {
        if let Some(j) = path[i..].find('/').map(|j| j + i) {
            path = &path[i..j]
        } else {
            path = &path[i..]
        }
    }
    if "CONNECT" == method {
        let h_end = path.rfind(':').ok_or_else(|| anyhow!("invalid http CONNECT uri"))?;
        let host = path[..h_end].to_owned();
        let port = path[h_end + 1..].parse()?;
        Ok(Proxy::Https(Address::Domain(host, port)))
    } else {
        let h_end = path.rfind(':');
        let h_v6_end: Option<usize> = path.rfind(']');
        if h_end.is_none() || h_v6_end.map(|i| h_end.unwrap() < i).unwrap_or(false) {
            let host = path.to_owned();
            Ok(Proxy::Http(Address::Domain(host, 80)))
        } else {
            let h_end = h_end.unwrap();
            let p_start = h_end + 1;
            let host = path[..h_end].to_owned();
            let port = path[p_start..].parse().unwrap();
            Ok(Proxy::Http(Address::Domain(host, port)))
        }
    }
}

#[cfg(test)]
mod test {
    use super::recognize_http;
    use super::Proxy;

    macro_rules! assert_parse {
        ($type:ident, $method:tt, $path:tt, $expect:tt) => {
            if let Ok(Proxy::$type(addr)) = recognize_http($method, $path) {
                assert_eq!($expect, addr.to_string())
            } else {
                panic!("unexpected type")
            }
        };
    }

    #[test]
    fn test_parse() {
        assert_parse!(Https, "CONNECT", "www.example.com:443", "www.example.com:443");
        assert_parse!(Http, "POST", "http://www.example.com:8080/?a=b&c=d", "www.example.com:8080");
        assert_parse!(Http, "GET", "http://www.example.com/a/b/c?a=b&c=d", "www.example.com:80");
        assert_parse!(Http, "PUT", "http://[::1]", "[::1]:80");
        assert_parse!(Http, "OPTIONS", "http://[0:0:0:0:0:0:0:1]:8080", "[0:0:0:0:0:0:0:1]:8080");
    }
}
