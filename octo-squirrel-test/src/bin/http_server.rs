use std::env;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args();
    let addr = if let Some(addr) = args.nth(1) { addr } else { "127.0.0.1:16802".to_owned() };
    println!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).await?;
    let mut buf = [0; 1024];
    while let Ok((mut inbound, local_addr)) = listener.accept().await {
        let len = inbound.read(&mut buf).await?;
        println!("Receive from {}\n{}", local_addr, String::from_utf8_lossy(&buf[..len]));
        inbound.write_all(b"HTTP/1.1 200 OK\r\nServer: HttpTestServer\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n").await?;
        let res = format!("<h1>{}</h1>\r\n", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis());
        inbound.write_all(res.as_bytes()).await?;
        inbound.flush().await?;
        inbound.shutdown().await?;
    }
    Ok(())
}
