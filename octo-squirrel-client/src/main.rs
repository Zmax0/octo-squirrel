// #![windows_subsystem = "windows"]

mod client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    client::main().await
}
