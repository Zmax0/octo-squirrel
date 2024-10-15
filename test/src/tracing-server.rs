use octo_squirrel_server::server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    console_subscriber::ConsoleLayer::builder().server_addr(([127, 0, 0, 1], 6670)).init();
    server::main().await
}
