use octo_squirrel_client::client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    console_subscriber::init();
    client::main().await
}
