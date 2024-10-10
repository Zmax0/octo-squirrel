use std::env;

use futures::future::join_all;
use octo_squirrel_server::server;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    console_subscriber::ConsoleLayer::builder().server_addr(([127, 0, 0, 1], 6670)).init();
    let servers = octo_squirrel::config::init_server()?;
    if let Some(level) = env::args().nth(2) {
        octo_squirrel::log::init(&level)?;
    } else {
        octo_squirrel::log::init("info")?;
    }
    let tasks: Vec<JoinHandle<()>> = servers.into_iter().map(|server| tokio::spawn(async move { server::startup(server).await })).collect();
    join_all(tasks).await;
    Ok(())
}
