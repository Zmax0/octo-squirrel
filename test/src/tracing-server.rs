use std::env;

use futures::future::join_all;
use octo_squirrel::log::Logger;
use octo_squirrel_server::server;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    console_subscriber::ConsoleLayer::builder().server_addr(([127, 0, 0, 1], 6670)).init();
    let servers = octo_squirrel::config::init_server()?;
    let logger = Logger::new(env::args().nth(2).unwrap_or("info".to_owned()));
    octo_squirrel::log::init(&logger)?;
    let tasks: Vec<JoinHandle<()>> = servers.into_iter().map(|server| tokio::spawn(async move { server::startup(server).await })).collect();
    join_all(tasks).await;
    Ok(())
}
