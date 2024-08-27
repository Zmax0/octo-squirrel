use futures::future::join_all;
use octo_squirrel::log::Logger;
use tokio::task::JoinHandle;

mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let servers = octo_squirrel::config::init_server()?;
    let logger = Logger::new("info".to_owned());
    octo_squirrel::log::init(&logger)?;
    let tasks: Vec<JoinHandle<()>> = servers.into_iter().map(|server| tokio::spawn(async move { server::startup(server).await })).collect();
    join_all(tasks).await;
    Ok(())
}
