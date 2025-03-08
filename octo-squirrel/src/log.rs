use std::str::FromStr;

use anyhow::Result;
use log::LevelFilter;
use log::info;
use log::warn;
use log4rs::Config;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::Appender;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;
use serde::Deserialize;
use serde::Serialize;

pub fn init(level: &str) -> Result<()> {
    let mut path = std::env::current_exe().expect("Can't get the current exe path");
    path.pop();
    path.push("log4rs.yaml");
    match log4rs::init_file(&path, Default::default()) {
        Ok(_) => info!("Init log4rs.yaml, path={}", path.display()),
        Err(e) => {
            log4rs::init_config(build_config(level))?;
            warn!("Init log4rs.yaml failed; {}", e);
            info!("Init custom logger; level={}", level);
        }
    }
    Ok(())
}

fn build_config(level: &str) -> Config {
    let quinn_logger = log4rs::config::Logger::builder().build("quinn", LevelFilter::Info);
    let quinn_proto_logger = log4rs::config::Logger::builder().build("quinn_proto", LevelFilter::Info);
    let rustls_logger = log4rs::config::Logger::builder().build("rustls", LevelFilter::Info);
    let name = "stdout";
    Config::builder()
        .loggers(vec![quinn_logger, quinn_proto_logger, rustls_logger])
        .appender(Appender::builder().build(
            name,
            Box::new(ConsoleAppender::builder().encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} {h({l}):<6} {m}{n}"))).build()),
        ))
        .build(Root::builder().appender(name).build(LevelFilter::from_str(level).unwrap()))
        .unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logger {
    level: String,
}

impl Logger {
    pub fn new(level: String) -> Self {
        Self { level }
    }

    pub fn level(&self) -> &str {
        &self.level
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self { level: "info".to_owned() }
    }
}
