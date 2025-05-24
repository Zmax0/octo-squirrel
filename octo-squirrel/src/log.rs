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

pub fn init(root_level: &str, level: &str) -> Result<()> {
    let mut path = std::env::current_exe().expect("Can't get the current exe path");
    path.pop();
    path.push("log4rs.yaml");
    match log4rs::init_file(&path, Default::default()) {
        Ok(_) => info!("Init log4rs.yaml, path={}", path.display()),
        Err(e) => {
            log4rs::init_config(build_config(root_level, level))?;
            warn!("Init log4rs.yaml failed; {}", e);
            info!("Init custom logger; level={}", level);
        }
    }
    Ok(())
}

fn build_config(root_level: &str, level: &str) -> Config {
    let level = LevelFilter::from_str(level).expect("invalid log level");
    let octo_squirrel_client = log4rs::config::Logger::builder().build("octo_squirrel_client", level);
    let octo_squirrel = log4rs::config::Logger::builder().build("octo_squirrel", level);
    let octo_squirrel_server = log4rs::config::Logger::builder().build("octo_squirrel_server", level);
    let name = "stdout";
    Config::builder()
        .loggers(vec![octo_squirrel_client, octo_squirrel, octo_squirrel_server])
        .appender(Appender::builder().build(
            name,
            Box::new(ConsoleAppender::builder().encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} [{t}] {h({l}):<5} {m}{n}"))).build()),
        ))
        .build(Root::builder().appender(name).build(LevelFilter::from_str(root_level).expect("invalid log level")))
        .unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logger {
    #[serde(default = "Logger::default_level")]
    level: String,
    #[serde(default = "Logger::default_level")]
    root_level: String,
}

impl Logger {
    pub fn new(level: String, root_level: String) -> Self {
        Self { level, root_level }
    }

    pub fn level(&self) -> &str {
        &self.level
    }

    pub fn root_level(&self) -> &str {
        &self.root_level
    }

    fn default_level() -> String {
        "info".to_owned()
    }
}
