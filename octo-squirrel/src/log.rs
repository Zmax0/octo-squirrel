use std::str::FromStr;

use anyhow::Result;
use log::info;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::Appender;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use serde::Deserialize;
use serde::Serialize;

pub fn init(config: &Logger) -> Result<()> {
    if let Ok(()) = log4rs::init_file("log4rs.yaml", Default::default()) {
        info!("Init default logger");
    } else {
        log4rs::init_config(config.into())?;
        info!("Init custom logger; level={}", config.level);
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logger {
    level: String,
}

impl Logger {
    pub fn new(level: String) -> Self {
        Self { level }
    }
}

impl From<&Logger> for Config {
    fn from(value: &Logger) -> Self {
        let name = "stdout";
        Config::builder()
            .appender(Appender::builder().build(
                name,
                Box::new(
                    ConsoleAppender::builder().encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} {h({l}):<5} {M} - {m}{n}"))).build(),
                ),
            ))
            .build(Root::builder().appender(name).build(LevelFilter::from_str(value.level.as_str()).unwrap()))
            .unwrap()
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self { level: "info".to_owned() }
    }
}
