use std::error::Error;
use std::str::FromStr;

use log::info;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::Appender;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;
use serde::Deserialize;
use serde::Serialize;

pub fn init(config: &Logger) -> Result<(), Box<dyn Error>> {
    let path = "log4rs.yaml";
    if let Ok(()) = log4rs::init_file(path, Default::default()) {
        info!("Init custom logger.");
    } else {
        log4rs::init_config(default(config))?;
        info!("Init default logger; level={}", config.level);
    }
    Ok(())
}

fn default(config: &Logger) -> Config {
    let name = "stdout";
    Config::builder()
        .appender(Appender::builder().build(
            name,
            Box::new(ConsoleAppender::builder().encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} {l} {M} - {m}{n}"))).build()),
        ))
        .build(Root::builder().appender(name).build(LevelFilter::from_str(config.level.as_str()).unwrap()))
        .unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logger {
    level: String,
}

impl Default for Logger {
    fn default() -> Self {
        Self { level: "info".to_owned() }
    }
}
