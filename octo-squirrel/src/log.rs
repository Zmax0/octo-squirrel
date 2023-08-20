use std::error::Error;

use log::{info, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;

pub fn init() -> Result<(), Box<dyn Error>> {
    let path = "log4rs.yaml";
    if let Ok(()) = log4rs::init_file(path, Default::default()) {
        info!("Init custom log config.");
    } else {
        log4rs::init_config(default())?;
        info!("Init default log config.");
    }
    Ok(())
}

fn default() -> Config {
    let name = "stdout";
    Config::builder()
        .appender(Appender::builder().build(
            name,
            Box::new(ConsoleAppender::builder().encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} {l} {M} - {m}{n}"))).build()),
        ))
        .build(Root::builder().appender(name).build(LevelFilter::Info))
        .unwrap()
}
