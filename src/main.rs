use log::{error, info, warn};
#[cfg(feature = "osv")]
use vex_hk::osv_scraper;

#[tokio::main]
async fn main() {
    // initialize env_logger with log level Info as default
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    // todo: is this necessary?
    info!("This is an info log.");
    warn!("This is a warning.");
    error!("This is an error.");
    // _exploit_vulnerability_hunter().await;
    // _exploitdb_scraper().await;
    #[cfg(feature = "osv")]
    osv_scraper().await;
}
