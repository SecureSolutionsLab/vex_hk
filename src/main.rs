use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use log::{error, info, warn};

#[tokio::main]
async fn main() {
    // initialize env_logger with log level Info as default
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();

    // indicatif rust log progress bar initialization
    let level = logger.filter();
    let pg_bars = MultiProgress::new();
    LogWrapper::new(pg_bars.clone(), logger).try_init().unwrap();
    log::set_max_level(level);

    // todo: is this necessary?
    info!("This is an info log.");
    warn!("This is a warning.");
    error!("This is an error.");
    // _exploit_vulnerability_hunter().await;
    // _exploitdb_scraper().await;
    #[cfg(feature = "osv")]
    vex_hk::osv_scraper_sequential(pg_bars).await;
}
