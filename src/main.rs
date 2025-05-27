use std::io::Read;

use chrono::{DateTime, Utc};
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;

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

    // _exploit_vulnerability_hunter().await;
    // _exploitdb_scraper().await;
    // #[cfg(feature = "osv")]
    // vex_hk::osv_scraper(pg_bars).await;

    // vex_hk::github_advisories_scraper(pg_bars).await;

    let token = {
        let mut buf = String::new();
        let mut file = std::fs::File::open("./tokens/github").unwrap();
        file.read_to_string(&mut buf).unwrap();
        buf
    };

    let client = reqwest::Client::new();

    vex_hk::scrape_mod::github::api_caller::get_paginated_github_advisories_data(
        client,
        token,
        &[("published", ">2025-05-20"), ("type", "reviewed"), ("per_page", "10")],
    )
    .await;
}
