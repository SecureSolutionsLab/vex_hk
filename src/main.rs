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
    let request = client
        .get("https://api.github.com/advisories")
        .bearer_auth(token)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, "User")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .query(&[("published", ">2025-05-20"), ("type", "reviewed")])
        .build()
        .unwrap();

    println!("{:#?}", request);

    let response = client.execute(request).await.unwrap();

    println!("{:#?}", response);

    let data = response
        .json::<vex_hk::scrape_mod::github::api_response::GitHubAdvisoryAPIResponses>()
        .await
        .unwrap();
    println!("{:#?}", data);

    println!("{}", data.len());
}
