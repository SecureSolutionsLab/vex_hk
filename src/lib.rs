use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Command, Stdio},
    time::Instant,
};

#[cfg(feature = "nvd")]
use chrono::NaiveDate;
#[cfg(feature = "nvd")]
use log::error;
use sqlx::postgres::PgPoolCopyExt;
#[cfg(feature = "nvd")]
use std::{
    iter::once,
    time::{Duration, Instant},
};

#[cfg(feature = "nvd")]
use crate::{
    db_api::{
        consts::CVE_TABLE,
        db_connection::get_db,
        query_db::{count_table_entries, verify_database},
    },
    utils::{
        config::store_key,
        time::{get_timestamp, instant_to_datetime},
    },
};

#[cfg(feature = "alienvault")]
use crate::scrape_mod::alienvault_scraper::alienvault_scraper;
#[cfg(feature = "exploitdb")]
use crate::scrape_mod::exploitdb_scraper::exploitdb_scrape;
#[cfg(feature = "nvd")]
use crate::scrape_mod::nvd_scraper::{consts_checker, query_nvd_cvecount, scrape_nvd};

// Verifies every hour
#[cfg(feature = "nvd")]
const TIME_INTERVAL: u64 = 3600;
#[cfg(feature = "nvd")]
const EMPTY: i64 = 0;

const GITHUB_TOKEN_LOCATION: &str = "./tokens/github";

pub mod csv_postgres_integration;
mod db_api;
mod download;
pub mod scrape_mod;
mod utils;

pub use db_api::consts;

// mod github;

mod osv_schema;
// mod scaf_schema;

// pub use github::update_github;

#[cfg(feature = "nvd")]
pub async fn _exploit_vulnerability_hunter() {
    if let Err(e) = consts_checker() {
        eprintln!("Error: {}", e);
        std::process::exit(1); // Gracefully exit with an error code
    }
    // year_nvd("1988", "2016").await; // 74327 // 74327
    // year_nvd("1988", "2017").await; // 6517  // 80844
    // year_nvd("2017", "2018").await; // 18113 // 98957
    // year_nvd("2018", "2019").await; // 18154 // 117111
    // year_nvd("2019", "2020").await; // 18938 // 136049
    // year_nvd("2020", "2021").await; // 19222 // 155271
    // year_nvd("2021", "2022").await; // 21950 // 177221
    // year_nvd("2022", "2023").await; // 26431 // 203652
    // year_nvd("2023", "2024").await; // 30949 //234601

    // exploitdb_scraper().await;
    // panic!("hello there");

    let ticker_interval = Duration::from_secs(TIME_INTERVAL);
    let mut last_tick_time = Instant::now();

    let mut timestamp = get_timestamp();
    let db_connection = get_db();
    println!("db_connection {}", db_connection);

    loop {
        nvd_scraper(timestamp).await;

        let current_time = Instant::now();
        let elapsed_since_last_tick = current_time.duration_since(last_tick_time);
        let time_to_next_tick = if elapsed_since_last_tick < ticker_interval {
            ticker_interval - elapsed_since_last_tick
        } else {
            Duration::from_secs(0)
        };

        //save the timestamp for the last retrieval
        timestamp = instant_to_datetime();
        store_key("last_timestamp".to_string(), timestamp.clone());

        let mut verify = true;
        while Instant::now() - current_time < time_to_next_tick {
            if verify {
                verify = false;
                let result = verify_database().await;
                if result > 0 {
                    println!("Repeated entires, please verify");
                }
            }
        }
        last_tick_time += ticker_interval;
        println!("Tick!");
    }
}

/// Retrieves the exploits from NVD database (timestamp required for new additions and updates)
/// Designed for performance, update removes the entry and adds the latest one
#[cfg(feature = "nvd")]
async fn nvd_scraper(timestamp: String) {
    let db_cve_total = count_table_entries(CVE_TABLE).await;

    // query to see the amount of stored cves and load the latest timestamp
    let query = "?";
    let cve_count = query_nvd_cvecount(query).await.unwrap_or_else(|e| {
        error!("Error fetching CVE count: {}", e);
        0
    });
    if db_cve_total == EMPTY && cve_count > EMPTY as u32 {
        scrape_nvd(cve_count, query.to_string(), false).await;
    } else {
        // added and changed
        let local = instant_to_datetime();

        //last added
        let last_added = format!("?pubStartDate={}&pubEndDate={}", &timestamp, &local);
        let cve_count = query_nvd_cvecount(&*last_added).await.unwrap_or_else(|e| {
            error!("Error fetching CVE count: {}", e);
            0
        });
        if cve_count > EMPTY as u32 {
            scrape_nvd(cve_count, last_added, false).await;
        }

        //last modified
        let last_modified = format!("?lastModStartDate={}&lastModEndDate={}", &timestamp, &local);
        let cve_count = query_nvd_cvecount(&*last_modified)
            .await
            .unwrap_or_else(|e| {
                error!("Error fetching CVE count: {}", e);
                0
            });
        if cve_count > EMPTY as u32 {
            scrape_nvd(cve_count, last_modified, true).await;
        }
    }
}

#[cfg(feature = "exploitdb")]
pub async fn _exploitdb_scraper() {
    match exploitdb_scrape().await {
        Ok(_) => {
            log::info!("Successfully uploaded exploitdb database");
        }
        Err(_) => {
            log::error!("Failed to upload exploitdb database");
        }
    };
}

#[cfg(feature = "osv")]
pub async fn osv_scraper(pg_bars: &indicatif::MultiProgress) {
    // todo: unhandled errors

    use sqlx::Executor;

    let db_conn = db_api::db_connection::get_db_connection().await.unwrap();

    let client = reqwest::Client::new();

    scrape_mod::osv_scraper::scrape_osv_full(client, db_conn, pg_bars)
        .await
        .unwrap();
}

// todo: this kind of sucks
pub async fn github_advisories_scraper(pg_bars: indicatif::MultiProgress) {
    use sqlx::Executor;

    let db_conn = db_api::db_connection::get_db_connection().await.unwrap();

    let client = reqwest::Client::new();

    scrape_mod::github::repository::download_osv_full(client, db_conn, &pg_bars)
        .await
        .unwrap();
}

#[cfg(feature = "alienvault")]
pub async fn _alienvault_otx_scraper() {
    match alienvault_scraper().await {
        Ok(_) => {
            log::info!("Successfully uploaded exploitdb database");
        }
        Err(_) => {
            log::error!("Failed to upload exploitdb database");
        }
    };
}

pub fn exec_stream<P: AsRef<Path>>(binary: P, args: Vec<String>) {
    // todo: probably must be waited
    let mut cmd = Command::new(binary.as_ref())
        .args(&args)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdout = cmd.stdout.as_mut().unwrap();
        let stdout_reader = BufReader::new(stdout);
        let stdout_lines = stdout_reader.lines();

        let vector: Vec<String> = stdout_lines
            .into_iter()
            .map(|line| line.unwrap().clone())
            .collect();

        let mut parse = vec![];
        for value in vector {
            if value.contains("Could not find EDB-ID") {
                return;
            }
            let details: Vec<&str> = value.splitn(2, ":").collect();
            // println!("{:?}", details);
            let parse_details = details.get(1).unwrap().to_string();
            let parse_details = parse_details.clone().trim().to_string().clone();
            parse.push(parse_details);
        }
    }

    cmd.wait().unwrap();
}

// todo: ?
fn _parse_bool(bool_string: &String) -> bool {
    if bool_string == "True" {
        return true;
    }
    false
}

#[cfg(feature = "nvd")]
pub async fn year_nvd(year: &str, end_year: &str) {
    let instant = Instant::now();
    let start_year = parse_year(year);
    let end_year = parse_year(end_year);

    let start_date_year1 = NaiveDate::from_ymd_opt(start_year, 1, 1).unwrap();
    let start_date_year2 = NaiveDate::from_ymd_opt(end_year, 1, 1).unwrap();

    // Calculate the difference in days
    let difference_in_days = start_date_year2
        .signed_duration_since(start_date_year1)
        .num_days();

    println!(
        "Difference in days between {} and {} is: {}",
        year, end_year, difference_in_days
    );
    let mut timestamp = format!("{}-T00:00:00.000", start_date_year1);
    for value in (120..difference_in_days)
        .step_by(120)
        .chain(once(difference_in_days))
    {
        let result = start_date_year1 + chrono::Duration::days(value);
        let end_date = format!("{}T23:59:59.999", result - chrono::Duration::days(1));

        let last_added = format!("?pubStartDate={}&pubEndDate={}", &timestamp, &end_date);
        let cve_count = query_nvd_cvecount(&*last_added).await.unwrap_or_else(|e| {
            error!("Error fetching CVE count: {}", e);
            0
        });
        if cve_count > EMPTY as u32 {
            scrape_nvd(cve_count, last_added, false).await;
        }
        println!(
            "begin {} end {}, cve_count {}",
            timestamp, end_date, cve_count
        );
        timestamp = format!("{}T00:00:00.000", result);
    }
    println!("manual exec {:.2?}", instant.elapsed());
}

#[cfg(feature = "nvd")]
fn parse_year(year: &str) -> i32 {
    year.parse::<i32>().unwrap_or_else(|_| {
        error!("Failed to parse year: '{}'", year);
        0
    })
}
