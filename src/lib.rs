use chrono::NaiveDate;
use reqwest::{get, Client};
use scraper::{Html, Selector};
use std::fmt::format;
use std::io::{BufRead, BufReader};
use std::iter::once;
use std::ops::Add;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use sqlx::{query, Row};
use crate::crawl_mod::structs::ExploitDB;
use crate::crawl_mod::{consts_checker, query_nvd_and_insert, query_nvd_cvecount};
use crate::db_mod::{count_cve_db, get_db_connection, verify_database};
use crate::utils::tools::{get_db, get_timestamp, instant_to_datetime, store_key};

//Verifies every hour
const TIME_INTERVAL: u64 = 3600;
const EMPTY: i64 = 0;

mod crawl_mod;
mod db_mod;
mod utils;

pub async fn exploit_vulnerability_hunter() {
    consts_checker();
    // year_nvd("1988", "2016").await; // 74327 // 74327
    // year_nvd("1988", "2017").await; // 6517  // 80844
    // year_nvd("2017", "2018").await; // 18113 // 98957
    // year_nvd("2018", "2019").await; // 18154 // 117111
    // year_nvd("2019", "2020").await; // 18938 // 136049
    // year_nvd("2020", "2021").await; // 19222 // 155271
    // year_nvd("2021", "2022").await; // 21950 // 177221
    // year_nvd("2022", "2023").await; // 26431 // 203652
    // year_nvd("2023", "2024").await; // 30949 //234601

    exploitdb_crawler().await;
    // panic!("hello there");
    //
    // let ticker_interval = Duration::from_secs(TIME_INTERVAL);
    // let mut last_tick_time = Instant::now();
    //
    let mut timestamp = get_timestamp();
    // let db_connection = get_db();
    // println!("db_connection {}", db_connection);
    //
    // loop {
    //     nvd_crawler(timestamp).await;
    //
    //     let current_time = Instant::now();
    //     let elapsed_since_last_tick = current_time.duration_since(last_tick_time);
    //     let time_to_next_tick = if elapsed_since_last_tick < ticker_interval {
    //         ticker_interval - elapsed_since_last_tick
    //     } else {
    //         Duration::from_secs(0)
    //     };
    //
    //     //save the timestamp for the last retrieval
    //     timestamp = instant_to_datetime();
    //     store_key("last_timestamp".to_string(), timestamp.clone());
    //
    //     let mut verify = true;
    //     while Instant::now() - current_time < time_to_next_tick {
    //         if verify {
    //             verify = false;
    //             let result = verify_database().await;
    //             if result > 0 {
    //                 println!("Repeated entires, please verify");
    //             }
    //         }
    //     }
    //     last_tick_time += ticker_interval;
    //     println!("Tick!");
    // }
}

/// Retrieves the exploits from NVD database (timestamp required for new additions and updates)
/// Designed for performance, update removes the entry and adds the latest one
async fn nvd_crawler(timestamp: String) {
    let db_cve_total = count_cve_db().await;

    // query to see the amount of stored cves and load the latest timestamp
    let query = "?";
    let cve_count = query_nvd_cvecount(query).await;
    if db_cve_total == EMPTY && cve_count > EMPTY as u32 {
        query_nvd_and_insert(cve_count, query.to_string(), false).await;
    } else {
        // added and changed
        let local = instant_to_datetime();

        //last added
        let last_added = format!("?pubStartDate={}&pubEndDate={}", &timestamp, &local);
        let cve_count = query_nvd_cvecount(&*last_added).await;
        if cve_count > EMPTY as u32 {
            query_nvd_and_insert(cve_count, last_added, false).await;
        }

        //last modified
        let last_modified = format!("?lastModStartDate={}&lastModEndDate={}", &timestamp, &local);
        let cve_count = query_nvd_cvecount(&*last_modified).await;
        if cve_count > EMPTY as u32 {
            query_nvd_and_insert(cve_count, last_modified, true).await;
        }
    }
}

async fn exploitdb_crawler() {

    // Execute searchsploit with sudo to update the database
    // let output = Command::new("sudo")
    //     .arg("searchsploit")
    //     .arg("-u") // Update the database
    //     .output()
    //     .expect("Failed to execute command");
    //
    // // Check if the command was successful
    // if output.status.success() {
    //     // Convert the output to a string and print it
    //     let stdout = String::from_utf8_lossy(&output.stdout);
    //     println!("Update output:\n{}", stdout);
    // } else {
    //     // Convert the error output to a string and print it
    //     let stderr = String::from_utf8_lossy(&output.stderr);
    //     eprintln!("Error updating searchsploit:\n{}", stderr);
    // }
    //
    // panic!("test");

    let output = Command::new("searchsploit")
        .arg("--id")
        .output()
        .expect("Failed to execute searchsploit");

    // Convert the output to a string using from_utf8_lossy to handle invalid UTF-8
    let output_str = String::from_utf8_lossy(&output.stdout);

    let re = Regex::new(r"\|\s*(\d+)\s*\n").unwrap();
    let mut edb_ids: Vec<String> = Vec::new();

    // Step 3: Iterate through the matches and collect the IDs
    for caps in re.captures_iter(&output_str) {
        if let Some(id) = caps.get(1) {
            edb_ids.push(id.as_str().to_string());
        }
    }
    edb_ids.sort_by(|a, b| a.parse::<i32>().unwrap().cmp(&b.parse::<i32>().unwrap()));


    // Step 4: Print the extracted EDB-IDs or use them in further logic

    println!("{}", edb_ids.len());


    let instant = Instant::now();

    for id in edb_ids {
        exec_stream("searchsploit", vec!["-p".to_string(), id]);
    }

    println!("time of execution {:.2?}", instant.elapsed());
}

pub fn exec_stream<P: AsRef<Path>>(binary: P, args: Vec<String>) {
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

        let exploit_db = ExploitDB {
            exploit_name: parse.get(0).unwrap().clone(),
            exploit_db_url: parse.get(1).unwrap().clone(),
            local_path: parse.get(2).unwrap().clone(),
            codes: parse.get(3).unwrap().clone(),
            verified: parse_bool(parse.get(4).unwrap()),
            file_type: parse.get(5).unwrap().clone(),
        };

        println!("exploit db {:?}", exploit_db);
        // panic!("hello")
    }

    cmd.wait().unwrap();
}

fn parse_bool(bool_string: &String) -> bool {
    if bool_string == "True" {
        return true;
    }
    return false;
}

pub async fn year_nvd(year: &str, end_year: &str) {
    let instant = Instant::now();
    let start_year = parse_year(year);
    let end_year = parse_year(end_year);

    let start_date_year1 = NaiveDate::from_ymd_opt(start_year, 1, 1).unwrap();
    let start_date_year2 = NaiveDate::from_ymd_opt(end_year, 1, 1).unwrap();

    // Calculate the difference in days
    let mut difference_in_days = start_date_year2
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
        let cve_count = query_nvd_cvecount(&*last_added).await;
        if cve_count > EMPTY as u32 {
            query_nvd_and_insert(cve_count, last_added, false).await;
        }
        println!(
            "begin {} end {}, cve_count {}",
            timestamp, end_date, cve_count
        );
        timestamp = format!("{}T00:00:00.000", result);
    }
    println!("manual exec {:.2?}", instant.elapsed());
}

fn parse_year(year: &str) -> i32 {
    match year.parse::<i32>() {
        Ok(year_num) => year_num,
        Err(e) => 0,
    }
}
