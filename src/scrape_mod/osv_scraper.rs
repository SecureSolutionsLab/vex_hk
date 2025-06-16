use chrono::{DateTime, FixedOffset, Utc};
use log::{error, info};
use quick_xml::{events::Event, Reader};
use reqwest::Client;
use scraper::{Html, Selector};
use serde_json::Value;
use sqlx::{Execute, Executor, Postgres, QueryBuilder};
use std::{
    collections::HashMap,
    error::Error,
    fs::{self, File},
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::time::sleep;
use zip::ZipArchive;

use crate::{
    csv_postgres_integration::{send_csv_to_database_whole, GeneralizedCsvRecord},
    db_api::{
        consts::{ID, OSV_DATA_COLUMN_NAME, OSV_TABLE_NAME},
        db_connection::get_db_connection,
        delete::remove_entries_id,
        insert::insert_parallel,
        query_db::find_missing_or_stale_entries_by_id,
        structs::{EntryInput, EntryStatus},
    },
    download::download_and_save_to_file_in_chunks,
    osv_schema::OSVGeneralized,
    scrape_mod::structs::Sitemap,
    utils::config::{read_key, store_key},
};

/// Custom error type for `fetch_osv_details`.
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Failed to parse HTML: {0}")]
    Html(String),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JSON Data URL not found in HTML.")]
    MissingJsonUrl,
}

const FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE: usize = 42_000_000; // 42mb

const INDEX: &str = "https://osv.dev/sitemap_index.xml";
const FULL_DATA_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities/all.zip";

const TIMESTAMP_FILE_NAME: &str = "last_timestamp_osv";

const TEMP_DOWNLOAD_FILE_PATH: &str = "/zmnt/osv_all_temp.zip";
const TEMP_CSV_FILE_PATH: &str = "/zmnt/vex/osv_temp.csv";

// example id: ALBA-2019:0973
// the specification does not specify a max character limit for the value of an id
// some of these can get quite big (ex. BIT-grafana-image-renderer-2022-31176)
const OSV_ID_MAX_CHARACTERS: usize = 48;

/// Downloads whole OSV ZIP archive data and stores all separate records to a database.
/// A OSV timestamp is then created to aid in future partial updates.
///
/// This function should only run if the local database is empty or very outdated
// todo: needs testing, urls may return errors
pub async fn scrape_osv_full(
    client: reqwest::Client,
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    info!("Starting full OSV database download.");

    let download_path = Path::new(TEMP_DOWNLOAD_FILE_PATH);
    let csv_path = Path::new(TEMP_CSV_FILE_PATH);

    download_and_save_to_file_in_chunks(
        client,
        FULL_DATA_URL,
        Path::new(TEMP_DOWNLOAD_FILE_PATH),
        &pg_bars,
    )
    .await?;

    log::info!("Recreating database table.");
    let database_delete_start = Instant::now();
    db_connection
        .execute(
            QueryBuilder::<Postgres>::new(format!(
                "
        DROP TABLE IF EXISTS \"{OSV_TABLE_NAME}\";
        CREATE TABLE \"{OSV_TABLE_NAME}\" (
            \"id\" character varying({OSV_ID_MAX_CHARACTERS}) PRIMARY KEY,
            \"published\" TIMESTAMPTZ NOT NULL,
            \"modified\" TIMESTAMPTZ NOT NULL,
            \"{OSV_DATA_COLUMN_NAME}\" JSONB NOT NULL
        );",
            ))
            .build()
            .sql(),
        )
        .await
        .unwrap();
    info!("Creating a new OSV table with name \"{OSV_TABLE_NAME}\" and data column \"{OSV_DATA_COLUMN_NAME}\"");
    log::info!(
        "Finished recreating database table. Time: {:?}",
        database_delete_start.elapsed()
    );

    let row_count = create_csv(download_path, csv_path, pg_bars).await?;
    send_csv_to_database_whole(&db_connection, csv_path, OSV_TABLE_NAME, row_count).await?;
    // update_osv_timestamp()?;

    info!(
        "Finished downloading and parsing the full OSV database. Total time: {:?}",
        start.elapsed()
    );

    fs::remove_file(TEMP_CSV_FILE_PATH)?;
    fs::remove_file(TEMP_DOWNLOAD_FILE_PATH)?;
    Ok(())
}

pub async fn create_csv(
    download: &Path,
    csv: &Path,
    pg_bars: &indicatif::MultiProgress,
) -> Result<usize, Box<dyn std::error::Error>> {
    let processing_start = Instant::now();

    let download_file = File::open(download)?;
    let mut archive = ZipArchive::new(download_file)?;

    log::info!(
        "About to process and convert {} files to csv. File created at {:?}",
        archive.len(),
        csv
    );

    let bar = pg_bars.add(indicatif::ProgressBar::new(archive.len() as u64));

    let parent = csv.parent().unwrap();
    if !fs::exists(parent)? {
        fs::create_dir_all(parent)?;
    }
    let mut csv_writer = csv::WriterBuilder::new()
        .buffer_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE)
        .has_headers(false)
        .from_path(csv)?;

    let mut buffer: String = String::with_capacity(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE);
    let mut processed_file_count = 0;
    for file_i in 0..archive.len() {
        let mut file = archive.by_index(file_i)?;

        // skip any non .json files
        if file.name().ends_with(".json") {
            let file_size = file.size() as usize;

            if file_size > FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE {
                // buffer gets resized later automatically
                log::warn!(
                    "File \"{}\" with size {} is bigger than available buffer size ({})",
                    file.name(),
                    human_bytes::human_bytes(file.size() as f64),
                    human_bytes::human_bytes(FIRST_TIME_SEND_TO_DATABASE_BUFFER_SIZE as f64)
                );
            }

            let osv_record = {
                // faster than using serde_json::from_reader and BufReader
                file.read_to_string(&mut buffer)?;
                let res = serde_json::from_str::<OSVGeneralized>(&buffer);
                // todo: update to panic better
                // error probably because the schema updated
                let res_ok = match res {
                    Ok(v) => v,
                    Err(err) => {
                        log::error!("{}", &buffer);
                        panic!("{}: {}", file_i, err);
                    }
                };
                res_ok
            };
            let id = &osv_record.id;
            if id.len() > OSV_ID_MAX_CHARACTERS {
                if id.chars().count() > OSV_ID_MAX_CHARACTERS {
                    panic!(
                        "ID {} has more characters ({}) than the maximum set to the database ({})",
                        id,
                        id.chars().count(),
                        OSV_ID_MAX_CHARACTERS
                    );
                }
            }

            let generalized = GeneralizedCsvRecord::from_osv(osv_record);
            csv_writer.write_record(&generalized.as_row())?;
            buffer.clear();
            bar.set_position((file_i + 1) as u64);
            processed_file_count += 1;
        }
    }

    csv_writer.flush()?;

    bar.finish();
    pg_bars.remove(&bar);
    log::info!(
        "Finished. Total processing time: {:?}",
        processing_start.elapsed()
    );

    Ok(processed_file_count)
}

/// OSV timestamp is updated to today's date at midnight (UTC) in RFC3339 format using `store_key`.
pub fn update_osv_timestamp() -> Result<(), String> {
    let today = Utc::now().date_naive();
    let midnight = today.and_hms_opt(0, 0, 0).unwrap();
    let rfc3339_midnight = midnight.and_utc().to_rfc3339();
    store_key(TIMESTAMP_FILE_NAME.to_string(), rfc3339_midnight);
    Ok(())
}

/// Updates the OSV database by checking for missing or stale OSV entries and then
/// fetching and inserting updated records.
///
/// This function performs the following steps:
///
/// 1. **Load Timestamp:**
///    Loads the stored OSV timestamp and parses it as a `DateTime`. This timestamp
///    represents the minimum modification date for records in the database.
///
/// 2. **Parse Ecosystems:**
///    Retrieves ecosystem sitemaps from the OSV index (using `first_parse`) and then
///    parses each ecosystem using `ecosystem_parse`, merging the results into a single
///    `HashMap` keyed by entry ID.
///
/// 3. **Database Comparison:**
///    Obtains a database connection and constructs a list of `EntryInput` items (ID and
///    modification date) from the collected entries. It serializes these into JSON and
///    queries the database for entries that are missing or have an older `"lastmod"` value.
///
/// 4. **Update Process:**
///    For each missing or stale entry, if the input timestamp is more recent (or the entry
///    does not exist), it fetches updated data via `parse_again`. If many updates are needed,
///    the process is throttled using asynchronous sleep. Outdated entries are removed from
///    the database, and new/updated records are inserted.
///
/// # Returns
///
/// * `Ok(())` if the update process completes successfully.
/// * An error of type `Box<dyn std::error::Error>` if any operation fails (e.g., I/O, parsing,
///   or database errors).
///
/// # Errors
///
/// This function uses the `?` operator to propagate errors encountered during:
/// - Reading the stored OSV timestamp.
/// - Parsing dates and XML.
/// - Database connection and operations.
/// - Fetching and parsing updated OSV data.
pub async fn scrape_osv_update() -> Result<(), Box<dyn std::error::Error>> {
    // Load the stored OSV timestamp.
    let load_osv_timestamp = read_key(TIMESTAMP_FILE_NAME.to_string())
        .ok_or_else(|| format!("OSV timestamp not found for key {}", TIMESTAMP_FILE_NAME))?;
    info!("Loading OSV timestamp: {}", load_osv_timestamp);
    let osv_timestamp = DateTime::parse_from_rfc3339(load_osv_timestamp.as_str())?;
    info!("Using OSV timestamp: {}", osv_timestamp);

    // Parse the OSV index and filter ecosystem sitemaps newer than the stored timestamp.
    let ecosystems = match sitemap_parse(INDEX, osv_timestamp).await {
        Ok(ecosystems) => ecosystems,
        Err(e) => {
            error!("Error in retrieving ecosystems {}", e);
            return Err(e);
        }
    };
    let mut need_to_add = HashMap::new();
    for ecosystem in &ecosystems {
        let entries = match ecosystem_parse(&ecosystem.loc, osv_timestamp).await {
            Ok(entries) => entries,
            Err(e) => {
                error!("Error in retrieving ecosystems {}", e);
                return Err(e);
            }
        };
        need_to_add.extend(entries);
    }

    // Obtain a database connection.
    let db_conn = match get_db_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Issue with db connection: {}", e);
            return Ok(()); // Early exit if DB connection fails.
        }
    };

    // Build a list of entry inputs from the aggregated data.
    let entry_inputs: Vec<EntryInput> = need_to_add
        .iter()
        .map(|(id, sitemap)| EntryInput {
            id: id.clone(),
            modified: sitemap.lastmod.to_string(),
        })
        .collect();

    let entry_inputs_json: Value =
        serde_json::to_value(entry_inputs).expect("Failed to serialize entries to JSON");

    // Query the database for entries that are missing or stale.
    let missing_ids: Vec<EntryStatus> = find_missing_or_stale_entries_by_id(
        &db_conn,
        OSV_TABLE_NAME,
        OSV_DATA_COLUMN_NAME,
        entry_inputs_json,
    )
    .await?;
    info!("Found {} entries needing update", missing_ids.len());

    let mut osvs = Vec::new();
    let mut remove = Vec::new();

    // Process each missing or stale entry.
    for miss in &missing_ids {
        if miss.status == "Input is more recent" {
            remove.push(miss);
        }
        if miss.status == "Input is more recent" || miss.status == "Entry does not exist" {
            // Throttle requests if a large number of updates is required.
            if missing_ids.len() > 100 {
                sleep(Duration::from_secs(2)).await;
            }
            // Fetch updated OSV data.
            let sitemap = need_to_add
                .get(&miss.id)
                .ok_or_else(|| format!("No entry found in need_to_add for id: {}", miss.id))?;
            let osv = match fetch_osv_details(&sitemap.loc).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Error in fecthing osv details: {}", e);
                    return Err(e.into());
                }
            };
            osvs.push(osv);
        }
    }

    // Remove outdated records if necessary.
    if !remove.is_empty() {
        info!("Removing {} outdated items", remove.len());
        remove_entries_id(&db_conn, OSV_TABLE_NAME, OSV_DATA_COLUMN_NAME, ID, &remove).await?;
    }

    // Insert the updated OSV records into the database.
    insert_parallel(&db_conn, OSV_TABLE_NAME, OSV_DATA_COLUMN_NAME, &osvs).await?;

    Ok(())
}
/// Asynchronously parses a sitemap XML from the specified URL and returns all sitemap entries that have a
/// `lastmod` date later than the provided `min_timestamp`.
///
/// # Arguments
///
/// * `url` - A string slice representing the URL of the sitemap XML to parse.
/// * `min_timestamp` - A `DateTime<FixedOffset>` representing the minimum modification date; only entries
///                     with a `lastmod` greater than this timestamp will be returned.
///
/// # Returns
///
/// * `Result<Vec<Sitemap>, Box<dyn std::error::Error>>` - On success, returns a vector of `Sitemap` entries.
///   If any error occurs (e.g. HTTP request, XML parsing, or date parsing error), it is returned as a boxed error.
///
/// # Errors
///
/// This function will return an error if:
///
/// - The HTTP request to fetch the XML fails.
/// - The XML response text cannot be retrieved.
/// - The XML cannot be parsed.
/// - Any of the date strings cannot be parsed into a `DateTime<FixedOffset>`.
///
/// # Example
///
/// ```rust,no_run
/// # use chrono::{DateTime, FixedOffset};
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let url = "https://example.com/sitemap.xml";
/// let min_timestamp = DateTime::parse_from_rfc3339("2025-01-01T00:00:00+00:00")?;
/// let sitemaps = sitemap_parse(url, min_timestamp).await?;
/// println!("Found {} sitemap entries.", sitemaps.len());
/// # Ok(())
/// # }
/// ```
pub async fn sitemap_parse(
    url: &str,
    min_timestamp: DateTime<FixedOffset>,
) -> Result<Vec<Sitemap>, Box<dyn std::error::Error>> {
    let client = Client::new();

    // Fetch the sitemap XML.
    let response = client.get(url).send().await?;
    let xml_text = response.text().await?;

    let mut reader = Reader::from_str(&xml_text);
    reader.config_mut().trim_text(true);
    let mut sitemaps = Vec::new();
    let mut current: Option<Sitemap> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"sitemap" => {
                    // Begin a new sitemap entry with a default lastmod.
                    current = Some(Sitemap {
                        loc: String::new(),
                        lastmod: DateTime::parse_from_rfc3339("1970-01-01T00:00:00+00:00")?,
                    });
                }
                b"loc" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <loc>...</loc>.
                        if let Ok(Event::Text(e)) = reader.read_event() {
                            sitemap.loc = e.unescape()?.into_owned();
                        }
                    }
                }
                b"lastmod" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <lastmod>...</lastmod>.
                        if let Ok(Event::Text(e)) = reader.read_event() {
                            let text = e.unescape()?.into_owned();
                            sitemap.lastmod = DateTime::parse_from_rfc3339(&text)?;
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(ref e)) => {
                if e.name().as_ref() == b"sitemap" {
                    // End of a sitemap entry.
                    if let Some(sitemap) = current.take() {
                        if sitemap.lastmod > min_timestamp {
                            sitemaps.push(sitemap);
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(Box::new(e)),
            _ => {}
        }
    }

    Ok(sitemaps)
}

/// Parses a sitemap index XML from a given URL and returns a filtered map of sitemaps.
///
/// This asynchronous function fetches an XML sitemap from the provided `url`, then parses the XML to
/// extract each `<url>` element. For every `<url>` element, the function extracts the location (`<loc>`)
/// and the last modification date (`<lastmod>`). Only those sitemaps with a `lastmod` greater than the
/// provided `min_timestamp` are included in the resulting `HashMap`.
///
/// # Arguments
///
/// * `url` - A string slice representing the URL where the sitemap XML is located.
/// * `min_timestamp` - A `DateTime<FixedOffset>` value used to filter out sitemap entries with an older
///   modification date.
///
/// # Returns
///
/// On success, returns a `HashMap` where the keys are titles extracted from the sitemap URL (using
/// the `extract_title` function) and the values are `Sitemap` structs. If an error occurs during the
/// HTTP request, XML parsing, or date parsing, a boxed error is returned.
///
/// # Errors
///
/// This function will return an error in any of the following cases:
///
/// * The HTTP GET request fails.
/// * The response body cannot be converted to text.
/// * The XML cannot be parsed correctly.
/// * The `<lastmod>` element contains an invalid datetime format.
///
/// # Example
///
/// ```no_run
/// # use chrono::{DateTime, FixedOffset};
/// # use std::collections::HashMap;
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let url = "https://example.com/sitemap.xml";
/// let min_timestamp = DateTime::parse_from_rfc3339("2020-01-01T00:00:00+00:00")?;
/// let sitemaps: HashMap<String, Sitemap> = ecosystem_parse(url, min_timestamp).await?;
/// // Process the sitemaps as needed.
/// # Ok(()) }
/// ```
///
async fn ecosystem_parse(
    url: &str,
    min_timestamp: DateTime<FixedOffset>,
) -> Result<HashMap<String, Sitemap>, Box<dyn Error>> {
    let client = Client::new();
    let response = client.get(url).send().await?;
    let xml_text = response.text().await?;

    let mut reader = Reader::from_str(&xml_text);
    reader.config_mut().trim_text(true);

    let mut sitemaps = HashMap::new();
    let mut current: Option<Sitemap> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"urlset" => {
                    // Skip the <urlset> element.
                }
                b"url" => {
                    // Begin a new entry for a URL.
                    current = Some(Sitemap {
                        loc: String::new(),
                        // Default date; will be overwritten by <lastmod>
                        lastmod: DateTime::parse_from_rfc3339("1970-01-01T00:00:00+00:00")?,
                    });
                }
                b"loc" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <loc>...</loc>.
                        if let Ok(Event::Text(e)) = reader.read_event() {
                            sitemap.loc = e.unescape()?.into_owned();
                        }
                    }
                }
                b"lastmod" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <lastmod>...</lastmod>.
                        if let Ok(Event::Text(e)) = reader.read_event() {
                            let text = e.unescape()?.into_owned();
                            sitemap.lastmod = DateTime::parse_from_rfc3339(&text)?;
                        }
                    }
                }
                other => {
                    // Log unhandled tags for debugging purposes.
                    eprintln!("Unhandled start tag: {}", String::from_utf8_lossy(other));
                }
            },
            Ok(Event::End(ref e)) => {
                if e.name().as_ref() == b"url" {
                    if let Some(sitemap) = current.take() {
                        if sitemap.lastmod > min_timestamp {
                            if let Some(title) = extract_title(&sitemap.loc) {
                                sitemaps.insert(title.to_string(), sitemap);
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            _ => {}
        }
    }

    Ok(sitemaps)
}

/// Extracts the title from a URL by returning the last non-empty segment after splitting by `/`.
///
/// This function splits the given URL on the '/' character and returns the first non-empty segment
/// found in reverse order. This means that if the URL ends with a '/', the function will skip the
/// empty segment and return the preceding non-empty part.
///
/// # Examples
///
/// ```rust
/// let url = "https://example.com/vulnerability/CVE-2024-26256";
/// assert_eq!(extract_title(url), Some("CVE-2024-26256"));
///
/// // Even if the URL ends with a slash, it still returns the correct title.
/// let url_with_slash = "https://example.com/vulnerability/CVE-2024-26256/";
/// assert_eq!(extract_title(url_with_slash), Some("CVE-2024-26256"));
///
/// // For a URL with no '/', it returns the whole string if non-empty.
/// let simple = "CVE-2024-26256";
/// assert_eq!(extract_title(simple), Some("CVE-2024-26256"));
/// ```
///
/// # Returns
///
/// * `Some(&str)` - The last non-empty segment of the URL.
/// * `None` - If no non-empty segment is found (e.g. an empty string).
fn extract_title(url: &str) -> Option<&str> {
    url.rsplit('/').find(|segment| !segment.is_empty())
}

/// Asynchronously fetches an HTML page from the given URL, extracts a JSON data URL from it,
/// fetches the JSON from that URL, and deserializes it into an `OSV` struct.
///
/// # Arguments
///
/// * `url` - A string slice that holds the URL of the HTML page to fetch.
///
/// # Returns
///
/// * `Ok(OSV)` if the JSON data is successfully fetched and parsed.
/// * `Err(ParseError)` if any error occurs during the process (HTTP, HTML parsing, or JSON deserialization).
async fn fetch_osv_details(url: &str) -> Result<OSVGeneralized, ParseError> {
    info!("Fetching HTML from: {}", url);
    let client = Client::new();

    // Fetch the HTML page.
    let response = client.get(url).send().await?;
    let html_text = response.text().await?;

    // Parse the HTML document.
    let document = Html::parse_document(&html_text);

    // Define selectors for dt and dd elements.
    let dt_selector = Selector::parse("dl.vulnerability-details dt")
        .map_err(|e| ParseError::Html(format!("Invalid dt selector: {}", e)))?;
    let dd_selector = Selector::parse("dl.vulnerability-details dd")
        .map_err(|e| ParseError::Html(format!("Invalid dd selector: {}", e)))?;

    let dt_elements: Vec<_> = document.select(&dt_selector).collect();
    let dd_elements: Vec<_> = document.select(&dd_selector).collect();

    // Find the JSON Data URL by iterating over paired dt and dd elements.
    let mut json_url: Option<String> = None;
    for (dt, dd) in dt_elements.iter().zip(dd_elements.iter()) {
        let dt_text = dt.text().collect::<Vec<_>>().join(" ").trim().to_string();
        if dt_text == "JSON Data" {
            let a_selector = Selector::parse("a")
                .map_err(|e| ParseError::Html(format!("Invalid a selector: {}", e)))?;
            if let Some(a) = dd.select(&a_selector).next() {
                json_url = a.value().attr("href").map(|s| s.to_string());
            }
            break;
        }
    }

    let json_url = json_url.ok_or(ParseError::MissingJsonUrl)?;
    info!("Found JSON URL: {}", json_url);

    // Fetch the JSON data from the extracted URL.
    let json_response = client.get(&json_url).send().await?;
    let json_text = json_response.text().await?;

    // Deserialize the JSON into the OSV struct.
    let osv: OSVGeneralized = serde_json::from_str(&json_text)?;
    Ok(osv)
}
