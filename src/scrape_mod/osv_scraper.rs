use chrono::{DateTime, FixedOffset, Utc};
use log::{error, info};
use quick_xml::{events::Event, Reader};
use reqwest::Client;
use scraper::{Html, Selector};
use serde_json::Value;
use std::{
    cmp::min,
    collections::HashMap,
    error::Error,
    fs,
    fs::File,
    io::{Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{sync::Mutex, time::sleep};
use zip::ZipArchive;

use crate::{
    db_api::{
        consts::{ID, OSV_COLUMN, OSV_TABLE},
        db_connection::get_db_connection,
        delete::remove_entries_id,
        insert::insert_parallel,
        query_db::find_missing_or_stale_entries_by_id,
        structs::{EntryInput, EntryStatus},
    },
    scrape_mod::{
        consts::{OSV_BATCH_SIZE, OSV_INDEX, OSV_TIMESTAMP, TOTAL_THREADS},
        structs::{Sitemap, OSV},
    },
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

/// Downloads the OSV ZIP archive, processes its JSON files concurrently, and inserts the parsed OSV records
/// into the database in batches. After processing, the OSV timestamp is updated and the local archive file is removed.
///
/// # Overview
///
/// 1. **Download:**
///    Downloads the ZIP archive from a remote URL and saves it locally as `"all.zip"`.
///
/// 2. **Processing:**
///    Opens the ZIP archive and processes its JSON files concurrently. The archive is divided among multiple tasks,
///    where each task:
///      - Obtains a database connection.
///      - Reads its assigned range of files while holding a lock only during file access.
///      - Parses JSON files into `OSV` records and accumulates them into batches.
///      - Inserts a batch of records into the database using `insert_parallel` once a certain chunk size is reached.
///
/// 3. **Finalization:**
///    After all tasks complete:
///      - The OSV timestamp is updated to today's date at midnight (UTC) in RFC3339 format using `store_key`.
///      - The local ZIP file is removed.
///
/// # Returns
///
/// * `Ok(())` if the entire process completes successfully.
/// * An error of type `Box<dyn std::error::Error>` if any step fails (e.g. network, I/O, parsing, or database errors).
///
/// # Errors
///
/// This function uses the `?` operator to propagate errors encountered during:
/// - Downloading the ZIP file.
/// - Writing to or reading from the file system.
/// - Extracting the ZIP archive.
/// - Parsing JSON records.
/// - Database insertion operations.
///
/// # Dependencies
///
/// This function relies on the following crates:
/// - `reqwest` for HTTP requests.
/// - `zip` for ZIP archive handling.
/// - `chrono` for date and time manipulation.
/// - `tokio` for asynchronous runtime and synchronization primitives.
/// - `sqlx` (assumed) for database operations.
/// - `log` for logging.
pub async fn scrape_osv() -> Result<(), Box<dyn std::error::Error>> {
    // Start the overall timer.
    let start = Instant::now();
    let file_path = "all.zip";
    let url = "https://storage.googleapis.com/osv-vulnerabilities/all.zip";

    // Download the ZIP archive.
    info!("Downloading file from {}...", url);
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    info!("Download complete.");

    // Save the downloaded bytes to a local file.
    {
        let mut file = File::create(file_path)?;
        file.write_all(&bytes)?;
    }
    info!("File saved locally as: {}", file_path);
    info!("Download time: {:?}", start.elapsed());

    // Start processing timer.
    let processing_start = Instant::now();

    // Open the ZIP archive and wrap it in an Arc+Mutex for concurrent access.
    let file = File::open(file_path)?;
    let archive = Arc::new(Mutex::new(ZipArchive::new(file)?));

    // Get the total number of files in the archive.
    let total_files = {
        let archive = archive.lock().await;
        archive.len()
    };
    info!("Total number of files in archive: {}", total_files);

    // Calculate the batch size for each task (ceiling division).
    let batch_size = (total_files + TOTAL_THREADS as usize - 1) / TOTAL_THREADS as usize;
    // Number of OSV records to accumulate before insertion.

    // Create a vector to hold our asynchronous tasks.
    let mut tasks = Vec::with_capacity(TOTAL_THREADS as usize);

    // Spawn tasks to process different parts of the archive concurrently.
    for task_id in 0..TOTAL_THREADS as usize {
        let archive_clone = Arc::clone(&archive);
        let start_index = task_id * batch_size;
        let end_index = min(start_index + batch_size, total_files);

        let task = tokio::spawn(async move {
            info!(
                "Task {} processing files {} to {}",
                task_id,
                start_index,
                end_index - 1
            );

            // Get a database connection for this task.
            let db_conn = match get_db_connection().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Task {}: Error obtaining DB connection: {}", task_id, e);
                    return;
                }
            };

            let mut batch_results = Vec::with_capacity(OSV_BATCH_SIZE);

            for i in start_index..end_index {
                // Acquire the lock only while reading a single file.
                {
                    let mut archive = archive_clone.lock().await;
                    let mut file = match archive.by_index(i) {
                        Ok(file) => file,
                        Err(err) => {
                            error!(
                                "Task {}: Error retrieving file at index {}: {:?}",
                                task_id, i, err
                            );
                            continue;
                        }
                    };

                    let file_name = file.name().to_string();
                    // Process only JSON files.
                    if file_name.ends_with(".json") {
                        let mut json_content = String::new();
                        if let Err(err) = file.read_to_string(&mut json_content) {
                            error!(
                                "Task {}: Error reading file {}: {:?}",
                                task_id, file_name, err
                            );
                        } else if let Ok(osv_record) = serde_json::from_str::<OSV>(&json_content) {
                            batch_results.push(osv_record);
                        } else {
                            error!(
                                "Task {}: Error parsing JSON from file {}",
                                task_id, file_name
                            );
                        }
                    }
                } // Release the lock immediately.

                // Insert a batch if the chunk size is reached.
                if batch_results.len() >= OSV_BATCH_SIZE {
                    if let Err(err) =
                        insert_parallel(&db_conn, OSV_TABLE, OSV_COLUMN, &batch_results).await
                    {
                        error!("Task {}: Error inserting batch: {:?}", task_id, err);
                    }
                    batch_results.clear();
                }
            }

            // Insert any remaining records.
            if !batch_results.is_empty() {
                if let Err(err) =
                    insert_parallel(&db_conn, OSV_TABLE, OSV_COLUMN, &batch_results).await
                {
                    error!("Task {}: Error inserting final batch: {:?}", task_id, err);
                }
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete.
    for handle in tasks {
        if let Err(err) = handle.await {
            error!("A task failed: {:?}", err);
        }
    }

    info!("Total processing time: {:?}", processing_start.elapsed());

    // Update the OSV timestamp to today's date at midnight (UTC) in RFC3339 format.
    let today = Utc::now().date_naive();
    let midnight = today
        .and_hms_opt(0, 0, 0)
        .ok_or("Failed to construct midnight timestamp")?;
    let rfc3339_midnight = midnight.and_utc().to_rfc3339();
    store_key(OSV_TIMESTAMP.to_string(), rfc3339_midnight);

    // Remove the local ZIP file.
    fs::remove_file(file_path)?;
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
    let load_osv_timestamp = read_key(OSV_TIMESTAMP.to_string())
        .ok_or_else(|| format!("OSV timestamp not found for key {}", OSV_TIMESTAMP))?;
    info!("Loading OSV timestamp: {}", load_osv_timestamp);
    let osv_timestamp = DateTime::parse_from_rfc3339(load_osv_timestamp.as_str())?;
    info!("Using OSV timestamp: {}", osv_timestamp);

    // Parse the OSV index and filter ecosystem sitemaps newer than the stored timestamp.
    let ecosystems = match sitemap_parse(OSV_INDEX, osv_timestamp).await {
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
    let missing_ids: Vec<EntryStatus> =
        find_missing_or_stale_entries_by_id(&db_conn, OSV_TABLE, OSV_COLUMN, entry_inputs_json)
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
        remove_entries_id(&db_conn, OSV_TABLE, OSV_COLUMN, ID, &remove).await?;
    }

    // Insert the updated OSV records into the database.
    insert_parallel(&db_conn, OSV_TABLE, OSV_COLUMN, &osvs).await?;

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
async fn fetch_osv_details(url: &str) -> Result<OSV, ParseError> {
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
    let osv: OSV = serde_json::from_str(&json_text)?;
    Ok(osv)
}
