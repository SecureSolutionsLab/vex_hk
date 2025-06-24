use std::{collections::HashMap, time::Duration};

use chrono::{DateTime, Utc};
use scraper::Selector;

use super::ParseError;
use crate::{
    config::Config,
    db_api::structs::{EntryInput, EntryStatus},
    osv_schema::OSVGeneralized,
    scrape_mod::structs::Sitemap,
    state::ScraperState,
};

/// See [scrape_osv_full] for more information
///
/// This function saves scraper state
pub async fn manual_update_and_save_state(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    _pg_bars: &indicatif::MultiProgress,
    state: &mut ScraperState,
) -> anyhow::Result<()> {
    if !state.osv.initialized {
        return Err(anyhow::anyhow!(
            "OSV is not initialized. Perform a full download first."
        ));
    }

    let start_time = Utc::now();
    let Some(last_timestamp) = state.osv.last_update_timestamp else {
        return Err(anyhow::anyhow!(
            "last_timestamp is missing. This may be a bug. Perform a full redownload."
        ));
    };

    scrape_osv_update(config, client, db_connection, last_timestamp).await?;
    state.save_osv(config, start_time);
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
pub async fn scrape_osv_update(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    last_timestamp: DateTime<Utc>,
) -> anyhow::Result<()> {
    // Parse the OSV index and filter ecosystem sitemaps newer than the stored timestamp.
    let ecosystems = match sitemap_parse(client, &config.osv.index, last_timestamp).await {
        Ok(ecosystems) => ecosystems,
        Err(e) => {
            log::error!("Error in retrieving ecosystems {e}");
            return Err(e);
        }
    };
    let mut need_to_add = HashMap::new();
    for ecosystem in &ecosystems {
        let entries = match ecosystem_parse(client, &ecosystem.loc, last_timestamp).await {
            Ok(entries) => entries,
            Err(e) => {
                log::error!("Error in retrieving ecosystems {e}");
                return Err(e);
            }
        };
        need_to_add.extend(entries);
    }

    // Build a list of entry inputs from the aggregated data.
    let entry_inputs: Vec<EntryInput> = need_to_add
        .iter()
        .map(|(id, sitemap)| EntryInput {
            id: id.clone(),
            modified: sitemap.lastmod.to_string(),
        })
        .collect();

    let entry_inputs_json: serde_json::Value = serde_json::to_value(entry_inputs)?;

    // Query the database for entries that are missing or stale.
    let missing_ids: Vec<EntryStatus> =
        crate::db_api::query_db::find_missing_or_stale_entries_by_id(
            db_connection,
            &config.osv.table_name,
            "data",
            entry_inputs_json,
        )
        .await?;
    log::info!("Found {} entries needing update", missing_ids.len());

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
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            // Fetch updated OSV data.
            let sitemap = need_to_add
                .get(&miss.id)
                .ok_or_else(|| format!("No entry found in need_to_add for id: {}", miss.id))
                .map_err(|str| anyhow::anyhow!(str))?;
            let osv = match fetch_osv_details(client, &sitemap.loc).await {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Error in fecthing osv details: {e}");
                    return Err(e.into());
                }
            };
            osvs.push(osv);
        }
    }

    println!("to remove: {remove:#?}");
    println!("to add: {osvs:#?}");

    // // Remove outdated records if necessary.
    // if !remove.is_empty() {
    //     log::info!("Removing {} outdated items", remove.len());
    //     crate::db_api::delete::remove_entries_id(&db_conn, OSV_TABLE_NAME, OSV_DATA_COLUMN_NAME, ID, &remove).await?;
    // }

    // // Insert the updated OSV records into the database.
    // insert_parallel(&db_conn, OSV_TABLE_NAME, OSV_DATA_COLUMN_NAME, &osvs).await?;

    Ok(())
}

/// Asynchronously parses a sitemap XML from the specified URL and returns all sitemap entries that have a
/// `lastmod` date later than the provided `min_timestamp`.
pub async fn sitemap_parse(
    client: &reqwest::Client,
    url: &str,
    min_timestamp: DateTime<Utc>,
) -> anyhow::Result<Vec<Sitemap>> {
    // Fetch the sitemap XML.
    let response = client.get(url).send().await?;
    let xml_text = response.text().await?;

    let mut reader = quick_xml::Reader::from_str(&xml_text);
    reader.config_mut().trim_text(true);
    let mut sitemaps = Vec::new();
    let mut current: Option<Sitemap> = None;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e)) => match e.name().as_ref() {
                b"sitemap" => {
                    // Begin a new sitemap entry with a default lastmod.
                    current = Some(Sitemap::default());
                }
                b"loc" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <loc>...</loc>.
                        if let Ok(quick_xml::events::Event::Text(e)) = reader.read_event() {
                            sitemap.loc = e.unescape()?.into_owned();
                        }
                    }
                }
                b"lastmod" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <lastmod>...</lastmod>.
                        if let Ok(quick_xml::events::Event::Text(e)) = reader.read_event() {
                            let text = e.unescape()?.into_owned();
                            sitemap.lastmod = DateTime::parse_from_rfc3339(&text)?;
                        }
                    }
                }
                _ => {}
            },
            Ok(quick_xml::events::Event::End(ref e)) => {
                if e.name().as_ref() == b"sitemap" {
                    // End of a sitemap entry.
                    if let Some(sitemap) = current.take() {
                        if sitemap.lastmod > min_timestamp {
                            sitemaps.push(sitemap);
                        }
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return anyhow::Result::Err(e.into()),
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
async fn ecosystem_parse(
    client: &reqwest::Client,
    url: &str,
    min_timestamp: DateTime<Utc>,
) -> anyhow::Result<HashMap<String, Sitemap>> {
    let response = client.get(url).send().await?;
    let xml_text = response.text().await?;

    let mut reader = quick_xml::Reader::from_str(&xml_text);
    reader.config_mut().trim_text(true);

    let mut sitemaps = HashMap::new();
    let mut current: Option<Sitemap> = None;

    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(ref e)) => match e.name().as_ref() {
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
                        if let Ok(quick_xml::events::Event::Text(e)) = reader.read_event() {
                            sitemap.loc = e.unescape()?.into_owned();
                        }
                    }
                }
                b"lastmod" => {
                    if let Some(ref mut sitemap) = current {
                        // Read the text content inside <lastmod>...</lastmod>.
                        if let Ok(quick_xml::events::Event::Text(e)) = reader.read_event() {
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
            Ok(quick_xml::events::Event::End(ref e)) => {
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
            Ok(quick_xml::events::Event::Eof) => break,
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
// todo: any reason this doesn't just use the api?
async fn fetch_osv_details(
    client: &reqwest::Client,
    url: &str,
) -> Result<OSVGeneralized, ParseError> {
    log::info!("Fetching HTML from: {url}");

    // Fetch the HTML page.
    let response = client.get(url).send().await?;
    let html_text = response.text().await?;

    // Parse the HTML document.
    let document = scraper::Html::parse_document(&html_text);

    // Define selectors for dt and dd elements.
    let dt_selector = Selector::parse("dl.vulnerability-details dt")
        .map_err(|e| ParseError::Html(format!("Invalid dt selector: {e}")))?;
    let dd_selector = Selector::parse("dl.vulnerability-details dd")
        .map_err(|e| ParseError::Html(format!("Invalid dd selector: {e}")))?;

    let dt_elements: Vec<_> = document.select(&dt_selector).collect();
    let dd_elements: Vec<_> = document.select(&dd_selector).collect();

    // Find the JSON Data URL by iterating over paired dt and dd elements.
    let mut json_url: Option<String> = None;
    for (dt, dd) in dt_elements.iter().zip(dd_elements.iter()) {
        let dt_text = dt.text().collect::<Vec<_>>().join(" ").trim().to_string();
        if dt_text == "JSON Data" {
            let a_selector = Selector::parse("a")
                .map_err(|e| ParseError::Html(format!("Invalid a selector: {e}")))?;
            if let Some(a) = dd.select(&a_selector).next() {
                json_url = a.value().attr("href").map(|s| s.to_string());
            }
            break;
        }
    }

    let json_url = json_url.ok_or(ParseError::MissingJsonUrl)?;
    log::info!("Found JSON URL: {json_url}");

    // Fetch the JSON data from the extracted URL.
    let json_response = client.get(&json_url).send().await?;
    let json_text = json_response.text().await?;

    // Deserialize the JSON into the OSV struct.
    let osv: OSVGeneralized = serde_json::from_str(&json_text)?;
    Ok(osv)
}
