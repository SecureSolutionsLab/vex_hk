use chrono::Utc;

use crate::utils::config::{read_key, store_key};

/// Retrieves the timestamp for the last scrape from the configuration file.
///
/// This function fetches the value associated with the `last_timestamp` key from the
/// configuration file. If the key is not found, it generates a new timestamp based
/// on the current time, stores it in the configuration file, and returns it. The
/// timestamp is necessary for requesting new CVEs or updating existing data from
/// the NVD database.
///
/// # Returns
/// - A `String` representing the last scrape timestamp in the format `Y-m-dTH:M:SZ`.
///
/// # Behavior
/// - Reads the `last_timestamp` value from the configuration file using `read_config`.
/// - If the value is missing, generates a new timestamp using [`instant_to_datetime`],
///   stores it in the configuration file with the key `last_timestamp`, and returns it.
///
/// # Example
/// ```no_run
/// let last_crawl_timestamp = get_timestamp();
/// println!("Last crawl timestamp: {}", last_crawl_timestamp);
/// ```
///
/// # Dependencies
/// - Requires the configuration file to be accessible for reading and writing.
/// - Relies on [`instant_to_datetime`] for generating new timestamps.
///
/// # Errors
/// - Panics if reading or writing to the configuration file fails.
pub fn get_timestamp() -> String {
    let value = read_key("last_timestamp".to_string());

    let timestamp = if value.is_none() {
        let local_timestamp = instant_to_datetime();
        store_key("last_timestamp".to_string(), local_timestamp.clone());
        local_timestamp
    } else {
        value.unwrap()
    };
    timestamp
}

/// Converts the current time to a datetime string.
///
/// This function generates a timestamp representing the current time in the format
/// `Y-m-dTH:M:SZ` as per the guidelines stipulated by the NVD. The timestamp is
/// formatted to include milliseconds and the UTC timezone.
///
/// # Returns
/// - A `String` representing the current time in the format `Y-m-dTH:M:SZ`.
///
/// # Format
/// - The returned string follows the format `%Y-%m-%dT%H:%M:%S%.3fZ`:
///   - `Y`: Year (e.g., `2024`)
///   - `m`: Month (e.g., `01`)
///   - `d`: Day (e.g., `12`)
///   - `T`: Literal `T` separating the date and time.
///   - `H`: Hour (e.g., `15` for 3 PM UTC).
///   - `M`: Minutes (e.g., `45`).
///   - `S`: Seconds (e.g., `30`).
///   - `%.3f`: Milliseconds (e.g., `123`).
///   - `Z`: Literal `Z` indicating UTC timezone.
///
/// # Example
/// ```
/// let datetime = instant_to_datetime();
/// println!("Current timestamp: {}", datetime);
/// ```
///
/// # Dependencies
/// - Uses the `chrono` crate to get the current UTC time and format it.
pub fn instant_to_datetime() -> String {
    let current_time = Utc::now();
    let formatted_date = current_time.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    formatted_date.to_string()
}
