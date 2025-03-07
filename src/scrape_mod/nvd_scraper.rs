use crate::scrape_mod::consts::{
    API_KEY_NVD, MIN_RESULTS_PER_THREAD, SERVICE_SLEEP, TOTAL_PAGE, TOTAL_THREADS,
};
use crate::scrape_mod::structs::{CPEMatch, FilteredCVE, HasId, Metrics, NVDCve, Nodes, NvdResponse, Weaknesses, EPSS};
use crate::db_api::consts::{CVE_COLUMN, CVE_TABLE, ID};
use crate::db_api::db_connection::get_db_connection;
use crate::db_api::delete::remove_entries_id;
use crate::db_api::insert::insert_parallel_cve;
use log::{error, info, warn};
use reqwest::{Client, Response};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use std::time::{Duration, Instant};
use std::usize;
use thiserror::Error;
use tokio::time::sleep;

/// Fetches the total number of CVEs matching a query from the NVD API.
///
/// This function constructs a URL using the provided query string and makes
/// a request to the NVD API to determine the total number of CVEs matching the query.
/// The total count is returned for further processing.
///
/// # Parameters
/// - `query_count`: A string slice containing the query parameters to be sent to the NVD API.
///
/// # Returns
/// - `Ok(u32)`: The total number of CVEs matching the query.
/// - `Err(Box<dyn std::error::Error>)`: If an error occurs during the request or response parsing.
///
/// # Behavior
/// - Constructs a full URL using the base NVD API endpoint and the `query_count`.
/// - Makes a GET request to the API and parses the response into a `NvdResponse` struct.
/// - Logs the time taken to complete the query and the total results returned.
///
/// # Errors
/// - Returns an error if the request to the NVD API fails or if the response cannot be parsed.
///
/// # Example
/// ```no_run
/// use log::{error, info};
/// let query = "cpeName=cpe:/o:debian:debian_linux";
/// match query_nvd_cvecount(query).await {
///     Ok(count) => info!("Total CVEs: {}", count),
///     Err(e) => error!("Error fetching CVE count: {}", e),
/// }
/// ```
pub async fn query_nvd_cvecount(query_count: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/";
    let full_url = format!("{}{}&resultsPerPage=1", base_url, query_count);

    let start_time = Instant::now();

    // Make the API request
    let response = match request_nvd(&*full_url).await {
        Ok(response) => {
            response
        }
        Err(e) => {
            error!("Network error occurred: {}", e);
            return Ok(0);
        }
    };

    let count_response: NvdResponse = match response.json::<NvdResponse>().await {
        Ok(parsed) => parsed,
        Err(e) => {
            error!("Failed to parse response: {}", e);
            return Ok(0);
        }
    };


    info!(
        "Query completed in {:.2?}. Total results {}. URL: {}",
        start_time.elapsed(),
        count_response.total_results,
        full_url
    );

    Ok(count_response.total_results)
}

/// Queries the NVD API and inserts the retrieved CVE data into the database.
///
/// This function performs the following:
/// 1. Determines the number of threads to use based on the total CVE count.
/// 2. Spawns threads to process CVE data concurrently or sequentially based on the thread count.
/// 3. Each thread fetches and processes a subset of CVE data, inserting it into the database.
///
/// # Parameters
/// - `cve_count`: The total number of CVEs to process.
/// - `query`: A `String` representing the query parameters to be sent to the NVD API.
/// - `update`: A boolean indicating whether to update existing database entries.
///
/// # Behavior
/// - If `cve_count` warrants parallel processing, threads are spawned to handle different portions of the data.
/// - If sequential processing is chosen, only one thread is used.
/// - Logs the total execution time for the operation.
///
/// # Example
/// ```no_run
/// let cve_count = 1000;
/// let query = "cpeName=cpe:/o:debian:debian_linux".to_string();
/// scrape_nvd(cve_count, query, true).await;
/// ```
///
/// # Dependencies
/// - Relies on [`process_thread`] to handle API requests and data insertion.
///
/// # Errors
/// - Logs errors if any threads fail or encounter issues during processing.
pub async fn scrape_nvd(cve_count: u32, query: String, update: bool) {
    // Determine the number of threads to use
    let local_threads = if cve_count / TOTAL_PAGE > 1 || cve_count / MIN_RESULTS_PER_THREAD >= 1 {
        TOTAL_THREADS
    } else {
        1
    };

    if local_threads == 1 {
        info!("Executing sequentially");
    }

    let start_time = Instant::now();
    let mut thread_handles = Vec::new();

    // Spawn threads for parallel processing
    for thread_id in 0..local_threads {
        let query_clone = query.clone();

        thread_handles.push(tokio::spawn(async move {
            process_thread(thread_id, cve_count, local_threads, query_clone, update).await;
        }));
    }

    // Await all threads
    for handle in thread_handles {
        if let Err(e) = handle.await {
            error!("Error in thread: {:?}", e);
        }
    }

    info!("Total execution time: {:.2?}", start_time.elapsed());
}

/// Processes a portion of the CVE data in a single thread.
///
/// This function fetches and processes a subset of CVE data for the specified thread.
/// It handles API requests, parses the responses, and inserts the data into the database.
///
/// # Parameters
/// - `thread_id`: The ID of the thread.
/// - `cve_count`: The total number of CVEs to process.
/// - `local_threads`: The total number of threads used for processing.
/// - `query`: A `String` representing the query parameters for the NVD API.
/// - `update`: A boolean indicating whether to update existing database entries.
///
/// # Behavior
/// - Divides the total CVE count among threads and determines the number of pages to fetch.
/// - Makes API requests for the assigned pages using `body_verifier`.
/// - Parses the response and inserts the CVE data using `parse_response_insert`.
/// - Logs the time taken for the thread to complete its work.
///
/// # Example
/// This function is not typically called directly but is used internally by [`scrape_nvd`].
///
/// # Errors
/// - Logs errors if parsing or inserting data fails.
async fn process_thread(
    thread_id: u32,
    cve_count: u32,
    local_threads: u32,
    query: String,
    update: bool,
) {
    let start_time = Instant::now();

    let amount_per_thread = cve_count / local_threads;
    let rest_amount = cve_count % local_threads;

    let mut pages = amount_per_thread / TOTAL_PAGE;
    if amount_per_thread % TOTAL_PAGE != 0 {
        pages += 1;
    }

    for page in 0..pages {
        let mut end = TOTAL_PAGE;
        if page == pages - 1 {
            end = amount_per_thread % TOTAL_PAGE;
            if thread_id == local_threads - 1 {
                end += rest_amount;
            }
        }

        // Perform the API request
        let body = body_verifier(page, thread_id, amount_per_thread, query.clone(), end).await;

        // Parse and process the response
        match serde_json::from_str::<Value>(&body) {
            Ok(cves_body) => parse_response_insert(cves_body, end, update).await,
            Err(e) => {
                error!("Failed to parse response: {:?}", e);
                continue; // Skip this page
            }
        }
    }

    info!(
        "Thread {} completed in {:.2?}",
        thread_id,
        start_time.elapsed()
    );
}

/// Parses the response from the NVD API, filters and processes CVE data, and inserts it into the database.
///
/// This function processes CVEs from the given JSON response, filters and prepares the data for insertion,
/// updates or removes existing entries if necessary, and finally inserts the filtered data into the database.
///
/// # Parameters
/// - `cves_body`: A `Value` representing the JSON response containing CVE data.
/// - `end`: The number of CVEs to process from the response.
/// - `update`: A boolean indicating whether to update the database by removing existing entries before insertion.
///
/// # Errors
/// - Logs and skips CVEs that cannot be parsed or processed.
/// - Fails gracefully if the database connection cannot be established or if the insertion fails.
///
/// # Example
/// ```no_run
/// let cves_body = /* JSON response from NVD API */;
/// parse_response_insert(cves_body, 10, true).await;
/// ```
async fn parse_response_insert(cves_body: Value, end: u32, update: bool) {
    // Establish database connection
    let db_conn = match get_db_connection().await {
        Ok(db_conn) => db_conn,
        Err(_) => {
            error!("Failed to establish database connection");
            return;
        }
    };

    let now = Instant::now();
    let cves = &cves_body["vulnerabilities"];
    let mut cves_to_insert = Vec::new();
    let mut configuration = Vec::new();

    // Process CVEs
    for cve_index in 0..end as usize {
        let cve_nvd = serde_json::from_value::<NVDCve>(cves[cve_index]["cve"].to_owned());
        let (filter_cve, vec_configuration) = match cve_nvd {
            Ok(cve) => filter_and_insert(cve),
            Err(e) => {
                error!(
                    "Failed to parse CVE at index {}: {:?}. Error: {}",
                    cve_index, &cves[cve_index]["cve"], e
                );
                continue; // Skip this CVE and proceed
            }
        };

        // Avoid duplicate entries
        if !contains_cve(&cves_to_insert, &filter_cve).await {
            configuration.push((filter_cve.get_id().to_string(), vec_configuration));
            cves_to_insert.push(filter_cve);
        }
    }
    cves_to_insert = epss_score(cves_to_insert).await;

    // Update database if required
    if update {
        if let Err(e) = remove_entries_id(&db_conn, CVE_TABLE, CVE_COLUMN, ID, &cves_to_insert).await {
            error!("Failed to remove existing entries: {}", e);
        }
    }
    // Insert data into the database
    if let Err(e) = insert_parallel_cve(&db_conn, CVE_TABLE, CVE_COLUMN, &cves_to_insert, configuration).await {
        error!("Failed to insert data into the database: {}", e);
    }

    info!("Successfully processed and inserted CVEs. Execution time: {:.2?}", now.elapsed());
}

/// Checks if a CVE exists in a list of filtered CVEs.
///
/// This function iterates over a list of `FilteredCVE` entries to check if a specific CVE
/// is already present. If the CVE is found, a warning is logged indicating that the CVE
/// already exists.
///
/// # Parameters
/// - `cves`: A slice reference to a list of `FilteredCVE` objects to search within.
/// - `cve`: A reference to the `FilteredCVE` object to check for existence.
///
/// # Returns
/// - `true`: If the CVE exists in the list.
/// - `false`: If the CVE is not found.
///
/// # Logging
/// - Logs a warning message when a duplicate CVE is detected.
///
/// # Example
/// ```no_run
/// use log::info;
/// let existing_cves = vec![FilteredCVE { id: "CVE-2024-1234".to_string() }];
/// let new_cve = FilteredCVE { id: "CVE-2024-1234".to_string() };
/// if contains_cve(&existing_cves, &new_cve).await {
///     info!("Duplicate CVE found!");
/// } else {
///     info!("CVE is unique.");
/// }
/// ```
async fn contains_cve(cves: &[FilteredCVE], cve: &FilteredCVE) -> bool {
    if let Some(existing) = cves.iter().find(|existing| existing.get_id() == cve.get_id()) {
        warn!("CVE {} already exists. Skipping insertion.", existing.get_id());
        return true;
    }
    false
}

/// Verifies and retrieves the body of a response from the NVD API.
///
/// This function constructs a paginated query to the NVD API, verifies the response for errors,
/// and retrieves the response body. If the service is unavailable, it retries the request with a
/// delay until the service becomes available.
///
/// # Parameters
/// - `page`: The current page number for the API query.
/// - `id`: The thread ID used for parallelization.
/// - `amount_per_thread`: The number of items processed per thread.
/// - `override_query`: The base query string for the NVD API.
/// - `results_per_page`: The number of results requested per page.
///
/// # Returns
/// - A `String` containing the response body from the NVD API if successful.
///
/// # Behavior
/// - Retries with a delay if the service is unavailable (`503` or similar errors).
/// - Logs any errors encountered during the process.
///
/// # Example
/// ```no_run
/// let body = body_verifier(0, 1, 1000, "query=example".to_string(), 100).await;
/// println!("Response body: {}", body);
/// ```
pub async fn body_verifier(
    page: u32,
    id: u32,
    amount_per_thread: u32,
    override_query: String,
    results_per_page: u32,
) -> String {
    let mut service_unavailable = true;
    let mut body = String::new();

    while service_unavailable {
        // Construct the query URL
        let get_cves = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0/{}&resultsPerPage={}&startIndex={}",
            override_query,
            results_per_page,
            page * TOTAL_PAGE + id * amount_per_thread
        );

        // Perform the API request
        match request_nvd(&get_cves).await {
            Ok(response) => {
                match response.text().await {
                    Ok(nvd_response) => {
                        if http_errors(&nvd_response) {
                            service_unavailable = false;
                        }
                        body = nvd_response;
                    }
                    Err(e) => {
                        error!("Failed to read response body: {:?}", e);
                    }
                }
            }
            Err(e) => {
                error!("Request failed for URL {}: {:?}", get_cves, e);
            }
        }

        // Wait if the service is unavailable
        if service_unavailable {
            // warn!("Service unavailable, retrying after {}ms", SERVICE_SLEEP);
            sleep(Duration::from_millis(SERVICE_SLEEP)).await;
        }
    }

    body
}


/// Checks for predefined HTTP error messages in a response body.
///
/// This function scans the provided response body for a set of known HTTP error messages
/// and returns whether the body is free of those errors.
///
/// # Parameters
/// - `body`: A reference to a `str` containing the HTTP response body.
///
/// # Returns
/// - `true`: If the body does not contain any known error messages.
/// - `false`: If the body contains one of the predefined error messages.
///
/// # Known Errors
/// The list of error messages is stored in a static array for easy modification.
///
/// # Example
/// ```
/// use log::info;
/// let response_body = "<h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n";
/// if http_errors(response_body) {
///     info!("No HTTP errors detected.");
/// } else {
///     info!("HTTP error detected.");
/// }
/// ```
fn http_errors(body: &str) -> bool {
    static ERROR_PATTERNS: &[&str] = &[
        "Request forbidden by administrative rules.",
        "<h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n",
        "<title>502 - Web server received an invalid response while acting as a gateway or proxy server.</title>",
    ];

    !ERROR_PATTERNS.iter().any(|error| body.contains(error))
}


/// Processes an `NVDCve` object, filters and extracts relevant information, and generates
/// a `FilteredCVE` object along with associated configurations.
///
/// # Parameters
/// - `cve`: An `NVDCve` object containing raw CVE data.
///
/// # Returns
/// A tuple containing:
/// - `FilteredCVE`: A structured representation of the CVE with extracted details.
/// - `Vec<Vec<CPEMatch>>`: A collection of configuration combinations derived from the CVE.
///
/// # Example
/// ```rust
/// use log::info;
/// let nvd_cve = NVDCve { /* populate with test data */ };
/// let (filtered_cve, configurations) = filter_and_insert(nvd_cve);
/// info!("Filtered CVE ID: {}", filtered_cve.id);
/// info!("Number of configurations: {}", configurations.len());
/// ```
fn filter_and_insert(cve: NVDCve) -> (FilteredCVE, Vec<Vec<CPEMatch>>) {
    // Extract and clean the English description if available.
    let description = cve
        .descriptions
        .iter()
        .find(|x| x.lang == "en")
        .map(|x| x.value.replace('\n', " ").replace('\r', "").to_lowercase())
        .unwrap_or_else(|| "".to_string());

    // Retrieve the latest CVSS information.
    let (
        cvss_version,
        cvss_vector,
        cvss_base_score,
        cvss_base_severity,
        exploitability_score,
        impact_score,
        v2_fields,
    ) = get_latest_cvss(cve.metrics);

    // Extract weaknesses.
    let weaknesses = get_weaknesses(cve.weaknesses);

    // Generate configurations.
    let mut configurations = Vec::new();
    for config in cve.configurations {
        let combine = matches!(config.operator.as_str(), "AND");
        configurations.extend(config_combinations(config.nodes, combine));
    }

    // Collect unique vulnerable products.
    let mut vulnerable = Vec::new();
    for config in &configurations {
        for cpe in config {
            if cpe.vulnerable && !vulnerable.contains(&cpe.criteria) {
                vulnerable.push(cpe.criteria.clone());
            }
        }
    }

    // Build the `FilteredCVE` object.
    let filter_cve = FilteredCVE {
        id: cve.id,
        source_identifier: cve.source_identifier,
        published: cve.published.clone(),
        last_modified: cve.last_modified.clone(),
        vuln_status: cve.vuln_status.clone(),
        description,
        cvss_version,
        cvss_vector,
        cvss_base_score,
        cvss_base_severity,
        exploitability_score,
        impact_score,
        v2_fields,
        weaknesses,
        references: cve.references.clone(),
        epss_score: 0.0, // Default value, can be updated later.
        vulnerable_product: vulnerable,
    };

    (filter_cve, configurations)
}


/// Generates configurations based on combinations of nodes and operators.
///
/// This function processes a list of nodes, each containing an operator (`AND` or `OR`) and associated CPE matches,
/// to create configurations based on the specified combination rules. If the `combine` flag is `true`,
/// `OR` nodes are combined using Cartesian products, and `AND` nodes are appended to each configuration. Otherwise,
/// each node is treated independently.
///
/// # Parameters
/// - `combinations`: A vector of `Nodes`, each containing an operator and associated CPE matches.
/// - `combine`: A boolean flag indicating whether to combine `OR` nodes into Cartesian products or treat them separately.
///
/// # Returns
/// - A vector of configurations, where each configuration is a vector of `CPEMatch` objects.
///
/// # Example
/// ```rust
/// use log::info;
/// let nodes = vec![
///     Nodes { operator: "AND".to_string(), cpe_match: vec![CPEMatch { /* ... */ }] },
///     Nodes { operator: "OR".to_string(), cpe_match: vec![CPEMatch { /* ... */ }, CPEMatch { /* ... */ }] },
/// ];
/// let result = config_combinations(nodes, true);
/// info!("{:?}", result);
/// ```
fn config_combinations(combinations: Vec<Nodes>, combine: bool) -> Vec<Vec<CPEMatch>> {
    let mut result = Vec::new();
    let mut config_builder_and = Vec::new();
    let mut config_builder_or = Vec::new();

    for node in combinations {
        match node.operator.as_str() {
            "AND" => {
                // Extend AND matches
                config_builder_and.extend(node.cpe_match.clone());
                if !combine {
                    result.push(config_builder_and.clone());
                    config_builder_and.clear();
                }
            }
            "OR" => {
                if combine {
                    // Add OR matches to builder for Cartesian product
                    config_builder_or.push(node.cpe_match);
                } else {
                    // Add each OR match individually
                    for cpe in &node.cpe_match {
                        result.push(vec![cpe.clone()]);
                    }
                }
            }
            _ => {
                error!("Unknown operator: {}", node.operator);
            }
        }
    }

    if combine {
        // Add Cartesian products of OR matches to the result
        if !config_builder_or.is_empty() {
            result.extend(comb(&config_builder_or));
        }

        // Append AND matches to each configuration in the result
        if !config_builder_and.is_empty() {
            for config in result.iter_mut() {
                config.extend(config_builder_and.clone());
            }
        }
    }

    result
}

/// Computes the Cartesian product of a slice of vectors.
///
/// This function takes a slice of vectors and computes all possible combinations
/// where one element is chosen from each vector. The Cartesian product is returned
/// as a vector of vectors.
///
/// # Parameters
/// - `vectors`: A slice of vectors from which the Cartesian product will be computed.
///
/// # Returns
/// - A vector of vectors representing all combinations of elements, where each combination
///   contains one element from each vector.
///
/// # Example
/// ```
/// let input = vec![vec![1, 2], vec![3, 4]];
/// let result = comb(&input);
/// assert_eq!(result, vec![
///     vec![1, 3],
///     vec![1, 4],
///     vec![2, 3],
///     vec![2, 4],
/// ]);
/// ```
fn comb<T: Clone>(vectors: &[Vec<T>]) -> Vec<Vec<T>> {
    // Base case: if the input is empty, return a single empty combination.
    if vectors.is_empty() {
        return vec![vec![]];
    }

    // Take the first vector and compute combinations with the rest.
    let first = &vectors[0];
    let rest_combinations = comb(&vectors[1..]);

    // Generate the Cartesian product.
    first
        .iter()
        .flat_map(|elem| {
            rest_combinations.iter().map(move |combination| {
                let mut new_combination = Vec::with_capacity(combination.len() + 1);
                new_combination.push(elem.clone());
                new_combination.extend_from_slice(combination);
                new_combination
            })
        })
        .collect()
}


/// Extracts unique English descriptions of weaknesses from a list of `Weaknesses`.
///
/// This function iterates over a vector of `Weaknesses` objects and extracts tuples containing
/// the source and the English description of each weakness. It ensures that the result contains
/// only unique entries.
///
/// # Parameters
/// - `weak_vec`: A vector of `Weaknesses` objects from which data will be extracted.
///
/// # Returns
/// - A vector of unique tuples, where each tuple contains:
///   - `String`: The source of the weakness.
///   - `String`: The English description of the weakness.
///
/// # Logging
/// - Logs a warning message when a weakness has no English description.
///
/// # Example
/// ```no_run
/// let weaknesses = vec![
///     Weaknesses {
///         source: "Source1".to_string(),
///         description: vec![Description {
///             lang: "en".to_string(),
///             value: "Weakness description".to_string(),
///         }],
///     },
///     Weaknesses {
///         source: "Source2".to_string(),
///         description: vec![Description {
///             lang: "en".to_string(),
///             value: "Another description".to_string(),
///         }],
///     },
/// ];
///
/// let result = get_weaknesses(weaknesses);
/// assert_eq!(
///     result,
///     vec![
///         ("Source1".to_string(), "Weakness description".to_string()),
///         ("Source2".to_string(), "Another description".to_string()),
///     ]
/// );
/// ```
fn get_weaknesses(weak_vec: Vec<Weaknesses>) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for weakness in weak_vec {
        if let Some(weakness_desc) = weakness.description.iter().find(|x| x.lang == "en") {
            let value = (weakness.source.clone(), weakness_desc.value.clone());
            if seen.insert(value.clone()) {
                result.push(value);
            }
        } else {
            error!(
                "Weakness with source '{}' has no English description.",
                weakness.source
            );
        }
    }

    result
}


/// Retrieves the latest CVSS score attributed by the NVD.
///
/// This function checks multiple versions of CVSS metrics (`v3.1`, `v3.0`, and `v2`) for a given
/// `Metrics` structure and retrieves the most recent score from the source "nvd@nist.gov".
///
/// # Parameters
/// - `cve_metrics`: A `Metrics` object containing CVSS metric data.
///
/// # Returns
/// A tuple containing:
/// - `version` (`String`): The CVSS version.
/// - `vector_string` (`String`): The CVSS vector string.
/// - `base_score` (`f64`): The base score of the CVSS.
/// - `base_severity` (`String`): The base severity of the CVSS.
/// - `exploit_score` (`f64`): The exploitability score.
/// - `impact_score` (`f64`): The impact score.
/// - `string_v2` (`String`): Additional information for `v2` metrics, formatted as a string.
///
/// If no metrics from "nvd@nist.gov" are found, returns a tuple with empty strings and zeroed scores.
///
/// # Example
/// ```rust
/// use log::info;
/// let metrics = Metrics {
///     cvss_metrics_v31: vec![/* ... */],
///     cvss_metrics_v3: vec![/* ... */],
///     cvss_metrics_v2: vec![/* ... */],
/// };
/// let latest_cvss = get_latest_cvss(metrics);
/// info!("Latest CVSS: {:?}", latest_cvss);
/// ```
fn get_latest_cvss(cve_metrics: Metrics) -> (String, String, f64, String, f64, f64, String) {
    const SOURCE_NVD: &str = "nvd@nist.gov";

    // Check CVSS v3.1 metrics
    if let Some(cvss) = cve_metrics
        .cvss_metrics_v31
        .into_iter()
        .find(|cvss| cvss.source == SOURCE_NVD)
    {
        return (
            cvss.cvss_data.version,
            cvss.cvss_data.vector_string,
            cvss.cvss_data.base_score,
            cvss.cvss_data.base_severity,
            cvss.exploitability_score,
            cvss.impact_score,
            "".to_string(),
        );
    }

    // Check CVSS v3.0 metrics
    if let Some(cvss) = cve_metrics
        .cvss_metrics_v3
        .into_iter()
        .find(|cvss| cvss.source == SOURCE_NVD)
    {
        return (
            cvss.cvss_data.version,
            cvss.cvss_data.vector_string,
            cvss.cvss_data.base_score,
            cvss.cvss_data.base_severity,
            cvss.exploitability_score,
            cvss.impact_score,
            "".to_string(),
        );
    }

    // Check CVSS v2 metrics
    if let Some(cvss) = cve_metrics
        .cvss_metrics_v2
        .into_iter()
        .find(|cvss| cvss.source == SOURCE_NVD)
    {
        let string_v2 = format!(
            "AIF:{}/OAP:{}/OUP:{}/OOP:{}/UIR:{}",
            cvss.ac_insuf_info,
            cvss.obtain_all_privilege,
            cvss.obtain_user_privilege,
            cvss.obtain_other_privilege,
            cvss.user_interaction_required
        );
        return (
            cvss.cvss_data.version,
            cvss.cvss_data.vector_string,
            cvss.cvss_data.base_score,
            cvss.base_severity,
            cvss.exploitability_score,
            cvss.impact_score,
            string_v2,
        );
    }

    // Default return if no metrics are found
    (
        "".to_string(),
        "".to_string(),
        0.0,
        "".to_string(),
        0.0,
        0.0,
        "".to_string(),
    )
}


/// Custom error type for handling API request errors.
#[derive(Debug, Error)]
enum RequestNvdError {
    #[error("Network error occurred: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Non-success status code: {0}")]
    StatusCodeError(reqwest::StatusCode),
}

/// Sends a GET request to the NVD API and parses the response into an `NvdResponse` struct.
///
/// This function creates an HTTP client, sends a GET request to the specified URL,
/// attaches the required API key for authentication
///
/// # Parameters
/// - `url`: A string slice representing the target URL for the API request.
///
/// # Returns
/// - `Ok(Response)`: The response.
/// - `Err(RequestNvdError)`: If the request fails due to a network error or non-success status code.
///
/// # Errors
/// - Returns `RequestNvdError` for network issues or non-success HTTP status codes.
///
/// # Example
/// ```no_run
/// use log::{error, info};
/// let url = "https://services.nvd.nist.gov/rest/json/cves/2.0/";
/// match request_nvd(url).await {
///     Ok(response) => info!("Total results: {}", response),
///     Err(e) => error!("Request failed: {}", e),
/// }
/// ```
async fn request_nvd(url: &str) -> Result<Response, RequestNvdError> {
    let client = Client::new();

    let response = client
        .get(url)
        .header("apiKey", API_KEY_NVD)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(RequestNvdError::StatusCodeError(response.status()));
    }


    Ok(response)
}



/// Validates application constants to ensure logical consistency.
///
/// This function checks if the value of `MIN_RESULTS_PER_THREAD` is greater than or equal to
/// `TOTAL_THREADS`. If the condition is violated, it panics with an appropriate error message.
///
/// # Panics
/// - Panics if `MIN_RESULTS_PER_THREAD` is less than `TOTAL_THREADS`, as this would lead to
///   inconsistent behavior in the application's threading logic.
///
/// # Best Practices
/// - This function is intended to be called during application initialization to ensure
///   constants are correctly defined.
/// - If the condition can be violated during runtime due to external configuration changes,
///   consider returning a `Result` instead of panicking.
///
/// # Example
/// ```no_run
/// const MIN_RESULTS_PER_THREAD: u32 = 5;
/// const TOTAL_THREADS: u32 = 10;
///
/// consts_checker(); // Will panic because `MIN_RESULTS_PER_THREAD < TOTAL_THREADS`.
/// ```
pub fn consts_checker() -> Result<(), String> {
    if MIN_RESULTS_PER_THREAD < TOTAL_THREADS {
        Err(format!(
            "Invalid configuration: MIN_RESULTS_PER_THREAD ({}) < TOTAL_THREADS ({}).",
            MIN_RESULTS_PER_THREAD, TOTAL_THREADS
        ))
    } else {
        Ok(())
    }
}

/// Fetches the EPSS scores for a vector of CVEs and updates the vector with the scores.
///
/// This function queries the `https://api.first.org` API in batches of 100 CVEs.
/// Any CVEs that do not have a corresponding score in the API response will be assigned a default score of `0.0`.
///
/// # Arguments
///
/// * `cves` - A vector of `FilteredCVE` instances to be updated with EPSS scores.
///
/// # Returns
///
/// A vector of `FilteredCVE` instances with updated EPSS scores.
pub async fn epss_score(mut cves: Vec<FilteredCVE>) -> Vec<FilteredCVE> {
    let mut hash_score: HashMap<String, EPSS> = HashMap::new();
    let client = Client::new();
    let batch_size = 100;

    let mut batch: Vec<String> = Vec::with_capacity(batch_size);
    let cves_len = cves.len(); // Compute the length outside the loop

    for (index, cve) in cves.iter_mut().enumerate() {
        batch.push(cve.get_id().to_string());

        if batch.len() == batch_size || index == cves_len - 1 {
            let query = batch.join(",");
            let url = format!("https://api.first.org/data/v1/epss?cve={}", query);

            let resp = client
                .get(&url)
                .send()
                .await
                .expect("Failed to send request to EPSS API")
                .text()
                .await
                .expect("Failed to read response from EPSS API");

            let response: Value = serde_json::from_str(&resp)
                .expect("Failed to parse JSON response from EPSS API");

            if let Some(total) = response["total"].as_u64() {
                for i in 0..total as usize {
                    if let Ok(epss_entry) = serde_json::from_value::<EPSS>(
                        response["data"][i].clone(),
                    ) {
                        hash_score.insert(epss_entry.cve.clone(), epss_entry);
                    } else {
                        error!(
                            "Failed to deserialize EPSS entry at index {} for batch: {}",
                            i, query
                        );
                    }
                }
            } else {
                error!("Missing 'total' field in API response for batch: {}", query);
            }

            batch.clear();
        }
    }

    // Update CVEs with their corresponding EPSS scores.
    for cve in &mut cves {
        let default_epss = EPSS {
            epss: "0.0".to_string(),
            cve: cve.get_id().to_string(),
            percentile: "0.0".to_string(),
            date: "unknown".to_string(),
        };

        let epss = hash_score.get(&*cve.get_id()).unwrap_or(&default_epss);
        cve.epss_score = epss
            .epss
            .parse::<f64>()
            .unwrap_or_else(|_| {
                error!("Failed to parse EPSS score for CVE: {}", epss.cve);
                0.0
            });
    }

    cves
}
