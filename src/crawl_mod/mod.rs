use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::thread::Thread;
use std::time::{Duration, Instant};

use reqwest::Response;
use serde_json::{Error, Value};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::crawl_mod::consts::{
    API_KEY_NVD, MAX_REQUESTS_API, MIN_RESULTS_PER_THREAD, SERVICE_SLEEP, TOTAL_PAGE, TOTAL_THREADS,
};
use crate::crawl_mod::structs::{CPEMatch, EPSS, FilteredCVE, Metrics, Nodes, NVDCve, NvdResponse, Weaknesses};
use crate::db_mod::{insert_parallel_db, remove_to_update};

mod consts;
pub mod structs;

fn _private_hello() {
    println!("hello world")
}

pub async fn query_nvd_cvecount(query_count: &str) -> u32 {
    let cve = "https://services.nvd.nist.gov/rest/json/cves/2.0/";
    let mut local_query = format!("{}{}", cve, query_count);
    local_query.push_str("&resultsPerPage=1");
    let get_cve_count = &*local_query;
    let now = Instant::now();

    // let get_cve_count = ;
    let count_response = match request_nvd(get_cve_count).await.json::<NvdResponse>().await {
        Ok(nvd_response) => nvd_response,
        Err(e) => {
            eprintln!("error in response {} {}", e, get_cve_count);
            // panic!("panic in parser")
            return 0;
        }
    };

    println!("{}", get_cve_count);
    println!("{:?}", count_response);
    println!("execution time {:.2?}\n", now.elapsed());
    count_response.total_results
}

pub async fn query_nvd_and_insert(cve_count: u32, query: String, update: bool) {
    let mut local_threads = 1;
    // Activates the concurrency
    if cve_count / TOTAL_PAGE > 1 || cve_count / MIN_RESULTS_PER_THREAD >= 1 {
        local_threads = TOTAL_THREADS;
    }
    if local_threads == 1 {
        println!("Executing sequentially");
    }

    let instant = Instant::now();
    let mut thread_vec = Vec::new();
    let mut nr_pages = cve_count / TOTAL_PAGE;
    let last_page = cve_count % TOTAL_PAGE;
    if last_page != 0 {
        nr_pages += 1;
    }
    // println!("number of pages {} last_page {}", nr_pages, last_page);
    // println!("page per thread {} last thread {}", nr_pages / local_threads, nr_pages % local_threads);

    let counter = Arc::new(Mutex::new(MAX_REQUESTS_API));
    for thread_id in 0..local_threads {
        let id = thread_id;
        let counter_clone = counter.clone();
        let override_query_clone = query.clone();
        thread_vec.push(tokio::spawn(async move {
            let instant = Instant::now();
            let amount_per_thread = cve_count / local_threads;
            let rest_amount = cve_count % local_threads;
            let mut n_pages = amount_per_thread / TOTAL_PAGE;
            let rest_page = amount_per_thread % TOTAL_PAGE;
            if rest_page != 0 {
                n_pages += 1;
            }

            for page in 0..n_pages {
                let mut end = TOTAL_PAGE;
                if page == n_pages - 1 {
                    end = rest_page;
                }
                if thread_id == TOTAL_THREADS - 1 && page == n_pages - 1 {
                    end += rest_amount;
                }

                // println!("thread {} end {} current page {}", thread_id, end, page);

                let mut lock = counter_clone.lock().await;
                if *lock == 0 {
                    println!("Max requests reached, standby");
                    sleep(Duration::from_millis(SERVICE_SLEEP)).await;
                    *lock = MAX_REQUESTS_API;
                }
                *lock -= 1;
                drop(lock);
                let instant = Instant::now();
                let body = body_verifier(
                    page,
                    id,
                    amount_per_thread,
                    override_query_clone.clone(),
                    end,
                )
                    .await;
                let cves_body: Value = match serde_json::from_str(&*body) {
                    Ok(body) => body,
                    Err(e) => {
                        eprintln!("body {:?}", body);
                        eprintln!("error value {}", e);
                        panic!("error in value");
                    }
                };
                // println!("response time {:.2?}", instant.elapsed());
                let instant2 = Instant::now();
                parse_response_insert(cves_body, end, update).await;
                // println!("parse response time {:.2?}", instant2.elapsed());
            }
            println!("thread {} time {:.2?}", id, instant.elapsed());
        }));
    }

    for thread in thread_vec {
        thread.await.unwrap();
        println!("finished the process");
    }
    println!("time for concurrent execution {:.2?}", instant.elapsed());
}

async fn parse_response_insert(cves_body: Value, end: u32, update: bool) {
    let now = Instant::now();
    let cves = &cves_body["vulnerabilities"];
    let mut cves_to_insert = Vec::new();
    let mut configuration = Vec::new();
    for cve_index in 0..end as usize {
        let cve_nvd = serde_json::from_value::<NVDCve>(cves[cve_index]["cve"].to_owned());
        let (filter_cve, vec_configuration) = match cve_nvd {
            Ok(cve) => {
                // if verify_cve_db(&*cve.id).await && !update {
                //     continue;
                // }

                //Verify cve
                // if cve.vuln_status == "Rejected" || cve.vuln_status == "Deferred"{
                //     continue
                // }
                filter_and_insert(cve)
            }
            Err(e) => {
                println!("error in response {}", &cves[cve_index]["cve"]);
                println!("cve {:?}", e);
                panic!("Could not filer cve")
            }
        };
        if !contains_cve(&cves_to_insert, &filter_cve).await {
            configuration.push((filter_cve.id.clone(), vec_configuration));
            cves_to_insert.push(filter_cve);

        }
    }
    cves_to_insert = epss_score(cves_to_insert).await;

    if update {
        remove_to_update(&cves_to_insert).await;
    }
    insert_parallel_db(&cves_to_insert, configuration).await;
    println!("execution query nvd time {:.2?}", now.elapsed());
}

async fn contains_cve(cves: &Vec<FilteredCVE>, cve: &FilteredCVE) -> bool {
    for cve_in in cves {
        if cve_in.id == cve.id {
            println!("i have been found!!! {}", cve.id);
            panic!("hoooooold!!");
            return true;
        }
    }
    false
}

async fn body_verifier(
    page: u32,
    id: u32,
    amount_per_thread: u32,
    override_query: String,
    results_per_page: u32,
) -> String {
    let mut service_unavailable = true;
    let mut body = "".to_string();
    while service_unavailable {
        let get_cves = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0/{}&resultsPerPage={}&startIndex={}",
            override_query,
            results_per_page,
            page * TOTAL_PAGE + id * amount_per_thread
        );
        // println!("url {}", get_cves);
        let cves = request_nvd(&*get_cves).await;
        body = match cves.text().await {
            Ok(nvd_response) => {
                if http_errors(&nvd_response) {
                    service_unavailable = false;
                }
                nvd_response
            }
            Err(e) => {
                eprintln!("error in response {:?}", e);
                body
            }
        };

        if service_unavailable {
            sleep(Duration::from_millis(SERVICE_SLEEP)).await;
        }
    }
    body
}

fn http_errors(body: &String) -> bool {
    if body.contains("Request forbidden by administrative rules.") {
        return false;
    }
    if body.contains(
        "<h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n",
    ) {
        return false;
    }
    if body.contains("<title>502 - Web server received an invalid response while acting as a gateway or proxy server.</title>"){
        return false;
    }
    true
}

fn filter_and_insert(cve: NVDCve) -> (FilteredCVE, Vec<Vec<CPEMatch>>) {
    // let instant = Instant::now();
    let description = cve
        .descriptions
        .iter()
        .find(|x| x.lang == "en")
        .map(|x| x.value.to_string());
    let description = if description.is_some() {
        let mut description = description.unwrap().clone();
        description = description.replace("\n", " ").to_lowercase();
        description = description.replace("\r", "");
        description
    } else {
        "".to_string()
    };
    // println!("description elapsed {:.2?}", instant.elapsed());
    let (
        cvss_version,
        cvss_vector,
        cvss_base_score,
        cvss_base_severity,
        exploitability_score,
        impact_score,
        v2_fields,
    ) = get_latest_cvss(cve.metrics);
    // println!("cvss elapsed {:.2?}", instant.elapsed());
    let weaknesses = get_weaknesses(cve.weaknesses);
    // println!("weaknesses elapsed {:.2?}", instant.elapsed());
    let mut configurations = Vec::new();

    for config in cve.configurations {
        let combine = if config.operator == "OR" || config.operator == "" {
            false
        } else {
            true
        };
        configurations.extend(config_combinations(config.nodes, combine));
    }
    let mut vulnerable = Vec::new();
    for config in &configurations{
        for cpe in config{
            if cpe.vulnerable && !vulnerable.contains(&cpe.criteria){
                vulnerable.push(cpe.criteria.clone());
            }
        }
    }


    // println!("configurations elapsed {:.2?}\n", instant.elapsed());
    let filter_cve = FilteredCVE {
        id: cve.id.clone(),
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
        epss_score: 0.0,
        vulnerable_product: vulnerable,
    };
    // println!("parser time {:.2?}", instant.elapsed());
    (filter_cve, configurations)
    // println!("{:?}", filter_cve);
}

fn config_combinations(combinations: Vec<Nodes>, combine: bool) -> Vec<Vec<CPEMatch>> {
    let mut result: Vec<Vec<CPEMatch>> = Vec::new();
    let mut config_builder_and = Vec::new();
    let mut config_builder_or = Vec::new();
    for vec in combinations {
        if vec.operator == "AND" {
            config_builder_and.extend(vec.cpe_match.clone());
            if !combine {
                result.push(config_builder_and.clone());
                config_builder_and.clear();
            }
        } else if vec.operator == "OR" {
            if combine {
                config_builder_or.push(vec.cpe_match);
            } else {
                for cpe in &vec.cpe_match {
                    result.push(vec![cpe.clone()]);
                }
            }
        }
    }
    if combine {
        result.extend(comb(&config_builder_or));
    }
    if config_builder_and.len() > 0 && combine {
        for config in result.iter_mut() {
            config.extend(config_builder_and.clone());
        }
    }
    result
}

fn comb<T: Clone>(vectors: &[Vec<T>]) -> Vec<Vec<T>> {
    if vectors.is_empty() {
        return vec![vec![]];
    }

    let mut result = Vec::new();
    let rest_combinations = comb(&vectors[1..]);

    for elem in &vectors[0] {
        for combination in &rest_combinations {
            let mut new_combination = vec![elem.clone()];
            new_combination.extend_from_slice(combination);
            result.push(new_combination);
        }
    }

    result
}

fn get_weaknesses(weak_vec: Vec<Weaknesses>) -> Vec<(String, String)> {
    let mut vec_result = Vec::new();
    for weakness in weak_vec {
        let weakness_desc = weakness.description.iter().find(|x| x.lang == "en");
        let value = (weakness.source, weakness_desc.unwrap().value.clone());
        if !vec_result.contains(&value) {
            vec_result.push(value);
        }
    }
    vec_result
}

/// Retrieves the latest CVSS score attributed by the NVD
/// (version: String, vector_string:String, base_score:f64, base_severity:String, exploit_score:f64, impact_score:f64, string_v2:String)
fn get_latest_cvss(cve_metrics: Metrics) -> (String, String, f64, String, f64, f64, String) {
    let source_og = "nvd@nist.gov";
    if cve_metrics.cvss_metrics_v31.len() != 0 {
        for cvss in cve_metrics.cvss_metrics_v31 {
            if cvss.source == source_og {
                let cvss_v31 = cvss;
                return (
                    cvss_v31.cvss_data.version.clone(),
                    cvss_v31.cvss_data.vector_string.clone(),
                    cvss_v31.cvss_data.base_score,
                    cvss_v31.cvss_data.base_severity.clone(),
                    cvss_v31.exploitability_score,
                    cvss_v31.impact_score,
                    "".to_string(),
                );
            }
        }
    }
    if cve_metrics.cvss_metrics_v3.len() != 0 {
        for cvss in cve_metrics.cvss_metrics_v3 {
            if cvss.source == source_og {
                let cvss_v3 = cvss;
                return (
                    cvss_v3.cvss_data.version,
                    cvss_v3.cvss_data.vector_string,
                    cvss_v3.cvss_data.base_score,
                    cvss_v3.cvss_data.base_severity.clone(),
                    cvss_v3.exploitability_score,
                    cvss_v3.impact_score,
                    "".to_string(),
                );
            }
        }
    }
    for cvss in cve_metrics.cvss_metrics_v2 {
        if cvss.source == source_og {
            let cvss_v2 = cvss;
            let string_v2 = format!(
                "AIF:{}/OAP:{}/OUP:{}/OOP:{}/UIR:{}",
                cvss_v2.ac_insuf_info,
                cvss_v2.obtain_all_privilege,
                cvss_v2.obtain_user_privilege,
                cvss_v2.obtain_other_privilege,
                cvss_v2.user_interaction_required
            );
            return (
                cvss_v2.cvss_data.version.clone(),
                cvss_v2.cvss_data.vector_string.clone(),
                cvss_v2.cvss_data.base_score,
                cvss_v2.base_severity.clone(),
                cvss_v2.exploitability_score,
                cvss_v2.impact_score,
                string_v2,
            );
        }
    }
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

async fn request_nvd(url: &str) -> Response {
    // let instant = Instant::now();
    let client = reqwest::Client::new();
    match client
        .get(url.to_owned())
        .header("apiKey", API_KEY_NVD)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            eprintln!("error in response {}", e);
            panic!("panic in response")
        }
    }
}

pub fn consts_checker() {
    if MIN_RESULTS_PER_THREAD < TOTAL_THREADS {
        panic!("This cannot occur MIN_RESULTS_PER_THREAD < TOTAL_THREADS");
    }
}

pub async fn epss_score(mut vec: Vec<FilteredCVE>) -> Vec<FilteredCVE> {
    let instant = Instant::now();
    let mut hash_score: HashMap<String, EPSS> = HashMap::new();
    let client = reqwest::Client::new();

    let size_vec = vec.len() - 1;
    let mut string_vec = vec![];

    for (index, cve) in vec.iter_mut().enumerate() {
        string_vec.push(cve.id.clone());
        if string_vec.len() == 100 || index==size_vec{
            let stringify = string_vec.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");
            let url = format!("https://api.first.org/data/v1/epss?cve={}", stringify);

            let resp = client
                .get(url.to_owned())
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();

            let response: Value = serde_json::from_str(&*resp).unwrap();
            let total = response["total"].clone().as_u64().unwrap();
            for value in 0..total as usize {
                // println!("total {} counter {} value {}", total, counter, value);
                let value = match serde_json::from_value::<EPSS>(response["data"][value].to_owned()){
                    Ok(value) => {value}
                    Err(error) => {
                        println!("{}", error);
                        panic!("response EPSS panicked");
                    }
                };
                hash_score.insert(value.cve.clone(), value.clone());

            }
            string_vec.clear();
        }

    }
    for mut cve in &mut vec{
        let temp = &EPSS{
            epss: "0.0".to_string(),
            cve: cve.id.clone(),
            percentile: "0.0".to_string(),
            date: "today".to_string(),
        }.to_owned();

        let score = match hash_score.get(&cve.id){
            None => {
                // println!("missing cve_ids {}", temp.cve );
                temp
            }
            Some(value) => {value}
        };
        let score = &*score.clone().epss;
        cve.epss_score = score.parse::<f64>().unwrap();
    }
    vec

}
