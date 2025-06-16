use std::{collections::HashMap, fs, path::Path, time::Instant};

use chrono::{NaiveDate, Utc};
use sqlx::{Execute, Executor, Postgres, QueryBuilder};

use crate::{
    csv_postgres_integration::GeneralizedCsvRecord,
    osv_schema::OsvEssentials,
    scrape_mod::github::{
        rest_api::get_only_essential_after_modified_date, OSVGitHubExtended,
        MIN_TIME_BETWEEN_REQUESTS,
    },
};

use super::{GithubApiDownloadError, GithubApiDownloadType};

// NOTE
// Structured api for files and directories less than 1MB
// // https://docs.github.com/en/rest/repos/contents?apiVersion=2022-11-28
// #[derive(Debug, serde::Deserialize, serde::Serialize)]
// #[serde(deny_unknown_fields)]
// struct GithubRepositoryFileResponse {
//     r#type: String,
//     size: usize,
//     name: String,
//     path: String,
//     sha: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(default)]
//     content: Option<String>,
//     url: String,
//     git_url: Option<String>,
//     html_url: Option<String>,
//     download_url: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(default)]
//     entries: Option<Vec<GithubRepositoryFileResponseEntry>>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(default)]
//     encoding: Option<String>,
//     _links: GithubRepositoryFileResponseLinks,
// }

// #[derive(Debug, serde::Deserialize, serde::Serialize)]
// #[serde(deny_unknown_fields)]
// struct GithubRepositoryFileResponseEntry {
//     pub r#type: Option<String>,
//     pub size: usize,
//     pub name: String,
//     pub path: String,
//     pub sha: String,
//     pub url: String,
//     pub git_url: Option<String>,
//     pub html_url: Option<String>,
//     pub download_url: Option<String>,
//     pub _links: GithubRepositoryFileResponseLinks,
// }

// #[derive(Debug, serde::Deserialize, serde::Serialize)]
// #[serde(deny_unknown_fields)]
// struct GithubRepositoryFileResponseLinks {
//     pub git: Option<String>,
//     pub html: Option<String>,
//     #[serde(rename = "self")]
//     pub self_: String,
// }

#[derive(thiserror::Error, Debug)]
pub enum SingleFileError {
    #[error("File not found, url: {0}")]
    NotFound(reqwest::Url),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

pub async fn get_single_osv_file_data(
    client: &reqwest::Client,
    token: &str,
    publish_date: chrono::DateTime<Utc>,
    id: &str,
    ty: GithubApiDownloadType,
) -> Result<OSVGitHubExtended, SingleFileError> {
    let url = format!(
        "https://api.github.com/repos/github/advisory-database/contents/advisories/{}/{}/{}/{}.json",
        ty.path_str(),
        &publish_date.format("%Y/%m").to_string(),
        id,
        id
    );
    let request = client
        .get(url)
        .bearer_auth(token)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, "User")
        .header(reqwest::header::ACCEPT, "application/vnd.github.raw+json")
        .build()?;
    let response = client.execute(request).await?;
    log::debug!(
        "[{}, {}]\nurl: {}\nFile response headers:\n{:?}",
        id,
        publish_date.format("%Y/%m/%d").to_string(),
        response.url(),
        response.headers()
    );
    if response.status().as_u16() == 404 {
        return Err(SingleFileError::NotFound(response.url().clone()));
    }

    let data = response.json::<OSVGitHubExtended>().await?;
    Ok(data)
}

/// # Result of an repository file retrieval
#[must_use]
#[derive(Debug)]
pub enum GithubOsvUpdate {
    /// All requests completed. Total number of updated entries
    AllOk(usize),
    /// Api limit reached. Requests completed / Total required requests
    ApiLimitReached((usize, usize)),
}

// Try to get OSV files that were modified after a specific date (inclusive)
//      (7 july will include advisories modified in 7 of july)
// This function saves its progress and doesn't commit if the maximum number of requests is reached,
// continuing on a subsequent function call.
// Check GithubOsvUpdate
pub async fn read_ids_and_download_files_into_database(
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
    client: &reqwest::Client,
    token: &str,
    date: NaiveDate,
    ty: GithubApiDownloadType,
) -> Result<GithubOsvUpdate, GithubApiDownloadError> {
    let start = Instant::now();
    log::info!("Starting GitHub OSV file update.");

    let essentials_inst = Instant::now();
    log::info!(
        "Requesting a list of modified advisories after {}",
        date.format("%Y/%m/%d")
    );
    let essentials = get_only_essential_after_modified_date(client, token, date, ty).await?;
    log::info!(
        "Request finished. Total time: {:?}. Total number of advisories: {}",
        essentials_inst.elapsed(),
        essentials.len()
    );
    let update = download_repository_files_into_osv_from_list_incremental(
        client,
        token,
        &essentials,
        ty,
        Path::new(ty.csv_update_path()),
        Path::new(ty.csv_update_path_temp()),
        pg_bars,
    )
    .await?;

    match update {
        GithubOsvUpdate::ApiLimitReached(_) => {
            log::info!("Update postponed. Total time: {:?}", start.elapsed());
            Ok(update)
        }
        GithubOsvUpdate::AllOk(_) => {
            todo!();
        }
    }
}

/// # Download files from repository from a list, incremental
///
/// Given a list of ids, download OSV files from repository and save them to a CSV file.
///
/// This function can resume function in case of an error, given it receives the same ids list as it worked previously. It will compare ids to download with existing ones and redownload them if the modified date has been updated.
///
/// This function creates a separate temporary csv file containing the data worked upon, in order to not corrupt the original file in case of an error. That file is copied to replace the original at the end when the file is complete.
///
/// Note: retrieving repository files through the REST API is very inefficient, as it cannot be done in bulk and so requires performing individual requests for each file. This function may be needed to be converted to use the graphql API. Use it only for small database updates.
pub async fn download_repository_files_into_osv_from_list_incremental(
    client: &reqwest::Client,
    token: &str,
    ids_to_download: &Vec<OsvEssentials>,
    ty: GithubApiDownloadType,
    csv_file_path: &Path,
    csv_file_path_temp: &Path,
    pg_bars: &indicatif::MultiProgress,
) -> Result<GithubOsvUpdate, GithubApiDownloadError> {
    let processing_start = Instant::now();
    let mut already_updated_entry_count = 0;

    {
        let parent = csv_file_path.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    {
        let parent = csv_file_path_temp.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(csv_file_path_temp)?;

    log::info!(
        "Updating OSV files from API database. Filtering for existing files.\nTotal number of ids: {}\nTemporary CSV file created at {:?}",
        ids_to_download.len(),
        csv_file_path_temp
    );

    // filter for only ids that need downloading
    let new_ids_to_download = if fs::exists(csv_file_path)? {
        log::info!(
            "Detected old CSV file at {:?}. Reading existing contents.",
            csv_file_path
        );
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(csv_file_path)?;
        let mut existing_ids = HashMap::new();
        for record_res in reader.records() {
            let csv_record = record_res?;
            let record = GeneralizedCsvRecord::from_csv_record(csv_record.clone());
            let essentials = record.to_essentials();
            existing_ids.insert(essentials.id, (essentials.modified, csv_record));
        }
        log::info!(
            "Read {} existing entries from old CSV file.",
            existing_ids.len()
        );

        let mut to_remain = Vec::new();
        let old_len = ids_to_download.len();
        let new_ids_to_download: Vec<OsvEssentials> = ids_to_download
            .into_iter()
            .filter(|&item| {
                if let Some((modified_date, record)) = existing_ids.remove(&item.id) {
                    if item.modified > modified_date {
                        true // download new one has been modified
                    } else {
                        to_remain.push(record);
                        false // do not download otherwise
                    }
                } else {
                    true // download if not exists
                }
            })
            .map(|filtered| filtered.clone())
            .collect();
        already_updated_entry_count = old_len - new_ids_to_download.len();
        log::info!(
            "Filtered {} entries not requiring updates.",
            already_updated_entry_count
        );

        log::debug!("Writing old entries to new file");
        if !to_remain.is_empty() {
            for old in to_remain {
                writer.write_record(&old)?;
            }
        }

        Some(new_ids_to_download)
    } else {
        log::info!(
            "Old CSV file does not exist at {:?}. Downloading files for all ids.",
            csv_file_path
        );
        None
    };
    let new_ids_to_download = if let Some(ids) = new_ids_to_download.as_ref() {
        ids
    } else {
        &ids_to_download
    };

    let bar = pg_bars.add(indicatif::ProgressBar::new(new_ids_to_download.len() as u64));
    let mut previous_call_instant = processing_start;
    for (i, item) in new_ids_to_download.iter().enumerate() {
        let current_instant = Instant::now();
        let elapsed = current_instant.duration_since(previous_call_instant);
        if elapsed < MIN_TIME_BETWEEN_REQUESTS {
            log::debug!(
                "Going too fast. Sleeping {:?}",
                MIN_TIME_BETWEEN_REQUESTS - elapsed
            );
            std::thread::sleep(MIN_TIME_BETWEEN_REQUESTS - elapsed);
        }
        previous_call_instant = current_instant;

        let osv = match get_single_osv_file_data(client, token, item.published, &item.id, ty).await
        {
            Ok(v) => v,
            Err(err) => {
                match err {
                    SingleFileError::NotFound(url) => {
                        log::error!("Requested file returned 404, it likely hasn't been yet published to the advisories repository. Url:\n{}\nSKIPPING", url);
                        continue;
                    }
                    SingleFileError::Reqwest(err) => {
                        if let Some(status) = err.status() {
                            // https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
                            if status == 422 || status == 429 {
                                log::info!(
                            "Stopping updating csv files. Limit reached, or token is invalid. Saving existing entries.\nTotal entries: {}/{}. Previously updated entries: {}. Time: {:?}",
                            i,
                            new_ids_to_download.len(),
                            already_updated_entry_count,
                            processing_start.elapsed()
                        );
                                bar.finish();
                                pg_bars.remove(&bar);
                                writer.flush()?;
                                drop(writer);

                                log::info!("Copying updated file...");
                                fs::copy(csv_file_path_temp, csv_file_path)?;
                                fs::remove_file(csv_file_path_temp)?;

                                return Ok(GithubOsvUpdate::ApiLimitReached((
                                    i + already_updated_entry_count,
                                    new_ids_to_download.len() + already_updated_entry_count,
                                )));
                            }
                        }
                        return Err(err.into());
                    }
                }
            }
        };
        let record = GeneralizedCsvRecord::from_osv(osv);
        writer.write_record(record.as_row())?;
        bar.set_position(i as u64);
    }

    log::info!(
        "Finished updating csv files. All requests completed. Saving entries.\nTotal new entries: {}. Previously updated entries {}. Time: {:?}",
        new_ids_to_download.len(),
        already_updated_entry_count,
        processing_start.elapsed()
    );
    bar.finish();
    pg_bars.remove(&bar);
    writer.flush()?;

    log::info!("Copying updated file...");
    fs::copy(csv_file_path_temp, csv_file_path)?;
    fs::remove_file(csv_file_path_temp)?;

    Ok(GithubOsvUpdate::AllOk(
        new_ids_to_download.len() + already_updated_entry_count,
    ))
}
