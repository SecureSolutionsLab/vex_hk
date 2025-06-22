use std::{collections::HashSet, fs, path::Path};

use chrono::Utc;
use regex::Regex;
use serde::Deserialize;

use crate::{
    config::Config, csv_postgres_integration::GeneralizedCsvRecord, osv_schema::OsvEssentials,
};

use super::{
    api_response::GitHubAdvisoryAPIResponse, paginated_api::PaginatedApiDataIter,
    GithubApiDownloadError, GithubType,
};

/// Ignore everything else and just get the main commit url
#[derive(Debug, Deserialize)]
pub struct GithubCommit {
    pub url: String,
}

/// Ignore everything else and just get the files
#[derive(Debug, Deserialize)]
pub struct GithubSingleCommit {
    pub url: String,
    pub files: Vec<GithubCommitFile>,
}

/// Ignore everything else and just get the filename
#[derive(Debug, Deserialize)]
pub struct GithubCommitFile {
    pub filename: String,
}

/// Get all updated files after an update (by looking at commits)
pub async fn get_commits(
    config: &Config,
    client: &reqwest::Client,
    token: &str,
    since_date: &chrono::DateTime<Utc>,
) -> Result<Vec<GithubCommit>, GithubApiDownloadError> {
    log::info!("Querying commits...");
    let commits_iter = PaginatedApiDataIter::new(
        client,
        &config.github.osv.commits_url,
        token,
        &[
            ("since", &since_date.to_rfc3339()), // iso 8601 complaint
        ],
    )?;
    let commits: Vec<GithubCommit> = commits_iter.exhaust().await?;
    log::info!("Received {} commits. Processing.", commits.len());
    log::info!("{:#?}", commits);

    // get just filenames of all the files
    let mut files: HashSet<String> = HashSet::new();
    for commit in commits {
        let mut commit_data_iter = PaginatedApiDataIter::new(client, &commit.url, token, &[])?;
        while let Some(next_page_res) = commit_data_iter.next_page_request().await {
            let request = next_page_res?;
            let data: GithubSingleCommit = request.json().await?;
            files.extend(data.files.into_iter().map(|obj| obj.filename));
        }
    }

    println!("files {:#?}", files);

    todo!();
    // Ok(data)
}

/// Download and save data in one single csv file, in [crate::csv_postgres_integration::GeneralizedCsvRecord] format
///
/// Download advisories modified after a specific date (inclusive, includes the day itself). Saves everything in a CSV file, where each row corresponds to one advisory. See [crate::csv_postgres_integration] for details.
///
/// Note: this function does NOT save progress during requests, and it won't be able to continue if it gets interrupted or an error occurs, so it should NOT be used for long or error-prone downloads that may require more than the API limit of requests for one hour.
///
/// Returns the number of total entries.
pub async fn api_data_after_update_date_single_csv_file(
    config: &Config,
    client: &reqwest::Client,
    token: &str,
    csv_file_path: &Path,
    date: chrono::NaiveDate,
    ty: GithubType,
) -> Result<usize, GithubApiDownloadError> {
    {
        let parent = csv_file_path.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_path(csv_file_path)?;

    log::info!(
        "Performing requests to the GitHub API and saving data to CSV. CSV File created at {:?}",
        csv_file_path
    );

    let mut paginated_iter = PaginatedApiDataIter::new(
        client,
        &config.github.api.url,
        token,
        &[
            ("published", &date.format(">=%Y-%m-%d").to_string()),
            ("type", ty.api_str()),
        ],
    )?;
    let mut total_entries = 0;
    while let Some(next_page_res) = paginated_iter.next_page_data().await {
        let next_page_data = next_page_res?;
        total_entries += next_page_data.len();

        for advisory in next_page_data {
            let record = GeneralizedCsvRecord::from_github_api_response(advisory);
            writer.write_record(record.as_row())?;
        }
    }
    writer.flush()?;

    Ok(total_entries)
}

/// Download api data and store only names, publish dates and modified dates
///
/// To be used for osv file retrieval
pub async fn get_only_essential_after_modified_date(
    config: &Config,
    client: &reqwest::Client,
    token: &str,
    date: &chrono::DateTime<Utc>,
    ty: GithubType,
) -> Result<Vec<OsvEssentials>, GithubApiDownloadError> {
    let mut paginated_iter = PaginatedApiDataIter::new(
        client,
        &config.github.api.url,
        token,
        &[
            ("published", &date.format(">=%Y-%m-%d").to_string()),
            ("type", ty.api_str()),
        ],
    )?;
    let mut data = Vec::new();
    while let Some(next_page_res) = paginated_iter.next_page_data().await {
        let next_page_data = next_page_res?;

        for full_data in next_page_data {
            data.push(OsvEssentials::from_github_api(&full_data));
        }
    }

    Ok(data)
}
