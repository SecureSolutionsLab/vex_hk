use std::{collections::HashSet, fs, io};

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::{
    config::Config,
    csv_postgres_integration::{self, GeneralizedCsvRecord},
    scrape_mod::github::{paginated_api::PaginatedApiDataIter, OSVGitHubExtended},
};

use super::{paginated_api::PaginatedApiDataIterError, GithubType};

/// Ignore everything else and just get the main commit url
#[derive(Debug, Deserialize, PartialEq)]
pub struct GithubCommit {
    pub url: String,
    pub commit: GithubCommitData,
}

impl GithubCommit {
    pub fn try_get_date(&self) -> &DateTime<Utc> {
        if let Some(committer) = self.commit.committer.as_ref() {
            return &committer.date;
        }
        if let Some(author) = self.commit.author.as_ref() {
            return &author.date;
        }
        panic!("GithubCommit no committer or author")
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct GithubCommitData {
    author: Option<GithubCommitDataAuthor>,
    committer: Option<GithubCommitDataCommitter>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct GithubCommitDataAuthor {
    date: DateTime<Utc>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct GithubCommitDataCommitter {
    date: DateTime<Utc>,
}

/// Ignore everything else and just get the files
#[derive(Debug, Deserialize)]
pub struct GithubSingleCommit {
    pub url: String,
    pub files: Vec<GithubCommitFile>,
}

/// Ignore everything else and just get the filename
///
/// Example of a file in a single commit:
/// ```json
/// {
///   "sha": "11d8e72e6baf8d2d9f023927f9ecd80f149ad929",
///   "filename": "advisories/unreviewed/2025/06/GHSA-2gg5-4wg8-wvxp/GHSA-2gg5-4wg8-wvxp.json",
///   "status": "added",
///   "additions": 57,
///   "deletions": 0,
///   "changes": 57,
///   "blob_url": "https://github.com/github/advisory-database/blob/e7f6897eec449da6cfdb271dc8b6d12e6be5ae3b/advisories%2Funreviewed%2F2025%2F06%2FGHSA-2gg5-4wg8-wvxp%2FGHSA-2gg5-4wg8-wvxp.json",
///   "raw_url": "https://github.com/github/advisory-database/raw/e7f6897eec449da6cfdb271dc8b6d12e6be5ae3b/advisories%2Funreviewed%2F2025%2F06%2FGHSA-2gg5-4wg8-wvxp%2FGHSA-2gg5-4wg8-wvxp.json",
///   "contents_url": "https://api.github.com/repos/github/advisory-database/contents/advisories%2Funreviewed%2F2025%2F06%2FGHSA-2gg5-4wg8-wvxp%2FGHSA-2gg5-4wg8-wvxp.json?ref=e7f6897eec449da6cfdb271dc8b6d12e6be5ae3b",
///   "patch": "@@ -0,0 +1,57 @@\n+{\n+  \"schema_version\": \"1.4.0\", <FILE STRIPED FOR BREVITY> "nvd_published_at\": \"2025-06-18T11:15:20Z\"\n+  }\n+}\n\\ No newline at end of file"
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct GithubCommitFile {
    pub filename: String,
    pub status: GithubCommitFileStatus,
    pub patch: Option<String>,
    pub previous_filename: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GithubCommitFileStatus {
    Added,
    Removed,
    Modified,
    Renamed,
    Copied,
    Changed,
    Unchanged,
}

#[derive(Debug, thiserror::Error)]
pub enum GithubOsvUpdateError {
    #[error("One of the commit files contains a status that isn't \"added\" or \"modified\" -> \"{0:?}\", and it is unknown to the program")]
    UnhandledCommitFileStatus(GithubCommitFileStatus),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<io::Error> for GithubOsvUpdateError {
    fn from(value: io::Error) -> Self {
        Self::Other(value.into())
    }
}

impl From<PaginatedApiDataIterError> for GithubOsvUpdateError {
    fn from(value: PaginatedApiDataIterError) -> Self {
        Self::Other(value.into())
    }
}

impl From<reqwest::Error> for GithubOsvUpdateError {
    fn from(value: reqwest::Error) -> Self {
        Self::Other(value.into())
    }
}

impl From<csv::Error> for GithubOsvUpdateError {
    fn from(value: csv::Error) -> Self {
        Self::Other(value.into())
    }
}

impl From<SingleFileError> for GithubOsvUpdateError {
    fn from(value: SingleFileError) -> Self {
        Self::Other(value.into())
    }
}

/// Try to get file contents from git's patch "@@ -0,0 +1,37 @@\n+{\n+  \"..." field
///
/// A bit finicky
fn parse_new_file_contents_from_patch_info(file_patch: &str) -> String {
    let initial_bracket_pos = file_patch
        .find('{')
        .expect("Parsing new file patch contents: Failed to find initial bracket.");
    let final_bracket_pos = file_patch
        .rfind('}')
        .expect("Parsing new file patch contents: Failed to find final bracket.");
    // include both initial and final bracket
    let mut middle_json = file_patch[initial_bracket_pos..(final_bracket_pos + 1)].to_string();

    // remove all initial "+" symbols of the patch notation
    middle_json.remove_matches("\n+");

    middle_json
}

/// Get type from advisory filename, assuming is a valid file advisory
fn get_file_type_from_filename(filename: &str) -> GithubType {
    // filenames should start with "advisories/"
    let filename_after_advisories_slash = &filename[11..];
    let next_slash = filename_after_advisories_slash
        .find('/')
        .expect("Unexpected filename. Failed to find slash.");
    let type_text = &filename_after_advisories_slash[0..next_slash];
    if type_text == GithubType::Reviewed.path_str() {
        GithubType::Reviewed
    } else if type_text == GithubType::Unreviewed.path_str() {
        GithubType::Unreviewed
    } else {
        panic!(
            "Found invalid type in advisories file path: Invalid type {:?}",
            type_text
        );
    }
}

/// Get all updated files after an update (by looking at commits)
pub async fn update_osv(
    config: &Config,
    client: &reqwest::Client,
    db_connection: &sqlx::Pool<sqlx::Postgres>,
    token: &str,
    since_date: &chrono::DateTime<Utc>,
    pg_bars: &indicatif::MultiProgress,
) -> Result<Vec<GithubCommit>, GithubOsvUpdateError> {
    log::info!("Querying commits...");
    let commits_iter = PaginatedApiDataIter::new(
        client,
        &config.github.osv.commits_url,
        token,
        &[
            ("since", &since_date.to_rfc3339()), // iso 8601 complaint
        ],
    )?;
    let mut commits: Vec<GithubCommit> = commits_iter.exhaust().await?;
    // sort commits by earliest first
    commits.sort_by(|a, b| a.try_get_date().cmp(b.try_get_date()));
    log::info!("Received {} commits. Processing.", commits.len());
    log::debug!("{:#?}", commits);

    let mut to_add_files: HashSet<String> = HashSet::new();
    let mut to_update_files: HashSet<String> = HashSet::new();
    let mut to_delete_files: HashSet<String> = HashSet::new();
    let mut skipped: usize = 0;

    let new_files_reviewed = &config
        .temp_dir_path
        .join(GithubType::Reviewed.csv_new_files_update_path());
    let new_files_unreviewed = &config
        .temp_dir_path
        .join(GithubType::Unreviewed.csv_new_files_update_path());
    let updated_files_reviewed = &config
        .temp_dir_path
        .join(GithubType::Reviewed.csv_updated_files_update_path());
    let updated_files_unreviewed = &config
        .temp_dir_path
        .join(GithubType::Unreviewed.csv_updated_files_update_path());

    // create files directories
    {
        let parent = new_files_reviewed.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    {
        let parent = new_files_unreviewed.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    {
        let parent = updated_files_reviewed.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }
    {
        let parent = updated_files_unreviewed.parent().unwrap();
        if !fs::exists(parent)? {
            fs::create_dir_all(parent)?;
        }
    }

    {
        let mut new_reviewed_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(new_files_reviewed)?;
        let mut new_unreviewed_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(new_files_unreviewed)?;

        let bar = pg_bars.add(indicatif::ProgressBar::new(commits.len() as u64));
        // go through commits in reverse (earliest first)
        for commit in commits.into_iter().rev() {
            let mut commit_data_iter = PaginatedApiDataIter::new(client, &commit.url, token, &[])?;
            while let Some(next_page_res) = commit_data_iter.next_page_request().await {
                let request = next_page_res?;
                let data: GithubSingleCommit = request.json().await?;

                let file_bar = pg_bars.add(indicatif::ProgressBar::new(data.files.len() as u64));
                for file in data.files {
                    let filename = &file.filename;
                    // todo: use single regex
                    if filename.starts_with("advisories/") && filename.ends_with(".json") {
                        if to_add_files.contains(filename)
                            || to_update_files.contains(filename)
                            || to_delete_files.contains(filename)
                        {
                            skipped += 1;
                            continue;
                        }
                        match file.status {
                            GithubCommitFileStatus::Added => {
                                let file_ty = get_file_type_from_filename(filename);
                                let file_patch = &file.patch.expect("Listing commits: File marked as \"added\" does not come with patch data");
                                let file_contents =
                                    parse_new_file_contents_from_patch_info(file_patch);
                                let parsed_osv =
                                    serde_json::from_str::<OSVGitHubExtended>(&file_contents).map_err(|err|
                                        anyhow::anyhow!("Failed to parse new file contents from patch information: {}", err)
                                    )?;
                                let id = &parsed_osv.id;
                                super::assert_osv_github_id(id);

                                to_add_files.insert(filename.to_owned());

                                let row_data = GeneralizedCsvRecord::from_osv(parsed_osv);
                                let record: [&str; 4] = row_data.as_row();
                                match file_ty {
                                    GithubType::Reviewed => {
                                        new_reviewed_writer.write_record(&record)?;
                                    }
                                    GithubType::Unreviewed => {
                                        new_unreviewed_writer.write_record(&record)?
                                    }
                                }
                            }
                            GithubCommitFileStatus::Modified => {
                                to_update_files.insert(filename.to_owned());
                            }
                            GithubCommitFileStatus::Removed => {
                                to_delete_files.insert(filename.to_owned());
                            }
                            GithubCommitFileStatus::Renamed => {
                                // file may still contain edits
                                let previous_filename = file.previous_filename.unwrap();
                                to_delete_files.insert(previous_filename);
                                to_update_files.insert(filename.to_owned());
                            }
                            _ => {
                                return Err(GithubOsvUpdateError::UnhandledCommitFileStatus(
                                    file.status,
                                ));
                            }
                        }
                    }
                    file_bar.inc(1);
                }
                pg_bars.remove(&file_bar);
            }
            bar.inc(1);
        }
        pg_bars.remove(&bar);

        new_reviewed_writer.flush()?;
        new_unreviewed_writer.flush()?;
    }

    log::info!(
        "Update status: {} new files, {} to modify, {} to remove, {} skipped because of multiple commits.",
        to_add_files.len(),
        to_update_files.len(),
        to_delete_files.len(),
        skipped
    );

    {
        let mut updated_reviewed_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(updated_files_reviewed)?;
        let mut updated_unreviewed_writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(updated_files_unreviewed)?;
        let mut url = String::new();
        log::info!("Downloading updated files.");
        let bar = pg_bars.add(indicatif::ProgressBar::new(to_update_files.len() as u64));
        for filename in to_update_files.iter() {
            let file_ty = get_file_type_from_filename(filename);

            url.clear();
            url.push_str(&config.github.osv.files_url); // https://api.github.com/repos/github/advisory-database/contents/
            url.push_str(filename); // advisories/unreviewed/2025/06/GHSA-2gg5-4wg8-wvxp/GHSA-2gg5-4wg8-wvxp.json
            let parsed_osv = get_single_osv_file_data(client, token, &url).await?;

            let id = &parsed_osv.id;
            super::assert_osv_github_id(id);

            let row_data = GeneralizedCsvRecord::from_osv(parsed_osv);
            let record: [&str; 4] = row_data.as_row();
            match file_ty {
                GithubType::Reviewed => {
                    updated_reviewed_writer.write_record(&record)?;
                }
                GithubType::Unreviewed => updated_unreviewed_writer.write_record(&record)?,
            }
            bar.inc(1);
        }
        pg_bars.remove(&bar);

        updated_reviewed_writer.flush()?;
        updated_unreviewed_writer.flush()?;
    }
    log::info!("All downloads finished.");

    todo!();
    // Ok(data)
}

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
    url: &str,
) -> Result<OSVGitHubExtended, SingleFileError> {
    let request = client
        .get(url)
        .bearer_auth(token)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, "User")
        .header(reqwest::header::ACCEPT, "application/vnd.github.raw+json")
        .build()?;
    let response = client.execute(request).await?;
    log::debug!(
        "url: {}\nFile response headers:\n{:?}",
        response.url(),
        response.headers()
    );
    if response.status().as_u16() == 404 {
        return Err(SingleFileError::NotFound(response.url().clone()));
    }

    let data = response.json::<OSVGitHubExtended>().await?;
    Ok(data)
}
