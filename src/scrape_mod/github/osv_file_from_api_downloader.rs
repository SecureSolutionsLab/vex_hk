use std::{path::Path, time::Instant};

use sqlx::{Execute, Executor, Postgres, QueryBuilder};

use crate::{
    db_api::consts::GITHUB_REVIEWED_TMP_UPDATE_TABLE_NAME,
    download::DownloadError,
    scrape_mod::github::{OSVGitHubExtended, GITHUB_ID_CHARACTERS},
};

use super::api_data_retriever::GithubApiDownloadType;

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

pub async fn get_single_osv_file_data(
    client: &reqwest::Client,
    token: &str,
    publish_date: chrono::NaiveDate,
    id: &str,
    ty: GithubApiDownloadType,
) -> Result<OSVGitHubExtended, DownloadError> {
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
    let data = response.json::<OSVGitHubExtended>().await?;
    Ok(data)
}

pub async fn read_ids_and_download_files_into_database(
    db_connection: sqlx::Pool<sqlx::Postgres>,
    pg_bars: &indicatif::MultiProgress,
    client: &reqwest::Client,
    token: &str,
    id_csv_path: &Path,
    ty: GithubApiDownloadType,
) -> Result<(), DownloadError> {
    let start = Instant::now();

    // save to csv file first
    // this should be able to happen in multiple function calls
    // when csv is completely ok send it to database

    todo!();
    Ok(())
}
