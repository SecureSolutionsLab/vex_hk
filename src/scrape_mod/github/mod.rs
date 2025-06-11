pub mod api_data_retriever;
pub mod api_response;
mod full_data;
mod osv_file_from_api_downloader;

use std::{fmt::Display, time::Duration};

use const_format::concatcp;
pub use full_data::download_full;
pub use osv_file_from_api_downloader::{
    read_ids_and_download_files_into_database, GithubOsvUpdate,
};
use serde::{Deserialize, Serialize};

use crate::{download::DownloadError, osv_schema::OSV};

const TEMP_PATH_FOLDER: &str = "/zmnt/vex/";

const TEMP_DOWNLOAD_FILE_PATH: &str = concatcp!(TEMP_PATH_FOLDER, "github_all_temp.zip");
const TEMP_CSV_FILE_PATH_REVIEWED: &str = concatcp!(TEMP_PATH_FOLDER, "github_reviewed_temp.csv");
const TEMP_CSV_FILE_PATH_UNREVIEWED: &str =
    concatcp!(TEMP_PATH_FOLDER, "github_unreviewed_temp.csv");

const UPDATE_CSV_FILE_PATH_REVIEWED: &str =
    concatcp!(TEMP_PATH_FOLDER, "github_update_reviewed.csv");
const UPDATE_CSV_FILE_PATH_UNREVIEWED: &str =
    concatcp!(TEMP_PATH_FOLDER, "github_update_unreviewed.csv");
const TEMP_UPDATE_CSV_FILE_PATH_REVIEWED: &str =
    concatcp!(TEMP_PATH_FOLDER, "github_update_reviewed_temp.csv");
const TEMP_UPDATE_CSV_FILE_PATH_UNREVIEWED: &str =
    concatcp!(TEMP_PATH_FOLDER, "github_update_unreviewed_temp.csv");

const FULL_DATA_URL: &str =
    "https://github.com/github/advisory-database/archive/refs/heads/main.zip";

// https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
// ids come in the format of GHSA-xxxx-xxxx-xxxx
const GITHUB_ID_CHARACTERS: usize = 19;

// max 900 request per minute (60 / 900)
const MIN_TIME_BETWEEN_REQUESTS: Duration = Duration::new(0, 66666667);

pub type OSVGitHubExtended = OSV<GitHubDatabaseSpecific>;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GitHubDatabaseSpecific {
    cwe_ids: Vec<String>,
    // can be null for unreviewed
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    severity: Option<GithubSeverity>,
    github_reviewed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    github_reviewed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    nvd_published_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    last_known_affected_version_range: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GithubSeverity {
    Unknown,
    Low,
    Moderate,
    High,
    Critical,
}

// "malware" unimplemented
#[derive(Clone, Copy)]
pub enum GithubApiDownloadType {
    Reviewed,
    Unreviewed,
}

impl GithubApiDownloadType {
    pub fn api_str(self) -> &'static str {
        match self {
            Self::Reviewed => "reviewed",
            Self::Unreviewed => "unreviewed",
        }
    }

    pub fn path_str(self) -> &'static str {
        match self {
            Self::Reviewed => "github-reviewed",
            Self::Unreviewed => "unreviewed",
        }
    }

    pub const fn csv_update_path(self) -> &'static str {
        match self {
            Self::Reviewed => UPDATE_CSV_FILE_PATH_REVIEWED,
            Self::Unreviewed => UPDATE_CSV_FILE_PATH_UNREVIEWED,
        }
    }

    pub const fn csv_update_path_temp(self) -> &'static str {
        match self {
            Self::Reviewed => TEMP_UPDATE_CSV_FILE_PATH_REVIEWED,
            Self::Unreviewed => TEMP_UPDATE_CSV_FILE_PATH_UNREVIEWED,
        }
    }
}

impl Display for GithubApiDownloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.api_str())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GithubApiDownloadError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Reqwest HTTP Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to serialize data to json:\n{0}")]
    Serialization(#[from] serde_json::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}

impl From<DownloadError> for GithubApiDownloadError {
    fn from(value: DownloadError) -> Self {
        match value {
            DownloadError::Io(v) => Self::Io(v),
            DownloadError::Reqwest(v) => Self::Reqwest(v),
        }
    }
}

fn get_create_table_text(name: &str) -> String {
    format!(
        "CREATE TABLE \"{}\" (
            \"id\" CHARACTER({GITHUB_ID_CHARACTERS}) PRIMARY KEY,
            \"published\" TIMESTAMPTZ NOT NULL,
            \"modified\" TIMESTAMPTZ NOT NULL,
            \"data\" JSONB NOT NULL
        );",
        name
    )
}
