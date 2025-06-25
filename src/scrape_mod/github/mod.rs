//! # GitHub ([https://github.com/advisories](https://github.com/advisories))
//!
//! This module incudes functionality for downloading advisory data in OSV format as well as in the GitHub specific format.
//!
//! This module is subdivided in different parts. See each submodule for details.
//!
//!  - [repository]: Functions for downloading repository data in OSV format. Fast, but only downloads in bulk.
//!  - [rest_api]: Functions related to the GitHub REST API. Requires token. Not slow, but can get problematic if data is required in bulk. The returned format is different from OSV, and it can be more updated / newer than the repository (clarification needed). See format in [api_response]. Contains multiple functions.
//!  - [individual_rep_osv]: Utilities for getting OSV files from the repository individually by calling the API or given an preexisting list. Can be slow, but useful for performing updates to preexisting data from [repository].

pub mod api_response;
mod paginated_api;
pub mod repository;
pub mod repository_update;
pub mod rest_api;

use std::fmt::Display;

use const_format::formatcp;
use paginated_api::PaginatedApiDataIterError;
use serde::{Deserialize, Serialize};

use crate::{config::Config, csv_postgres_integration, download::DownloadError, osv_schema::Osv};

const TMP_DOWNLOAD_FILE_NAME: &str = "github_all_tmp.zip";
const TMP_CSV_FILE_REVIEWED_NAME: &str = "github_reviewed_tmp.csv";
const TMP_CSV_FILE_UNREVIEWED_NAME: &str = "github_unreviewed_tmp.csv";

const UPDATE_NEW_FILES_CSV_FILE_PATH_REVIEWED: &str = "github_update_new_reviewed.csv";
const UPDATE_NEW_FILES_CSV_FILE_PATH_UNREVIEWED: &str = "github_update_new_unreviewed.csv";
const UPDATE_UPDATED_FILES_CSV_FILE_PATH_REVIEWED: &str = "github_update_reviewed.csv";
const UPDATE_UPDATED_FILES_CSV_FILE_PATH_UNREVIEWED: &str = "github_update_unreviewed.csv";

const TMP_REVIEWED_TABLE_NAME: &str = "vex_hk_github_reviewed_tmp";
const TMP_UNREVIEWED_TABLE_NAME: &str = "vex_hk_github_unreviewed_tmp";

// https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
// ids come in the format of GHSA-xxxx-xxxx-xxxx
const GITHUB_ID_CHARACTERS: usize = 19;
const GITHUB_ID_SQL_TYPE: &str = formatcp!("CHARACTER({})", GITHUB_ID_CHARACTERS);

const API_REQUESTS_LIMIT: usize = 5000;

pub type OsvGithubExtended = Osv<GitHubDatabaseSpecific>;

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
pub enum GithubType {
    Reviewed,
    Unreviewed,
}

impl GithubType {
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

    pub const fn csv_general_tmp_file_path(self) -> &'static str {
        match self {
            Self::Reviewed => TMP_CSV_FILE_REVIEWED_NAME,
            Self::Unreviewed => TMP_CSV_FILE_UNREVIEWED_NAME,
        }
    }

    pub const fn csv_new_files_update_path(self) -> &'static str {
        match self {
            Self::Reviewed => UPDATE_NEW_FILES_CSV_FILE_PATH_REVIEWED,
            Self::Unreviewed => UPDATE_NEW_FILES_CSV_FILE_PATH_UNREVIEWED,
        }
    }

    pub const fn csv_updated_files_update_path(self) -> &'static str {
        match self {
            Self::Reviewed => UPDATE_UPDATED_FILES_CSV_FILE_PATH_REVIEWED,
            Self::Unreviewed => UPDATE_UPDATED_FILES_CSV_FILE_PATH_UNREVIEWED,
        }
    }

    pub const fn tmp_table_name(self) -> &'static str {
        match self {
            Self::Reviewed => TMP_REVIEWED_TABLE_NAME,
            Self::Unreviewed => TMP_UNREVIEWED_TABLE_NAME,
        }
    }

    pub fn osv_table_name(self, config: &Config) -> &str {
        match self {
            Self::Reviewed => &config.github.osv.reviewed_table_name,
            Self::Unreviewed => &config.github.osv.unreviewed_table_name,
        }
    }

    pub fn api_table_name(self, config: &Config) -> &str {
        match self {
            Self::Reviewed => &config.github.api.reviewed_table_name,
            Self::Unreviewed => &config.github.api.reviewed_table_name,
        }
    }

    pub fn api_initialization_table_name(self, config: &Config) -> &str {
        match self {
            Self::Reviewed => &config.github.api.reviewed_incomplete_table_name,
            Self::Unreviewed => &config.github.api.unreviewed_incomplete_table_name,
        }
    }

    pub fn osv_format_sql_create_table_command(self, config: &Config) -> String {
        csv_postgres_integration::format_sql_create_table_command(
            self.osv_table_name(config),
            GITHUB_ID_SQL_TYPE,
        )
    }

    pub fn api_initialization_format_sql_create_table_command(self, config: &Config) -> String {
        csv_postgres_integration::format_sql_create_table_command(
            self.api_initialization_table_name(config),
            GITHUB_ID_SQL_TYPE,
        )
    }

    pub fn api_format_sql_create_table_command(self, config: &Config) -> String {
        csv_postgres_integration::format_sql_create_table_command(
            self.api_table_name(config),
            GITHUB_ID_SQL_TYPE,
        )
    }
}

impl Display for GithubType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.api_str())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GithubApiDownloadError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Failed single HTTP Request (Reqwest error): {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed to retrieve paginated data:\n{0}")]
    PaginatedApiDataIter(#[from] PaginatedApiDataIterError),
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

fn assert_osv_github_id(id: &str) {
    if id.len() > GITHUB_ID_CHARACTERS && id.chars().count() > GITHUB_ID_CHARACTERS {
        panic!(
            "ID {} has more characters ({}) than the maximum set to the database ({})",
            id,
            id.chars().count(),
            GITHUB_ID_CHARACTERS
        );
    }
}
