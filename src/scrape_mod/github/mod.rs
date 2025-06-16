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
pub mod individual_rep_osv;
pub mod repository;
pub mod rest_api;

use std::{fmt::Display, time::Duration};

use const_format::{concatcp, formatcp};
use serde::{Deserialize, Serialize};

use crate::{
    consts::{
        GITHUB_API_REVIEWED_TABLE_NAME, GITHUB_API_UNREVIEWED_TABLE_NAME,
        GITHUB_OSV_REVIEWED_TABLE_NAME, GITHUB_OSV_UNREVIEWED_TABLE_NAME,
    },
    download::DownloadError,
    osv_schema::OSV,
};

/// Location of the directory / folder where temporary files are created. This can get quite big depending on operations.
pub const TEMP_PATH_DIR: &str = "/zmnt/vex/";

const TEMP_DOWNLOAD_FILE_PATH: &str = concatcp!(TEMP_PATH_DIR, "github_all_temp.zip");
const TEMP_CSV_FILE_PATH_REVIEWED: &str = concatcp!(TEMP_PATH_DIR, "github_reviewed_temp.csv");
const TEMP_CSV_FILE_PATH_UNREVIEWED: &str = concatcp!(TEMP_PATH_DIR, "github_unreviewed_temp.csv");

const UPDATE_CSV_FILE_PATH_REVIEWED: &str = concatcp!(TEMP_PATH_DIR, "github_update_reviewed.csv");
const UPDATE_CSV_FILE_PATH_UNREVIEWED: &str =
    concatcp!(TEMP_PATH_DIR, "github_update_unreviewed.csv");
const TEMP_UPDATE_CSV_FILE_PATH_REVIEWED: &str =
    concatcp!(TEMP_PATH_DIR, "github_update_reviewed_temp.csv");
const TEMP_UPDATE_CSV_FILE_PATH_UNREVIEWED: &str =
    concatcp!(TEMP_PATH_DIR, "github_update_unreviewed_temp.csv");

// url refers to the "zip file download" of the repository
pub const REPOSITORY_URL: &str =
    "https://github.com/github/advisory-database/archive/refs/heads/main.zip";

pub const API_URL: &str = "https://api.github.com/advisories";

// https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
// ids come in the format of GHSA-xxxx-xxxx-xxxx
const GITHUB_ID_CHARACTERS: usize = 19;

// max 900 request per minute (60 / 900)
const MIN_TIME_BETWEEN_REQUESTS: Duration = Duration::new(0, 66666667);

const API_REQUESTS_LIMIT: usize = 5000;

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

    pub const fn osv_table_name(self) -> &'static str {
        match self {
            Self::Reviewed => GITHUB_OSV_REVIEWED_TABLE_NAME,
            Self::Unreviewed => GITHUB_OSV_UNREVIEWED_TABLE_NAME,
        }
    }

    pub const fn api_table_name(self) -> &'static str {
        match self {
            Self::Reviewed => GITHUB_API_REVIEWED_TABLE_NAME,
            Self::Unreviewed => GITHUB_API_UNREVIEWED_TABLE_NAME,
        }
    }

    pub const fn create_table_sql_text(self) -> &'static str {
        // working with consts makes this really finicky
        // if attempting to update, take care to not mess up formatcp arguments
        // WARNING: do not change without checking how CSV data is loaded.
        match self {
            Self::Reviewed => formatcp!(
                "CREATE TABLE \"{}\" (
                    \"id\" CHARACTER({GITHUB_ID_CHARACTERS}) PRIMARY KEY,
                    \"published\" TIMESTAMPTZ NOT NULL,
                    \"modified\" TIMESTAMPTZ NOT NULL,
                    \"data\" JSONB NOT NULL
                );",
                GITHUB_API_REVIEWED_TABLE_NAME
            ),
            Self::Unreviewed => formatcp!(
                "CREATE TABLE \"{}\" (
                    \"id\" CHARACTER({GITHUB_ID_CHARACTERS}) PRIMARY KEY,
                    \"published\" TIMESTAMPTZ NOT NULL,
                    \"modified\" TIMESTAMPTZ NOT NULL,
                    \"data\" JSONB NOT NULL
                );",
                GITHUB_API_UNREVIEWED_TABLE_NAME
            ),
        }
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
