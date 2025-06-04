pub mod api_data_retriever;
pub mod api_response;
mod full_data;

use const_format::concatcp;
pub use full_data::download_full;
use serde::{Deserialize, Serialize};

use crate::osv_schema::OSV;

const TEMP_PATH_FOLDER: &str = "/zmnt";

const TEMP_DIR_PATH_API_DATA_REVIEWED: &str =  concatcp!(TEMP_PATH_FOLDER, "/vex/api_data_download_reviewed");

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
