use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::default_config as defaults;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub osv: ConfigOsv,
    pub github: ConfigGithub,
    pub tokens: Tokens,
    /// path for storing temporary items
    pub temp_dir_path: PathBuf,
    pub state_file_location: PathBuf,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            osv: ConfigOsv::default(),
            github: ConfigGithub::default(),
            tokens: Tokens::default(),
            temp_dir_path: PathBuf::from(defaults::TEMP_DIR_LOCATION),
            state_file_location: PathBuf::from(defaults::STATE_FILE_LOCATION),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigOsv {
    pub table_name: String,
    pub full_data_url: String,
    pub index: String,
    /// Won't forbid manual updates
    pub enable_update: bool,
}

impl Default for ConfigOsv {
    fn default() -> Self {
        Self {
            table_name: defaults::osv::OSV_TABLE_NAME.to_owned(),
            full_data_url: defaults::osv::FULL_DATA_URL.to_owned(),
            index: defaults::osv::INDEX.to_owned(),
            enable_update: defaults::ENABLE_OSV,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ConfigGithub {
    pub osv: ConfigGithubOsv,
    pub api: ConfigGithubApi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigGithubOsv {
    pub url: String,
    pub reviewed_table_name: String,
    pub unreviewed_table_name: String,
    /// Won't forbid manual updates
    pub enable_update: bool,
    /// If true, will use the api for small updates instead of redownloading all data
    pub use_api_for_update: bool,
    /// Threshold over which a full update is started instead of a file by file one
    pub full_download_threshold: usize,
    /// Where to get commits from the API
    pub commits_url: String,
}

impl Default for ConfigGithubOsv {
    fn default() -> Self {
        Self {
            url: defaults::github::repository::URL.to_owned(),
            reviewed_table_name: defaults::github::repository::REVIEWED_TABLE_NAME.to_owned(),
            unreviewed_table_name: defaults::github::repository::UNREVIEWED_TABLE_NAME.to_owned(),
            enable_update: defaults::ENABLE_GITHUB_OSV,

            full_download_threshold: defaults::github::repository::UPDATE_THRESHOLD,
            use_api_for_update: defaults::USE_API_FOR_GITHUB_OSV,
            commits_url: defaults::github::repository::COMMITS_URL.to_owned(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigGithubApi {
    pub url: String,
    pub reviewed_table_name: String,
    pub unreviewed_table_name: String,
    /// Table name for storing incomplete data during initial population
    pub reviewed_incomplete_table_name: String,
    /// Table name for storing incomplete data during initial population
    pub unreviewed_incomplete_table_name: String,
    pub enable_update: bool,
}

impl Default for ConfigGithubApi {
    fn default() -> Self {
        Self {
            url: defaults::github::api::URL.to_owned(),
            reviewed_table_name: defaults::github::api::REVIEWED_TABLE_NAME.to_owned(),
            unreviewed_table_name: defaults::github::api::UNREVIEWED_TABLE_NAME.to_owned(),
            reviewed_incomplete_table_name: defaults::github::api::INCOMPLETE_REVIEWED_TABLE_NAME
                .to_owned(),
            unreviewed_incomplete_table_name:
                defaults::github::api::INCOMPLETE_UNREVIEWED_TABLE_NAME.to_owned(),
            enable_update: defaults::ENABLE_GITHUB_API,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Tokens {
    pub github: Option<String>,
}
