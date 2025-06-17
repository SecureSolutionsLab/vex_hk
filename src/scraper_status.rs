use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::default_config as defaults;

const SELF_TEMP_FILE_NAME: &str = "config_status.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct ScraperStatus {
    pub osv: ScraperStatusOsv,
    pub github: ScraperStatusGithub,
    pub tokens: Tokens,
    /// path for storing temporary items
    pub temp_dir_path: PathBuf,
    #[serde(skip_serializing, skip_deserializing)]
    own_config_location: PathBuf,
    #[serde(skip_serializing, skip_deserializing)]
    own_config_location_temp: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum SaveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}

impl ScraperStatus {
    fn save_err(&self) -> Result<(), SaveError> {
        let mut writer = io::BufWriter::new(fs::File::create(&self.own_config_location_temp)?);
        serde_json::to_writer_pretty(&mut writer, self)?;
        writer.flush()?;
        fs::copy(&self.own_config_location_temp, &self.own_config_location);
        Ok(())
    }

    fn save(&self) {
        match self.save_err() {
            Ok(()) => log::info!("Config status saved."),
            Err(err) => log::error!("CONFIG STATUS ERROR: FAILED TO SAVE\n{}", err),
        }
    }

    pub fn save_download_osv_full(&mut self, download_start: DateTime<Utc>) {
        self.osv.last_update_timestamp = Some(download_start);
        self.osv.initialized = true;
        self.save();
    }

    pub fn save_download_github_osv_full(&mut self, download_start: DateTime<Utc>) {
        self.github.osv.last_update_timestamp = Some(download_start);
        self.github.osv.initialized = true;
        self.save();
    }

    pub fn save_update_github_osv_completed(&mut self, start_time: DateTime<Utc>) {
        assert_eq!(self.github.osv.initialized, true);
        self.github.osv.last_update_timestamp = Some(start_time);
        self.github.osv.api_update_progress_file_reviewed = None;
        self.github.osv.api_update_progress_file_unreviewed = None;
        self.save();
    }

    pub fn save_update_github_osv_postponed_reviewed(&mut self, path: PathBuf) {
        self.github.osv.api_update_progress_file_reviewed = Some(path);
        self.save();
    }

    pub fn save_update_github_osv_postponed_unreviewed(&mut self, path: PathBuf) {
        self.github.osv.api_update_progress_file_unreviewed = Some(path);
        self.save();
    }
}

impl Default for ScraperStatus {
    fn default() -> Self {
        let temp_dir_path = PathBuf::from(defaults::TEMP_DIR_LOCATION);
        let own_config_location_temp = temp_dir_path.join(SELF_TEMP_FILE_NAME);
        Self {
            osv: ScraperStatusOsv::default(),
            github: ScraperStatusGithub::default(),
            tokens: Tokens::default(),
            temp_dir_path,
            own_config_location: PathBuf::from(defaults::TEMP_DIR_LOCATION),
            own_config_location_temp,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScraperStatusOsv {
    pub table_name: String,
    pub full_data_url: String,
    pub index: String,

    pub enable_update: bool,
    pub initialized: bool,
    pub last_update_timestamp: Option<DateTime<Utc>>,
}

impl Default for ScraperStatusOsv {
    fn default() -> Self {
        Self {
            table_name: defaults::osv::OSV_TABLE_NAME.to_owned(),
            full_data_url: defaults::osv::FULL_DATA_URL.to_owned(),
            index: defaults::osv::INDEX.to_owned(),
            enable_update: true,
            initialized: false,
            last_update_timestamp: None,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ScraperStatusGithub {
    pub osv: ScraperStatusGithubOsv,
    pub api: ScraperStatusGithubApi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScraperStatusGithubOsv {
    pub url: String,
    pub reviewed_table_name: String,
    pub unreviewed_table_name: String,
    pub enable_update: bool,
    /// If true, will use the api for small updates instead of redownloading all data
    pub use_api_for_update: bool,
    pub initialized: bool,
    pub last_update_timestamp: Option<DateTime<Utc>>,
    /// Api update started but not completed
    pub api_update_progress_file_reviewed: Option<PathBuf>,
    pub api_update_progress_file_unreviewed: Option<PathBuf>,
    /// What is the threshold where a full update is started instead of a file by file one
    pub full_download_threshold: usize,
}

impl Default for ScraperStatusGithubOsv {
    fn default() -> Self {
        Self {
            url: defaults::github::repository::URL.to_owned(),
            reviewed_table_name: defaults::github::repository::REVIEWED_TABLE_NAME.to_owned(),
            unreviewed_table_name: defaults::github::repository::UNREVIEWED_TABLE_NAME.to_owned(),
            enable_update: true,
            initialized: false,
            last_update_timestamp: None,
            full_download_threshold: defaults::github::repository::UPDATE_THRESHOLD,
            api_update_progress_file_reviewed: None,
            api_update_progress_file_unreviewed: None,
            use_api_for_update: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScraperStatusGithubApi {
    pub url: String,
    pub reviewed_table_name: String,
    pub unreviewed_table_name: String,
    /// Table name for storing incomplete data during initial population
    pub reviewed_incomplete_table_name: String,
    /// Table name for storing incomplete data during initial population
    pub unreviewed_incomplete_table_name: String,
    pub enable_update: bool,
    pub initialized: bool,
    pub last_update_timestamp: Option<DateTime<Utc>>,
}

impl Default for ScraperStatusGithubApi {
    fn default() -> Self {
        Self {
            url: defaults::github::api::URL.to_owned(),
            reviewed_table_name: defaults::github::api::REVIEWED_TABLE_NAME.to_owned(),
            unreviewed_table_name: defaults::github::api::UNREVIEWED_TABLE_NAME.to_owned(),
            reviewed_incomplete_table_name: defaults::github::api::INCOMPLETE_REVIEWED_TABLE_NAME
                .to_owned(),
            unreviewed_incomplete_table_name:
                defaults::github::api::INCOMPLETE_UNREVIEWED_TABLE_NAME.to_owned(),
            enable_update: true,
            initialized: false,
            last_update_timestamp: None,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Tokens {
    pub github: Option<String>,
}
