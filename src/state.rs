use std::{
    fs,
    io::{self, Write},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Config;

const SELF_TEMP_FILE_NAME: &str = "config_status.json";

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ScraperState {
    pub osv: ScraperStateOsv,
    pub github: ScraperStateGithub,
}

#[derive(Debug, thiserror::Error)]
enum SaveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}

impl ScraperState {
    fn save_err(&self, config: &Config) -> Result<(), SaveError> {
        let own_config_location_temp = config.temp_dir_path.join(SELF_TEMP_FILE_NAME);

        let mut writer = io::BufWriter::new(fs::File::create(&own_config_location_temp)?);
        serde_json::to_writer_pretty(&mut writer, self)?;
        writer.flush()?;
        fs::copy(&own_config_location_temp, &config.state_file_location)?;
        Ok(())
    }

    fn save(&self, config: &Config) {
        match self.save_err(config) {
            Ok(()) => log::info!("Scraper state saved."),
            Err(err) => log::error!("FAILED TO UPDATE SCRAPER STATUS\n{err}"),
        }
    }

    pub fn save_osv(&mut self, config: &Config, download_start: DateTime<Utc>) {
        self.osv.last_update_timestamp = Some(download_start);
        self.osv.initialized = true;
        self.save(config);
    }

    pub fn save_download_github_osv_full(
        &mut self,
        config: &Config,
        download_start: DateTime<Utc>,
    ) {
        self.github.osv.last_update_timestamp = Some(download_start);
        self.github.osv.initialized = true;
        self.save(config);
    }

    pub fn save_update_github_osv(&mut self, config: &Config, start_time: DateTime<Utc>) {
        assert!(self.github.osv.initialized);
        self.github.osv.last_update_timestamp = Some(start_time);
        self.save(config);
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScraperStateOsv {
    pub initialized: bool,
    pub last_update_timestamp: Option<DateTime<Utc>>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ScraperStateGithub {
    pub osv: ScraperStateGithubOsv,
    pub api: ScraperStateGithubApi,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScraperStateGithubOsv {
    pub initialized: bool,
    pub last_update_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScraperStateGithubApi {
    pub initialized: bool,
    pub last_update_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Tokens {
    pub github: Option<String>,
}
