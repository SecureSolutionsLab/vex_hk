use std::{
    fs,
    io::{self, Write},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{config::Config, scrape_mod::github::GithubType};

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

    pub fn get_github_api_state(&mut self, ty: GithubType) -> &mut ScraperStateGithubApi {
        match ty {
            GithubType::Reviewed => &mut self.github.api_reviewed,
            GithubType::Unreviewed => &mut self.github.api_unreviewed,
        }
    }

    pub fn save_download_github_api_initialization_start(
        &mut self,
        config: &Config,
        start_time: DateTime<Utc>,
        starting_initialization_link: String,
        ty: GithubType,
    ) {
        let api_state = self.get_github_api_state(ty);
        api_state.in_initialization = true;
        api_state.initialization_started_time = Some(start_time);
        api_state.current_initialization_next_link = Some(starting_initialization_link);
        self.save(config);
    }

    pub fn save_download_github_api_initialization_in_progress(
        &mut self,
        config: &Config,
        current_initialization_next_link: String,
        ty: GithubType,
    ) {
        let api_state = self.get_github_api_state(ty);
        api_state.in_initialization = true;
        api_state.current_initialization_next_link = Some(current_initialization_next_link);
        self.save(config);
    }

    pub fn save_download_github_api_initialization_finished(
        &mut self,
        config: &Config,
        ty: GithubType,
    ) {
        let api_state = self.get_github_api_state(ty);

        api_state.initialized = true;
        api_state.last_update_timestamp = api_state.initialization_started_time;

        api_state.in_initialization = false;
        api_state.current_initialization_next_link = None;
        api_state.initialization_started_time = None;

        self.save(config);
    }

    pub fn save_update_github_api(
        &mut self,
        config: &Config,
        new_update_timestamp: DateTime<Utc>,
        ty: GithubType,
    ) {
        let api_state = self.get_github_api_state(ty);
        assert!(api_state.initialized);

        api_state.last_update_timestamp = Some(new_update_timestamp);
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
    pub api_reviewed: ScraperStateGithubApi,
    pub api_unreviewed: ScraperStateGithubApi,
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

    pub in_initialization: bool,
    pub current_initialization_next_link: Option<String>,
    pub initialization_started_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Tokens {
    pub github: Option<String>,
}
